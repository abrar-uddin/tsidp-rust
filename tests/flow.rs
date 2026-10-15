//! End-to-end tests through the axum routers with a static identity and an
//! in-memory store: no tailscaled, no network.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use std::sync::Arc;
use tower::ServiceExt;

use tsidp::clients::Client;
use tsidp::config::Config;
use tsidp::identity::Identity;
use tsidp::server::{AppState, cluster_router, tailnet_router, test_state};

const PEER: &str = "100.64.0.7";

async fn state() -> Arc<AppState> {
    test_state(Config::for_tests(), None).await
}

fn tailnet_req(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-forwarded-for", PEER)
        .header("host", "tsidp.dev.example.ts.net")
}

async fn body_json(resp: axum::response::Response) -> Value {
    let b = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&b)
        .unwrap_or_else(|e| panic!("not json ({e}): {}", String::from_utf8_lossy(&b)))
}

async fn body_text(resp: axum::response::Response) -> String {
    String::from_utf8(to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap()
}

fn query_param(location: &str, key: &str) -> Option<String> {
    let u = url::Url::parse(location).unwrap();
    u.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn basic(id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
    )
}

async fn add_client(st: &AppState, public: bool) -> Client {
    let c = Client::new(
        "Test App",
        vec!["https://app.example.com/cb".into()],
        public,
    );
    st.clients.insert(c.clone()).await.unwrap();
    c
}

fn decode_id_token(st: &AppState, token: &str, aud: &str) -> Map<String, Value> {
    let (n, e) = st.key.public_components();
    let dk = DecodingKey::from_rsa_components(n, e).unwrap();
    let mut v = Validation::new(Algorithm::RS256);
    v.set_audience(&[aud]);
    v.set_issuer(&["https://tsidp.dev.example.ts.net"]);
    jsonwebtoken::decode::<Map<String, Value>>(token, &dk, &v)
        .unwrap()
        .claims
}

#[tokio::test]
async fn discovery_and_jwks() {
    let st = state().await;
    let app = tailnet_router(st.clone());
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("GET", "/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(doc["issuer"], "https://tsidp.dev.example.ts.net");
    assert_eq!(
        doc["registration_endpoint"],
        "https://tsidp.dev.example.ts.net/register"
    );
    assert!(
        doc["scopes_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "offline_access")
    );
    assert!(
        doc["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "none")
    );

    let resp = app
        .oneshot(
            tailnet_req("GET", "/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let jwks = body_json(resp).await;
    assert_eq!(jwks["keys"][0]["kty"], "RSA");
    assert_eq!(jwks["keys"][0]["kid"], st.key.kid_string());
}

#[tokio::test]
async fn full_code_flow_confidential_client() {
    let st = state().await;
    let client = add_client(&st, false).await;
    let app = tailnet_router(st.clone());

    // /authorize -> 302 with code
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid%20email%20profile&state=xyz&nonce=n1",
        client.id
    );
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", &uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert!(loc.starts_with("https://app.example.com/cb?"), "{loc}");
    assert_eq!(query_param(&loc, "state").as_deref(), Some("xyz"));
    let code = query_param(&loc, "code").unwrap();

    // /token with basic auth
    let form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"
    );
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tok = body_json(resp).await;
    assert_eq!(tok["token_type"], "Bearer");
    let claims = decode_id_token(&st, tok["id_token"].as_str().unwrap(), &client.id);
    assert_eq!(claims["sub"], "userid:1");
    assert_eq!(claims["email"], "alice@example.com");
    assert_eq!(claims["preferred_username"], "alice");
    assert_eq!(claims["nonce"], "n1");
    assert_eq!(claims["tailnet"], "example.ts.net");
    assert!(
        claims.get("azp").is_none(),
        "single audience must not carry azp"
    );

    // code is single use
    let form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"
    );
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");

    // /userinfo
    let at = tok["access_token"].as_str().unwrap().to_string();
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("GET", "/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {at}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ui = body_json(resp).await;
    assert_eq!(ui["sub"], "userid:1");
    assert_eq!(ui["email"], "alice@example.com");
    assert_eq!(ui["preferred_username"], "alice");

    // /introspect with client credentials
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(format!("token={at}")))
                .unwrap(),
        )
        .await
        .unwrap();
    let intro = body_json(resp).await;
    assert_eq!(intro["active"], true);
    assert_eq!(intro["client_id"], client.id);
    assert_eq!(intro["scope"], "openid email profile");

    // unauthenticated introspection reveals nothing
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("token={at}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await, serde_json::json!({"active": false}));

    // refresh
    let rt = tok["refresh_token"].as_str().unwrap().to_string();
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={rt}&client_id={}&client_secret={}",
                    client.id, client.secret
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tok2 = body_json(resp).await;
    assert_ne!(tok2["access_token"], tok["access_token"]);

    // refresh tokens are single use
    let resp = app
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={rt}&client_id={}&client_secret={}",
                    client.id, client.secret
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn public_client_requires_pkce_and_no_secret() {
    let st = state().await;
    let client = add_client(&st, true).await;
    assert!(client.is_public());
    let app = tailnet_router(st.clone());

    // Without PKCE: error redirect.
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code",
        client.id
    );
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", &uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let loc = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("invalid_request")
    );

    // With S256 PKCE, as a POST form body (issue #195).
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let form = format!(
        "client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&code_challenge={challenge}&code_challenge_method=S256",
        client.id
    );
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let loc = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let code = query_param(&loc, "code").expect(&loc);

    // Token without verifier fails; with verifier and only client_id succeeds.
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&client_id={}", client.id)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The code was consumed; get a new one.
    let form = format!(
        "client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&code_challenge={challenge}&code_challenge_method=S256",
        client.id
    );
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    let code = query_param(resp.headers()[header::LOCATION].to_str().unwrap(), "code").unwrap();
    let resp = app
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&client_id={}&code_verifier={verifier}",
                    client.id
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tok = body_json(resp).await;
    assert!(tok["id_token"].as_str().is_some());
}

#[tokio::test]
async fn cluster_listener_serves_tokens_but_never_identity() {
    let st = state().await;
    let client = add_client(&st, false).await;
    let tailnet = tailnet_router(st.clone());
    let cluster = cluster_router(st.clone());

    // No /authorize, /register or UI on the cluster listener.
    for path in [
        "/authorize?client_id=x&redirect_uri=y",
        "/register",
        "/",
        "/clients/",
    ] {
        let resp = cluster
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
    // Discovery works but hides registration.
    let resp = cluster
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header("x-forwarded-for", PEER)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let doc = body_json(resp).await;
    assert!(doc.get("registration_endpoint").is_none());

    // Code from the tailnet, token from the cluster.
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
        client.id
    );
    let resp = tailnet
        .oneshot(tailnet_req("GET", &uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let code = query_param(resp.headers()[header::LOCATION].to_str().unwrap(), "code").unwrap();
    let resp = cluster
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tok = body_json(resp).await;
    let at = tok["access_token"].as_str().unwrap();
    let resp = cluster
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {at}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn funnel_and_cluster_callers_cannot_authorize_or_register() {
    let st = state().await;
    let client = add_client(&st, false).await;
    let app = tailnet_router(st.clone());
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
        client.id
    );
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("GET", &uri)
                .header("tailscale-funnel-request", "?1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let loc = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(query_param(&loc, "error").as_deref(), Some("access_denied"));

    let resp = app
        .oneshot(
            tailnet_req("POST", "/register")
                .header("tailscale-funnel-request", "?1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"redirect_uris":["https://x/cb"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn dynamic_client_registration_and_clients_api() {
    let inspector = || {
        tailnet_req("POST", "/register")
            .header(header::CONTENT_TYPE, "application/json")
            .header("origin", "http://localhost:6274")
            .header("sec-fetch-site", "cross-site")
            .body(Body::from(r#"{"client_name":"inspector","redirect_uris":["http://localhost:6274/oauth/callback"],"token_endpoint_auth_method":"none"}"#))
            .unwrap()
    };

    // Default: a browser page on another origin cannot register clients with
    // the visitor's ambient tailnet identity, but curl-style callers can.
    let strict = tailnet_router(state().await);
    let resp = strict.clone().oneshot(inspector()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = strict
        .oneshot(
            tailnet_req("POST", "/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"client_name":"operator","redirect_uris":["https://op/cb"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Opt in for browser-based MCP clients.
    let mut cfg = Config::for_tests();
    cfg.allow_cross_origin_dcr = true;
    let st = test_state(cfg, None).await;
    let app = tailnet_router(st.clone());
    let resp = app.clone().oneshot(inspector()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(resp.headers()["access-control-allow-origin"], "*");
    let reg = body_json(resp).await;
    let id = reg["client_id"].as_str().unwrap().to_string();
    assert_eq!(reg["token_endpoint_auth_method"], "none");
    assert!(reg.get("client_secret").is_none());
    assert!(st.clients.get(&id).unwrap().is_public());

    // Clients API: list hides secrets, delete works, CSRF blocks cross-site mutation.
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", "/clients/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let list = body_json(resp).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(list[0].get("client_secret").is_none());

    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/clients/new")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "cross-site")
                .body(Body::from("name=evil&redirect_uri=https://evil/cb"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/clients/new")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from("name=cli&redirect_uri=https://cli/cb"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    assert!(created["client_secret"].as_str().unwrap().len() == 64);

    let resp = app
        .clone()
        .oneshot(
            tailnet_req("DELETE", &format!("/clients/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(st.clients.get(&id).is_none());
}

#[tokio::test]
async fn admin_ui_renders_and_denies_without_grant() {
    let st = state().await;
    let app = tailnet_router(st.clone());
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", "/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(html.contains("No OIDC clients configured"));

    // Create via the form, then the list shows it.
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/new")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(
                    "name=Grafana&redirect_uris=https%3A%2F%2Fgrafana%2Flogin%2Fgeneric_oauth",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(html.contains("Client Secret"));
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", "/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(body_text(resp).await.contains("Grafana"));

    // A user without the grant is refused.
    let mut id = Identity::dev("bob@example.com");
    id.cap_rules.clear();
    let st2 = test_state(Config::for_tests(), Some(id)).await;
    let app2 = tailnet_router(st2);
    let resp = app2
        .oneshot(tailnet_req("GET", "/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tagged_nodes_are_refused_unless_enabled() {
    let mut id = Identity::dev("tagged-devices");
    id.tags = vec!["tag:ci".into()];
    let st = test_state(Config::for_tests(), Some(id.clone())).await;
    let client = add_client(&st, false).await;
    let app = tailnet_router(st.clone());
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
        client.id
    );
    let resp = app
        .oneshot(tailnet_req("GET", &uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let loc = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(query_param(&loc, "error").as_deref(), Some("access_denied"));

    let mut cfg = Config::for_tests();
    cfg.allow_tagged_nodes = true;
    let st = test_state(cfg, Some(id)).await;
    let client = add_client(&st, false).await;
    let app = tailnet_router(st.clone());
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid%20profile",
        client.id
    );
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", &uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let code = query_param(resp.headers()[header::LOCATION].to_str().unwrap(), "code").unwrap();
    let resp = app
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tok = body_json(resp).await;
    let claims = decode_id_token(&st, tok["id_token"].as_str().unwrap(), &client.id);
    assert_eq!(claims["sub"], "node:nDEV");
    assert_eq!(claims["tags"], serde_json::json!(["tag:ci"]));
    assert!(claims.get("email").is_none());
}

#[tokio::test]
async fn jwt_access_tokens_and_extra_claims_and_groups() {
    let mut cfg = Config::for_tests();
    cfg.jwt_access_tokens = true;
    let mut id = Identity::dev("alice@example.com");
    id.cap_rules = vec![
        serde_json::from_value(serde_json::json!({
            "allow_admin_ui": true, "includeInUserInfo": true,
            "extraClaims": {"email_verified": true, "roles": ["admin"], "sub": "evil"},
            "groups": ["platform"], "users": ["*"], "resources": ["https://api.example.com"]
        }))
        .unwrap(),
    ];
    let st = test_state(cfg, Some(id)).await;
    let client = add_client(&st, false).await;
    let app = tailnet_router(st.clone());
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid%20email",
        client.id
    );
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", &uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let code = query_param(resp.headers()[header::LOCATION].to_str().unwrap(), "code").unwrap();
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&resource=https%3A%2F%2Fapi.example.com"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tok = body_json(resp).await;
    let claims = decode_id_token(&st, tok["id_token"].as_str().unwrap(), &client.id);
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["roles"], serde_json::json!(["admin"]));
    assert_eq!(claims["groups"], serde_json::json!(["platform"]));
    assert_eq!(claims["sub"], "userid:1");
    assert_eq!(claims["azp"], client.id);
    assert_eq!(
        claims["aud"],
        serde_json::json!([client.id, "https://api.example.com"])
    );

    // The access token is a verifiable JWT too (RFC 9068).
    let at = tok["access_token"].as_str().unwrap();
    let at_claims = decode_id_token(&st, at, &client.id);
    assert_eq!(at_claims["client_id"], client.id);
    assert_eq!(at_claims["scope"], "openid email");
    let header = jsonwebtoken::decode_header(at).unwrap();
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));

    // ...and still works for userinfo, which includes the extra claims.
    let resp = app
        .oneshot(
            tailnet_req("GET", "/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {at}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let ui = body_json(resp).await;
    assert_eq!(ui["email_verified"], true);
    assert_eq!(ui["groups"], serde_json::json!(["platform"]));
}

#[tokio::test]
async fn token_exchange() {
    let mut cfg = Config::for_tests();
    cfg.enable_sts = true;
    let st = test_state(cfg, None).await;
    let client = add_client(&st, false).await;
    let gateway = Client::new("gateway", vec!["https://gw/cb".into()], false);
    st.clients.insert(gateway.clone()).await.unwrap();
    let app = tailnet_router(st.clone());

    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
        client.id
    );
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", &uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let code = query_param(resp.headers()[header::LOCATION].to_str().unwrap(), "code").unwrap();
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb")))
                .unwrap(),
        )
        .await
        .unwrap();
    let tok = body_json(resp).await;
    let subject = tok["access_token"].as_str().unwrap();

    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&gateway.id, &gateway.secret))
                .body(Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token={subject}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&audience=https%3A%2F%2Fmcp.example.com"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ex = body_json(resp).await;
    assert_eq!(
        ex["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
    let new_at = ex["access_token"].as_str().unwrap();

    let resp = app
        .oneshot(
            tailnet_req("POST", "/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&gateway.id, &gateway.secret))
                .body(Body::from(format!("token={new_at}")))
                .unwrap(),
        )
        .await
        .unwrap();
    let intro = body_json(resp).await;
    assert_eq!(intro["active"], true);
    assert_eq!(intro["aud"], serde_json::json!(["https://mcp.example.com"]));
    assert_eq!(intro["client_id"], gateway.id);
}

#[tokio::test]
async fn error_shapes() {
    let st = state().await;
    let app = tailnet_router(st.clone());
    // Unknown client: direct 400, no redirect.
    let resp = app
        .clone()
        .oneshot(
            tailnet_req(
                "GET",
                "/authorize?client_id=nope&redirect_uri=https%3A%2F%2Fx%2Fcb",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_client");

    // Unsupported grant type.
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=password"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "unsupported_grant_type");

    // Userinfo without bearer: RFC 6750 header.
    let resp = app
        .oneshot(tailnet_req("GET", "/userinfo").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        resp.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .starts_with("Bearer error=")
    );
}
