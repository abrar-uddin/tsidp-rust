//! Regression tests for the 2026-10 security review: attribute escaping in the
//! admin UI, the CSP, refresh-token re-validation and reuse detection, the
//! client-credential fallback in STS/introspection, and redirect URI policy.

mod support;

use axum::body::Body;
use axum::http::{StatusCode, header};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

use support::*;
use tsidp::clients::Client;
use tsidp::config::Config;
use tsidp::identity::Identity;
use tsidp::server::{AppState, tailnet_router, test_state};

async fn add_client(st: &AppState, name: &str, public: bool) -> Client {
    let c = Client::new(name, vec!["https://app.example.com/cb".into()], public);
    st.clients.insert(c.clone()).await.unwrap();
    c
}

/// Authorization code -> token response for `client`.
async fn login(app: &axum::Router, client: &Client) -> serde_json::Value {
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid%20email",
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
    let code = loc
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

async fn refresh(app: &axum::Router, client: &Client, rt: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={rt}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

#[tokio::test]
async fn client_name_cannot_break_out_of_attributes() {
    let st = test_state(Config::for_tests(), None).await;
    let app = tailnet_router(st.clone());
    let payload = r#"x" autofocus onfocus="alert(document.domain)"#;

    // Plant it through dynamic client registration (needs only allow_dcr).
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"client_name": payload, "redirect_uris": ["https://evil/cb"]})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let id = body_json(resp).await["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            tailnet_req("GET", &format!("/edit/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-security-policy"],
        tsidp::server::ui::CSP
    );
    let html = body_text(resp).await;
    assert!(
        !html.contains(r#"onfocus="alert"#),
        "payload reached the DOM unescaped:\n{html}"
    );
    assert!(
        html.contains(r#"value="x&quot; autofocus onfocus=&quot;alert(document.domain)""#),
        "{html}"
    );
    assert!(!html.contains("<script>"), "no inline script: {html}");
    assert!(!html.contains("onclick="), "no inline handlers: {html}");

    // The JS moved to its own resource.
    let resp = app
        .oneshot(tailnet_req("GET", "/ui.js").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/javascript")
    );
}

#[tokio::test]
async fn refresh_token_replay_revokes_the_whole_family() {
    let st = test_state(Config::for_tests(), None).await;
    let app = tailnet_router(st.clone());
    let c = add_client(&st, "rp", false).await;
    let first = login(&app, &c).await;
    let rt1 = first["refresh_token"].as_str().unwrap().to_string();

    let (status, second) = refresh(&app, &c, &rt1).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let at2 = second["access_token"].as_str().unwrap().to_string();
    let rt2 = second["refresh_token"].as_str().unwrap().to_string();
    assert!(st.tokens.get_access(&at2).is_some());

    // Replaying the already-used token is treated as theft...
    let (status, body) = refresh(&app, &c, &rt1).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("already used")
    );
    // ...and takes the legitimate successor tokens down with it.
    assert!(
        st.tokens.get_access(&at2).is_none(),
        "access token survived"
    );
    let (status, _) = refresh(&app, &c, &rt2).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "refresh token survived");
    assert_eq!(st.tokens.counts(), (0, 0, 0));
}

#[tokio::test]
async fn refresh_revalidates_identity_and_recomputes_grants() {
    // A snapshot without a node address cannot be re-validated: fail closed.
    let mut id = Identity::dev("alice@example.com");
    id.addresses.clear();
    let st = test_state(Config::for_tests(), Some(id)).await;
    let app = tailnet_router(st.clone());
    let c = add_client(&st, "rp", false).await;
    let tok = login(&app, &c).await;
    let (status, body) = refresh(&app, &c, tok["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("re-validate")
    );

    // The dev resolver answers every address with the same identity, so a
    // normal snapshot refreshes fine and carries the resolver's current grant.
    let st = test_state(Config::for_tests(), None).await;
    let app = tailnet_router(st.clone());
    let c = add_client(&st, "rp", false).await;
    let tok = login(&app, &c).await;
    let (status, body) = refresh(&app, &c, tok["refresh_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ar = st
        .tokens
        .get_access(body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(ar.identity.login_name, "alice@example.com");
}

#[tokio::test]
async fn wrong_client_secret_never_degrades_to_node_identity() {
    let mut cfg = Config::for_tests();
    cfg.enable_sts = true;
    let st = test_state(cfg, None).await;
    let app = tailnet_router(st.clone());
    let c = add_client(&st, "rp", false).await;
    let tok = login(&app, &c).await;
    let at = tok["access_token"].as_str().unwrap().to_string();

    let exchange = |auth: Option<String>| {
        let mut b = tailnet_req("POST", "/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        b.body(Body::from(format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token={at}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&audience=https%3A%2F%2Fapi"
        )))
        .unwrap()
    };
    // bad secret: refused
    let resp = app
        .clone()
        .oneshot(exchange(Some(basic(&c.id, "WRONG"))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // unknown client id: refused
    let resp = app
        .clone()
        .oneshot(exchange(Some(basic("nobody", "x"))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // no credentials at all: the tailnet node is the client
    let resp = app.clone().oneshot(exchange(None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // right secret: the registered client is the client
    let resp = app
        .clone()
        .oneshot(exchange(Some(basic(&c.id, &c.secret))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Same rule for introspection.
    let introspect = |auth: Option<String>| {
        let mut b = tailnet_req("POST", "/introspect")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        b.body(Body::from(format!("token={at}"))).unwrap()
    };
    let resp = app
        .clone()
        .oneshot(introspect(Some(basic(&c.id, "WRONG"))))
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["active"], false);
    let resp = app.oneshot(introspect(None)).await.unwrap();
    assert_eq!(body_json(resp).await["active"], true);
}

#[tokio::test]
async fn http_redirect_uris_need_loopback_or_opt_in() {
    let register = |st: Arc<AppState>, uri: &str| {
        let body = json!({"redirect_uris": [uri]}).to_string();
        async move {
            tailnet_router(st)
                .oneshot(
                    tailnet_req("POST", "/register")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }
    };
    let strict = test_state(Config::for_tests(), None).await;
    assert_eq!(
        register(strict.clone(), "http://localhost:1234/cb").await,
        StatusCode::CREATED
    );
    assert_eq!(
        register(strict.clone(), "http://grafana.internal/login").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        register(strict, "https://grafana.internal/login").await,
        StatusCode::CREATED
    );
    let mut cfg = Config::for_tests();
    cfg.allow_http_redirect_uris = true;
    let lax = test_state(cfg, None).await;
    assert_eq!(
        register(lax, "http://grafana.internal/login").await,
        StatusCode::CREATED
    );
}
