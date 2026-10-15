//! Discovery served on the cluster listener must advertise
//! endpoints that are reachable from the cluster, while `issuer` and
//! `authorization_endpoint` stay on the tailnet (or, with
//! `--cluster-issuer-url`, the cluster listener acts as a second issuer).

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use std::sync::Arc;
use tower::ServiceExt;

use support::*;
use tsidp::clients::Client;
use tsidp::config::Config;
use tsidp::server::{AppState, cluster_router, tailnet_router, test_state};
use tsidp::store::MemoryStore;

const TAILNET: &str = "https://tsidp.dev.example.ts.net";
const SVC: &str = "http://tsidp.tsidp.svc:8080";

fn cfg(public: Option<&str>, issuer: Option<&str>) -> Config {
    let mut c = Config::for_tests();
    c.cluster_listen = Some("127.0.0.1:0".into());
    c.cluster_public_url = public.map(|s| s.to_string());
    c.cluster_issuer_url = issuer.map(|s| s.to_string());
    c
}

async fn discovery(
    app: &axum::Router,
    path: &str,
    host: Option<&str>,
    extra: &[(&str, &str)],
) -> Value {
    let mut b = Request::builder().uri(path);
    if let Some(h) = host {
        b = b.header(header::HOST, h);
    }
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{path}");
    body_json(resp).await
}

fn assert_split(doc: &Value, issuer: &str, base: &str) {
    assert_eq!(doc["issuer"], issuer);
    assert_eq!(
        doc["authorization_endpoint"],
        format!("{TAILNET}/authorize"),
        "browsers go to the tailnet"
    );
    assert_eq!(doc["token_endpoint"], format!("{base}/token"));
    assert_eq!(doc["introspection_endpoint"], format!("{base}/introspect"));
    assert_eq!(doc["jwks_uri"], format!("{base}/.well-known/jwks.json"));
    if doc.get("userinfo_endpoint").is_some() {
        assert_eq!(doc["userinfo_endpoint"], format!("{base}/userinfo"));
    }
    assert!(
        doc.get("registration_endpoint").is_none(),
        "never advertised on the cluster listener"
    );
}

const DOCS: [&str; 2] = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
];

#[tokio::test]
async fn cluster_discovery_uses_host_header_by_default_and_ignores_forwarded_headers() {
    let st = test_state(cfg(None, None), None).await;
    let app = cluster_router(st.clone());
    for path in DOCS {
        let doc = discovery(&app, path, Some("tsidp.tsidp.svc:8080"), &[]).await;
        assert_split(&doc, TAILNET, SVC);
        // forwarded headers are not trusted on this listener: same document
        let spoofed = discovery(
            &app,
            path,
            Some("tsidp.tsidp.svc:8080"),
            &[
                ("x-forwarded-host", "evil.example"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-for", "100.64.0.1"),
            ],
        )
        .await;
        assert_eq!(spoofed, doc);
        // a ClusterIP works just as well
        let ip = discovery(&app, path, Some("10.43.0.5:8080"), &[]).await;
        assert_eq!(ip["token_endpoint"], "http://10.43.0.5:8080/token");
        // without a Host header there is nothing better than the tailnet URLs
        let bare = discovery(&app, path, None, &[]).await;
        assert_eq!(bare["token_endpoint"], format!("{TAILNET}/token"));
        // a garbage Host header is not echoed
        let bad = discovery(&app, path, Some("evil.example/x y"), &[]).await;
        assert_eq!(bad["token_endpoint"], format!("{TAILNET}/token"));
    }
}

#[tokio::test]
async fn cluster_public_url_wins_over_host_and_tailnet_output_is_unchanged() {
    let st = test_state(
        cfg(Some("http://tsidp.tsidp.svc.cluster.local:8080/"), None),
        None,
    )
    .await;
    let cluster = cluster_router(st.clone());
    let tailnet = tailnet_router(st.clone());
    let plain = test_state(cfg(None, None), None).await;
    let tailnet_plain = tailnet_router(plain);
    for path in DOCS {
        let doc = discovery(&cluster, path, Some("whatever:1"), &[]).await;
        assert_split(&doc, TAILNET, "http://tsidp.tsidp.svc.cluster.local:8080");

        // Tailnet document: every URL on the tailnet issuer, identical with or
        // without the cluster flags set.
        let t = discovery(
            &tailnet,
            path,
            Some("tsidp.dev.example.ts.net"),
            &[("x-forwarded-for", PEER)],
        )
        .await;
        for key in [
            "authorization_endpoint",
            "token_endpoint",
            "introspection_endpoint",
            "jwks_uri",
            "registration_endpoint",
        ] {
            assert!(
                t[key].as_str().unwrap().starts_with(TAILNET),
                "{key}: {}",
                t[key]
            );
        }
        assert_eq!(t["issuer"], TAILNET);
        let t2 = discovery(
            &tailnet_plain,
            path,
            Some("tsidp.dev.example.ts.net"),
            &[("x-forwarded-for", PEER)],
        )
        .await;
        assert_eq!(t, t2);
    }
}

fn decode(st: &AppState, token: &str, aud: &str, iss: &str) -> Map<String, Value> {
    let (n, e) = st.key.public_components();
    let dk = DecodingKey::from_rsa_components(n, e).unwrap();
    let mut v = Validation::new(Algorithm::RS256);
    v.set_audience(&[aud]);
    v.set_issuer(&[iss]);
    jsonwebtoken::decode::<Map<String, Value>>(token, &dk, &v)
        .unwrap()
        .claims
}

async fn code_for(tailnet: &axum::Router, client: &Client) -> String {
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp%2Fcb&scope=openid%20email",
        client.id
    );
    let resp = tailnet
        .clone()
        .oneshot(tailnet_req("GET", &uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    query_param(resp.headers()[header::LOCATION].to_str().unwrap(), "code").unwrap()
}

async fn redeem(app: &axum::Router, client: &Client, code: &str, host: &str) -> Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::HOST, host)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp%2Fcb"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

async fn introspect(app: &axum::Router, client: &Client, token: &str) -> Value {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(format!("token={token}")))
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(resp).await
}

#[tokio::test]
async fn tokens_minted_on_the_cluster_listener_keep_the_tailnet_issuer_by_default() {
    let st = test_state(cfg(Some(SVC), None), None).await;
    let client = Client::new("headlamp", vec!["https://app/cb".into()], false);
    st.clients.insert(client.clone()).await.unwrap();
    let tailnet = tailnet_router(st.clone());
    let cluster = cluster_router(st.clone());

    let code = code_for(&tailnet, &client).await;
    let tok = redeem(&cluster, &client, &code, "tsidp.tsidp.svc:8080").await;
    let claims = decode(&st, tok["id_token"].as_str().unwrap(), &client.id, TAILNET);
    assert_eq!(
        claims["iss"], TAILNET,
        "kube-apiserver validates against the tailnet issuer"
    );
    let intro = introspect(&cluster, &client, tok["access_token"].as_str().unwrap()).await;
    assert_eq!(intro["iss"], TAILNET);
}

#[tokio::test]
async fn cluster_issuer_url_makes_the_cluster_listener_a_second_issuer() {
    let st = test_state(cfg(None, Some("http://tsidp.tsidp.svc:8080")), None).await;
    let client = Client::new("argocd", vec!["https://app/cb".into()], false);
    st.clients.insert(client.clone()).await.unwrap();
    let tailnet = tailnet_router(st.clone());
    let cluster = cluster_router(st.clone());

    // discovery: issuer == the URL the RP fetched it from; endpoints default to it too
    for path in DOCS {
        let doc = discovery(&cluster, path, Some("tsidp.tsidp.svc:8080"), &[]).await;
        assert_split(&doc, SVC, SVC);
    }

    // token minted via the cluster listener carries the cluster issuer...
    let code = code_for(&tailnet, &client).await;
    let tok = redeem(&cluster, &client, &code, "tsidp.tsidp.svc:8080").await;
    let claims = decode(&st, tok["id_token"].as_str().unwrap(), &client.id, SVC);
    assert_eq!(claims["iss"], SVC);
    assert_eq!(
        introspect(&cluster, &client, tok["access_token"].as_str().unwrap()).await["iss"],
        SVC
    );

    // ...while the same client via the tailnet gets the tailnet issuer, and
    // tokens from either listener work at either userinfo
    let code = code_for(&tailnet, &client).await;
    let tok2 = redeem(&tailnet, &client, &code, "tsidp.dev.example.ts.net").await;
    let claims2 = decode(&st, tok2["id_token"].as_str().unwrap(), &client.id, TAILNET);
    assert_eq!(claims2["iss"], TAILNET);
    assert_eq!(
        introspect(&tailnet, &client, tok2["access_token"].as_str().unwrap()).await["iss"],
        TAILNET
    );
    for (app, at) in [
        (&tailnet, tok["access_token"].as_str().unwrap()),
        (&cluster, tok2["access_token"].as_str().unwrap()),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/userinfo")
                    .header("x-forwarded-for", PEER)
                    .header(header::AUTHORIZATION, format!("Bearer {at}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // refresh on the cluster listener keeps the cluster issuer; the same refresh
    // chain moved to the tailnet listener gets the tailnet issuer
    let rt = tok["refresh_token"].as_str().unwrap();
    let resp = cluster
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={rt}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let tok3 = body_json(resp).await;
    assert_eq!(
        decode(&st, tok3["id_token"].as_str().unwrap(), &client.id, SVC)["iss"],
        SVC
    );

    // JWT access tokens and exchanged tokens follow the same rule
    let mut c = cfg(None, Some(SVC));
    c.jwt_access_tokens = true;
    c.enable_sts = true;
    let st2 = test_state(c, None).await;
    let client2 = Client::new("gw", vec!["https://app/cb".into()], false);
    st2.clients.insert(client2.clone()).await.unwrap();
    let tailnet2 = tailnet_router(st2.clone());
    let cluster2 = cluster_router(st2.clone());
    let code = code_for(&tailnet2, &client2).await;
    let tok = redeem(&cluster2, &client2, &code, "tsidp.tsidp.svc:8080").await;
    let at = tok["access_token"].as_str().unwrap();
    assert_eq!(decode(&st2, at, &client2.id, SVC)["iss"], SVC);
    let resp = cluster2
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client2.id, &client2.secret))
                .body(Body::from(format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token={at}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&audience=https%3A%2F%2Fsvc"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ex = body_json(resp).await;
    let ex_at = ex["access_token"].as_str().unwrap();
    assert_eq!(decode(&st2, ex_at, "https://svc", SVC)["iss"], SVC);
    assert_eq!(introspect(&cluster2, &client2, ex_at).await["iss"], SVC);
}

#[tokio::test]
async fn cluster_flags_are_validated_at_startup() {
    let store = || Arc::new(MemoryStore::default());
    let mut c = Config::for_tests();
    c.cluster_public_url = Some(SVC.into());
    let err = AppState::build_with(c, store())
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("requires --cluster-listen"), "{err}");

    let mut c = Config::for_tests();
    c.cluster_listen = Some("127.0.0.1:0".into());
    c.cluster_issuer_url = Some("not a url".into());
    let err = AppState::build_with(c, store())
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("--cluster-issuer-url"), "{err}");

    let st = AppState::build_with(
        cfg(Some("http://svc:8080///"), Some("http://svc:8080")),
        store(),
    )
    .await
    .unwrap();
    assert_eq!(st.cluster_public.as_ref().unwrap().url, "http://svc:8080");
    assert_eq!(st.cluster_issuer.as_ref().unwrap().host, "svc");
}
