//! The real LocalAPI client and identity resolver against a mock tailscaled.
#![cfg(unix)]

mod support;

use axum::body::Body;
use axum::http::{StatusCode, header};
use clap::Parser;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

use support::*;
use tsidp::clients::Client;
use tsidp::config::Config;
use tsidp::identity::{IdentityResolver, LocalApiResolver, ResolveError};
use tsidp::server::{AppState, admin_router, ensure_serve_config, poll_link_once, tailnet_router};
use tsidp::store::MemoryStore;
use tsidp::tailscale::LocalApi;

fn cfg_for(mock: &MockLocalApi) -> Config {
    let mut cfg = Config::parse_from(["tsidp-server"]);
    cfg.tailscale_socket = Some(mock.socket.clone());
    cfg.configure_serve = true;
    cfg
}

async fn state_for(cfg: Config) -> Arc<AppState> {
    AppState::build_with(cfg, Arc::new(MemoryStore::default()))
        .await
        .unwrap()
}

#[tokio::test]
async fn status_whois_and_serve_config_roundtrip() {
    let mock = MockLocalApi::start().await;
    let api = LocalApi::new(&mock.socket);

    let st = api.status().await.unwrap();
    assert!(st.is_running());
    assert_eq!(st.dns_name().as_deref(), Some("idp.tn.ts.net"));
    assert_eq!(st.version, "1.96.5-mock");

    mock.set_whois(
        "100.64.0.7",
        whois_json("alice@example.com", json!([{"allow_admin_ui": true}])),
    );
    let w = api.whois("100.64.0.7:51234").await.unwrap();
    assert_eq!(w.node.id, 4242);
    assert_eq!(w.user_profile.unwrap().login_name, "alice@example.com");
    let err = api.whois("100.64.0.99").await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));

    // null serve config becomes {} and carries the etag
    let (cur, etag) = api.get_serve_config().await.unwrap();
    assert!(cur.as_object().unwrap().is_empty());
    assert_eq!(etag.as_deref(), Some("\"1\""));
    api.set_serve_config(&json!({"TCP": {"443": {"HTTPS": true}}}), etag.as_deref())
        .await
        .unwrap();
    let (cur, etag2) = api.get_serve_config().await.unwrap();
    assert_eq!(cur["TCP"]["443"]["HTTPS"], true);
    assert_eq!(etag2.as_deref(), Some("\"2\""));
    // stale etag is rejected by tailscaled
    let err = api
        .set_serve_config(&json!({}), Some("\"1\""))
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::PRECONDITION_FAILED));
}

#[tokio::test]
async fn client_errors_are_descriptive() {
    let api = LocalApi::new("/nonexistent/tailscaled.sock");
    let err = api.status().await.unwrap_err();
    assert!(err.to_string().contains("not reachable"), "{err}");
    assert!(err.status().is_none());
    let r = LocalApiResolver { api: Arc::new(api) };
    assert!(matches!(
        r.whois("100.64.0.1").await,
        Err(ResolveError::Backend(_))
    ));
    assert!(r.describe().contains("nonexistent"));
}

#[tokio::test]
async fn resolver_maps_not_found_and_parses_identity() {
    let mock = MockLocalApi::start().await;
    mock.set_whois(
        "100.64.0.7",
        whois_json("bob@github", json!([{"groups": ["g1"]}])),
    );
    let r = LocalApiResolver {
        api: Arc::new(LocalApi::new(&mock.socket)),
    };
    let id = r.whois("100.64.0.7").await.unwrap();
    assert_eq!(id.login_name, "bob@github");
    assert_eq!(id.subject(), "userid:777");
    assert_eq!(id.node_name, "laptop.tn.ts.net");
    assert_eq!(id.cap_rules.len(), 1);
    assert!(matches!(
        r.whois("100.64.0.8").await,
        Err(ResolveError::NotFound(_))
    ));
    mock.state.lock().whois_error = Some(500);
    assert!(matches!(
        r.whois("100.64.0.7").await,
        Err(ResolveError::Backend(_))
    ));
    assert!(r.status().await.unwrap().is_running());
}

#[tokio::test]
async fn link_loop_derives_issuer_and_writes_serve_config() {
    let mock = MockLocalApi::start().await;
    let state = state_for(cfg_for(&mock)).await;
    assert!(!state.ready());
    assert!(state.issuer().is_none());

    assert!(poll_link_once(&state).await);
    assert_eq!(state.issuer().unwrap().url, "https://idp.tn.ts.net");
    let link = state.link.read().clone();
    assert!(link.running);
    assert_eq!(link.version, "1.96.5-mock");
    assert!(link.serve_config.as_ref().unwrap().is_ok());

    let serve = mock.state.lock().serve.clone();
    assert_eq!(serve["TCP"]["443"]["HTTPS"], true);
    assert_eq!(
        serve["Web"]["idp.tn.ts.net:443"]["Handlers"]["/"]["Proxy"],
        "http://127.0.0.1:8443"
    );
    assert!(serve.get("AllowFunnel").is_none());
    let writes = mock
        .state
        .lock()
        .requests
        .iter()
        .filter(|r| r.0 == "POST")
        .count();
    assert_eq!(writes, 1);
    let if_match = mock
        .state
        .lock()
        .requests
        .iter()
        .find(|r| r.0 == "POST")
        .unwrap()
        .2
        .clone();
    assert_eq!(if_match.as_deref(), Some("\"1\""));

    // Second pass is idempotent: no further write.
    assert!(poll_link_once(&state).await);
    let writes = mock
        .state
        .lock()
        .requests
        .iter()
        .filter(|r| r.0 == "POST")
        .count();
    assert_eq!(writes, 1);

    // readyz on the admin router reflects it
    let resp = admin_router(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["issuer"], "https://idp.tn.ts.net");
    assert_eq!(body["tailscaled"]["running"], true);
}

#[tokio::test]
async fn link_loop_handles_not_running_funnel_and_denied_writes() {
    let mock = MockLocalApi::start().await;
    mock.set_backend_state("NeedsLogin");
    mock.state.lock().status["AuthURL"] = json!("https://login.tailscale.com/a/abc");
    let mut cfg = cfg_for(&mock);
    cfg.funnel = true;
    cfg.issuer_port = Some(8443);
    let state = state_for(cfg).await;
    assert!(!poll_link_once(&state).await);
    assert!(state.issuer().is_none());
    assert!(!state.link.read().running);

    // Node logs in; the issuer now includes the non-default port and funnel is allowed.
    mock.set_backend_state("Running");
    assert!(poll_link_once(&state).await);
    assert_eq!(state.issuer().unwrap().url, "https://idp.tn.ts.net:8443");
    let serve = mock.state.lock().serve.clone();
    assert_eq!(serve["AllowFunnel"]["idp.tn.ts.net:8443"], true);
    assert_eq!(serve["TCP"]["8443"]["HTTPS"], true);

    // A read-only LocalAPI (403) is recorded, not fatal, and retried next pass.
    let mock2 = MockLocalApi::start().await;
    mock2.state.lock().serve_write_status = 403;
    let state2 = state_for(cfg_for(&mock2)).await;
    assert!(
        poll_link_once(&state2).await,
        "readiness does not depend on serve config"
    );
    let sc = state2.link.read().serve_config.clone().unwrap();
    assert!(sc.is_err(), "{sc:?}");
    mock2.state.lock().serve_write_status = 200;
    ensure_serve_config(&state2).await;
    assert!(state2.link.read().serve_config.clone().unwrap().is_ok());

    // Explicit issuer override and configure_serve=false: nothing is written.
    let mock3 = MockLocalApi::start().await;
    let mut cfg3 = cfg_for(&mock3);
    cfg3.issuer_url = Some("https://sso.example.com/".into());
    cfg3.configure_serve = false;
    let state3 = state_for(cfg3).await;
    assert_eq!(state3.issuer().unwrap().url, "https://sso.example.com");
    assert!(poll_link_once(&state3).await);
    assert!(state3.link.read().serve_config.is_none());
    assert!(mock3.state.lock().requests.iter().all(|r| r.0 == "GET"));
}

#[tokio::test]
async fn link_loop_records_unreachable_tailscaled_and_missing_dns() {
    let mock = MockLocalApi::start().await;
    let mut cfg = cfg_for(&mock);
    cfg.tailscale_socket = Some(mock.socket.with_extension("missing"));
    let state = state_for(cfg).await;
    assert!(!poll_link_once(&state).await);
    let link = state.link.read().clone();
    assert!(
        link.last_error
            .as_deref()
            .unwrap_or("")
            .contains("not reachable")
    );
    assert!(link.last_ok.is_none());

    // Running but no DNS name (MagicDNS off): not ready, clear state.
    let mock2 = MockLocalApi::start().await;
    mock2.state.lock().status["Self"]["DNSName"] = json!("");
    let state2 = state_for(cfg_for(&mock2)).await;
    assert!(!poll_link_once(&state2).await);
    assert!(state2.issuer().is_none());
    assert!(state2.link.read().running);
    // discovery is 503 until the issuer is known
    let resp = tailnet_router(state2.clone())
        .oneshot(
            tailnet_req("GET", "/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(resp).await["error"], "temporarily_unavailable");
}

#[tokio::test]
async fn end_to_end_identity_through_real_whois() {
    let mock = MockLocalApi::start().await;
    mock.set_whois(
        PEER,
        whois_json(
            "alice@example.com",
            json!([{"allow_admin_ui": true, "extraClaims": {"team": "infra"}}]),
        ),
    );
    let state = state_for(cfg_for(&mock)).await;
    assert!(poll_link_once(&state).await);
    let client = Client::new("app", vec!["https://app/cb".into()], false);
    state.clients.insert(client.clone()).await.unwrap();
    let app = tailnet_router(state.clone());

    // admin UI allowed by the grant delivered through whois
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", "/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // authorize -> token with the real identity
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp%2Fcb&scope=openid%20email%20profile",
        client.id
    );
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", &uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let code = query_param(resp.headers()[header::LOCATION].to_str().unwrap(), "code").unwrap();
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
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
    let tok = body_json(resp).await;
    let at = tok["access_token"].as_str().unwrap();
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
    let ui = body_json(resp).await;
    assert_eq!(ui["sub"], "userid:777");
    assert_eq!(ui["name"], "Test User");
    assert_eq!(ui["picture"], "https://pic/x.png");
    assert!(ui.get("team").is_none(), "includeInUserInfo was not set");

    // an unknown peer is refused; a whois backend failure is a 500 on authorize
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("GET", &uri)
                .header("x-forwarded-for", "100.64.0.200")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(query_param(&loc, "error").as_deref(), Some("access_denied"));
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("GET", "/")
                .header("x-forwarded-for", "100.64.0.200")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    mock.state.lock().whois_error = Some(500);
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", &uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let resp = app
        .oneshot(tailnet_req("GET", "/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        state
            .metrics
            .whois_failures
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 3
    );
}

#[tokio::test]
async fn direct_requests_without_proxy_headers() {
    let mock = MockLocalApi::start().await;
    let state = state_for(cfg_for(&mock)).await;
    poll_link_once(&state).await;
    let no_xff = |uri: &str| {
        axum::http::Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    };
    let resp = tailnet_router(state.clone())
        .oneshot(no_xff("/"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        body_json(resp).await["error_description"]
            .as_str()
            .unwrap()
            .contains("X-Forwarded-For")
    );

    let mut cfg = cfg_for(&mock);
    cfg.allow_loopback_admin = true;
    let state = state_for(cfg).await;
    poll_link_once(&state).await;
    let resp = tailnet_router(state).oneshot(no_xff("/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
