//! Edge cases per endpoint: admin UI forms, the /clients API, registration
//! validation, token grants, CSRF, the admin router.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

use support::*;
use tsidp::clients::Client;
use tsidp::config::Config;
use tsidp::identity::Identity;
use tsidp::server::{AppState, admin_router, tailnet_router, test_state};

async fn state() -> Arc<AppState> {
    test_state(Config::for_tests(), None).await
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

async fn get_code(app: &axum::Router, client: &Client, extra: &str) -> String {
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb{extra}",
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
    query_param(&loc, "code").unwrap_or_else(|| panic!("no code in {loc}"))
}

async fn token_form(
    app: &axum::Router,
    client: &Client,
    body: String,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&client.id, &client.secret))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

#[tokio::test]
async fn admin_router_endpoints() {
    let st = state().await;
    let app = admin_router(st.clone());
    let get = |p: &str| Request::builder().uri(p).body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(get("/healthz")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp).await, "ok\n");
    let resp = app.clone().oneshot(get("/version")).await.unwrap();
    assert_eq!(body_json(resp).await["name"], "tsidp");
    let resp = app.clone().oneshot(get("/readyz")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["ready"], true);
    assert_eq!(body["tailscaled"]["reachable"], true);
    // the unauthenticated readiness body must not describe the deployment
    for leaky in ["state_backend", "clients"] {
        assert!(body.get(leaky).is_none(), "{leaky} leaked: {body}");
    }
    for leaky in ["version", "last_error", "backend"] {
        assert!(
            body["tailscaled"].get(leaky).is_none(),
            "{leaky} leaked: {body}"
        );
    }

    st.metrics.inc_tokens();
    st.metrics.inc_exchanges();
    let resp = app.clone().oneshot(get("/metrics")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()[header::CONTENT_TYPE],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let text = body_text(resp).await;
    assert!(text.contains("tsidp_tokens_issued_total 1\n"), "{text}");
    assert!(text.contains("tsidp_token_exchanges_total 1\n"));
    assert!(text.contains("tsidp_ready 1\n"));
    assert!(text.contains("tsidp_active_tokens{kind=\"code\"} 0\n"));
    assert!(text.contains("tsidp_build_info{version=\""));

    // Not ready when no issuer is known.
    let st2 = test_state(Config::for_tests(), None).await;
    *st2.issuer.write() = None;
    let resp = admin_router(st2).oneshot(get("/readyz")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn ui_edit_update_regenerate_delete_and_validation() {
    let st = state().await;
    let c = add_client(&st, false).await;
    let app = tailnet_router(st.clone());

    let resp = app
        .clone()
        .oneshot(
            tailnet_req("GET", "/style.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/css")
    );

    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", "/new").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(body_text(resp).await.contains("Add New OIDC Client"));

    let edit = format!("/edit/{}", c.id);
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", &edit).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = body_text(resp).await;
    assert!(
        html.contains("Edit OIDC Client") && html.contains(&c.id) && html.contains("Confidential")
    );

    // validation: empty / dangerous URIs
    let resp = app
        .clone()
        .oneshot(form_req("POST", &edit, "name=x&redirect_uris="))
        .await
        .unwrap();
    assert!(
        body_text(resp)
            .await
            .contains("At least one redirect URI is required")
    );
    let resp = app
        .clone()
        .oneshot(form_req(
            "POST",
            &edit,
            "name=x&redirect_uris=javascript:alert(1)",
        ))
        .await
        .unwrap();
    assert!(body_text(resp).await.contains("not allowed"));
    let resp = app
        .clone()
        .oneshot(form_req("POST", "/new", "name=x&redirect_uris="))
        .await
        .unwrap();
    assert!(
        body_text(resp)
            .await
            .contains("At least one redirect URI is required")
    );
    let resp = app
        .clone()
        .oneshot(form_req("POST", "/new", "name=x&redirect_uris=nope"))
        .await
        .unwrap();
    assert!(body_text(resp).await.contains("Invalid redirect URI"));

    // update
    let resp = app
        .clone()
        .oneshot(form_req(
            "POST",
            &edit,
            "action=save&name=Renamed&redirect_uris=https%3A%2F%2Fa%2Fcb%0Ahttps%3A%2F%2Fb%2Fcb",
        ))
        .await
        .unwrap();
    assert!(
        body_text(resp)
            .await
            .contains("Client updated successfully")
    );
    let updated = st.clients.get(&c.id).unwrap();
    assert_eq!(updated.name, "Renamed");
    assert_eq!(
        updated.redirect_uris,
        vec!["https://a/cb".to_string(), "https://b/cb".to_string()]
    );

    // regenerate secret shows it once and rotates it
    let resp = app
        .clone()
        .oneshot(form_req("POST", &edit, "action=regenerate_secret"))
        .await
        .unwrap();
    let html = body_text(resp).await;
    assert!(html.contains("New client secret generated"));
    let rotated = st.clients.get(&c.id).unwrap();
    assert_ne!(rotated.secret, c.secret);
    assert!(html.contains(&rotated.secret));

    // public client via the UI shows no secret
    let resp = app
        .clone()
        .oneshot(form_req(
            "POST",
            "/new",
            "name=spa&redirect_uris=myapp%3A%2F%2Fcb&public=1",
        ))
        .await
        .unwrap();
    let html = body_text(resp).await;
    assert!(html.contains("Public client created"));
    assert!(!html.contains("Client Secret"));

    // delete redirects to the list; unknown id is 404; bad method is 405
    let resp = app
        .clone()
        .oneshot(form_req("POST", &edit, "action=delete"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(st.clients.get(&c.id).is_none());
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", &edit).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = app
        .clone()
        .oneshot(tailnet_req("PUT", "/new").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    // UI is never served over funnel
    let resp = app
        .oneshot(
            tailnet_req("GET", "/")
                .header("tailscale-funnel-request", "?1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn clients_api_get_rotate_json_create_and_errors() {
    let st = state().await;
    let c = add_client(&st, true).await;
    let app = tailnet_router(st.clone());

    let resp = app
        .clone()
        .oneshot(
            tailnet_req("GET", &format!("/clients/{}", c.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["client_id"], c.id);
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert!(body.get("client_secret").is_none());

    let resp = app
        .clone()
        .oneshot(
            tailnet_req("GET", "/clients/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("PUT", &format!("/clients/{}", c.id))
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    // rotating the secret of a public client makes it confidential
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", &format!("/clients/{}/secret", c.id))
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["client_secret"].as_str().unwrap().len(), 64);
    assert!(!st.clients.get(&c.id).unwrap().is_public());
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/clients/missing/secret")
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // JSON create with multiple URIs
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/clients/new")
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(json!({"name": "svc", "redirect_uris": ["https://x/cb", "https://y/cb"], "public": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["redirect_uris"].as_array().unwrap().len(), 2);
    assert!(body.get("client_secret").is_none());

    // validation errors
    for (ct, b) in [
        ("application/json", "{not json"),
        ("application/json", r#"{"name":"x","redirect_uri":""}"#),
        (
            "application/x-www-form-urlencoded",
            "name=&redirect_uri=https://x/cb",
        ),
        (
            "application/x-www-form-urlencoded",
            "name=x&redirect_uri=file:///etc/passwd",
        ),
    ] {
        let resp = app
            .clone()
            .oneshot(
                tailnet_req("POST", "/clients/new")
                    .header(header::CONTENT_TYPE, ct)
                    .header("sec-fetch-site", "same-origin")
                    .body(Body::from(b.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{b}");
    }

    // /clients without trailing slash and over funnel
    let resp = app
        .clone()
        .oneshot(tailnet_req("GET", "/clients").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .oneshot(
            tailnet_req("GET", "/clients")
                .header("tailscale-funnel-request", "?1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registration_validation_and_grant() {
    let st = state().await;
    let app = tailnet_router(st.clone());
    let reg = |body: &str| {
        tailnet_req("POST", "/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let resp = app.clone().oneshot(reg("{")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_client_metadata");
    let resp = app
        .clone()
        .oneshot(reg(r#"{"client_name":"x"}"#))
        .await
        .unwrap();
    assert_eq!(
        body_json(resp).await["error_description"],
        "redirect_uris is required"
    );
    let resp = app
        .clone()
        .oneshot(reg(r#"{"redirect_uris":["data:text/html,hi"]}"#))
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["error"], "invalid_redirect_uri");

    // full metadata is echoed with RFC 7591 extras
    let resp = app
        .clone()
        .oneshot(reg(
            r#"{"redirect_uris":["https://rp/cb"],"client_name":"RP","grant_types":["authorization_code"],"response_types":["code"],"scope":"openid","client_uri":"https://rp","logo_uri":"https://rp/logo.png","contacts":["a@b"],"application_type":"native"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(body["application_type"], "native");
    assert_eq!(body["client_secret_expires_at"], 0);
    assert!(body["client_id_issued_at"].as_i64().unwrap() > 1_700_000_000);
    assert!(
        body["registration_client_uri"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/clients/{}", body["client_id"].as_str().unwrap()))
    );
    assert!(body.get("redirect_uri").is_none());

    // By default /register has no CORS: a preflight gets nothing useful back.
    let preflight = || {
        tailnet_req("OPTIONS", "/register")
            .header("origin", "http://localhost:6274")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap()
    };
    let resp = app.clone().oneshot(preflight()).await.unwrap();
    assert!(resp.headers().get("access-control-allow-origin").is_none());

    // With --allow-cross-origin-dcr the CORS layer answers the preflight.
    let mut cfg = Config::for_tests();
    cfg.allow_cross_origin_dcr = true;
    let open = tailnet_router(test_state(cfg, None).await);
    let resp = open.oneshot(preflight()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["access-control-allow-origin"], "*");

    // without allow_dcr the grant check fails
    let mut id = Identity::dev("bob@example.com");
    id.cap_rules = vec![serde_json::from_value(json!({"allow_admin_ui": true})).unwrap()];
    let st2 = test_state(Config::for_tests(), Some(id)).await;
    let resp = tailnet_router(st2)
        .oneshot(reg(r#"{"redirect_uris":["https://rp/cb"]}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn authorize_error_cases() {
    let st = state().await;
    let c = add_client(&st, false).await;
    let app = tailnet_router(st.clone());
    let direct = |uri: &str| tailnet_req("GET", uri).body(Body::empty()).unwrap();
    let base = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb",
        c.id
    );

    let resp = app.clone().oneshot(direct("/authorize")).await.unwrap();
    assert_eq!(
        body_json(resp).await["error_description"],
        "must specify redirect_uri"
    );
    let resp = app
        .clone()
        .oneshot(direct("/authorize?redirect_uri=https%3A%2F%2Fx"))
        .await
        .unwrap();
    assert_eq!(
        body_json(resp).await["error_description"],
        "must specify client_id"
    );
    let resp = app
        .clone()
        .oneshot(direct(&format!(
            "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fevil%2Fcb",
            c.id
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(resp).await["error_description"],
        "redirect_uri mismatch"
    );
    let resp = app
        .clone()
        .oneshot(tailnet_req("DELETE", &base).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    let redirected = |extra: &str| {
        let app = app.clone();
        let uri = format!("{base}{extra}&state=st");
        async move {
            let resp = app.oneshot(direct(&uri)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::FOUND);
            let loc = resp.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .to_string();
            assert_eq!(query_param(&loc, "state").as_deref(), Some("st"));
            (
                query_param(&loc, "error").unwrap(),
                query_param(&loc, "error_description").unwrap_or_default(),
            )
        }
    };
    assert_eq!(
        redirected("&response_type=token").await.0,
        "unsupported_response_type"
    );
    assert_eq!(redirected("&scope=openid%20admin").await.0, "invalid_scope");
    let (e, d) = redirected("&code_challenge=abc&code_challenge_method=S512").await;
    assert_eq!(
        (e.as_str(), d.as_str()),
        (
            "invalid_request",
            "unsupported code_challenge_method (only S256 is accepted)"
        )
    );

    // `plain` is refused outright, also when it is the implied default
    let (e, _) = redirected(&format!("&code_challenge={}", "a".repeat(43))).await;
    assert_eq!(e, "invalid_request");
    let (e, d) = redirected(&format!(
        "&code_challenge={}&code_challenge_method=plain",
        "a".repeat(43)
    ))
    .await;
    assert_eq!(e, "invalid_request");
    assert!(d.contains("only S256"), "{d}");

    // an S256 PKCE challenge is accepted for confidential clients and verified at /token
    let verifier = "a".repeat(43);
    let challenge =
        tsidp::util::b64url(&<sha2::Sha256 as sha2::Digest>::digest(verifier.as_bytes()));
    let pkce = format!("&code_challenge={challenge}&code_challenge_method=S256");
    let code = get_code(&app, &c, &pkce).await;
    let (status, body) = token_form(&app, &c, format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb")).await;
    assert_eq!(
        (status, body["error_description"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "code_verifier is required")
    );
    let code = get_code(&app, &c, &pkce).await;
    let (status, body) = token_form(&app, &c, format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&code_verifier={}", "b".repeat(43))).await;
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "invalid_grant")
    );
    let code = get_code(&app, &c, &pkce).await;
    let (status, _) = token_form(&app, &c, format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&code_verifier={verifier}")).await;
    assert_eq!(status, StatusCode::OK);

    // extra scopes are accepted when configured
    let mut cfg = Config::for_tests();
    cfg.extra_scopes = "mcp:tools, groups".into();
    let st2 = test_state(cfg, None).await;
    assert!(st2.supported_scopes.contains(&"mcp:tools".to_string()));
    assert_eq!(
        st2.validate_scopes("openid mcp:tools mcp:tools").unwrap(),
        vec!["openid", "mcp:tools"]
    );
    assert_eq!(st2.validate_scopes("").unwrap(), vec!["openid"]);
    assert_eq!(st2.validate_scopes("openid nope").unwrap_err(), "nope");
}

#[tokio::test]
async fn token_grant_edge_cases() {
    let st = state().await;
    let c = add_client(&st, false).await;
    let app = tailnet_router(st.clone());
    let cb = "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb";

    let (status, body) = token_form(&app, &c, "grant_type=authorization_code".into()).await;
    assert_eq!(
        (status, body["error_description"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "code is required")
    );

    // redirect_uri mismatch at the token endpoint
    let code = get_code(&app, &c, "").await;
    let (_, body) = token_form(
        &app,
        &c,
        format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fother"),
    )
    .await;
    assert_eq!(body["error_description"], "redirect_uri mismatch");

    // wrong secret / missing credentials / mismatched id
    let code = get_code(&app, &c, "").await;
    let bad = Client {
        secret: "nope".into(),
        ..c.clone()
    };
    let (status, body) = token_form(
        &app,
        &bad,
        format!("grant_type=authorization_code&code={code}&{cb}"),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (StatusCode::UNAUTHORIZED, "invalid_client")
    );
    assert!(
        !body.to_string().contains("nope"),
        "secret must not be echoed"
    );
    let code = get_code(&app, &c, "").await;
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={code}&{cb}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let code = get_code(&app, &c, "").await;
    let other = Client {
        id: "someone-else".into(),
        ..c.clone()
    };
    let (status, _) = token_form(
        &app,
        &other,
        format!("grant_type=authorization_code&code={code}&{cb}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // resource indicators are checked against the grant (the dev identity
    // allows "*", so use a user with a narrow grant)
    let mut narrow = Identity::dev("dana@example.com");
    narrow.cap_rules = vec![
        serde_json::from_value(json!({"users": ["*"], "resources": ["https://api.example.com"]}))
            .unwrap(),
    ];
    let stn = test_state(Config::for_tests(), Some(narrow)).await;
    let cn = add_client(&stn, false).await;
    let appn = tailnet_router(stn.clone());
    let code = get_code(&appn, &cn, "").await;
    let (status, body) = token_form(
        &appn,
        &cn,
        format!(
            "grant_type=authorization_code&code={code}&{cb}&resource=https%3A%2F%2Fnot.granted"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("resource")
    );
    let code = get_code(&appn, &cn, "&resource=https%3A%2F%2Fnot.granted").await;
    let (status, body) = token_form(
        &appn,
        &cn,
        format!("grant_type=authorization_code&code={code}&{cb}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ungranted resource from /authorize is dropped, not fatal"
    );
    let code = get_code(&appn, &cn, "").await;
    let (status, body2) = token_form(
        &appn,
        &cn,
        format!(
            "grant_type=authorization_code&code={code}&{cb}&resource=https%3A%2F%2Fapi.example.com"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rtn = body2["refresh_token"].as_str().unwrap().to_string();
    let _ = body;
    // refresh may not widen resources beyond the original grant
    let (status, body) = token_form(
        &appn,
        &cn,
        format!("grant_type=refresh_token&refresh_token={rtn}&resource=https%3A%2F%2Fnot.granted"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("resource")
    );

    // refresh: missing token, wrong client, scope narrowing, scope escalation, resource not in grant
    let (status, body) = token_form(&app, &c, "grant_type=refresh_token".into()).await;
    assert_eq!(
        (status, body["error_description"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "refresh_token is required")
    );
    let code = get_code(&app, &c, "&scope=openid%20email%20profile").await;
    let (_, tok) = token_form(
        &app,
        &c,
        format!("grant_type=authorization_code&code={code}&{cb}"),
    )
    .await;
    let rt = tok["refresh_token"].as_str().unwrap().to_string();
    let (status, _) = token_form(
        &app,
        &bad,
        format!("grant_type=refresh_token&refresh_token={rt}"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // the failed attempt consumed it (single use); presenting it again is a replay
    let (status, body) = token_form(
        &app,
        &c,
        format!("grant_type=refresh_token&refresh_token={rt}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .starts_with("refresh token already used"),
        "{body}"
    );

    let code = get_code(&app, &c, "&scope=openid%20email").await;
    let (_, tok) = token_form(
        &app,
        &c,
        format!("grant_type=authorization_code&code={code}&{cb}"),
    )
    .await;
    let rt = tok["refresh_token"].as_str().unwrap().to_string();
    let (status, body) = token_form(
        &app,
        &c,
        format!("grant_type=refresh_token&refresh_token={rt}&scope=openid%20email%20profile"),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "invalid_scope")
    );
    let code = get_code(&app, &c, "&scope=openid%20email").await;
    let (_, tok) = token_form(
        &app,
        &c,
        format!("grant_type=authorization_code&code={code}&{cb}"),
    )
    .await;
    let rt = tok["refresh_token"].as_str().unwrap().to_string();
    let (status, body) = token_form(
        &app,
        &c,
        format!("grant_type=refresh_token&refresh_token={rt}&scope=openid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scope"], "openid");
    let rt = body["refresh_token"].as_str().unwrap().to_string();
    // the wildcard grant lets a refresh add a resource; it shows up in aud
    let (status, body) = token_form(
        &app,
        &c,
        format!("grant_type=refresh_token&refresh_token={rt}&resource=https%3A%2F%2Fanything"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].as_str().is_some());

    // introspection: missing token, unknown token, expired-by-config token
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&c.id, &c.secret))
                .body(Body::from("token=unknown"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await, json!({"active": false}));

    // userinfo with an expired token and a token minted with a 0s ttl
    let mut cfg = Config::for_tests();
    cfg.access_token_ttl = 0;
    let st3 = test_state(cfg, None).await;
    let c3 = add_client(&st3, false).await;
    let app3 = tailnet_router(st3.clone());
    let code = get_code(&app3, &c3, "").await;
    let (status, tok) = token_form(
        &app3,
        &c3,
        format!("grant_type=authorization_code&code={code}&{cb}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let at = tok["access_token"].as_str().unwrap();
    let resp = app3
        .clone()
        .oneshot(
            tailnet_req("GET", "/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {at}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );
    assert_eq!(
        st3.tokens.counts().1,
        0,
        "expired access token dropped on lookup"
    );
}

#[tokio::test]
async fn token_exchange_errors_and_delegation() {
    let mut cfg = Config::for_tests();
    cfg.enable_sts = true;
    let st = test_state(cfg, None).await;
    let c = add_client(&st, false).await;
    let app = tailnet_router(st.clone());
    let cb = "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb";
    let code = get_code(&app, &c, "").await;
    let (_, tok) = token_form(
        &app,
        &c,
        format!("grant_type=authorization_code&code={code}&{cb}"),
    )
    .await;
    let subject = tok["access_token"].as_str().unwrap().to_string();
    let ex = |extra: String| {
        format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token{extra}"
        )
    };
    let cases: Vec<(String, &str)> = vec![
        (ex(String::new()), "subject_token is required"),
        (
            format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token={subject}&subject_token_type=jwt"
            ),
            "unsupported subject_token_type",
        ),
        (
            ex(format!(
                "&subject_token={subject}&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token&audience=a"
            )),
            "unsupported requested_token_type",
        ),
        (
            ex(format!("&subject_token={subject}")),
            "audience is required",
        ),
        (
            ex("&subject_token=bogus&audience=a".to_string()),
            "invalid or expired subject token",
        ),
        (
            ex(format!(
                "&subject_token={subject}&audience=a&actor_token=bogus"
            )),
            "invalid or expired actor_token",
        ),
        (
            ex(format!(
                "&subject_token={subject}&audience=a&actor_token={subject}&actor_token_type=jwt"
            )),
            "unsupported actor_token_type",
        ),
    ];
    for (body, want) in cases {
        let (_, resp) = token_form(&app, &c, body.clone()).await;
        assert_eq!(resp["error_description"], want, "{body}");
    }

    // delegation: the act claim chains
    let (status, body) = token_form(
        &app,
        &c,
        ex(format!(
            "&subject_token={subject}&audience=https%3A%2F%2Fsvc&actor_token={subject}&scope=openid"
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("scope").is_none(),
        "scope equal to the request is omitted"
    );
    let t2 = body["access_token"].as_str().unwrap().to_string();
    let (status, body) = token_form(
        &app,
        &c,
        ex(format!(
            "&subject_token={t2}&audience=https%3A%2F%2Fsvc2&actor_token={t2}&scope=other"
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["scope"], "openid");
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/introspect")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, basic(&c.id, &c.secret))
                .body(Body::from(format!(
                    "token={}",
                    body["access_token"].as_str().unwrap()
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let intro = body_json(resp).await;
    assert_eq!(intro["act"]["sub"], "userid:1");
    assert_eq!(intro["act"]["act"]["sub"], "userid:1");

    // Unauthenticated exchanger
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("x-forwarded-for", "")
                .body(Body::from(ex(format!(
                    "&subject_token={subject}&audience=a"
                ))))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Audience not granted: user rules without a match
    let mut id = Identity::dev("carol@example.com");
    id.cap_rules = vec![
        serde_json::from_value(json!({"users": ["someone@else"], "resources": ["*"]})).unwrap(),
    ];
    let mut cfg = Config::for_tests();
    cfg.enable_sts = true;
    cfg.jwt_access_tokens = true;
    let st2 = test_state(cfg, Some(id)).await;
    let c2 = add_client(&st2, false).await;
    let app2 = tailnet_router(st2.clone());
    let code = get_code(&app2, &c2, "").await;
    let (_, tok) = token_form(
        &app2,
        &c2,
        format!("grant_type=authorization_code&code={code}&{cb}"),
    )
    .await;
    let subject = tok["access_token"].as_str().unwrap().to_string();
    let (status, body) = token_form(
        &app2,
        &c2,
        ex(format!("&subject_token={subject}&audience=a")),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (StatusCode::FORBIDDEN, "access_denied")
    );

    // STS disabled
    let st3 = state().await;
    let c3 = add_client(&st3, false).await;
    let (status, body) = token_form(
        &tailnet_router(st3),
        &c3,
        ex("&subject_token=x&audience=a".into()),
    )
    .await;
    assert_eq!(
        (status, body["error"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "unsupported_grant_type")
    );
}

#[tokio::test]
async fn jwt_exchange_tokens_are_signed() {
    let mut cfg = Config::for_tests();
    cfg.enable_sts = true;
    cfg.jwt_access_tokens = true;
    let st = test_state(cfg, None).await;
    let c = add_client(&st, false).await;
    let app = tailnet_router(st.clone());
    let code = get_code(&app, &c, "").await;
    let (_, tok) = token_form(&app, &c, format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb")).await;
    let subject = tok["access_token"].as_str().unwrap().to_string();
    let (status, body) = token_form(
        &app,
        &c,
        format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token={subject}&audience=https%3A%2F%2Fsvc&actor_token={subject}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let header = jsonwebtoken::decode_header(body["access_token"].as_str().unwrap()).unwrap();
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    assert_eq!(header.kid.as_deref(), Some(st.key.kid_string().as_str()));
}

#[tokio::test]
async fn csrf_origin_fallback_and_cluster_discovery() {
    let st = state().await;
    let app = tailnet_router(st.clone());
    let with_origin = |origin: &str| {
        tailnet_req("POST", "/clients/new")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("origin", origin)
            .body(Body::from("name=o&redirect_uri=https://o/cb"))
            .unwrap()
    };
    let resp = app
        .clone()
        .oneshot(with_origin("https://evil.example"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = app
        .clone()
        .oneshot(with_origin("https://tsidp.dev.example.ts.net"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    // no fetch metadata and no origin (curl): allowed
    let resp = app
        .clone()
        .oneshot(
            tailnet_req("POST", "/clients/new")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("name=curl&redirect_uri=https://c/cb"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    // security headers on every response
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");

    let resp = app
        .clone()
        .oneshot(
            tailnet_req("GET", "/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let doc = body_json(resp).await;
    assert_eq!(doc["resource_indicators_supported"], true);
    assert!(doc["registration_endpoint"].as_str().is_some());
    let resp = app
        .oneshot(
            tailnet_req("GET", "/.well-known/oauth-authorization-server")
                .header("tailscale-funnel-request", "?1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        body_json(resp).await.get("registration_endpoint").is_none(),
        "hidden over funnel"
    );
}

#[tokio::test]
async fn email_domain_and_realish_emails() {
    let mut cfg = Config::for_tests();
    cfg.email_domain = Some("mail.example.org".into());
    let st = test_state(cfg, Some(Identity::dev("bob@github"))).await;
    assert_eq!(
        st.realish_email("bob@github"),
        "bob@github.mail.example.org"
    );
    assert_eq!(st.realish_email("real@example.com"), "real@example.com");
    let st2 = state().await;
    assert_eq!(
        st2.realish_email("x@passkey"),
        "x@passkey.tsidp.dev.example.ts.net"
    );
    assert_eq!(st2.email_domain(), "tsidp.dev.example.ts.net");
}
