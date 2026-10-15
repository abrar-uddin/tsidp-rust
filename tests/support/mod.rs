//! Shared test helpers: request builders, a mock tailscaled LocalAPI served
//! over a unix socket, and a mock Kubernetes API over HTTP.
#![allow(dead_code)]

use axum::body::{Body, to_bytes};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

pub const PEER: &str = "100.64.0.7";

pub fn tailnet_req(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-forwarded-for", PEER)
        .header("host", "tsidp.dev.example.ts.net")
}

pub fn form_req(method: &str, uri: &str, body: &str) -> Request<Body> {
    tailnet_req(method, uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_string()))
        .unwrap()
}

pub async fn body_json(resp: Response) -> Value {
    let b = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&b)
        .unwrap_or_else(|e| panic!("not json ({e}): {}", String::from_utf8_lossy(&b)))
}

pub async fn body_text(resp: Response) -> String {
    String::from_utf8(to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap()
}

pub fn query_param(location: &str, key: &str) -> Option<String> {
    let u = url::Url::parse(location).unwrap();
    u.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

pub fn basic(id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
    )
}

/// A realistic WhoIs answer for `login` on an untagged node.
pub fn whois_json(login: &str, caps: Value) -> Value {
    json!({
        "Node": {
            "ID": 4242, "StableID": "nSTABLE", "Name": "laptop.tn.ts.net.", "User": 777,
            "Key": "nodekey:aa", "Addresses": ["100.64.0.7/32"], "Tags": null
        },
        "UserProfile": {"ID": 777, "LoginName": login, "DisplayName": "Test User", "ProfilePicURL": "https://pic/x.png"},
        "CapMap": {"tailscale.com/cap/tsidp": caps}
    })
}

#[derive(Default)]
pub struct MockState {
    pub status: Value,
    pub whois: HashMap<String, Value>,
    /// Force every whois to this HTTP status.
    pub whois_error: Option<u16>,
    pub serve: Value,
    pub etag: u64,
    /// Status to answer serve-config writes with (200 = accept).
    pub serve_write_status: u16,
    /// (method, path, if-match header) of every request seen.
    pub requests: Vec<(String, String, Option<String>)>,
}

type Shared = Arc<Mutex<MockState>>;

/// A fake tailscaled LocalAPI listening on a unix socket in a temp dir.
pub struct MockLocalApi {
    pub socket: PathBuf,
    pub state: Shared,
    _dir: tempfile::TempDir,
}

impl MockLocalApi {
    pub async fn start() -> MockLocalApi {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("tailscaled.sock");
        let state: Shared = Arc::new(Mutex::new(MockState {
            status: json!({
                "Version": "1.96.5-mock", "BackendState": "Running",
                "Self": {"ID": "nSELF", "DNSName": "idp.tn.ts.net.", "TailscaleIPs": ["100.64.0.1"]},
                "CurrentTailnet": {"Name": "tn", "MagicDNSSuffix": "tn.ts.net", "MagicDNSEnabled": true}
            }),
            serve: Value::Null,
            etag: 1,
            serve_write_status: 200,
            ..Default::default()
        }));
        let app = Router::new()
            .route("/localapi/v0/status", get(mock_status))
            .route("/localapi/v0/whois", get(mock_whois))
            .route(
                "/localapi/v0/serve-config",
                get(mock_get_serve).post(mock_set_serve),
            )
            .with_state(state.clone());
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        MockLocalApi {
            socket,
            state,
            _dir: dir,
        }
    }

    pub fn set_whois(&self, addr: &str, v: Value) {
        self.state.lock().whois.insert(addr.to_string(), v);
    }

    pub fn set_backend_state(&self, s: &str) {
        self.state.lock().status["BackendState"] = json!(s);
    }
}

fn record(s: &Shared, method: &str, path: &str, headers: &HeaderMap) {
    let im = headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());
    s.lock().requests.push((method.into(), path.into(), im));
}

async fn mock_status(State(s): State<Shared>, headers: HeaderMap) -> Json<Value> {
    record(&s, "GET", "/localapi/v0/status", &headers);
    Json(s.lock().status.clone())
}

async fn mock_whois(
    State(s): State<Shared>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    record(&s, "GET", "/localapi/v0/whois", &headers);
    let st = s.lock();
    if let Some(code) = st.whois_error {
        return (StatusCode::from_u16(code).unwrap(), "forced error").into_response();
    }
    let addr = q.get("addr").cloned().unwrap_or_default();
    let addr = addr.split(':').next().unwrap_or("").to_string();
    match st.whois.get(&addr) {
        Some(v) => Json(v.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "no match for IP:port").into_response(),
    }
}

async fn mock_get_serve(State(s): State<Shared>, headers: HeaderMap) -> Response {
    record(&s, "GET", "/localapi/v0/serve-config", &headers);
    let st = s.lock();
    ([("etag", format!("\"{}\"", st.etag))], st.serve.to_string()).into_response()
}

async fn mock_set_serve(State(s): State<Shared>, headers: HeaderMap, body: String) -> Response {
    record(&s, "POST", "/localapi/v0/serve-config", &headers);
    let mut st = s.lock();
    if st.serve_write_status != 200 {
        return (
            StatusCode::from_u16(st.serve_write_status).unwrap(),
            "serve config access denied",
        )
            .into_response();
    }
    let expected = format!("\"{}\"", st.etag);
    if headers.get("if-match").and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return (StatusCode::PRECONDITION_FAILED, "etag mismatch").into_response();
    }
    st.serve = serde_json::from_str(&body).unwrap();
    st.etag += 1;
    StatusCode::OK.into_response()
}

/// A fake Kubernetes API server (secrets only) over plain HTTP, plus a fake
/// service account directory.
pub struct MockKubeApi {
    pub url: String,
    pub sa_dir: PathBuf,
    pub secrets: Arc<Mutex<HashMap<String, Value>>>,
    pub fail_next: Arc<Mutex<Option<u16>>>,
    _dir: tempfile::TempDir,
}

#[derive(Clone)]
struct KubeShared {
    secrets: Arc<Mutex<HashMap<String, Value>>>,
    fail_next: Arc<Mutex<Option<u16>>>,
    token: String,
}

impl MockKubeApi {
    pub async fn start() -> MockKubeApi {
        let dir = tempfile::tempdir().unwrap();
        let sa_dir = dir.path().join("sa");
        std::fs::create_dir_all(&sa_dir).unwrap();
        std::fs::write(sa_dir.join("token"), "sa-token-123\n").unwrap();
        std::fs::write(sa_dir.join("namespace"), "tsidp\n").unwrap();
        let shared = KubeShared {
            secrets: Arc::new(Mutex::new(HashMap::new())),
            fail_next: Arc::new(Mutex::new(None)),
            token: "sa-token-123".into(),
        };
        let app = Router::new()
            .route("/api/v1/namespaces/{ns}/secrets", post(kube_create))
            .route(
                "/api/v1/namespaces/{ns}/secrets/{name}",
                get(kube_get).patch(kube_patch),
            )
            .with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        MockKubeApi {
            url: format!("http://{addr}"),
            sa_dir,
            secrets: shared.secrets,
            fail_next: shared.fail_next,
            _dir: dir,
        }
    }
}

#[allow(clippy::result_large_err)]
fn kube_auth(s: &KubeShared, headers: &HeaderMap) -> Result<(), Response> {
    if let Some(code) = s.fail_next.lock().take() {
        return Err((StatusCode::from_u16(code).unwrap(), "injected failure").into_response());
    }
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {}", s.token))
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "bad token").into_response())
    }
}

async fn kube_get(
    State(s): State<KubeShared>,
    axum::extract::Path((ns, name)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = kube_auth(&s, &headers) {
        return r;
    }
    match s.secrets.lock().get(&format!("{ns}/{name}")) {
        Some(v) => Json(v.clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            json!({"kind":"Status","code":404}).to_string(),
        )
            .into_response(),
    }
}

async fn kube_create(
    State(s): State<KubeShared>,
    axum::extract::Path(ns): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = kube_auth(&s, &headers) {
        return r;
    }
    let name = body["metadata"]["name"].as_str().unwrap_or("").to_string();
    let mut m = s.secrets.lock();
    let key = format!("{ns}/{name}");
    if m.contains_key(&key) {
        return (StatusCode::CONFLICT, "exists").into_response();
    }
    m.insert(key, body.clone());
    (StatusCode::CREATED, Json(body)).into_response()
}

async fn kube_patch(
    State(s): State<KubeShared>,
    axum::extract::Path((ns, name)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Err(r) = kube_auth(&s, &headers) {
        return r;
    }
    if headers.get("content-type").and_then(|v| v.to_str().ok())
        != Some("application/merge-patch+json")
    {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "want merge patch").into_response();
    }
    let patch: Value = serde_json::from_str(&body).unwrap();
    let mut m = s.secrets.lock();
    let Some(secret) = m.get_mut(&format!("{ns}/{name}")) else {
        return (StatusCode::NOT_FOUND, "missing").into_response();
    };
    if secret.get("data").map(|d| d.is_null()).unwrap_or(true) {
        secret["data"] = json!({});
    }
    for (k, v) in patch["data"].as_object().unwrap() {
        secret["data"][k] = v.clone();
    }
    Json(secret.clone()).into_response()
}
