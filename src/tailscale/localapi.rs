//! A tiny HTTP/1 client for tailscaled's LocalAPI over its unix socket.
//!
//! Each call opens a fresh connection; LocalAPI traffic is light (a whois per
//! identity-bearing request) and this keeps the client trivially robust to
//! tailscaled restarts.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{HOST, HeaderName, HeaderValue};
use hyper::{Method, Request, StatusCode};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::types::{Status, WhoIsResponse};

/// Capability version advertised in the `Tailscale-Cap` header. tailscaled uses
/// it to shape responses for older clients; any recent value works.
const TAILSCALE_CAP: &str = "125";

#[derive(Debug, thiserror::Error)]
pub enum LocalApiError {
    #[error("tailscaled socket {0} not reachable: {1}")]
    Connect(PathBuf, std::io::Error),
    #[error("LocalAPI request failed: {0}")]
    Transport(String),
    #[error("LocalAPI {path} returned {status}: {body}")]
    Status {
        path: String,
        status: StatusCode,
        body: String,
    },
    #[error("LocalAPI returned invalid JSON for {path}: {err}")]
    Json { path: String, err: String },
    #[error("LocalAPI is not supported on this platform (no unix sockets)")]
    Unsupported,
}

impl LocalApiError {
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            LocalApiError::Status { status, .. } => Some(*status),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalApi {
    socket: PathBuf,
    timeout: Duration,
}

pub struct RawResponse {
    pub status: StatusCode,
    pub headers: hyper::HeaderMap,
    pub body: Bytes,
}

impl LocalApi {
    pub fn new(socket: impl AsRef<Path>) -> Self {
        LocalApi {
            socket: socket.as_ref().to_path_buf(),
            timeout: Duration::from_secs(10),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub async fn request(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<Vec<u8>>,
        extra_headers: &[(HeaderName, HeaderValue)],
    ) -> Result<RawResponse, LocalApiError> {
        tokio::time::timeout(
            self.timeout,
            self.request_inner(method, path_and_query, body, extra_headers),
        )
        .await
        .map_err(|_| LocalApiError::Transport(format!("timeout after {:?}", self.timeout)))?
    }

    #[cfg(unix)]
    async fn request_inner(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<Vec<u8>>,
        extra_headers: &[(HeaderName, HeaderValue)],
    ) -> Result<RawResponse, LocalApiError> {
        use hyper_util::rt::TokioIo;
        use tokio::net::UnixStream;

        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|e| LocalApiError::Connect(self.socket.clone(), e))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| LocalApiError::Transport(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut builder = Request::builder()
            .method(method)
            .uri(format!("http://local-tailscaled.sock{path_and_query}"))
            .header(HOST, "local-tailscaled.sock")
            .header("Tailscale-Cap", TAILSCALE_CAP);
        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }
        for (k, v) in extra_headers {
            builder = builder.header(k.clone(), v.clone());
        }
        let req = builder
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| LocalApiError::Transport(e.to_string()))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| LocalApiError::Transport(e.to_string()))?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| LocalApiError::Transport(e.to_string()))?
            .to_bytes();
        Ok(RawResponse {
            status,
            headers,
            body,
        })
    }

    #[cfg(not(unix))]
    async fn request_inner(
        &self,
        _method: Method,
        _path_and_query: &str,
        _body: Option<Vec<u8>>,
        _extra_headers: &[(HeaderName, HeaderValue)],
    ) -> Result<RawResponse, LocalApiError> {
        Err(LocalApiError::Unsupported)
    }

    async fn get_ok(&self, path: &str) -> Result<RawResponse, LocalApiError> {
        let r = self.request(Method::GET, path, None, &[]).await?;
        if r.status != StatusCode::OK {
            return Err(LocalApiError::Status {
                path: path.to_string(),
                status: r.status,
                body: String::from_utf8_lossy(&r.body).trim().to_string(),
            });
        }
        Ok(r)
    }

    fn decode<T: serde::de::DeserializeOwned>(path: &str, body: &[u8]) -> Result<T, LocalApiError> {
        serde_json::from_slice(body).map_err(|e| LocalApiError::Json {
            path: path.to_string(),
            err: e.to_string(),
        })
    }

    /// `GET /localapi/v0/status?peers=false`
    pub async fn status(&self) -> Result<Status, LocalApiError> {
        let path = "/localapi/v0/status?peers=false";
        let r = self.get_ok(path).await?;
        Self::decode(path, &r.body)
    }

    /// `GET /localapi/v0/whois?addr=<ip or ip:port>`
    pub async fn whois(&self, addr: &str) -> Result<WhoIsResponse, LocalApiError> {
        let path = format!("/localapi/v0/whois?addr={}", urlencode(addr));
        let r = self.get_ok(&path).await?;
        Self::decode(&path, &r.body)
    }

    /// `GET /localapi/v0/serve-config` -> (config, etag). A never-configured
    /// node returns JSON `null`, which is normalised to an empty object.
    pub async fn get_serve_config(&self) -> Result<(Value, Option<String>), LocalApiError> {
        let path = "/localapi/v0/serve-config";
        let r = self.get_ok(path).await?;
        let etag = r
            .headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let mut v: Value = Self::decode(path, &r.body)?;
        if v.is_null() {
            v = Value::Object(Default::default());
        }
        Ok((v, etag))
    }

    /// `POST /localapi/v0/serve-config` with `If-Match: <etag>`.
    pub async fn set_serve_config(
        &self,
        cfg: &Value,
        etag: Option<&str>,
    ) -> Result<(), LocalApiError> {
        let path = "/localapi/v0/serve-config";
        let mut headers = Vec::new();
        if let Some(e) = etag {
            if let Ok(v) = HeaderValue::from_str(e) {
                headers.push((HeaderName::from_static("if-match"), v));
            }
        }
        let body = serde_json::to_vec(cfg).map_err(|e| LocalApiError::Transport(e.to_string()))?;
        let r = self
            .request(Method::POST, path, Some(body), &headers)
            .await?;
        if r.status != StatusCode::OK {
            return Err(LocalApiError::Status {
                path: path.to_string(),
                status: r.status,
                body: String::from_utf8_lossy(&r.body).trim().to_string(),
            });
        }
        Ok(())
    }
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Compute the desired serve configuration for tsidp given the current one.
/// Returns `None` when nothing needs to change.
///
/// The result: HTTPS on `public_port`, proxied to `http://127.0.0.1:<local_port>`
/// for host `fqdn`, with Funnel allowed or disallowed for that host:port.
pub fn desired_serve_config(
    current: &Value,
    fqdn: &str,
    public_port: u16,
    local_port: u16,
    funnel: bool,
) -> Option<Value> {
    let mut next = current.clone();
    if !next.is_object() {
        next = Value::Object(Default::default());
    }
    let obj = next.as_object_mut().unwrap();
    let host_port = format!("{fqdn}:{public_port}");

    let tcp = obj
        .entry("TCP")
        .or_insert_with(|| Value::Object(Default::default()));
    if !tcp.is_object() {
        *tcp = Value::Object(Default::default());
    }
    tcp.as_object_mut().unwrap().insert(
        public_port.to_string(),
        serde_json::json!({ "HTTPS": true }),
    );

    let web = obj
        .entry("Web")
        .or_insert_with(|| Value::Object(Default::default()));
    if !web.is_object() {
        *web = Value::Object(Default::default());
    }
    web.as_object_mut().unwrap().insert(
        host_port.clone(),
        serde_json::json!({ "Handlers": { "/": { "Proxy": format!("http://127.0.0.1:{local_port}") } } }),
    );

    if funnel {
        let af = obj
            .entry("AllowFunnel")
            .or_insert_with(|| Value::Object(Default::default()));
        if !af.is_object() {
            *af = Value::Object(Default::default());
        }
        af.as_object_mut()
            .unwrap()
            .insert(host_port, Value::Bool(true));
    } else if let Some(af) = obj.get_mut("AllowFunnel").and_then(|v| v.as_object_mut()) {
        af.remove(&host_port);
        if af.is_empty() {
            obj.remove("AllowFunnel");
        }
    }

    if &next == current { None } else { Some(next) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_config_from_empty() {
        let cur = Value::Object(Default::default());
        let next = desired_serve_config(&cur, "idp.tn.ts.net", 443, 8443, false).unwrap();
        assert_eq!(next["TCP"]["443"]["HTTPS"], true);
        assert_eq!(
            next["Web"]["idp.tn.ts.net:443"]["Handlers"]["/"]["Proxy"],
            "http://127.0.0.1:8443"
        );
        assert!(next.get("AllowFunnel").is_none());
        // idempotent
        assert!(desired_serve_config(&next, "idp.tn.ts.net", 443, 8443, false).is_none());
    }

    #[test]
    fn serve_config_preserves_other_entries_and_toggles_funnel() {
        let cur = serde_json::json!({
            "TCP": {"8080": {"TCPForward": "127.0.0.1:9000"}},
            "Web": {"other.tn.ts.net:8080": {"Handlers": {"/": {"Text": "hi"}}}},
            "AllowFunnel": {"idp.tn.ts.net:443": true}
        });
        let next = desired_serve_config(&cur, "idp.tn.ts.net", 443, 8443, false).unwrap();
        assert_eq!(next["TCP"]["8080"]["TCPForward"], "127.0.0.1:9000");
        assert!(next.get("AllowFunnel").is_none());
        let again = desired_serve_config(&next, "idp.tn.ts.net", 443, 8443, true).unwrap();
        assert_eq!(again["AllowFunnel"]["idp.tn.ts.net:443"], true);
    }
}
