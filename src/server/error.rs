//! OAuth 2.0 error responses (RFC 6749 §5.2) as JSON.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

pub const EC_ACCESS_DENIED: &str = "access_denied";
pub const EC_INVALID_REQUEST: &str = "invalid_request";
pub const EC_INVALID_CLIENT: &str = "invalid_client";
pub const EC_INVALID_GRANT: &str = "invalid_grant";
pub const EC_INVALID_SCOPE: &str = "invalid_scope";
pub const EC_SERVER_ERROR: &str = "server_error";
pub const EC_NOT_FOUND: &str = "not_found";
pub const EC_UNSUPPORTED_GRANT: &str = "unsupported_grant_type";
pub const EC_INVALID_TOKEN: &str = "invalid_token";
pub const EC_TEMPORARILY_UNAVAILABLE: &str = "temporarily_unavailable";

#[derive(Debug)]
pub struct OAuthError {
    pub status: StatusCode,
    pub code: &'static str,
    pub description: String,
    /// Extra detail for the log line only, never sent to the client.
    pub detail: Option<String>,
}

#[derive(Serialize)]
struct Body<'a> {
    error: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    error_description: &'a str,
}

impl OAuthError {
    pub fn new(status: StatusCode, code: &'static str, description: impl Into<String>) -> Self {
        OAuthError {
            status,
            code,
            description: description.into(),
            detail: None,
        }
    }

    pub fn detail(mut self, d: impl std::fmt::Display) -> Self {
        self.detail = Some(d.to_string());
        self
    }

    pub fn invalid_request(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, EC_INVALID_REQUEST, d)
    }
    pub fn invalid_client(d: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, EC_INVALID_CLIENT, d)
    }
    pub fn invalid_grant(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, EC_INVALID_GRANT, d)
    }
    pub fn invalid_scope(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, EC_INVALID_SCOPE, d)
    }
    pub fn access_denied(d: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, EC_ACCESS_DENIED, d)
    }
    pub fn unauthorized(d: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, EC_ACCESS_DENIED, d)
    }
    pub fn not_found(d: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, EC_NOT_FOUND, d)
    }
    pub fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            EC_INVALID_REQUEST,
            "method not allowed",
        )
    }
    pub fn server_error(d: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, EC_SERVER_ERROR, d)
    }
    pub fn unsupported_grant(d: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, EC_UNSUPPORTED_GRANT, d)
    }
    pub fn not_ready() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            EC_TEMPORARILY_UNAVAILABLE,
            "tsidp is not ready: waiting for tailscaled to report Running and a DNS name",
        )
    }

    /// RFC 6750 bearer error with a `WWW-Authenticate` header.
    pub fn bearer(
        status: StatusCode,
        code: &'static str,
        description: impl Into<String>,
    ) -> Response {
        let description = description.into();
        let mut resp = OAuthError::new(status, code, description.clone()).into_response();
        let value = if description.is_empty() {
            format!("Bearer error=\"{code}\"")
        } else {
            format!(
                "Bearer error=\"{code}\", error_description=\"{}\"",
                description.replace('"', "'")
            )
        };
        if let Ok(v) = header::HeaderValue::from_str(&value) {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
        resp
    }
}

impl From<anyhow::Error> for OAuthError {
    fn from(e: anyhow::Error) -> Self {
        OAuthError::server_error("internal error").detail(e)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let detail = self.detail.as_deref().unwrap_or("");
        match self.status.as_u16() {
            500..=599 => {
                tracing::error!(status = %self.status, code = self.code, desc = %self.description, detail, "request failed")
            }
            401 | 403 => {
                tracing::warn!(status = %self.status, code = self.code, desc = %self.description, detail, "request denied")
            }
            _ => {
                tracing::debug!(status = %self.status, code = self.code, desc = %self.description, detail, "request rejected")
            }
        }
        let body = serde_json::to_string(&Body {
            error: self.code,
            error_description: &self.description,
        })
        .unwrap_or_else(|_| "{\"error\":\"server_error\"}".into());
        (
            self.status,
            [
                (header::CONTENT_TYPE, "application/json;charset=UTF-8"),
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            body,
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn responses_and_constructors() {
        let cases = [
            (OAuthError::invalid_request("r"), 400, EC_INVALID_REQUEST),
            (OAuthError::invalid_client("c"), 401, EC_INVALID_CLIENT),
            (OAuthError::invalid_grant("g"), 400, EC_INVALID_GRANT),
            (OAuthError::invalid_scope("s"), 400, EC_INVALID_SCOPE),
            (OAuthError::access_denied("d"), 403, EC_ACCESS_DENIED),
            (OAuthError::unauthorized("u"), 401, EC_ACCESS_DENIED),
            (OAuthError::not_found("n"), 404, EC_NOT_FOUND),
            (OAuthError::method_not_allowed(), 405, EC_INVALID_REQUEST),
            (
                OAuthError::server_error("e").detail("secret detail"),
                500,
                EC_SERVER_ERROR,
            ),
            (
                OAuthError::unsupported_grant("x"),
                400,
                EC_UNSUPPORTED_GRANT,
            ),
            (OAuthError::not_ready(), 503, EC_TEMPORARILY_UNAVAILABLE),
            (
                OAuthError::from(anyhow::anyhow!("boom")),
                500,
                EC_SERVER_ERROR,
            ),
        ];
        for (e, status, code) in cases {
            let resp = e.into_response();
            assert_eq!(resp.status().as_u16(), status);
            assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 16).await.unwrap())
                    .unwrap();
            assert_eq!(body["error"], code);
            assert!(!body.to_string().contains("secret detail"));
            assert!(!body.to_string().contains("boom"));
        }
        let resp = OAuthError::bearer(StatusCode::UNAUTHORIZED, EC_INVALID_TOKEN, "say \"hi\"");
        assert_eq!(
            resp.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"invalid_token\", error_description=\"say 'hi'\""
        );
        let resp = OAuthError::bearer(StatusCode::UNAUTHORIZED, EC_INVALID_TOKEN, "");
        assert_eq!(
            resp.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"invalid_token\""
        );
    }
}
