//! Cross-site request forgery protection for the browser-facing admin UI and
//! the `/clients` API, based on Fetch Metadata (`Sec-Fetch-Site`) with an
//! `Origin` fallback for older browsers. OAuth endpoints are deliberately
//! not covered: they are cross-origin by design and protected by client
//! authentication and PKCE instead (the Go implementation wrapped everything,
//! which broke cross-origin dynamic registration, issue #106).

use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use super::AppState;
use super::error::OAuthError;

pub async fn protect(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let m = req.method();
    if m == Method::GET || m == Method::HEAD || m == Method::OPTIONS {
        return next.run(req).await;
    }
    let headers = req.headers();
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if site != "same-origin" && site != "none" {
            state.metrics.denied();
            return OAuthError::access_denied("cross-site request rejected")
                .detail(format!("Sec-Fetch-Site={site}"))
                .into_response();
        }
        return next.run(req).await;
    }
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let trusted = state.issuer().map(|i| i.url).unwrap_or_default();
        let origin_ok = origin == trusted
            || headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(|h| {
                    origin.strip_prefix("https://") == Some(h)
                        || origin.strip_prefix("http://") == Some(h)
                })
                .unwrap_or(false);
        if !origin_ok {
            state.metrics.denied();
            return OAuthError::access_denied("cross-origin request rejected")
                .detail(format!("Origin={origin}"))
                .into_response();
        }
    }
    next.run(req).await
}
