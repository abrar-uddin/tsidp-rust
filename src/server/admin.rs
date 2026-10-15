//! Health, readiness, metrics and version on the admin listener.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;

use super::AppState;

/// Liveness: the process is up and serving.
pub async fn healthz() -> &'static str {
    "ok\n"
}

/// Readiness: issuer known, signing key loaded and tailscaled reported
/// Running recently. Kubernetes keeps the pod out of Service endpoints
/// until this passes, and marks it unready again if tailscaled wedges.
///
/// The body is deliberately terse: the admin listener is unauthenticated and
/// usually reachable from the whole cluster network, so backend paths, Secret
/// names, versions and raw error strings stay in the logs.
pub async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    let link = state.link.read().clone();
    let issuer = state.issuer();
    let ready = state.ready();
    let body = json!({
        "ready": ready,
        "issuer": issuer.map(|i| i.url),
        "tailscaled": {
            "running": link.running,
            "reachable": link.last_error.is_none(),
            "last_ok_unix": link.last_ok,
            "serve_config": link.serve_config.as_ref().map(|r| match r {
                Ok(_) => "ok",
                Err(_) => "error",
            }),
        },
    });
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

pub async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let text = state.metrics.render(
        state.tokens.counts(),
        state.ready(),
        &[
            ("version", crate::version()),
            ("issuer", &state.issuer().map(|i| i.url).unwrap_or_default()),
        ],
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        text,
    )
        .into_response()
}

pub async fn version() -> Json<serde_json::Value> {
    Json(json!({ "version": crate::version(), "name": "tsidp" }))
}
