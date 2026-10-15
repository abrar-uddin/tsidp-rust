//! Discovery documents and JWKS.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::sync::Arc;

use super::caller::Caller;
use super::error::OAuthError;
use super::{AppState, Listener};

pub const RESPONSE_TYPES: &[&str] = &["code"];
pub const SUBJECT_TYPES: &[&str] = &["public"];
pub const SIGNING_ALGS: &[&str] = &["RS256"];
/// `plain` is deliberately not offered (RFC 7636 §7.2, OAuth 2.1).
pub const CODE_CHALLENGE_METHODS: &[&str] = &["S256"];
pub const TOKEN_AUTH_METHODS: &[&str] = &["client_secret_post", "client_secret_basic", "none"];
pub const CLAIMS_SUPPORTED: &[&str] = &[
    "sub",
    "aud",
    "exp",
    "iat",
    "iss",
    "jti",
    "nbf",
    "nonce",
    "azp",
    "email",
    "email_verified",
    "preferred_username",
    "username",
    "name",
    "picture",
    "groups",
    "key",
    "addresses",
    "nid",
    "node",
    "tailnet",
    "tags",
    "uid",
];

impl AppState {
    pub fn grant_types(&self) -> Vec<&'static str> {
        let mut g = vec!["authorization_code", "refresh_token"];
        if self.cfg.enable_sts {
            g.push("urn:ietf:params:oauth:grant-type:token-exchange");
        }
        g
    }

    /// Registration is advertised only where it can be used: on the tailnet
    /// listener and not over Funnel.
    fn registration_endpoint(&self, caller: &Caller, issuer: &str) -> Option<String> {
        if caller.listener == Listener::Tailnet && !caller.is_funnel {
            Some(format!("{issuer}/register"))
        } else {
            None
        }
    }
}

fn pretty(v: Value) -> Response {
    let body = serde_json::to_string_pretty(&v).unwrap_or_default();
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// URLs for one discovery document. `authorize` is always the tailnet issuer
/// (browsers must reach it there); the rest depends on the listener.
struct Urls {
    issuer: String,
    authorize: String,
    base: String,
}

fn urls(state: &AppState, caller: &Caller, headers: &HeaderMap) -> Result<Urls, OAuthError> {
    let tailnet = state.require_issuer()?.url;
    Ok(Urls {
        issuer: state.issuer_for(caller)?.url,
        authorize: tailnet,
        base: state.endpoint_base(caller, headers)?,
    })
}

pub async fn openid_configuration(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    headers: HeaderMap,
) -> Result<Response, OAuthError> {
    let Urls {
        issuer,
        authorize,
        base,
    } = urls(&state, &caller, &headers)?;
    let mut doc = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{authorize}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "userinfo_endpoint": format!("{base}/userinfo"),
        "introspection_endpoint": format!("{base}/introspect"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "scopes_supported": state.supported_scopes,
        "response_types_supported": RESPONSE_TYPES,
        "subject_types_supported": SUBJECT_TYPES,
        "claims_supported": CLAIMS_SUPPORTED,
        "id_token_signing_alg_values_supported": SIGNING_ALGS,
        "grant_types_supported": state.grant_types(),
        "token_endpoint_auth_methods_supported": TOKEN_AUTH_METHODS,
        "code_challenge_methods_supported": CODE_CHALLENGE_METHODS,
    });
    if let Some(reg) = state.registration_endpoint(&caller, &authorize) {
        doc["registration_endpoint"] = Value::String(reg);
    }
    Ok(pretty(doc))
}

pub async fn oauth_authorization_server(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    headers: HeaderMap,
) -> Result<Response, OAuthError> {
    let Urls {
        issuer,
        authorize,
        base,
    } = urls(&state, &caller, &headers)?;
    let mut doc = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{authorize}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "introspection_endpoint": format!("{base}/introspect"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "response_types_supported": RESPONSE_TYPES,
        "grant_types_supported": state.grant_types(),
        "scopes_supported": state.supported_scopes,
        "token_endpoint_auth_methods_supported": TOKEN_AUTH_METHODS,
        "resource_indicators_supported": true,
        "authorization_details_types_supported": ["resource_indicators"],
        "code_challenge_methods_supported": CODE_CHALLENGE_METHODS,
    });
    if let Some(reg) = state.registration_endpoint(&caller, &authorize) {
        doc["registration_endpoint"] = Value::String(reg);
    }
    Ok(pretty(doc))
}

pub async fn jwks(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({ "keys": [state.key.jwk()] }))
}
