//! OpenID Connect UserInfo.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use std::sync::Arc;

use super::AppState;
use super::error::{EC_INVALID_REQUEST, EC_INVALID_TOKEN, OAuthError};
use super::token::merged_groups;
use crate::capability::apply_extra_claims;

pub async fn userinfo(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    state.metrics.inc_userinfo();
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        return OAuthError::bearer(
            StatusCode::BAD_REQUEST,
            EC_INVALID_REQUEST,
            "invalid Authorization header",
        );
    };
    let Some(ar) = state.tokens.get_access(token) else {
        return OAuthError::bearer(
            StatusCode::UNAUTHORIZED,
            EC_INVALID_TOKEN,
            "invalid or expired token",
        );
    };
    let who = &ar.identity;
    if who.is_tagged() && !state.cfg.allow_tagged_nodes {
        return OAuthError::invalid_request("tagged nodes not supported").into_response();
    }

    let mut ui = Map::new();
    ui.insert("sub".into(), json!(who.subject()));
    if who.is_tagged() {
        ui.insert("preferred_username".into(), json!(who.node_name));
        ui.insert("name".into(), json!(who.node_name));
        ui.insert("tags".into(), json!(who.tags));
    } else {
        if !who.display_name.is_empty() {
            ui.insert("name".into(), json!(who.display_name));
        }
        ui.insert("email".into(), json!(state.realish_email(&who.login_name)));
        if !who.profile_pic_url.is_empty() {
            ui.insert("picture".into(), json!(who.profile_pic_url));
        }
        if let Some(u) = who.username() {
            ui.insert("username".into(), json!(u));
            ui.insert("preferred_username".into(), json!(u));
        }
    }
    let groups = merged_groups(who);
    if !groups.is_empty() {
        ui.insert("groups".into(), json!(groups));
    }
    let included: Vec<_> = who
        .cap_rules
        .iter()
        .filter(|r| r.include_in_user_info)
        .cloned()
        .collect();
    apply_extra_claims(&mut ui, &included);
    Json(Value::Object(ui)).into_response()
}
