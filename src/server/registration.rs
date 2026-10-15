//! RFC 7591 dynamic client registration and the JSON `/clients` API used by
//! automation (and the Kubernetes operator pattern: register a client, drop
//! the credentials into a Secret).

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use super::AppState;
use super::caller::Caller;
use super::error::OAuthError;
use crate::clients::{
    AUTH_METHOD_BASIC, AUTH_METHOD_NONE, Client, generate_client_secret, split_redirect_uris,
    validate_redirect_uri,
};

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct RegistrationRequest {
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: String,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    client_name: String,
    client_uri: String,
    logo_uri: String,
    scope: String,
    contacts: Vec<String>,
    application_type: String,
}

fn registration_response(c: &Client, issuer: &str) -> serde_json::Value {
    let mut v = serde_json::to_value(c).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.remove("redirect_uri");
        o.remove("dynamically_registered");
        o.insert(
            "client_id_issued_at".into(),
            json!(crate::util::parse_rfc3339(&c.created_at).unwrap_or(0)),
        );
        if c.has_secret() {
            o.insert("client_secret_expires_at".into(), json!(0));
        }
        o.insert(
            "registration_client_uri".into(),
            json!(format!("{issuer}/clients/{}", c.id)),
        );
    }
    v
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    body: Bytes,
) -> Result<Response, OAuthError> {
    let (_, access) = state.identify_with_access(&caller).await?;
    if !access.allow_dcr {
        state.metrics.denied();
        return Err(OAuthError::access_denied(
            "application capability allow_dcr not granted",
        ));
    }
    let req: RegistrationRequest = serde_json::from_slice(&body).map_err(|e| {
        OAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "invalid request body",
        )
        .detail(e)
    })?;
    if req.redirect_uris.is_empty() {
        return Err(OAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "redirect_uris is required",
        ));
    }
    for u in &req.redirect_uris {
        if let Err(reason) = validate_redirect_uri(u, state.cfg.allow_http_redirect_uris) {
            return Err(OAuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                format!("{u}: {reason}"),
            ));
        }
    }
    let public = req.token_endpoint_auth_method == AUTH_METHOD_NONE;
    let mut c = Client::new(&req.client_name, req.redirect_uris, public);
    c.token_endpoint_auth_method = if req.token_endpoint_auth_method.is_empty() {
        AUTH_METHOD_BASIC.to_string()
    } else {
        req.token_endpoint_auth_method
    };
    if !req.grant_types.is_empty() {
        c.grant_types = req.grant_types;
    }
    if !req.response_types.is_empty() {
        c.response_types = req.response_types;
    }
    if !req.application_type.is_empty() {
        c.application_type = req.application_type;
    }
    c.scope = req.scope;
    c.client_uri = req.client_uri;
    c.logo_uri = req.logo_uri;
    c.contacts = req.contacts;
    c.dynamically_registered = true;
    state
        .clients
        .insert(c.clone())
        .await
        .map_err(|e| OAuthError::server_error("failed to store client").detail(e))?;
    state.metrics.inc_registrations();
    tracing::info!(client_id = %c.id, name = %c.name, public, "client registered via DCR");
    let issuer = state.issuer().map(|i| i.url).unwrap_or_default();
    Ok((
        StatusCode::CREATED,
        Json(registration_response(&c, &issuer)),
    )
        .into_response())
}

async fn require_admin(state: &AppState, caller: &Caller) -> Result<(), OAuthError> {
    let (_, access) = state.identify_with_access(caller).await?;
    if !access.allow_admin_ui {
        state.metrics.denied();
        return Err(OAuthError::access_denied(
            "application capability allow_admin_ui not granted",
        ));
    }
    Ok(())
}

pub async fn clients_list(
    State(state): State<Arc<AppState>>,
    caller: Caller,
) -> Result<Response, OAuthError> {
    require_admin(&state, &caller).await?;
    let list: Vec<Client> = state
        .clients
        .list()
        .into_iter()
        .map(|c| c.redacted())
        .collect();
    Ok(Json(list).into_response())
}

/// `POST /clients/new` with form fields `name`, `redirect_uri` (one per line)
/// and optional `public=1`, or the same as JSON. Returns the client including
/// its secret: the only time it is ever shown.
pub async fn clients_new(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, OAuthError> {
    require_admin(&state, &caller).await?;
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (name, uris_text, public) = if ct.starts_with("application/json") {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct J {
            name: String,
            redirect_uri: String,
            redirect_uris: Vec<String>,
            public: bool,
        }
        let j: J = serde_json::from_slice(&body)
            .map_err(|e| OAuthError::invalid_request("invalid JSON").detail(e))?;
        let text = if j.redirect_uris.is_empty() {
            j.redirect_uri
        } else {
            j.redirect_uris.join("\n")
        };
        (j.name, text, j.public)
    } else {
        let form = super::token::Form::parse(&body);
        (
            form.get("name").unwrap_or("").to_string(),
            form.get("redirect_uri")
                .or(form.get("redirect_uris"))
                .unwrap_or("")
                .to_string(),
            form.get("public")
                .map(|v| crate::util::parse_bool(v).unwrap_or(false))
                .unwrap_or(false),
        )
    };
    let uris = split_redirect_uris(&uris_text);
    if uris.is_empty() || name.trim().is_empty() {
        return Err(OAuthError::invalid_request("missing redirect_uri or name"));
    }
    for u in &uris {
        validate_redirect_uri(u, state.cfg.allow_http_redirect_uris)
            .map_err(|r| OAuthError::invalid_request(format!("invalid redirect URI {u}: {r}")))?;
    }
    let c = Client::new(name.trim(), uris, public);
    state
        .clients
        .insert(c.clone())
        .await
        .map_err(|e| OAuthError::server_error("failed to store client").detail(e))?;
    state.metrics.inc_registrations();
    tracing::info!(client_id = %c.id, name = %c.name, public, "client created via API");
    Ok((StatusCode::CREATED, Json(c)).into_response())
}

pub async fn client_by_id(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    method: Method,
    Path(id): Path<String>,
) -> Result<Response, OAuthError> {
    require_admin(&state, &caller).await?;
    let Some(c) = state.clients.get(&id) else {
        return Err(OAuthError::not_found("client not found"));
    };
    match method {
        Method::GET => Ok(Json(c.redacted()).into_response()),
        Method::DELETE => {
            state
                .clients
                .delete(&id)
                .await
                .map_err(|e| OAuthError::server_error("failed to store clients").detail(e))?;
            state.tokens.revoke_client(&id);
            tracing::info!(client_id = %id, "client deleted via API");
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        _ => Err(OAuthError::method_not_allowed()),
    }
}

/// `POST /clients/{id}/secret` rotates the secret of a confidential client.
pub async fn client_rotate_secret(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(id): Path<String>,
) -> Result<Response, OAuthError> {
    require_admin(&state, &caller).await?;
    let secret = generate_client_secret();
    let s2 = secret.clone();
    let found = state
        .clients
        .update(&id, move |c| {
            c.secret = s2;
            if c.token_endpoint_auth_method == AUTH_METHOD_NONE {
                c.token_endpoint_auth_method = AUTH_METHOD_BASIC.to_string();
            }
        })
        .await
        .map_err(|e| OAuthError::server_error("failed to store clients").detail(e))?;
    if !found {
        return Err(OAuthError::not_found("client not found"));
    }
    state.tokens.revoke_client(&id);
    tracing::info!(client_id = %id, "client secret rotated via API");
    Ok(Json(json!({ "client_id": id, "client_secret": secret })).into_response())
}
