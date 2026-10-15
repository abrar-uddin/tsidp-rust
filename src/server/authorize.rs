//! The authorization endpoint. There is no login page: the caller's tailnet
//! identity *is* the authentication, so a valid request is answered with an
//! immediate redirect carrying a short-lived code.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::Arc;

use super::AppState;
use super::caller::Caller;
use super::error::{EC_ACCESS_DENIED, EC_INVALID_REQUEST, EC_INVALID_SCOPE, OAuthError};
use crate::tokens::AuthRequest;
use crate::util::{now_unix, random_hex};

/// Parameters from the query string (GET) or a form body (POST, RFC 6749
/// §3.1 allows both; the Go implementation only read the query, issue #195).
pub fn request_params(
    method: &Method,
    query: Option<&str>,
    headers: &HeaderMap,
    body: &Bytes,
) -> HashMap<String, String> {
    let mut params: HashMap<String, String> = HashMap::new();
    if let Some(q) = query {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            params
                .entry(k.into_owned())
                .or_insert_with(|| v.into_owned());
        }
    }
    if method == Method::POST {
        let ct = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct.starts_with("application/x-www-form-urlencoded") {
            for (k, v) in url::form_urlencoded::parse(body) {
                params.insert(k.into_owned(), v.into_owned());
            }
        }
    }
    params
}

/// `302 Found` to `location`. (axum's `Redirect::to` is a 303 and
/// `Redirect::temporary` a 307, which would replay a POSTed body.)
pub fn found(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, location.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
    )
        .into_response()
}

/// Redirect back to the client with an error (RFC 6749 §4.1.2.1).
fn redirect_error(
    redirect_uri: &str,
    code: &str,
    description: &str,
    state: Option<&str>,
) -> Response {
    match url::Url::parse(redirect_uri) {
        Ok(mut u) => {
            {
                let mut q = u.query_pairs_mut();
                q.append_pair("error", code);
                if !description.is_empty() {
                    q.append_pair("error_description", description);
                }
                if let Some(s) = state {
                    q.append_pair("state", s);
                }
            }
            tracing::info!(
                error = code,
                description,
                "authorize: redirecting with error"
            );
            found(u.as_str())
        }
        Err(e) => OAuthError::invalid_request("invalid redirect_uri")
            .detail(e)
            .into_response(),
    }
}

pub async fn authorize(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    method: Method,
    headers: HeaderMap,
    query: axum::extract::RawQuery,
    body: Bytes,
) -> Result<Response, OAuthError> {
    if method != Method::GET && method != Method::POST {
        return Err(OAuthError::method_not_allowed());
    }
    let p = request_params(&method, query.0.as_deref(), &headers, &body);
    let get = |k: &str| p.get(k).map(|s| s.trim()).filter(|s| !s.is_empty());
    let req_state = get("state");

    // Anything wrong with client_id / redirect_uri is reported directly: we
    // must not redirect to an unvalidated URI.
    let redirect_uri = get("redirect_uri")
        .ok_or_else(|| OAuthError::invalid_request("must specify redirect_uri"))?;
    let client_id =
        get("client_id").ok_or_else(|| OAuthError::invalid_request("must specify client_id"))?;
    let client = state.clients.get(client_id).ok_or_else(|| {
        OAuthError::new(
            StatusCode::BAD_REQUEST,
            super::error::EC_INVALID_CLIENT,
            "invalid client ID",
        )
    })?;
    if !client.redirect_uris.iter().any(|u| u == redirect_uri) {
        return Err(OAuthError::invalid_request("redirect_uri mismatch"));
    }

    // From here on errors go back to the client via redirect.
    if let Some(rt) = get("response_type") {
        if rt != "code" {
            return Ok(redirect_error(
                redirect_uri,
                "unsupported_response_type",
                "only response_type=code is supported",
                req_state,
            ));
        }
    }

    let identity = match state.identify(&caller).await {
        Ok(id) => id,
        Err(e) if e.status == StatusCode::INTERNAL_SERVER_ERROR => return Err(e),
        Err(e) => {
            return Ok(redirect_error(
                redirect_uri,
                EC_ACCESS_DENIED,
                &e.description,
                req_state,
            ));
        }
    };
    if identity.is_tagged() && !state.cfg.allow_tagged_nodes {
        return Ok(redirect_error(
            redirect_uri,
            EC_ACCESS_DENIED,
            "tagged node doesn't have a user identity (start tsidp with --allow-tagged-nodes to issue node tokens)",
            req_state,
        ));
    }

    let scopes = match state.validate_scopes(get("scope").unwrap_or("")) {
        Ok(s) => s,
        Err(bad) => {
            return Ok(redirect_error(
                redirect_uri,
                EC_INVALID_SCOPE,
                &format!("unsupported scope {bad:?}"),
                req_state,
            ));
        }
    };

    let mut code_challenge = None;
    let mut code_challenge_method = None;
    if let Some(cc) = get("code_challenge") {
        // RFC 7636 defaults to `plain`; we only accept S256 (OAuth 2.1), so a
        // missing method is an error rather than a silent downgrade.
        let m = get("code_challenge_method").unwrap_or("plain");
        if m != "S256" {
            return Ok(redirect_error(
                redirect_uri,
                EC_INVALID_REQUEST,
                "unsupported code_challenge_method (only S256 is accepted)",
                req_state,
            ));
        }
        code_challenge = Some(cc.to_string());
        code_challenge_method = Some(m.to_string());
    }
    if client.is_public() && code_challenge_method.as_deref() != Some("S256") {
        return Ok(redirect_error(
            redirect_uri,
            EC_INVALID_REQUEST,
            "public clients must use PKCE with code_challenge_method=S256",
            req_state,
        ));
    }

    // RFC 8707 resource indicators requested at authorization time are
    // validated at token issuance, as in the Go implementation.
    let resources: Vec<String> = p
        .get("resource")
        .map(|r| vec![r.clone()])
        .unwrap_or_default();

    let now = now_unix();
    let code = random_hex(32);
    let ar = AuthRequest {
        family: random_hex(16),
        client_id: client.id.clone(),
        client: Some(Arc::new(client.clone())),
        nonce: get("nonce").unwrap_or("").to_string(),
        redirect_uri: redirect_uri.to_string(),
        scopes,
        resources,
        code_challenge,
        code_challenge_method,
        identity,
        valid_till: now + state.cfg.code_ttl,
        issued_at: now,
        not_before: now,
        jti: String::new(),
        issuer: String::new(),
        is_exchanged: false,
        original_client_id: String::new(),
        exchanged_by: String::new(),
        audiences: Vec::new(),
        actor: None,
    };
    state.tokens.put_code(code.clone(), ar);
    state.metrics.inc_codes();

    let mut u = url::Url::parse(redirect_uri)
        .map_err(|e| OAuthError::server_error("invalid redirect URI").detail(e))?;
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("code", &code);
        if let Some(s) = req_state {
            q.append_pair("state", s);
        }
    }
    tracing::debug!(client_id, "authorize: issued code");
    Ok(found(u.as_str()))
}

impl AppState {
    /// Validate a space separated scope string. Empty defaults to `openid`.
    pub fn validate_scopes(&self, scope: &str) -> Result<Vec<String>, String> {
        let requested: Vec<&str> = scope.split_whitespace().collect();
        if requested.is_empty() {
            return Ok(vec!["openid".to_string()]);
        }
        let mut out = Vec::with_capacity(requested.len());
        for s in requested {
            if !self.supported_scopes.iter().any(|x| x == s) {
                return Err(s.to_string());
            }
            if !out.iter().any(|x| x == s) {
                out.push(s.to_string());
            }
        }
        Ok(out)
    }
}
