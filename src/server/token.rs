//! The token endpoint: authorization_code, refresh_token and RFC 8693 token
//! exchange grants, plus RFC 7662 introspection.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::AppState;
use super::caller::Caller;
use super::error::{EC_INVALID_CLIENT, OAuthError};
use crate::capability::{allowed_resources, apply_extra_claims, granted_groups, user_matches};
use crate::clients::Client;
use crate::identity::Identity;
use crate::tokens::{ActorClaim, AuthRequest, RefreshError};
use crate::util::{b64url, ct_eq, now_unix, random_hex};

/// Clock skew allowance between `nbf` and `iat`.
pub const NOT_BEFORE_SKEW: i64 = 5 * 60;
pub const TOKEN_TYPE_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
pub const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// Parsed `application/x-www-form-urlencoded` body with repeated keys kept.
pub struct Form(Vec<(String, String)>);

impl Form {
    pub fn parse(body: &[u8]) -> Form {
        Form(
            url::form_urlencoded::parse(body)
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
        )
    }
    pub fn get(&self, k: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }
    pub fn all(&self, k: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
            .collect()
    }
}

/// Client credentials from HTTP Basic auth or the form body.
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
}

pub fn client_credentials(headers: &HeaderMap, form: &Form) -> Option<ClientCredentials> {
    if let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(b64) = v.strip_prefix("Basic ") {
            if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                if let Ok(s) = String::from_utf8(raw) {
                    if let Some((id, secret)) = s.split_once(':') {
                        let id: String = url::form_urlencoded::parse(id.as_bytes())
                            .map(|(k, _)| k.into_owned())
                            .collect();
                        let secret: String = url::form_urlencoded::parse(secret.as_bytes())
                            .map(|(k, _)| k.into_owned())
                            .collect();
                        return Some(ClientCredentials {
                            client_id: id,
                            client_secret: Some(secret).filter(|s| !s.is_empty()),
                        });
                    }
                }
            }
        }
    }
    let id = form.get("client_id")?;
    Some(ClientCredentials {
        client_id: id.to_string(),
        client_secret: form.get("client_secret").map(|s| s.to_string()),
    })
}

/// Authenticate the relying party for a grant that was issued to `client`.
/// Confidential clients must present the secret; public clients only have
/// to name themselves (PKCE did the real work). Secrets never reach the logs.
pub fn authenticate_client(
    client: &Client,
    creds: Option<&ClientCredentials>,
) -> Result<(), OAuthError> {
    let Some(creds) = creds else {
        return Err(OAuthError::invalid_client("missing client credentials"));
    };
    if !ct_eq(&creds.client_id, &client.id) {
        return Err(OAuthError::new(
            StatusCode::BAD_REQUEST,
            EC_INVALID_CLIENT,
            "client_id mismatch",
        ));
    }
    if client.is_public() {
        return Ok(());
    }
    match &creds.client_secret {
        Some(s) if ct_eq(s, &client.secret) => Ok(()),
        Some(_) => Err(OAuthError::invalid_client("invalid client secret")
            .detail(format!("client {}", client.id))),
        None => Err(OAuthError::invalid_client("client secret required")),
    }
}

pub async fn token(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, OAuthError> {
    let form = Form::parse(&body);
    match form.get("grant_type") {
        Some("authorization_code") => {
            authorization_code_grant(&state, &caller, &headers, &form).await
        }
        Some("refresh_token") => refresh_token_grant(&state, &caller, &headers, &form).await,
        Some(GRANT_TOKEN_EXCHANGE) => {
            if !state.cfg.enable_sts {
                return Err(OAuthError::unsupported_grant(
                    "token exchange not enabled (start with --enable-sts)",
                ));
            }
            token_exchange(&state, &caller, &headers, &form).await
        }
        other => {
            Err(OAuthError::unsupported_grant("unsupported grant type")
                .detail(format!("{other:?}")))
        }
    }
}

async fn authorization_code_grant(
    state: &AppState,
    caller: &Caller,
    headers: &HeaderMap,
    form: &Form,
) -> Result<Response, OAuthError> {
    let code = form
        .get("code")
        .ok_or_else(|| OAuthError::invalid_request("code is required"))?;
    let mut ar = state
        .tokens
        .take_code(code)
        .ok_or_else(|| OAuthError::invalid_grant("code not found or expired"))?;
    let client = ar
        .client
        .clone()
        .ok_or_else(|| OAuthError::invalid_client("no relying party configured"))?;
    authenticate_client(&client, client_credentials(headers, form).as_ref())?;

    if form.get("redirect_uri").unwrap_or("") != ar.redirect_uri {
        return Err(OAuthError::invalid_request("redirect_uri mismatch"));
    }
    if let Some(challenge) = &ar.code_challenge {
        let verifier = form
            .get("code_verifier")
            .ok_or_else(|| OAuthError::invalid_request("code_verifier is required"))?;
        validate_code_verifier(
            verifier,
            challenge,
            ar.code_challenge_method.as_deref().unwrap_or("plain"),
        )
        .map_err(|e| OAuthError::invalid_grant("code verification failed").detail(e))?;
    }

    let resources = form.all("resource");
    if !resources.is_empty() {
        let allowed =
            allowed_resources(&ar.identity.cap_rules, &ar.identity.login_name, &resources);
        if allowed.is_empty() {
            return Err(OAuthError::invalid_request(
                "invalid resource: not granted to this user",
            ));
        }
        ar.resources = allowed;
    } else if !ar.resources.is_empty() {
        ar.resources = allowed_resources(
            &ar.identity.cap_rules,
            &ar.identity.login_name,
            &ar.resources,
        );
    }
    state.metrics.inc_tokens();
    issue_tokens(state, caller, ar)
}

async fn refresh_token_grant(
    state: &AppState,
    caller: &Caller,
    headers: &HeaderMap,
    form: &Form,
) -> Result<Response, OAuthError> {
    let rt = form
        .get("refresh_token")
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
    // Single use: the token is gone whether or not the rest succeeds, and a
    // replay revokes everything derived from the same authorization.
    let prev = state.tokens.take_refresh(rt).map_err(|e| match e {
        RefreshError::Invalid => OAuthError::invalid_grant("invalid refresh token"),
        RefreshError::Reused => {
            state.metrics.denied();
            OAuthError::invalid_grant(
                "refresh token already used; all tokens from this authorization are revoked",
            )
        }
    })?;
    let client = prev
        .client
        .clone()
        .ok_or_else(|| OAuthError::invalid_client("no relying party configured"))?;
    authenticate_client(&client, client_credentials(headers, form).as_ref())?;

    let mut ar = (*prev).clone();
    // The grant is only as good as the user's current standing on the tailnet.
    ar.identity = state.revalidate(&prev.identity).await?;
    if !ar.resources.is_empty() {
        ar.resources = allowed_resources(
            &ar.identity.cap_rules,
            &ar.identity.login_name,
            &ar.resources,
        );
    }
    let requested = form.all("resource");
    if !requested.is_empty() {
        let allowed =
            allowed_resources(&ar.identity.cap_rules, &ar.identity.login_name, &requested);
        if allowed.is_empty() {
            return Err(OAuthError::invalid_request("resource validation failed"));
        }
        if !ar.resources.is_empty() && allowed.iter().any(|r| !ar.resources.contains(r)) {
            return Err(OAuthError::invalid_request(
                "requested resource not in original grant",
            ));
        }
        ar.resources = allowed;
    }
    if let Some(scope) = form.get("scope") {
        let narrowed = state
            .validate_scopes(scope)
            .map_err(|s| OAuthError::invalid_scope(format!("unsupported scope {s:?}")))?;
        if narrowed.iter().any(|s| !ar.scopes.contains(s)) {
            return Err(OAuthError::invalid_scope(
                "scope exceeds the original grant",
            ));
        }
        ar.scopes = narrowed;
    }
    state.metrics.inc_refresh();
    state.metrics.inc_tokens();
    issue_tokens(state, caller, ar)
}

/// Mint an ID token, an access token and a refresh token for `ar`.
fn issue_tokens(
    state: &AppState,
    caller: &Caller,
    mut ar: AuthRequest,
) -> Result<Response, OAuthError> {
    let issuer = state.issuer_for(caller)?;
    let who = ar.identity.clone();
    if who.is_tagged() && !state.cfg.allow_tagged_nodes {
        return Err(OAuthError::invalid_request("tagged nodes not supported"));
    }

    let now = now_unix();
    let exp = now + state.cfg.access_token_ttl;
    let nbf = now - NOT_BEFORE_SKEW;
    let jti = random_hex(16);

    let audience: Vec<String> = if ar.is_exchanged && !ar.audiences.is_empty() {
        let mut a = ar.audiences.clone();
        if !ar.original_client_id.is_empty() && !a.contains(&ar.original_client_id) {
            a.push(ar.original_client_id.clone());
        }
        a
    } else {
        let mut a = vec![ar.client_id.clone()];
        a.extend(ar.resources.iter().cloned());
        a
    };

    let mut claims = Map::new();
    claims.insert("iss".into(), json!(issuer.url));
    claims.insert("sub".into(), json!(who.subject()));
    claims.insert("aud".into(), json!(audience));
    claims.insert("exp".into(), json!(exp));
    claims.insert("iat".into(), json!(now));
    claims.insert("nbf".into(), json!(nbf));
    claims.insert("jti".into(), json!(jti));
    if !ar.nonce.is_empty() {
        claims.insert("nonce".into(), json!(ar.nonce));
    }
    if audience.len() > 1 {
        claims.insert("azp".into(), json!(ar.client_id));
    }
    add_tailscale_claims(&mut claims, &who);
    add_profile_claims(state, &mut claims, &who, &ar.scopes);
    apply_extra_claims(&mut claims, &who.cap_rules);
    if let Some(act) = &ar.actor {
        claims.insert(
            "act".into(),
            serde_json::to_value(act).unwrap_or(Value::Null),
        );
    }
    let id_token = state
        .key
        .sign(&claims, "JWT")
        .map_err(|e| OAuthError::server_error("error creating JWT").detail(e))?;

    ar.issued_at = now;
    ar.valid_till = exp;
    ar.not_before = nbf;
    ar.jti = jti.clone();
    ar.issuer = issuer.url.clone();

    let access_token = if state.cfg.jwt_access_tokens {
        let mut at = Map::new();
        for k in ["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "act"] {
            if let Some(v) = claims.get(k) {
                at.insert(k.into(), v.clone());
            }
        }
        at.insert("client_id".into(), json!(ar.client_id));
        at.insert("scope".into(), json!(ar.scopes.join(" ")));
        if let Some(e) = claims.get("email") {
            at.insert("email".into(), e.clone());
        }
        if let Some(g) = claims.get("groups") {
            at.insert("groups".into(), g.clone());
        }
        for (k, v) in crate::capability::flatten_extra_claims(&who.cap_rules) {
            if !crate::capability::PROTECTED_CLAIMS.contains(&k.as_str()) {
                at.insert(k, v);
            }
        }
        state
            .key
            .sign(&at, "at+jwt")
            .map_err(|e| OAuthError::server_error("error creating access token").detail(e))?
    } else {
        random_hex(32)
    };
    let refresh_token = random_hex(32);

    let shared = Arc::new(ar);
    state
        .tokens
        .put_access(access_token.clone(), shared.clone());
    let mut rt = (*shared).clone();
    rt.valid_till = now + state.cfg.refresh_token_ttl;
    state
        .tokens
        .put_refresh(refresh_token.clone(), Arc::new(rt));

    tracing::info!(
        for_user = %who.login_name,
        sub = %who.subject(),
        client_id = %shared.client_id,
        redirect_uri = %shared.redirect_uri,
        scopes = %shared.scopes.join(" "),
        "token issued"
    );

    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.cfg.access_token_ttl,
        "id_token": id_token,
        "refresh_token": refresh_token,
    });
    if !shared.scopes.iter().any(|s| s == "openid") {
        body.as_object_mut().unwrap().remove("id_token");
    }
    body["scope"] = json!(shared.scopes.join(" "));
    Ok(json_no_store(body))
}

fn json_no_store(v: Value) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        v.to_string(),
    )
        .into_response()
}

pub fn add_tailscale_claims(claims: &mut Map<String, Value>, who: &Identity) {
    claims.insert("key".into(), json!(who.node_key));
    claims.insert("addresses".into(), json!(who.addresses));
    claims.insert("nid".into(), json!(who.node_id));
    claims.insert("node".into(), json!(who.node_name));
    claims.insert("tailnet".into(), json!(who.tailnet()));
    if who.is_tagged() {
        claims.insert("tags".into(), json!(who.tags));
    } else {
        claims.insert("uid".into(), json!(who.user_id));
    }
}

/// Scope-gated profile claims, mirroring the Go implementation.
pub fn add_profile_claims(
    state: &AppState,
    claims: &mut Map<String, Value>,
    who: &Identity,
    scopes: &[String],
) {
    for scope in scopes {
        match scope.as_str() {
            "email" if !who.is_tagged() => {
                claims.insert("email".into(), json!(state.realish_email(&who.login_name)));
            }
            "profile" => {
                if who.is_tagged() {
                    claims.insert("preferred_username".into(), json!(who.node_name));
                } else {
                    if let Some(u) = who.username() {
                        claims.insert("preferred_username".into(), json!(u));
                    }
                    if !who.display_name.is_empty() {
                        claims.insert("name".into(), json!(who.display_name));
                    }
                    if !who.profile_pic_url.is_empty() {
                        claims.insert("picture".into(), json!(who.profile_pic_url));
                    }
                }
            }
            _ => {}
        }
    }
    let groups = merged_groups(who);
    if !groups.is_empty() {
        claims.insert("groups".into(), json!(groups));
    }
}

/// `groups` claim: tailnet user groups reported by tailscaled plus any from
/// the capability grant.
pub fn merged_groups(who: &Identity) -> Vec<String> {
    let mut g = who.groups.clone();
    for x in granted_groups(&who.cap_rules, &who.login_name) {
        if !g.contains(&x) {
            g.push(x);
        }
    }
    g
}

/// RFC 7636 §4.6. Only `S256` is supported; `plain` offers no protection
/// against a leaked authorization request and is rejected at `/authorize`.
pub fn validate_code_verifier(verifier: &str, challenge: &str, method: &str) -> Result<(), String> {
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err("code_verifier must be 43-128 characters".into());
    }
    if !verifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
    {
        return Err("code_verifier contains invalid characters".into());
    }
    let computed = match method {
        "S256" => b64url(&Sha256::digest(verifier.as_bytes())),
        other => return Err(format!("unsupported code_challenge_method: {other}")),
    };
    if ct_eq(&computed, challenge) {
        Ok(())
    } else {
        Err("invalid code_verifier".into())
    }
}

/// Identify the client making an STS or introspection call: a registered
/// confidential client via its credentials, or, when no credentials are
/// presented at all, the calling tailnet node. Presenting credentials that do
/// not verify is a hard failure: it must never degrade into node identity.
async fn identify_client(
    state: &AppState,
    caller: &Caller,
    headers: &HeaderMap,
    form: &Form,
) -> Option<String> {
    if let Some(creds) = client_credentials(headers, form) {
        let c = state.clients.get(&creds.client_id)?;
        if c.is_public() {
            // A public client has nothing to prove with; only the node can.
            return node_identity(state, caller).await;
        }
        return match &creds.client_secret {
            Some(secret) if ct_eq(secret, &c.secret) => Some(c.id),
            _ => {
                state.metrics.denied();
                tracing::warn!(client_id = %c.id, "client credentials rejected");
                None
            }
        };
    }
    node_identity(state, caller).await
}

async fn node_identity(state: &AppState, caller: &Caller) -> Option<String> {
    if caller.remote_addr.is_some() && !caller.is_funnel {
        if let Ok(id) = state.identify(caller).await {
            return Some(format!("node:{}", id.node_id));
        }
    }
    None
}

async fn token_exchange(
    state: &AppState,
    caller: &Caller,
    headers: &HeaderMap,
    form: &Form,
) -> Result<Response, OAuthError> {
    let subject_token = form
        .get("subject_token")
        .ok_or_else(|| OAuthError::invalid_request("subject_token is required"))?;
    if form.get("subject_token_type") != Some(TOKEN_TYPE_ACCESS) {
        return Err(OAuthError::invalid_request(
            "unsupported subject_token_type",
        ));
    }
    if let Some(rt) = form.get("requested_token_type") {
        if rt != TOKEN_TYPE_ACCESS {
            return Err(OAuthError::invalid_request(
                "unsupported requested_token_type",
            ));
        }
    }
    let audiences = form.all("audience");
    if audiences.is_empty() {
        return Err(OAuthError::invalid_request("audience is required"));
    }
    let exchanging_client_id = identify_client(state, caller, headers, form)
        .await
        .ok_or_else(|| OAuthError::invalid_client("invalid client credentials"))?;
    let exchanging_client = state.clients.get(&exchanging_client_id).map(Arc::new);

    let subject = state.tokens.get_access(subject_token).ok_or_else(|| {
        OAuthError::new(
            StatusCode::UNAUTHORIZED,
            super::error::EC_INVALID_GRANT,
            "invalid or expired subject token",
        )
    })?;
    let who = subject.identity.clone();

    let allowed: Vec<String> = audiences
        .iter()
        .filter(|aud| {
            who.cap_rules
                .iter()
                .filter(|r| user_matches(r, &who.login_name))
                .any(|r| r.resources.iter().any(|res| res == "*" || res == *aud))
        })
        .cloned()
        .collect();
    if allowed.is_empty() {
        return Err(OAuthError::access_denied(
            "access denied for requested audience",
        ));
    }

    let mut actor = None;
    if let Some(actor_token) = form.get("actor_token") {
        if let Some(t) = form.get("actor_token_type") {
            if t != TOKEN_TYPE_ACCESS {
                return Err(OAuthError::invalid_request("unsupported actor_token_type"));
            }
        }
        let actor_ar = state
            .tokens
            .get_access(actor_token)
            .ok_or_else(|| OAuthError::invalid_request("invalid or expired actor_token"))?;
        actor = Some(ActorClaim {
            sub: actor_ar.identity.subject(),
            client_id: actor_ar.client_id.clone(),
            act: actor_ar.actor.clone().map(Box::new),
        });
    }

    let now = now_unix();
    let exp = now + state.cfg.access_token_ttl;
    let new_ar = AuthRequest {
        family: subject.family.clone(),
        client_id: exchanging_client_id.clone(),
        client: exchanging_client.clone().or_else(|| subject.client.clone()),
        nonce: String::new(),
        redirect_uri: exchanging_client
            .as_ref()
            .and_then(|c| c.redirect_uris.first().cloned())
            .unwrap_or_else(|| subject.redirect_uri.clone()),
        scopes: subject.scopes.clone(),
        resources: allowed.clone(),
        code_challenge: None,
        code_challenge_method: None,
        identity: who.clone(),
        valid_till: exp,
        issued_at: now,
        not_before: now - NOT_BEFORE_SKEW,
        jti: random_hex(16),
        issuer: state.issuer_for(caller)?.url,
        is_exchanged: true,
        original_client_id: subject.client_id.clone(),
        exchanged_by: exchanging_client_id,
        audiences: allowed,
        actor,
    };

    let new_token = if state.cfg.jwt_access_tokens {
        let mut at = Map::new();
        at.insert("iss".into(), json!(new_ar.issuer));
        at.insert("sub".into(), json!(who.subject()));
        at.insert("aud".into(), json!(new_ar.audiences));
        at.insert("exp".into(), json!(exp));
        at.insert("iat".into(), json!(now));
        at.insert("nbf".into(), json!(new_ar.not_before));
        at.insert("jti".into(), json!(new_ar.jti));
        at.insert("client_id".into(), json!(new_ar.client_id));
        at.insert("scope".into(), json!(new_ar.scopes.join(" ")));
        if let Some(a) = &new_ar.actor {
            at.insert("act".into(), serde_json::to_value(a).unwrap_or(Value::Null));
        }
        state
            .key
            .sign(&at, "at+jwt")
            .map_err(|e| OAuthError::server_error("error creating access token").detail(e))?
    } else {
        random_hex(32)
    };
    let scopes = new_ar.scopes.join(" ");
    state.tokens.put_access(new_token.clone(), Arc::new(new_ar));
    state.metrics.inc_exchanges();

    let mut resp = json!({
        "access_token": new_token,
        "issued_token_type": TOKEN_TYPE_ACCESS,
        "token_type": "Bearer",
        "expires_in": state.cfg.access_token_ttl,
    });
    if let Some(requested) = form.get("scope") {
        if requested != scopes {
            resp["scope"] = json!(scopes);
        }
    }
    Ok(json_no_store(resp))
}

/// RFC 7662 token introspection. Unauthenticated callers always see
/// `active: false` so tokens cannot be enumerated.
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, OAuthError> {
    let form = Form::parse(&body);
    state.metrics.inc_introspections();
    let token = form
        .get("token")
        .ok_or_else(|| OAuthError::invalid_request("token is required"))?;
    let inactive = || Json(json!({ "active": false })).into_response();

    let Some(ar) = state.tokens.get_access(token) else {
        return Ok(inactive());
    };
    if identify_client(&state, &caller, &headers, &form)
        .await
        .is_none()
    {
        return Ok(inactive());
    }
    let issuer = if ar.issuer.is_empty() {
        state.require_issuer()?.url
    } else {
        ar.issuer.clone()
    };
    let who = &ar.identity;
    let mut resp = Map::new();
    resp.insert("active".into(), json!(true));
    resp.insert("client_id".into(), json!(ar.client_id));
    resp.insert("exp".into(), json!(ar.valid_till));
    resp.insert("iat".into(), json!(ar.issued_at));
    resp.insert("nbf".into(), json!(ar.not_before));
    resp.insert("token_type".into(), json!("Bearer"));
    resp.insert("iss".into(), json!(issuer));
    if !ar.jti.is_empty() {
        resp.insert("jti".into(), json!(ar.jti));
    }
    resp.insert("sub".into(), json!(who.subject()));
    if !who.login_name.is_empty() {
        resp.insert("username".into(), json!(who.login_name));
    }
    add_profile_claims(&state, &mut resp, who, &ar.scopes);
    let audience: Vec<String> = if ar.is_exchanged && !ar.audiences.is_empty() {
        ar.audiences.clone()
    } else {
        let mut a = vec![ar.client_id.clone()];
        a.extend(ar.resources.iter().cloned());
        a
    };
    resp.insert("aud".into(), json!(audience));
    if !ar.scopes.is_empty() {
        resp.insert("scope".into(), json!(ar.scopes.join(" ")));
    }
    if let Some(act) = &ar.actor {
        resp.insert(
            "act".into(),
            serde_json::to_value(act).unwrap_or(Value::Null),
        );
    }
    Ok(Json(Value::Object(resp)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(validate_code_verifier(verifier, challenge, "S256").is_ok());
        assert!(validate_code_verifier(verifier, challenge, "plain").is_err());
        assert!(validate_code_verifier("short", challenge, "S256").is_err());
        assert!(
            validate_code_verifier(&"a".repeat(50), &"a".repeat(50), "plain").is_err(),
            "plain is not supported even when it would match"
        );
        assert!(validate_code_verifier(&"a!".repeat(25), "x", "S256").is_err());
    }

    #[test]
    fn basic_auth_parsing() {
        let mut h = HeaderMap::new();
        let enc = base64::engine::general_purpose::STANDARD.encode("id%3A1:s%26cret");
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {enc}").parse().unwrap(),
        );
        let c = client_credentials(&h, &Form::parse(b"")).unwrap();
        assert_eq!(c.client_id, "id:1");
        assert_eq!(c.client_secret.as_deref(), Some("s&cret"));
        let c2 = client_credentials(
            &HeaderMap::new(),
            &Form::parse(b"client_id=a&client_secret=b"),
        )
        .unwrap();
        assert_eq!(
            (c2.client_id.as_str(), c2.client_secret.as_deref()),
            ("a", Some("b"))
        );
        assert!(client_credentials(&HeaderMap::new(), &Form::parse(b"x=y")).is_none());
    }

    #[test]
    fn public_client_needs_no_secret_but_right_id() {
        let c = Client::new("spa", vec!["https://spa/cb".into()], true);
        assert!(
            authenticate_client(
                &c,
                Some(&ClientCredentials {
                    client_id: c.id.clone(),
                    client_secret: None
                })
            )
            .is_ok()
        );
        assert!(
            authenticate_client(
                &c,
                Some(&ClientCredentials {
                    client_id: "other".into(),
                    client_secret: None
                })
            )
            .is_err()
        );
        let conf = Client::new("web", vec!["https://web/cb".into()], false);
        assert!(
            authenticate_client(
                &conf,
                Some(&ClientCredentials {
                    client_id: conf.id.clone(),
                    client_secret: None
                })
            )
            .is_err()
        );
        assert!(
            authenticate_client(
                &conf,
                Some(&ClientCredentials {
                    client_id: conf.id.clone(),
                    client_secret: Some(conf.secret.clone())
                })
            )
            .is_ok()
        );
    }
}
