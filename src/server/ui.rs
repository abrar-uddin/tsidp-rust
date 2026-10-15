//! The admin UI: a small server-rendered page set for managing clients.
//! Access requires the `allow_admin_ui` capability.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{Method, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
// `esc` is for text nodes only: it does not touch quotes. Anything that lands
// inside a quoted attribute value must go through `attr`.
use html_escape::encode_double_quoted_attribute as attr;
use html_escape::encode_text as esc;
use std::sync::Arc;

use super::AppState;
use super::caller::Caller;
use super::error::OAuthError;
use super::token::Form;
use crate::clients::{
    AUTH_METHOD_BASIC, AUTH_METHOD_NONE, Client, generate_client_secret, split_redirect_uris,
    validate_redirect_uri,
};

pub const STYLE_CSS: &str = include_str!("ui-style.css");
pub const UI_JS: &str = include_str!("ui-script.js");

/// Content-Security-Policy for every page served by the tailnet listener.
/// Only same-origin stylesheets and scripts, no inline code, no framing.
pub const CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - Tailscale OIDC Identity Provider</title>
<link rel="stylesheet" href="/style.css">
<script src="/ui.js" defer></script>
</head>
<body>
<header><nav><a href="/"><h1>Tailscale OIDC Identity Provider</h1></a></nav></header>
{body}
<footer class="app-footer"><span>tsidp {version}</span></footer>
</body>
</html>"#,
        title = esc(title),
        version = esc(crate::version()),
    ))
}

async fn require_admin(state: &AppState, caller: &Caller) -> Result<(), OAuthError> {
    let (_, access) = state.identify_with_access(caller).await?;
    if !access.allow_admin_ui {
        state.metrics.denied();
        return Err(OAuthError::access_denied(
            "application capability allow_admin_ui not granted; add a tailscale.com/cap/tsidp grant with \"allow_admin_ui\": true for your user",
        ));
    }
    Ok(())
}

pub async fn style() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        STYLE_CSS,
    )
        .into_response()
}

pub async fn script() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        UI_JS,
    )
        .into_response()
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    caller: Caller,
) -> Result<Response, OAuthError> {
    require_admin(&state, &caller).await?;
    let clients = state.clients.list();
    let mut rows = String::new();
    for c in &clients {
        let uris: String = c
            .redirect_uris
            .iter()
            .map(|u| format!("<span class=\"redirect-uri\">{}</span>", esc(u)))
            .collect::<Vec<_>>()
            .join("");
        let kind = if c.is_public() {
            "<span class=\"badge\">public (PKCE)</span>"
        } else {
            "<span class=\"badge badge-secret\">confidential</span>"
        };
        let dcr = if c.dynamically_registered {
            " <span class=\"badge\">DCR</span>"
        } else {
            ""
        };
        rows.push_str(&format!(
            "<tr><td>{name}</td><td><code class=\"client-id\">{id}</code></td><td><div class=\"redirect-uris\">{uris}</div></td><td>{kind}{dcr}</td><td><a class=\"btn btn-secondary btn-small\" href=\"/edit/{id}\">Edit</a></td></tr>",
            name = if c.name.is_empty() { "<span class=\"text-muted\">Unnamed client</span>".to_string() } else { format!("<strong>{}</strong>", esc(&c.name)) },
            id = esc(&c.id),
        ));
    }
    let body = if clients.is_empty() {
        r#"<main><div class="header-actions"><h2>OIDC Clients</h2><a href="/new" class="btn btn-primary">Add New Client</a></div>
<div class="empty-state"><h3>No OIDC clients configured</h3><p>Create your first client, or let applications register themselves with dynamic client registration.</p><a href="/new" class="btn btn-primary">Add New Client</a></div></main>"#.to_string()
    } else {
        format!(
            r#"<main><div class="header-actions"><div><h2>OIDC Clients</h2><p class="client-count">{n} client{s} configured</p></div><a href="/new" class="btn btn-primary">Add New Client</a></div>
<table><thead><tr><td>Name</td><td>Client ID</td><td>Redirect URIs</td><td>Type</td><td>Actions</td></tr></thead><tbody>{rows}</tbody></table></main>"#,
            n = clients.len(),
            s = if clients.len() == 1 { "" } else { "s" },
        )
    };
    Ok(page("OIDC Clients", &body).into_response())
}

struct FormView<'a> {
    client: Option<&'a Client>,
    name: &'a str,
    redirect_uris: &'a [String],
    public: bool,
    secret: Option<&'a str>,
    error: Option<&'a str>,
    success: Option<&'a str>,
}

fn render_form(v: FormView<'_>) -> Html<String> {
    let is_edit = v.client.is_some();
    let title = if is_edit {
        "Edit OIDC Client"
    } else {
        "Add New OIDC Client"
    };
    let mut body = String::new();
    body.push_str(&format!(
        "<main><div class=\"form-container\"><div class=\"form-header\"><h2>{title}</h2><a href=\"/\" class=\"btn btn-secondary\">&larr; Back to Clients</a></div>"
    ));
    if let Some(s) = v.success {
        body.push_str(&format!(
            "<div class=\"alert alert-success\">{}</div>",
            esc(s)
        ));
    }
    if let Some(e) = v.error {
        body.push_str(&format!(
            "<div class=\"alert alert-error\">{}</div>",
            esc(e)
        ));
    }
    if let (Some(secret), Some(c)) = (v.secret, v.client) {
        body.push_str(&format!(
            r#"<div class="client-info"><h3>Client credentials</h3><p class="warning">Save the client secret now. It will not be shown again.</p>
<div class="form-group"><label>Client ID</label><div class="secret-field"><input type="text" value="{id}" readonly class="secret-input" aria-label="Client ID"><button type="button" data-copy class="btn btn-secondary btn-small">Copy</button></div></div>
<div class="form-group"><label>Client Secret</label><div class="secret-field"><input type="text" value="{secret}" readonly class="secret-input" aria-label="Client Secret"><button type="button" data-copy class="btn btn-secondary btn-small">Copy</button></div></div></div>"#,
            id = attr(&c.id),
            secret = attr(secret),
        ));
    }
    let form_action = match v.client {
        Some(c) => format!("/edit/{}", attr(&c.id)),
        None => "/new".to_string(),
    };
    body.push_str(&format!(
        r#"<form method="POST" action="{action}" class="client-form">
<div class="form-group"><label for="name">Client Name</label><input type="text" id="name" name="name" value="{name}" placeholder="e.g. Grafana" class="form-input"><div class="form-help">A descriptive name for this client.</div></div>
<div class="form-group"><label for="redirect_uris">Redirect URIs <span class="required">*</span></label><textarea id="redirect_uris" name="redirect_uris" class="form-input" rows="4" required placeholder="https://app.example.com/oauth/callback">{uris}</textarea><div class="form-help">One per line. The authorization request must use one of these exactly.</div></div>
<div class="form-group"><label class="checkbox"><input type="checkbox" name="public" value="1" {checked} {disabled}> Public client (no secret, PKCE S256 required)</label><div class="form-help">For single-page apps and native/CLI tools that cannot keep a secret. Confidential clients get a client secret.</div></div>
{id_block}
<div class="form-actions"><button type="submit" name="action" value="save" class="btn btn-primary">{submit}</button>{extra}</div>
</form>"#,
        action = form_action,
        name = attr(v.name),
        uris = esc(&v.redirect_uris.join("\n")),
        checked = if v.public { "checked" } else { "" },
        disabled = if is_edit { "disabled" } else { "" },
        id_block = match v.client {
            Some(c) => format!("<div class=\"form-group\"><label>Client ID</label><input type=\"text\" value=\"{}\" readonly class=\"form-input form-input-readonly\"><div class=\"form-help\">The client ID cannot be changed.</div></div>", attr(&c.id)),
            None => String::new(),
        },
        submit = if is_edit { "Update Client" } else { "Create Client" },
        extra = if is_edit {
            r#"<button type="submit" name="action" value="regenerate_secret" class="btn btn-warning" data-confirm="Regenerate the client secret? The old secret stops working immediately and the client becomes confidential.">Regenerate Secret</button>
<button type="submit" name="action" value="delete" class="btn btn-danger" data-confirm="Delete this client? This cannot be undone.">Delete Client</button>"#
        } else {
            ""
        },
    ));
    if let Some(c) = v.client {
        body.push_str(&format!(
            "<div class=\"client-info\"><h3>Client Information</h3><dl><dt>Client ID</dt><dd><code>{}</code></dd><dt>Type</dt><dd>{}</dd><dt>Created</dt><dd>{}</dd></dl></div>",
            esc(&c.id),
            if c.is_public() { "Public (PKCE)" } else { "Confidential (secret configured)" },
            esc(&c.created_at),
        ));
    }
    body.push_str("</div></main>");
    page(title, &body)
}

pub async fn new_client(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    method: Method,
    body: Bytes,
) -> Result<Response, OAuthError> {
    require_admin(&state, &caller).await?;
    if method == Method::GET {
        return Ok(render_form(FormView {
            client: None,
            name: "",
            redirect_uris: &[],
            public: false,
            secret: None,
            error: None,
            success: None,
        })
        .into_response());
    }
    if method != Method::POST {
        return Err(OAuthError::method_not_allowed());
    }
    let form = Form::parse(&body);
    let name = form.get("name").unwrap_or("").trim().to_string();
    let uris = split_redirect_uris(form.get("redirect_uris").unwrap_or(""));
    let public = form.get("public").is_some();
    let view = |error: &str| {
        render_form(FormView {
            client: None,
            name: &name,
            redirect_uris: &uris,
            public,
            secret: None,
            error: Some(error),
            success: None,
        })
        .into_response()
    };
    if uris.is_empty() {
        return Ok(view("At least one redirect URI is required"));
    }
    for u in &uris {
        if let Err(reason) = validate_redirect_uri(u, state.cfg.allow_http_redirect_uris) {
            return Ok(view(&format!("Invalid redirect URI '{u}': {reason}")));
        }
    }
    let c = Client::new(&name, uris.clone(), public);
    if let Err(e) = state.clients.insert(c.clone()).await {
        tracing::error!(error = %e, "client create: could not write clients db");
        return Ok(view(
            "Failed to save client: the state backend is not writable (see server logs)",
        ));
    }
    state.metrics.inc_registrations();
    tracing::info!(client_id = %c.id, name = %c.name, public, "client created via UI");
    // Redirect-after-POST so a refresh does not create a duplicate (issue #52);
    // the secret is shown exactly once on the next page via a one-shot query.
    let secret = c.secret.clone();
    let html = render_form(FormView {
        client: Some(&c),
        name: &c.name,
        redirect_uris: &c.redirect_uris,
        public: c.is_public(),
        secret: if secret.is_empty() {
            None
        } else {
            Some(&secret)
        },
        error: None,
        success: Some(if c.is_public() {
            "Public client created."
        } else {
            "Client created successfully. Save the client secret: it won't be shown again."
        }),
    });
    Ok((StatusCode::OK, html).into_response())
}

pub async fn edit_client(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    method: Method,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, OAuthError> {
    require_admin(&state, &caller).await?;
    let Some(client) = state.clients.get(&id) else {
        return Err(OAuthError::not_found("client not found"));
    };
    let show = |c: &Client, secret: Option<&str>, error: Option<&str>, success: Option<&str>| {
        render_form(FormView {
            client: Some(c),
            name: &c.name,
            redirect_uris: &c.redirect_uris,
            public: c.is_public(),
            secret,
            error,
            success,
        })
        .into_response()
    };
    if method == Method::GET {
        return Ok(show(&client, None, None, None));
    }
    if method != Method::POST {
        return Err(OAuthError::method_not_allowed());
    }
    let form = Form::parse(&body);
    match form.get("action").unwrap_or("save") {
        "delete" => {
            if let Err(e) = state.clients.delete(&id).await {
                tracing::error!(error = %e, "client delete: could not write clients db");
                return Ok(show(
                    &client,
                    None,
                    Some("Failed to delete client. Please try again."),
                    None,
                ));
            }
            state.tokens.revoke_client(&id);
            tracing::info!(client_id = %id, "client deleted via UI");
            Ok(Redirect::to("/").into_response())
        }
        "regenerate_secret" => {
            let secret = generate_client_secret();
            let s2 = secret.clone();
            if let Err(e) = state
                .clients
                .update(&id, move |c| {
                    c.secret = s2;
                    if c.token_endpoint_auth_method == AUTH_METHOD_NONE {
                        c.token_endpoint_auth_method = AUTH_METHOD_BASIC.to_string();
                    }
                })
                .await
            {
                tracing::error!(error = %e, "client regen secret: could not write clients db");
                return Ok(show(
                    &client,
                    None,
                    Some("Failed to regenerate secret"),
                    None,
                ));
            }
            state.tokens.revoke_client(&id);
            let updated = state.clients.get(&id).unwrap_or(client);
            Ok(show(
                &updated,
                Some(&secret),
                None,
                Some("New client secret generated. Save it: it won't be shown again."),
            ))
        }
        _ => {
            let name = form.get("name").unwrap_or("").trim().to_string();
            let uris = split_redirect_uris(form.get("redirect_uris").unwrap_or(""));
            let mut preview = client.clone();
            preview.name = name.clone();
            preview.redirect_uris = uris.clone();
            if uris.is_empty() {
                return Ok(show(
                    &preview,
                    None,
                    Some("At least one redirect URI is required"),
                    None,
                ));
            }
            for u in &uris {
                if let Err(reason) = validate_redirect_uri(u, state.cfg.allow_http_redirect_uris) {
                    return Ok(show(
                        &preview,
                        None,
                        Some(&format!("Invalid redirect URI '{u}': {reason}")),
                        None,
                    ));
                }
            }
            if let Err(e) = state
                .clients
                .update(&id, move |c| {
                    c.name = name;
                    c.redirect_uris = uris;
                })
                .await
            {
                tracing::error!(error = %e, "client update: could not write clients db");
                return Ok(show(&preview, None, Some("Failed to update client"), None));
            }
            Ok(show(
                &preview,
                None,
                None,
                Some("Client updated successfully."),
            ))
        }
    }
}
