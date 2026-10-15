//! HTTP server: shared state, routers for the three listeners, startup and
//! the background task that keeps the tailscaled link healthy.

pub mod admin;
pub mod authorize;
pub mod caller;
pub mod csrf;
pub mod error;
pub mod metadata;
pub mod registration;
pub mod token;
pub mod ui;
pub mod userinfo;

use axum::http::{HeaderValue, Method, Request};
use axum::middleware;
use axum::response::Response;
use axum::routing::{any, get, post};
use axum::{Extension, Router};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};

use crate::clients::ClientRegistry;
use crate::config::{Config, StateBackend};
use crate::identity::{Identity, IdentityResolver, LocalApiResolver, StaticResolver};
use crate::keys::SigningKey;
use crate::metrics::Metrics;
use crate::store::{FileStore, KubeSecretStore, MemoryStore, StateStore};
use crate::tailscale::LocalApi;
use crate::tailscale::localapi::desired_serve_config;
use crate::tokens::TokenStore;
use crate::util::now_unix;
use error::OAuthError;

pub const KEY_FILE: &str = "oidc-key.json";

/// Which listener a request arrived on. Only the tailnet listener sits
/// behind `tailscale serve`, so only there are identity headers meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    Tailnet,
    Cluster,
}

#[derive(Debug, Clone)]
pub struct Issuer {
    /// `https://idp.tn.ts.net` (no trailing slash; port only when not 443).
    pub url: String,
    /// `idp.tn.ts.net`
    pub host: String,
}

impl Issuer {
    pub fn from_host(host: &str, port: u16) -> Issuer {
        let url = if port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{port}")
        };
        Issuer {
            url,
            host: host.to_string(),
        }
    }

    pub fn parse(url: &str) -> anyhow::Result<Issuer> {
        let u = url::Url::parse(url)?;
        let host = u
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("issuer URL has no host"))?
            .to_string();
        let mut s = u.to_string();
        while s.ends_with('/') {
            s.pop();
        }
        Ok(Issuer { url: s, host })
    }
}

/// Last known state of the tailscaled link, for readiness.
#[derive(Debug, Clone, Default)]
pub struct LinkStatus {
    pub running: bool,
    pub version: String,
    pub last_ok: Option<i64>,
    pub last_error: Option<String>,
    /// `Some(Ok)` once serve config is in place, `Some(Err)` when it could not
    /// be written (e.g. read-only LocalAPI), `None` if not attempted.
    pub serve_config: Option<Result<String, String>>,
}

pub struct AppState {
    pub cfg: Config,
    pub resolver: Arc<dyn IdentityResolver>,
    pub localapi: Option<Arc<LocalApi>>,
    pub store: Arc<dyn StateStore>,
    pub clients: ClientRegistry,
    pub tokens: TokenStore,
    pub key: SigningKey,
    pub issuer: RwLock<Option<Issuer>>,
    /// Base URL advertised to cluster-listener callers (`--cluster-public-url`).
    pub cluster_public: Option<Issuer>,
    /// Second issuer used on the cluster listener (`--cluster-issuer-url`).
    pub cluster_issuer: Option<Issuer>,
    pub link: RwLock<LinkStatus>,
    pub metrics: Metrics,
    pub supported_scopes: Vec<String>,
}

impl AppState {
    /// Wire everything up: state backend, identity resolver, signing key and
    /// client registry. Fails fast on an unwritable backend (issues #113/#114).
    pub async fn build(cfg: Config) -> anyhow::Result<Arc<AppState>> {
        let store: Arc<dyn StateStore> = match cfg.state_backend {
            StateBackend::File => Arc::new(FileStore::new(cfg.state_dir_or_cwd())),
            StateBackend::Kubernetes => Arc::new(KubeSecretStore::from_env(
                &cfg.kube_secret,
                cfg.kube_namespace.clone(),
            )?),
        };
        store.check_writable().await?;
        Self::build_with(cfg, store).await
    }

    pub async fn build_with(
        cfg: Config,
        store: Arc<dyn StateStore>,
    ) -> anyhow::Result<Arc<AppState>> {
        let (resolver, localapi): (Arc<dyn IdentityResolver>, Option<Arc<LocalApi>>) = match &cfg
            .dev_identity
        {
            Some(login) => {
                tracing::warn!(
                    login,
                    "DEV IDENTITY MODE: every request is treated as this user with full admin rights. Never use in production."
                );
                (
                    Arc::new(StaticResolver {
                        identity: Identity::dev(login),
                        dns_name: "tsidp.dev.example.ts.net".into(),
                    }),
                    None,
                )
            }
            None => {
                let api = Arc::new(LocalApi::new(cfg.socket_path()));
                (Arc::new(LocalApiResolver { api: api.clone() }), Some(api))
            }
        };

        let key = match store.get(KEY_FILE).await? {
            Some(bytes) => match SigningKey::from_json(&bytes) {
                Ok(k) => {
                    tracing::info!(kid = k.kid, "loaded signing key");
                    k
                }
                Err(e) => {
                    tracing::warn!(error = %e, "existing {KEY_FILE} is unreadable; generating a new signing key (existing tokens will stop verifying)");
                    let k = SigningKey::generate()?;
                    store.put(KEY_FILE, &k.to_json()?).await?;
                    k
                }
            },
            None => {
                let k = SigningKey::generate()?;
                store.put(KEY_FILE, &k.to_json()?).await?;
                tracing::info!(kid = k.kid, "generated new RSA signing key");
                k
            }
        };

        let clients = ClientRegistry::new(store.clone());
        let n = clients.load().await?;
        tracing::info!(clients = n, backend = %store.describe(), "loaded OIDC clients");

        let mut supported_scopes = vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
            "offline_access".to_string(),
        ];
        for s in cfg.extra_scope_list() {
            if !supported_scopes.contains(&s) {
                supported_scopes.push(s);
            }
        }

        let issuer = match &cfg.issuer_url {
            Some(u) => Some(Issuer::parse(u)?),
            None => None,
        };
        let parse_cluster = |flag: &str, v: &Option<String>| -> anyhow::Result<Option<Issuer>> {
            match v {
                None => Ok(None),
                Some(_) if cfg.cluster_listen.is_none() => {
                    anyhow::bail!("{flag} requires --cluster-listen")
                }
                Some(u) => Ok(Some(
                    Issuer::parse(u).map_err(|e| anyhow::anyhow!("{flag}: {e}"))?,
                )),
            }
        };
        let cluster_public = parse_cluster("--cluster-public-url", &cfg.cluster_public_url)?;
        let cluster_issuer = parse_cluster("--cluster-issuer-url", &cfg.cluster_issuer_url)?;
        if let Some(ci) = &cluster_issuer {
            tracing::warn!(
                issuer = %ci.url,
                "cluster listener acts as a second issuer; tokens minted there are not valid for relying parties expecting the tailnet issuer"
            );
        }

        Ok(Arc::new(AppState {
            cfg,
            resolver,
            localapi,
            store,
            clients,
            tokens: TokenStore::default(),
            key,
            issuer: RwLock::new(issuer),
            cluster_public,
            cluster_issuer,
            link: RwLock::new(LinkStatus::default()),
            metrics: Metrics::default(),
            supported_scopes,
        }))
    }

    pub fn issuer(&self) -> Option<Issuer> {
        self.issuer.read().clone()
    }

    pub fn require_issuer(&self) -> Result<Issuer, OAuthError> {
        self.issuer().ok_or_else(OAuthError::not_ready)
    }

    /// The issuer tokens minted for this caller carry, and the `issuer` value
    /// in the discovery document served to it: the tailnet issuer, unless the
    /// request came in on the cluster listener and `--cluster-issuer-url` is
    /// set.
    pub fn issuer_for(&self, caller: &caller::Caller) -> Result<Issuer, OAuthError> {
        if caller.listener == Listener::Cluster {
            if let Some(ci) = &self.cluster_issuer {
                return Ok(ci.clone());
            }
        }
        self.require_issuer()
    }

    /// Base URL for the server-to-server endpoints (token, userinfo,
    /// introspection, jwks) advertised to a caller. Tailnet callers get the
    /// tailnet issuer. Cluster callers get `--cluster-public-url`, else
    /// `--cluster-issuer-url`, else `http://<Host header>` (only ever echoed
    /// back to the same caller, so no header is trusted for anything else),
    /// and finally the tailnet issuer when no Host header was sent.
    pub fn endpoint_base(
        &self,
        caller: &caller::Caller,
        headers: &axum::http::HeaderMap,
    ) -> Result<String, OAuthError> {
        if caller.listener == Listener::Cluster {
            if let Some(p) = &self.cluster_public {
                return Ok(p.url.clone());
            }
            if let Some(ci) = &self.cluster_issuer {
                return Ok(ci.url.clone());
            }
            if let Some(host) = headers
                .get(axum::http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::trim)
                .filter(|h| !h.is_empty() && !h.contains('/') && !h.contains(char::is_whitespace))
            {
                return Ok(format!("http://{host}"));
            }
            tracing::warn!(
                "cluster-listener discovery request without a Host header; advertising tailnet URLs (set --cluster-public-url)"
            );
        }
        Ok(self.require_issuer()?.url)
    }

    pub fn ready(&self) -> bool {
        let link = self.link.read();
        self.issuer().is_some() && (self.cfg.dev_identity.is_some() || link.running)
    }

    /// Domain used to make `user@github` / `user@passkey` look like an email.
    pub fn email_domain(&self) -> String {
        self.cfg
            .email_domain
            .clone()
            .or_else(|| self.issuer().map(|i| i.host))
            .unwrap_or_else(|| "tsidp.invalid".to_string())
    }

    /// `user@github` -> `user@github.<email domain>`; real emails untouched.
    pub fn realish_email(&self, login: &str) -> String {
        if login.ends_with("@github") || login.ends_with("@passkey") {
            format!("{login}.{}", self.email_domain())
        } else {
            login.to_string()
        }
    }
}

fn permissive_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any)
        .max_age(Duration::from_secs(3600))
}

/// Endpoints that only need a bearer token or client credentials. Served on
/// both listeners.
fn public_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(metadata::openid_configuration),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::oauth_authorization_server),
        )
        .route("/.well-known/jwks.json", get(metadata::jwks))
        .route("/token", post(token::token))
        .route("/introspect", post(token::introspect))
        .route(
            "/userinfo",
            get(userinfo::userinfo).post(userinfo::userinfo),
        )
        .layer(permissive_cors())
        .layer(middleware::from_fn_with_state(state, count_errors))
}

async fn count_errors(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: Request<axum::body::Body>,
    next: middleware::Next,
) -> Response {
    let resp = next.run(req).await;
    if resp.status().is_client_error() || resp.status().is_server_error() {
        state.metrics.inc_oauth_errors();
    }
    resp
}

/// The full server, reachable only through `tailscale serve`.
pub fn tailnet_router(state: Arc<AppState>) -> Router {
    let admin = Router::new()
        .route("/", get(ui::list))
        .route("/new", any(ui::new_client))
        .route("/edit/{id}", any(ui::edit_client))
        .route("/clients", get(registration::clients_list))
        .route("/clients/", get(registration::clients_list))
        .route("/clients/new", post(registration::clients_new))
        .route("/clients/{id}", any(registration::client_by_id))
        .route(
            "/clients/{id}/secret",
            post(registration::client_rotate_secret),
        )
        .layer(middleware::from_fn_with_state(state.clone(), csrf::protect));

    // Dynamic client registration is an identity-bearing endpoint: a browser
    // page can call it with the visiting user's ambient tailnet identity. By
    // default it gets the same Fetch Metadata CSRF gate as the admin API
    // (non-browser callers are unaffected); --allow-cross-origin-dcr swaps
    // that for permissive CORS, which browser-based MCP clients need.
    let register = if state.cfg.allow_cross_origin_dcr {
        post(registration::register).layer(permissive_cors())
    } else {
        post(registration::register)
            .layer(middleware::from_fn_with_state(state.clone(), csrf::protect))
    };

    Router::new()
        .merge(public_routes(state.clone()))
        .route("/authorize", any(authorize::authorize))
        .route("/register", register)
        .route("/style.css", get(ui::style))
        .route("/ui.js", get(ui::script))
        .merge(admin)
        .layer(Extension(Listener::Tailnet))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Only the identity-free endpoints, for a Kubernetes Service.
pub fn cluster_router(state: Arc<AppState>) -> Router {
    Router::new()
        .merge(public_routes(state.clone()))
        .route("/healthz", get(admin::healthz))
        .layer(Extension(Listener::Cluster))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

pub fn admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(admin::healthz))
        .route("/readyz", get(admin::readyz))
        .route("/metrics", get(admin::metrics))
        .route("/version", get(admin::version))
        .with_state(state)
}

async fn security_headers(req: Request<axum::body::Body>, next: middleware::Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.entry("x-content-type-options")
        .or_insert(HeaderValue::from_static("nosniff"));
    h.entry("x-frame-options")
        .or_insert(HeaderValue::from_static("DENY"));
    h.entry("referrer-policy")
        .or_insert(HeaderValue::from_static("no-referrer"));
    // Harmless on JSON responses; on the admin UI it blocks inline script
    // and framing even if an escaping bug slips through again.
    h.entry("content-security-policy")
        .or_insert(HeaderValue::from_static(ui::CSP));
    resp
}

/// Bind all listeners, run background tasks, and serve until SIGTERM/SIGINT.
pub async fn run(state: Arc<AppState>) -> anyhow::Result<()> {
    let shutdown = shutdown_signal();
    let (tx, rx) = tokio::sync::watch::channel(false);

    let mut tasks = tokio::task::JoinSet::new();

    let tailnet = tokio::net::TcpListener::bind(&state.cfg.listen)
        .await
        .map_err(|e| anyhow::anyhow!("binding tailnet listener {}: {e}", state.cfg.listen))?;
    if !is_loopback_bind(&state.cfg.listen) {
        tracing::warn!(listen = %state.cfg.listen, "tailnet listener is not bound to loopback; anything that can reach it can forge X-Forwarded-For. Keep it on 127.0.0.1 and let tailscale serve proxy to it.");
    }
    tracing::info!(listen = %state.cfg.listen, "tailnet listener (behind tailscale serve) ready");
    tasks.spawn(serve(tailnet, tailnet_router(state.clone()), rx.clone()));

    if let Some(addr) = &state.cfg.cluster_listen {
        let l = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| anyhow::anyhow!("binding cluster listener {addr}: {e}"))?;
        tracing::info!(listen = %addr, "cluster listener (token/userinfo/jwks only) ready");
        tasks.spawn(serve(l, cluster_router(state.clone()), rx.clone()));
    }

    let admin = tokio::net::TcpListener::bind(&state.cfg.admin_listen)
        .await
        .map_err(|e| anyhow::anyhow!("binding admin listener {}: {e}", state.cfg.admin_listen))?;
    tracing::info!(listen = %state.cfg.admin_listen, "admin listener (/healthz /readyz /metrics) ready");
    tasks.spawn(serve(admin, admin_router(state.clone()), rx.clone()));

    tasks.spawn(link_task(state.clone(), rx.clone()));
    tasks.spawn(cleanup_task(state.clone(), rx.clone()));

    shutdown.await;
    tracing::info!("shutdown signal received; draining connections");
    let _ = tx.send(true);
    let drain = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(r) = tasks.join_next().await {
            if let Err(e) = r {
                tracing::warn!(error = %e, "task ended with error");
            }
        }
    });
    if drain.await.is_err() {
        tracing::warn!("drain timed out; exiting");
    }
    Ok(())
}

fn is_loopback_bind(addr: &str) -> bool {
    addr.parse::<std::net::SocketAddr>()
        .map(|a| a.ip().is_loopback())
        .unwrap_or(addr.starts_with("localhost:"))
}

async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = stop.wait_for(|v| *v).await;
        })
        .await;
    if let Err(e) = result {
        tracing::error!(error = %e, "listener failed");
    }
}

async fn cleanup_task(state: Arc<AppState>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let n = state.tokens.cleanup();
                if n > 0 {
                    tracing::debug!(removed = n, "cleaned up expired tokens");
                }
            }
            _ = stop.wait_for(|v| *v) => return,
        }
    }
}

/// Keep the tailscaled link healthy until shutdown.
async fn link_task(state: Arc<AppState>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let started = std::time::Instant::now();
    loop {
        let ready = poll_link_once(&state).await;
        let interval = if ready {
            Duration::from_secs(15)
        } else {
            Duration::from_secs(2)
        };
        if !ready && started.elapsed().as_secs() > state.cfg.startup_timeout {
            tracing::error!(
                timeout = state.cfg.startup_timeout,
                "still not ready after startup timeout; continuing to retry"
            );
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = stop.wait_for(|v| *v) => return,
        }
    }
}

/// One pass of the link loop: poll tailscaled, derive the issuer from the
/// node's DNS name once it is Running, write the serve config, and update
/// readiness. Returns `AppState::ready()`.
pub async fn poll_link_once(state: &AppState) -> bool {
    match state.resolver.status().await {
        Ok(st) => {
            let running = st.is_running();
            let dns = st.dns_name();
            {
                let mut link = state.link.write();
                link.running = running;
                link.version = st.version.clone();
                link.last_ok = Some(now_unix());
                link.last_error = None;
            }
            if !running {
                let hint = if st.auth_url.is_empty() {
                    String::new()
                } else {
                    format!("; login at {}", st.auth_url)
                };
                tracing::warn!(state = %st.backend_state, "tailscaled is not Running yet{hint}");
            } else if state.issuer().is_none() {
                match dns {
                    Some(host) => {
                        let issuer = Issuer::from_host(&host, state.cfg.issuer_port());
                        tracing::info!(issuer = %issuer.url, "issuer derived from MagicDNS name");
                        *state.issuer.write() = Some(issuer);
                    }
                    None => tracing::warn!(
                        "tailscaled is Running but reports no DNS name; is MagicDNS enabled for the tailnet?"
                    ),
                }
            }
            if running && state.issuer().is_some() {
                ensure_serve_config(state).await;
            }
        }
        Err(e) => {
            state.metrics.localapi_failed();
            let mut link = state.link.write();
            link.running = false;
            link.last_error = Some(e.to_string());
            tracing::warn!(error = %e, backend = %state.resolver.describe(), "cannot reach tailscaled");
        }
    }
    state.ready()
}

/// Install the `tailscale serve` proxy config through LocalAPI (once per
/// process; retried while it keeps failing).
pub async fn ensure_serve_config(state: &AppState) {
    if !state.cfg.configure_serve {
        return;
    }
    let Some(api) = &state.localapi else { return };
    if state
        .link
        .read()
        .serve_config
        .as_ref()
        .is_some_and(|r| r.is_ok())
    {
        return;
    }
    let Some(issuer) = state.issuer() else { return };
    let Some(local_port) = state.cfg.listen_port() else {
        tracing::warn!(listen = %state.cfg.listen, "cannot determine local port for serve config");
        return;
    };
    let result = async {
        let (current, etag) = api.get_serve_config().await?;
        match desired_serve_config(
            &current,
            &issuer.host,
            state.cfg.issuer_port(),
            local_port,
            state.cfg.funnel,
        ) {
            None => Ok("already configured".to_string()),
            Some(next) => {
                api.set_serve_config(&next, etag.as_deref()).await?;
                Ok(format!(
                    "configured https://{}:{} -> http://127.0.0.1:{local_port} (funnel={})",
                    issuer.host,
                    state.cfg.issuer_port(),
                    state.cfg.funnel
                ))
            }
        }
    }
    .await;
    match &result {
        Ok(msg) => tracing::info!(%msg, "tailscale serve"),
        Err(e) => {
            let e: &crate::tailscale::LocalApiError = e;
            state.metrics.localapi_failed();
            if e.status() == Some(hyper::StatusCode::FORBIDDEN) {
                tracing::warn!(error = %e, "LocalAPI refused to write the serve config (tsidp must run as root or as tailscaled's uid). Configure the sidecar with TS_SERVE_CONFIG instead, or set TSIDP_CONFIGURE_SERVE=false to silence this.");
            } else {
                tracing::warn!(error = %e, "could not write tailscale serve config; will retry");
            }
        }
    }
    state.link.write().serve_config = Some(result.map_err(|e| e.to_string()));
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// Build a state for tests with an in-memory store and the dev identity.
pub async fn test_state(mut cfg: Config, identity: Option<Identity>) -> Arc<AppState> {
    cfg.dev_identity
        .get_or_insert_with(|| "alice@example.com".to_string());
    let state = AppState::build_with(cfg, Arc::new(MemoryStore::default()))
        .await
        .expect("test state");
    if let Some(id) = identity {
        // Swap in a custom identity by rebuilding the resolver.
        let s = Arc::try_unwrap(state).ok().expect("unshared");
        let AppState {
            cfg,
            store,
            clients,
            tokens,
            key,
            issuer,
            cluster_public,
            cluster_issuer,
            link,
            metrics,
            supported_scopes,
            localapi,
            ..
        } = s;
        let resolver: Arc<dyn IdentityResolver> = Arc::new(StaticResolver {
            identity: id,
            dns_name: "tsidp.dev.example.ts.net".into(),
        });
        let st = Arc::new(AppState {
            cfg,
            resolver,
            localapi,
            store,
            clients,
            tokens,
            key,
            issuer,
            cluster_public,
            cluster_issuer,
            link,
            metrics,
            supported_scopes,
        });
        *st.issuer.write() = Some(Issuer::from_host("tsidp.dev.example.ts.net", 443));
        return st;
    }
    *state.issuer.write() = Some(Issuer::from_host("tsidp.dev.example.ts.net", 443));
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_forms() {
        assert_eq!(
            Issuer::from_host("idp.tn.ts.net", 443).url,
            "https://idp.tn.ts.net"
        );
        assert_eq!(
            Issuer::from_host("idp.tn.ts.net", 8443).url,
            "https://idp.tn.ts.net:8443"
        );
        let i = Issuer::parse("https://sso.example.com/path/").unwrap();
        assert_eq!(i.url, "https://sso.example.com/path");
        assert_eq!(i.host, "sso.example.com");
        assert!(Issuer::parse("not a url").is_err());
        assert!(Issuer::parse("mailto:x").is_err());
        assert!(is_loopback_bind("127.0.0.1:1"));
        assert!(is_loopback_bind("localhost:1"));
        assert!(!is_loopback_bind("0.0.0.0:1"));
    }

    #[tokio::test]
    async fn build_rejects_bad_issuer_and_recovers_corrupt_key() {
        let mut cfg = Config::for_tests();
        cfg.issuer_url = Some("::nope".into());
        assert!(
            AppState::build_with(cfg, Arc::new(MemoryStore::default()))
                .await
                .is_err()
        );

        let store = Arc::new(MemoryStore::default());
        store.put(KEY_FILE, b"garbage").await.unwrap();
        let st = AppState::build_with(Config::for_tests(), store.clone())
            .await
            .unwrap();
        let fresh = SigningKey::from_json(&store.get(KEY_FILE).await.unwrap().unwrap()).unwrap();
        assert_eq!(fresh.kid, st.key.kid, "a new key was written back");
        let again = AppState::build_with(Config::for_tests(), store)
            .await
            .unwrap();
        assert_eq!(again.key.kid, st.key.kid, "and is reused on the next start");
    }

    #[tokio::test]
    async fn build_with_file_backend_and_background_tasks() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_tests();
        cfg.state_dir = Some(dir.path().to_path_buf());
        let st = AppState::build(cfg).await.unwrap();
        assert!(dir.path().join(KEY_FILE).exists());
        assert!(st.store.describe().starts_with("files in"));

        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(cleanup_task(st.clone(), rx));
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(link_task(st.clone(), rx));
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(serve(listener, admin_router(st.clone()), rx));
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn run_binds_all_listeners_and_stops() {
        // `run` listens for signals, so exercise its pieces: binding each
        // router on an ephemeral port and serving one request.
        let st = test_state(Config::for_tests(), None).await;
        for router in [
            tailnet_router(st.clone()),
            cluster_router(st.clone()),
            admin_router(st.clone()),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = tokio::sync::watch::channel(false);
            let handle = tokio::spawn(serve(listener, router, rx));
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut s, b"GET /healthz HTTP/1.0\r\n\r\n")
                .await
                .unwrap();
            let mut out = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut s, &mut out)
                .await
                .unwrap();
            assert!(
                out.starts_with(b"HTTP/1.0 200") || out.starts_with(b"HTTP/1.0 404"),
                "{}",
                String::from_utf8_lossy(&out)
            );
            tx.send(true).unwrap();
            tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
