//! Command line and environment configuration.
//!
//! Every flag has a `TSIDP_*` environment variable. A few legacy `TS_*`
//! names from the Go implementation are honoured as fallbacks so existing
//! Compose files keep working.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

use crate::util::parse_bool;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StateBackend {
    /// JSON files in `--state-dir` (compatible with the Go tsidp layout).
    File,
    /// A Kubernetes Secret, read and written through the in-cluster API.
    Kubernetes,
}

#[derive(Debug, Parser, Clone)]
#[command(
    name = "tsidp-server",
    version = crate::version(),
    about = "Tailscale OIDC identity provider (Rust, sidecar/Kubernetes friendly)",
    long_about = None
)]
pub struct Config {
    /// Tailnet-facing listener. `tailscale serve` (in the sidecar) proxies
    /// https://<hostname>.<tailnet>.ts.net to this address. It trusts the
    /// X-Forwarded-For header, so keep it on loopback.
    #[arg(long, env = "TSIDP_LISTEN", default_value = "127.0.0.1:8443")]
    pub listen: String,

    /// Optional cluster-facing listener (e.g. 0.0.0.0:8080) that serves only
    /// the endpoints that do not need the caller's tailnet identity:
    /// discovery, jwks, token, introspect and userinfo. Point a Kubernetes
    /// Service at it so in-cluster relying parties never leave the cluster.
    #[arg(long, env = "TSIDP_CLUSTER_LISTEN")]
    pub cluster_listen: Option<String>,

    /// Base URL under which in-cluster relying parties reach the cluster
    /// listener, e.g. http://tsidp.tsidp.svc:8080. Discovery served on that
    /// listener advertises token, userinfo, introspection and jwks under it,
    /// while `issuer` and `authorization_endpoint` stay on the tailnet. When
    /// unset, the request's Host header is used.
    #[arg(long, env = "TSIDP_CLUSTER_PUBLIC_URL")]
    pub cluster_public_url: Option<String>,

    /// Make the cluster listener a second issuer: discovery served there
    /// reports this URL as `issuer` and tokens minted there carry it as `iss`.
    /// For relying parties that require issuer == discovery URL and have no
    /// override. Do not use when ID tokens are forwarded to kube-apiserver,
    /// which validates `iss` against the tailnet URL.
    #[arg(long, env = "TSIDP_CLUSTER_ISSUER_URL")]
    pub cluster_issuer_url: Option<String>,

    /// Listener for /healthz, /readyz and /metrics.
    #[arg(long, env = "TSIDP_ADMIN_LISTEN", default_value = "0.0.0.0:9464")]
    pub admin_listen: String,

    /// Path to the tailscaled LocalAPI unix socket.
    #[arg(long, env = "TSIDP_TAILSCALE_SOCKET")]
    pub tailscale_socket: Option<PathBuf>,

    /// Public port in the issuer URL (the port `tailscale serve` listens on).
    /// Defaults to 443. The environment name is deliberately not `TSIDP_PORT`:
    /// Kubernetes injects `<SERVICE>_PORT=tcp://ip:port` service links for a
    /// Service called `tsidp`, which would collide. `TSIDP_PORT` is still read
    /// as a deprecated alias when it holds a plain number.
    #[arg(long = "port", env = "TSIDP_ISSUER_PORT")]
    pub issuer_port: Option<u16>,

    /// Messages to log once logging is up (e.g. ignored legacy variables).
    #[arg(skip)]
    pub startup_warnings: Vec<String>,

    /// Override the issuer URL instead of deriving it from the node's MagicDNS
    /// name. Use this with Tailscale Services (https://svc.tailnet.ts.net) or a
    /// custom domain fronted by Funnel.
    #[arg(long, env = "TSIDP_ISSUER_URL")]
    pub issuer_url: Option<String>,

    /// Directory for persisted state (signing key, OIDC clients).
    #[arg(long, env = "TSIDP_STATE_DIR")]
    pub state_dir: Option<PathBuf>,

    /// Where to persist state.
    #[arg(long, env = "TSIDP_STATE_BACKEND", value_enum, default_value_t = StateBackend::File)]
    pub state_backend: StateBackend,

    /// Name of the Kubernetes Secret used by the kubernetes state backend.
    #[arg(long, env = "TSIDP_KUBE_SECRET", default_value = "tsidp-state")]
    pub kube_secret: String,

    /// Namespace of the Kubernetes Secret (defaults to the pod's namespace).
    #[arg(long, env = "TSIDP_KUBE_NAMESPACE")]
    pub kube_namespace: Option<String>,

    /// Expose tsidp on the public internet through Tailscale Funnel.
    #[arg(long, env = "TSIDP_USE_FUNNEL", value_parser = parse_bool, default_value = "false", num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub funnel: bool,

    /// Enable RFC 8693 token exchange.
    #[arg(long, env = "TSIDP_ENABLE_STS", value_parser = parse_bool, default_value = "false", num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub enable_sts: bool,

    /// Write the `tailscale serve` configuration (HTTPS on --port proxied to
    /// --listen, plus Funnel) through LocalAPI at startup. Requires tsidp to run
    /// as root or as the same uid as tailscaled; otherwise set TS_SERVE_CONFIG
    /// on the sidecar instead.
    #[arg(long, env = "TSIDP_CONFIGURE_SERVE", value_parser = parse_bool, default_value = "true", num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub configure_serve: bool,

    /// Issue access tokens as RS256 JWTs (RFC 9068) instead of opaque strings,
    /// for relying parties that validate access tokens offline.
    #[arg(long, env = "TSIDP_JWT_ACCESS_TOKENS", value_parser = parse_bool, default_value = "false", num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub jwt_access_tokens: bool,

    /// Issue tokens to tagged (non-user) nodes. The subject becomes
    /// `node:<stable id>` and a `tags` claim is included.
    #[arg(long, env = "TSIDP_ALLOW_TAGGED_NODES", value_parser = parse_bool, default_value = "false", num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub allow_tagged_nodes: bool,

    /// Let browser pages on other origins call `/register` (RFC 7591 dynamic
    /// client registration), e.g. the MCP inspector. Off by default: a web
    /// page a tailnet user merely visits could otherwise register OIDC
    /// clients with that user's ambient tailnet identity. Server-to-server
    /// registration (curl, operators) works either way.
    #[arg(long, env = "TSIDP_ALLOW_CROSS_ORIGIN_DCR", value_parser = parse_bool, default_value = "false", num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub allow_cross_origin_dcr: bool,

    /// Accept plain `http://` redirect URIs for hosts other than loopback when
    /// clients are created or registered. Off by default: authorization codes
    /// would travel unencrypted to such a URI.
    #[arg(long, env = "TSIDP_ALLOW_HTTP_REDIRECT_URIS", value_parser = parse_bool, default_value = "false", num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub allow_http_redirect_uris: bool,

    /// Extra OAuth scopes to advertise and accept (comma separated).
    #[arg(long, env = "TSIDP_EXTRA_SCOPES", default_value = "")]
    pub extra_scopes: String,

    /// Domain appended to pseudo-emails such as user@github or user@passkey.
    /// Defaults to the issuer hostname.
    #[arg(long, env = "TSIDP_EMAIL_DOMAIN")]
    pub email_domain: Option<String>,

    /// Access token lifetime in seconds.
    #[arg(long, env = "TSIDP_ACCESS_TOKEN_TTL", default_value_t = 300)]
    pub access_token_ttl: i64,

    /// Refresh token lifetime in seconds.
    #[arg(long, env = "TSIDP_REFRESH_TOKEN_TTL", default_value_t = 30 * 24 * 3600)]
    pub refresh_token_ttl: i64,

    /// Authorization code lifetime in seconds.
    #[arg(long, env = "TSIDP_CODE_TTL", default_value_t = 300)]
    pub code_ttl: i64,

    /// Log level: trace, debug, info, warn, error (or a tracing filter).
    #[arg(long = "log", env = "TSIDP_LOG", default_value = "info")]
    pub log_level: String,

    /// Log format.
    #[arg(long, env = "TSIDP_LOG_FORMAT", value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,

    /// Treat requests that reach the tailnet listener without an
    /// X-Forwarded-For header (i.e. from inside the pod) as an administrator.
    #[arg(long, env = "TSIDP_ALLOW_LOOPBACK_ADMIN", value_parser = parse_bool, default_value = "false", num_args = 0..=1, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub allow_loopback_admin: bool,

    /// DEVELOPMENT ONLY: skip tailscaled entirely and treat every request as
    /// coming from this login name with full admin and DCR grants.
    #[arg(long, env = "TSIDP_DEV_IDENTITY")]
    pub dev_identity: Option<String>,

    /// Probe a running server's /readyz on --admin-listen and exit 0 if ready
    /// (for container HEALTHCHECKs where no shell or curl exists).
    #[arg(long, default_value_t = false)]
    pub check_ready: bool,

    /// Seconds to wait for tailscaled to reach the Running state before
    /// giving up on self-configuring serve (readiness keeps retrying).
    #[arg(long, env = "TSIDP_STARTUP_TIMEOUT", default_value_t = 600)]
    pub startup_timeout: u64,
}

impl Config {
    /// Parse flags, then apply legacy environment fallbacks.
    pub fn from_args() -> Self {
        let mut c = Config::parse();
        c.apply_legacy_env();
        c
    }

    pub fn apply_legacy_env(&mut self) {
        self.apply_legacy_env_with(|k| std::env::var(k).ok());
    }

    /// Fill unset fields from the Go server's legacy variable names.
    pub fn apply_legacy_env_with(&mut self, lookup: impl Fn(&str) -> Option<String>) {
        let nonempty = |k: &str| lookup(k).filter(|v| !v.is_empty());
        if self.state_dir.is_none() {
            if let Some(v) = nonempty("TS_STATE_DIR") {
                self.state_dir = Some(PathBuf::from(v));
            }
        }
        if self.tailscale_socket.is_none() {
            if let Some(v) = nonempty("TS_SOCKET") {
                self.tailscale_socket = Some(PathBuf::from(v));
            }
        }
        if self.issuer_port.is_none() {
            if let Some(v) = nonempty("TSIDP_PORT") {
                match v.trim().parse::<u16>() {
                    Ok(p) => {
                        self.issuer_port = Some(p);
                        self.startup_warnings.push(
                            "TSIDP_PORT is deprecated; use TSIDP_ISSUER_PORT (or --port)".to_string(),
                        );
                    }
                    Err(_) => self.startup_warnings.push(format!(
                        "ignoring TSIDP_PORT={v:?}: not a port number. This is usually a Kubernetes service link injected for a Service named tsidp; set enableServiceLinks: false on the pod. Use TSIDP_ISSUER_PORT to set the issuer port."
                    )),
                }
            }
        }
    }

    /// Public port in the issuer URL.
    pub fn issuer_port(&self) -> u16 {
        self.issuer_port.unwrap_or(443)
    }

    pub fn socket_path(&self) -> PathBuf {
        self.tailscale_socket
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/run/tailscale/tailscaled.sock"))
    }

    pub fn state_dir_or_cwd(&self) -> PathBuf {
        self.state_dir.clone().unwrap_or_else(|| PathBuf::from("."))
    }

    pub fn extra_scope_list(&self) -> Vec<String> {
        crate::util::split_csv(&self.extra_scopes)
    }

    /// Port of the tailnet listener, used when writing the serve config.
    pub fn listen_port(&self) -> Option<u16> {
        self.listen.rsplit(':').next()?.parse().ok()
    }

    /// A configuration suitable for unit tests: no tailscaled, dev identity.
    pub fn for_tests() -> Self {
        let mut c = Config::parse_from(["tsidp-server"]);
        c.dev_identity = Some("alice@example.com".into());
        c.configure_serve = false;
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_helpers() {
        let c = Config::parse_from(["tsidp-server"]);
        assert_eq!(c.listen, "127.0.0.1:8443");
        assert_eq!(c.listen_port(), Some(8443));
        assert_eq!(c.issuer_port(), 443);
        assert!(c.issuer_port.is_none() && c.startup_warnings.is_empty());
        assert!(!c.funnel && !c.enable_sts && c.configure_serve);
        assert!(!c.allow_cross_origin_dcr && !c.allow_http_redirect_uris);
        assert_eq!(
            c.socket_path(),
            PathBuf::from("/var/run/tailscale/tailscaled.sock")
        );
        assert_eq!(c.state_dir_or_cwd(), PathBuf::from("."));
        assert!(c.extra_scope_list().is_empty());
        assert_eq!(c.state_backend, StateBackend::File);
    }

    #[test]
    fn flags_and_bool_spellings() {
        let c = Config::parse_from([
            "tsidp-server",
            "--enable-sts=1",
            "--funnel",
            "yes",
            "--configure-serve=false",
            "--extra-scopes",
            "a, b,,c",
            "--listen",
            "0.0.0.0:9000",
            "--state-backend",
            "kubernetes",
            "--log-format",
            "json",
        ]);
        assert!(c.enable_sts && c.funnel && !c.configure_serve);
        let bare = Config::parse_from([
            "tsidp-server",
            "--funnel",
            "--enable-sts",
            "--jwt-access-tokens=0",
        ]);
        assert!(bare.funnel && bare.enable_sts && !bare.jwt_access_tokens);
        assert_eq!(c.extra_scope_list(), vec!["a", "b", "c"]);
        assert_eq!(c.listen_port(), Some(9000));
        assert_eq!(c.state_backend, StateBackend::Kubernetes);
        assert_eq!(c.log_format, LogFormat::Json);
        assert!(Config::try_parse_from(["tsidp-server", "--enable-sts", "maybe"]).is_err());
        assert_eq!(
            Config::parse_from(["tsidp-server", "--listen", "nonsense"]).listen_port(),
            None
        );
    }

    #[test]
    fn legacy_env_fallbacks() {
        let mut c = Config::parse_from(["tsidp-server"]);
        c.apply_legacy_env_with(|k| match k {
            "TS_STATE_DIR" => Some("/data".into()),
            "TS_SOCKET" => Some("".into()),
            _ => None,
        });
        assert_eq!(c.state_dir, Some(PathBuf::from("/data")));
        assert!(c.tailscale_socket.is_none());
        // explicit flags win over legacy names
        let mut c = Config::parse_from([
            "tsidp-server",
            "--state-dir",
            "/explicit",
            "--tailscale-socket",
            "/s.sock",
        ]);
        c.apply_legacy_env_with(|_| Some("/legacy".into()));
        assert_eq!(c.state_dir, Some(PathBuf::from("/explicit")));
        assert_eq!(c.socket_path(), PathBuf::from("/s.sock"));
        let t = Config::for_tests();
        assert_eq!(t.dev_identity.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn kubernetes_service_link_does_not_break_port() {
        // What Kubernetes injects for a Service named `tsidp` (found in the
        // first k3s deployment; see docs/field-report-2026-10-14-k3s-headlamp.md).
        let link = |k: &str| match k {
            "TSIDP_PORT" => Some("tcp://10.43.40.20:8080".to_string()),
            "TSIDP_SERVICE_PORT" => Some("8080".to_string()),
            _ => None,
        };
        let mut c = Config::parse_from(["tsidp-server"]);
        c.apply_legacy_env_with(link);
        assert_eq!(c.issuer_port(), 443, "service link ignored");
        assert_eq!(c.startup_warnings.len(), 1);
        assert!(
            c.startup_warnings[0].contains("enableServiceLinks"),
            "{}",
            c.startup_warnings[0]
        );

        // A numeric legacy TSIDP_PORT still works, with a deprecation notice.
        let mut c = Config::parse_from(["tsidp-server"]);
        c.apply_legacy_env_with(|k| (k == "TSIDP_PORT").then(|| "8443".to_string()));
        assert_eq!(c.issuer_port(), 8443);
        assert!(c.startup_warnings[0].contains("deprecated"));

        // The flag / new variable always wins over the legacy name.
        let mut c = Config::parse_from(["tsidp-server", "--port", "9443"]);
        c.apply_legacy_env_with(|k| (k == "TSIDP_PORT").then(|| "tcp://1.2.3.4:1".to_string()));
        assert_eq!(c.issuer_port(), 9443);
        assert!(c.startup_warnings.is_empty());
        assert_eq!(
            Config::parse_from(["tsidp-server", "--port=8443"]).issuer_port(),
            8443
        );
        assert!(Config::try_parse_from(["tsidp-server", "--port", "tcp://x"]).is_err());
    }
}
