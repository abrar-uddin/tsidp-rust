//! tsidp: a Tailscale-backed OpenID Connect identity provider.
//!
//! This crate is a Rust port of <https://github.com/tailscale/tsidp> with a
//! deployment model designed for Kubernetes: instead of embedding a userspace
//! Tailscale node (tsnet), tsidp talks to a `tailscaled` running next to it
//! (a pod sidecar, or `network_mode: service:tailscale` in Compose) over the
//! LocalAPI unix socket. `tailscale serve` terminates TLS on the tailnet and
//! proxies to tsidp's loopback listener, while an optional second listener
//! exposes only the non-identity OAuth endpoints (token, userinfo, jwks, ...)
//! to in-cluster relying parties through a plain Kubernetes Service.

pub mod capability;
pub mod clients;
pub mod config;
pub mod identity;
pub mod keys;
pub mod metrics;
pub mod server;
pub mod store;
pub mod tailscale;
pub mod tokens;
pub mod util;

/// Build-time version string, injected via `TSIDP_VERSION` at compile time or
/// falling back to the crate version.
pub fn version() -> &'static str {
    option_env!("TSIDP_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}
