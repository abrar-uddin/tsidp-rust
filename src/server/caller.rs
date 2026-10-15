//! Who is on the other end of this request, and which listener did it come in
//! on? Identity is only ever trusted on the tailnet listener, where the only
//! thing that can reach us is the local `tailscale serve` proxy, which sets
//! `X-Forwarded-For` to the peer's tailnet address and marks Funnel traffic
//! with `Tailscale-Funnel-Request`.

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use std::sync::Arc;

use super::error::OAuthError;
use super::{AppState, Listener};
use crate::capability::AccessRules;
use crate::identity::{Identity, ResolveError};

#[derive(Debug, Clone)]
pub struct Caller {
    pub listener: Listener,
    /// Peer address reported by tailscaled (last X-Forwarded-For value).
    pub remote_addr: Option<String>,
    pub is_funnel: bool,
}

impl Caller {
    pub fn from_headers(listener: Listener, headers: &HeaderMap) -> Caller {
        let is_funnel =
            listener == Listener::Tailnet && headers.get("tailscale-funnel-request").is_some();
        let remote_addr = if listener == Listener::Tailnet {
            last_forwarded_for(headers)
        } else {
            None
        };
        Caller {
            listener,
            remote_addr,
            is_funnel,
        }
    }

    /// True when the request hit the tailnet listener directly (no proxy),
    /// i.e. from inside the pod or a developer's shell.
    pub fn is_direct(&self) -> bool {
        self.listener == Listener::Tailnet && self.remote_addr.is_none() && !self.is_funnel
    }
}

/// tailscaled is always the last proxy, so the last X-Forwarded-For header
/// (and the last element inside it) is the trustworthy one.
pub fn last_forwarded_for(headers: &HeaderMap) -> Option<String> {
    let last = headers.get_all("x-forwarded-for").iter().next_back()?;
    let s = last.to_str().ok()?;
    s.rsplit(',')
        .map(str::trim)
        .find(|p| !p.is_empty())
        .map(|p| p.to_string())
}

impl FromRequestParts<Arc<AppState>> for Caller {
    type Rejection = OAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let listener = parts
            .extensions
            .get::<Listener>()
            .copied()
            .unwrap_or(Listener::Cluster);
        Ok(Caller::from_headers(listener, &parts.headers))
    }
}

impl AppState {
    /// Resolve the caller's tailnet identity, or explain why that is impossible.
    pub async fn identify(&self, caller: &Caller) -> Result<Arc<Identity>, OAuthError> {
        if caller.is_funnel {
            self.metrics.denied();
            return Err(OAuthError::unauthorized(
                "not allowed over Tailscale Funnel",
            ));
        }
        if caller.listener == Listener::Cluster {
            self.metrics.denied();
            let issuer = self
                .issuer()
                .map(|i| i.url)
                .unwrap_or_else(|| "the tailnet URL".into());
            return Err(OAuthError::unauthorized(format!(
                "this endpoint needs the caller's tailnet identity; use it via {issuer} instead of the cluster listener"
            )));
        }
        let addr = match &caller.remote_addr {
            Some(a) => a.clone(),
            None if self.cfg.dev_identity.is_some() => "127.0.0.1".to_string(),
            None if self.cfg.allow_loopback_admin => {
                return Ok(Arc::new(Identity::dev("admin@localhost")));
            }
            None => {
                self.metrics.denied();
                return Err(OAuthError::unauthorized(
                    "no X-Forwarded-For header: requests must arrive through tailscale serve (or set --allow-loopback-admin for local testing)",
                ));
            }
        };
        match self.resolver.whois(&addr).await {
            Ok(id) => Ok(Arc::new(id)),
            Err(ResolveError::NotFound(_)) => {
                self.metrics.whois_failed();
                Err(OAuthError::unauthorized(format!(
                    "{addr} is not a tailnet peer"
                )))
            }
            Err(ResolveError::Backend(e)) => {
                self.metrics.whois_failed();
                Err(
                    OAuthError::server_error("failed to look up caller identity with tailscaled")
                        .detail(e),
                )
            }
        }
    }

    /// Re-resolve a previously captured identity before honouring a refresh
    /// token: the node must still be on the tailnet and still belong to the
    /// same subject, and the returned identity carries the *current*
    /// capability grant rather than the one snapshotted at authorization.
    pub async fn revalidate(&self, snapshot: &Identity) -> Result<Arc<Identity>, OAuthError> {
        let Some(addr) = snapshot
            .addresses
            .iter()
            .map(|a| a.split('/').next().unwrap_or(a).trim())
            .find(|a| !a.is_empty())
        else {
            self.metrics.denied();
            return Err(OAuthError::invalid_grant(
                "cannot re-validate the grant: no node address recorded",
            ));
        };
        match self.resolver.whois(addr).await {
            Ok(fresh) if fresh.subject() == snapshot.subject() => Ok(Arc::new(fresh)),
            Ok(fresh) => {
                self.metrics.denied();
                Err(OAuthError::invalid_grant(
                    "grant revoked: node now belongs to a different identity",
                )
                .detail(format!(
                    "was {}, now {}",
                    snapshot.subject(),
                    fresh.subject()
                )))
            }
            Err(ResolveError::NotFound(_)) => {
                self.metrics.denied();
                Err(OAuthError::invalid_grant(
                    "grant revoked: node is no longer part of the tailnet",
                ))
            }
            Err(ResolveError::Backend(e)) => {
                self.metrics.whois_failed();
                Err(OAuthError::new(
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    super::error::EC_TEMPORARILY_UNAVAILABLE,
                    "cannot re-validate the grant with tailscaled; retry later",
                )
                .detail(e))
            }
        }
    }

    /// Identity plus the accumulated capability grant.
    pub async fn identify_with_access(
        &self,
        caller: &Caller,
    ) -> Result<(Arc<Identity>, AccessRules), OAuthError> {
        let id = self.identify(caller).await?;
        let access = id.access();
        Ok((id, access))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn xff_last_wins() {
        let mut h = HeaderMap::new();
        h.append(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 2.2.2.2"),
        );
        h.append("x-forwarded-for", HeaderValue::from_static("100.64.0.5"));
        assert_eq!(last_forwarded_for(&h).as_deref(), Some("100.64.0.5"));
        let mut h2 = HeaderMap::new();
        h2.append(
            "x-forwarded-for",
            HeaderValue::from_static("spoof, 100.64.0.7"),
        );
        assert_eq!(last_forwarded_for(&h2).as_deref(), Some("100.64.0.7"));
        assert_eq!(last_forwarded_for(&HeaderMap::new()), None);
    }

    #[test]
    fn cluster_listener_never_trusts_headers() {
        let mut h = HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("100.64.0.5"));
        h.append("tailscale-funnel-request", HeaderValue::from_static("?1"));
        let c = Caller::from_headers(Listener::Cluster, &h);
        assert!(c.remote_addr.is_none());
        assert!(!c.is_funnel);
        let t = Caller::from_headers(Listener::Tailnet, &h);
        assert!(t.is_funnel);
        assert_eq!(t.remote_addr.as_deref(), Some("100.64.0.5"));
    }
}
