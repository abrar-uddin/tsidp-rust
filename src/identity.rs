//! Who is calling? Identity is resolved from the caller's tailnet address via
//! LocalAPI `whois`, which returns the node, its user and the capability
//! grants that apply to it.

use async_trait::async_trait;
use std::sync::Arc;

use crate::capability::{AccessRules, CapRule, parse_cap_rules};
use crate::tailscale::types::WhoIsResponse;
use crate::tailscale::{LocalApi, LocalApiError, Status};

/// A normalised view of a WhoIs answer.
#[derive(Debug, Clone)]
pub struct Identity {
    pub node_id: i64,
    pub stable_node_id: String,
    /// MagicDNS name of the node without trailing dot, e.g. `laptop.tn.ts.net`.
    pub node_name: String,
    pub node_key: String,
    pub addresses: Vec<String>,
    pub tags: Vec<String>,
    pub user_id: i64,
    pub login_name: String,
    pub display_name: String,
    pub profile_pic_url: String,
    pub groups: Vec<String>,
    pub cap_rules: Vec<CapRule>,
}

impl Identity {
    pub fn from_whois(w: WhoIsResponse) -> Identity {
        let profile = w.user_profile.unwrap_or_default();
        let cap_rules = parse_cap_rules(w.cap_map.as_ref());
        Identity {
            node_id: w.node.id,
            stable_node_id: w.node.stable_id,
            node_name: crate::util::trim_fqdn(&w.node.name).to_string(),
            node_key: w.node.key,
            addresses: w.node.addresses.unwrap_or_default(),
            tags: w.node.tags.unwrap_or_default(),
            user_id: if profile.id != 0 {
                profile.id
            } else {
                w.node.user
            },
            login_name: profile.login_name,
            display_name: profile.display_name,
            profile_pic_url: profile.profile_pic_url,
            groups: profile.groups.unwrap_or_default(),
            cap_rules,
        }
    }

    /// A tagged node has no user identity.
    pub fn is_tagged(&self) -> bool {
        !self.tags.is_empty()
    }

    /// The OIDC `sub`: `userid:<n>` for users (matches the Go tsidp) or
    /// `node:<stable id>` for tagged nodes.
    pub fn subject(&self) -> String {
        if self.is_tagged() {
            format!("node:{}", self.stable_node_id)
        } else {
            format!("userid:{}", self.user_id)
        }
    }

    /// `tn.ts.net` from `laptop.tn.ts.net`.
    pub fn tailnet(&self) -> String {
        self.node_name
            .split_once('.')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default()
    }

    /// The local part of the login name (`alice` from `alice@example.com`).
    pub fn username(&self) -> Option<String> {
        self.login_name.split_once('@').map(|(u, _)| u.to_string())
    }

    pub fn access(&self) -> AccessRules {
        AccessRules::from_rules(self.cap_rules.clone())
    }

    /// A synthetic identity for `--dev-identity` and tests: a user node with
    /// every tsidp capability granted.
    pub fn dev(login_name: &str) -> Identity {
        let rule: CapRule = serde_json::from_value(serde_json::json!({
            "allow_admin_ui": true, "allow_dcr": true, "users": ["*"], "resources": ["*"],
            "includeInUserInfo": true
        }))
        .expect("static rule");
        Identity {
            node_id: 1,
            stable_node_id: "nDEV".into(),
            node_name: "dev-node.example.ts.net".into(),
            node_key: "nodekey:0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            addresses: vec!["100.100.100.100/32".into()],
            tags: vec![],
            user_id: 1,
            login_name: login_name.to_string(),
            display_name: login_name.split('@').next().unwrap_or("dev").to_string(),
            profile_pic_url: String::new(),
            groups: vec![],
            cap_rules: vec![rule],
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The address is not a tailnet peer (funnel, cluster, loopback...).
    #[error("no tailnet identity for address {0}")]
    NotFound(String),
    #[error("identity backend error: {0}")]
    Backend(String),
}

/// Resolves identities and reports node status. Implemented over LocalAPI in
/// production and by a static resolver for development and tests.
#[async_trait]
pub trait IdentityResolver: Send + Sync {
    async fn whois(&self, addr: &str) -> Result<Identity, ResolveError>;
    async fn status(&self) -> Result<Status, ResolveError>;
    /// Human readable description for logs.
    fn describe(&self) -> String;
}

pub struct LocalApiResolver {
    pub api: Arc<LocalApi>,
}

#[async_trait]
impl IdentityResolver for LocalApiResolver {
    async fn whois(&self, addr: &str) -> Result<Identity, ResolveError> {
        match self.api.whois(addr).await {
            Ok(w) => Ok(Identity::from_whois(w)),
            Err(e) if e.status() == Some(hyper::StatusCode::NOT_FOUND) => {
                Err(ResolveError::NotFound(addr.to_string()))
            }
            Err(e) => Err(ResolveError::Backend(e.to_string())),
        }
    }

    async fn status(&self) -> Result<Status, ResolveError> {
        self.api
            .status()
            .await
            .map_err(|e: LocalApiError| ResolveError::Backend(e.to_string()))
    }

    fn describe(&self) -> String {
        format!(
            "tailscaled LocalAPI at {}",
            self.api.socket_path().display()
        )
    }
}

/// Every address resolves to the same identity. Development and tests only.
pub struct StaticResolver {
    pub identity: Identity,
    pub dns_name: String,
}

#[async_trait]
impl IdentityResolver for StaticResolver {
    async fn whois(&self, _addr: &str) -> Result<Identity, ResolveError> {
        Ok(self.identity.clone())
    }

    async fn status(&self) -> Result<Status, ResolveError> {
        let mut s = Status {
            backend_state: "Running".into(),
            version: "dev".into(),
            ..Default::default()
        };
        s.self_node = Some(crate::tailscale::types::SelfStatus {
            dns_name: format!("{}.", self.dns_name),
            tailscale_ips: Some(vec!["100.100.100.100".into()]),
            ..Default::default()
        });
        Ok(s)
    }

    fn describe(&self) -> String {
        format!(
            "STATIC DEV IDENTITY {} (not for production)",
            self.identity.login_name
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_and_tailnet() {
        let mut id = Identity::dev("alice@example.com");
        assert_eq!(id.subject(), "userid:1");
        assert_eq!(id.tailnet(), "example.ts.net");
        assert_eq!(id.username().as_deref(), Some("alice"));
        id.tags = vec!["tag:server".into()];
        assert_eq!(id.subject(), "node:nDEV");
        assert!(id.is_tagged());
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;
    use crate::tailscale::types::{Node, WhoIsResponse};

    #[test]
    fn from_whois_without_profile_or_caps() {
        let w = WhoIsResponse {
            node: Node {
                id: 5,
                stable_id: "nX".into(),
                name: "box.tn.ts.net.".into(),
                user: 9,
                tags: Some(vec!["tag:srv".into()]),
                ..Default::default()
            },
            user_profile: None,
            cap_map: None,
        };
        let id = Identity::from_whois(w);
        assert_eq!(id.user_id, 9, "falls back to the node's user");
        assert!(id.is_tagged());
        assert_eq!(id.subject(), "node:nX");
        assert_eq!(id.node_name, "box.tn.ts.net");
        assert!(id.cap_rules.is_empty() && id.addresses.is_empty() && id.groups.is_empty());
        assert!(id.username().is_none());
        assert!(!id.access().allow_admin_ui);
        let flat = Identity {
            node_name: "nodots".into(),
            ..Identity::dev("a@b")
        };
        assert_eq!(flat.tailnet(), "");
    }

    #[tokio::test]
    async fn static_resolver_reports_running() {
        let r = StaticResolver {
            identity: Identity::dev("a@b.c"),
            dns_name: "idp.tn.ts.net".into(),
        };
        let st = r.status().await.unwrap();
        assert!(st.is_running());
        assert_eq!(st.dns_name().as_deref(), Some("idp.tn.ts.net"));
        assert_eq!(r.whois("anything").await.unwrap().login_name, "a@b.c");
        assert!(r.describe().contains("DEV"));
    }
}
