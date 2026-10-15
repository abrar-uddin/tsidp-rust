//! Serde views of the LocalAPI JSON types we consume. Field names mirror the
//! Go structs (`tailcfg.Node`, `tailcfg.UserProfile`, `ipnstate.Status`).
//! Only the fields tsidp needs are declared; everything else is ignored.

use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

/// `apitype.WhoIsResponse`
#[derive(Debug, Clone, Deserialize)]
pub struct WhoIsResponse {
    #[serde(rename = "Node")]
    pub node: Node,
    #[serde(rename = "UserProfile")]
    pub user_profile: Option<UserProfile>,
    /// `tailcfg.PeerCapMap`: capability name -> list of raw JSON grant values.
    #[serde(rename = "CapMap", default)]
    pub cap_map: Option<HashMap<String, Vec<Value>>>,
}

/// `tailcfg.Node` (subset)
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "StableID")]
    pub stable_id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "User")]
    pub user: i64,
    #[serde(rename = "Sharer")]
    pub sharer: i64,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Addresses")]
    pub addresses: Option<Vec<String>>,
    #[serde(rename = "Tags")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "ComputedName")]
    pub computed_name: String,
}

/// `tailcfg.UserProfile`
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct UserProfile {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "LoginName")]
    pub login_name: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
    #[serde(rename = "ProfilePicURL")]
    pub profile_pic_url: String,
    #[serde(rename = "Groups")]
    pub groups: Option<Vec<String>>,
}

/// `ipnstate.Status` (subset)
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Status {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "BackendState")]
    pub backend_state: String,
    #[serde(rename = "AuthURL")]
    pub auth_url: String,
    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "Self")]
    pub self_node: Option<SelfStatus>,
    #[serde(rename = "CurrentTailnet")]
    pub current_tailnet: Option<TailnetStatus>,
    #[serde(rename = "MagicDNSSuffix")]
    pub magic_dns_suffix: String,
    #[serde(rename = "CertDomains")]
    pub cert_domains: Option<Vec<String>>,
    #[serde(rename = "Health")]
    pub health: Option<Vec<String>>,
}

/// `ipnstate.PeerStatus` for the local node (subset)
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SelfStatus {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "NodeID")]
    pub node_id: i64,
    #[serde(rename = "HostName")]
    pub host_name: String,
    #[serde(rename = "DNSName")]
    pub dns_name: String,
    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "Tags")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "Online")]
    pub online: bool,
}

/// `ipnstate.TailnetStatus`
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct TailnetStatus {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "MagicDNSSuffix")]
    pub magic_dns_suffix: String,
    #[serde(rename = "MagicDNSEnabled")]
    pub magic_dns_enabled: bool,
}

impl Status {
    pub fn is_running(&self) -> bool {
        self.backend_state == "Running"
    }

    /// The node's MagicDNS FQDN without the trailing dot, if known.
    pub fn dns_name(&self) -> Option<String> {
        let s = self.self_node.as_ref()?;
        if s.dns_name.is_empty() {
            return None;
        }
        Some(crate::util::trim_fqdn(&s.dns_name).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_whois_with_capmap() {
        let j = r#"{
          "Node": {"ID": 123, "StableID": "nABC", "Name": "laptop.tn.ts.net.", "User": 456,
                   "Key": "nodekey:00ff", "Addresses": ["100.64.0.1/32", "fd7a::1/128"], "Tags": null},
          "UserProfile": {"ID": 456, "LoginName": "alice@example.com", "DisplayName": "Alice", "ProfilePicURL": ""},
          "CapMap": {"tailscale.com/cap/tsidp": [{"allow_admin_ui": true, "extraClaims": {"a": [1,2]}}]}
        }"#;
        let w: WhoIsResponse = serde_json::from_str(j).unwrap();
        assert_eq!(w.node.id, 123);
        assert_eq!(w.node.addresses.as_ref().unwrap().len(), 2);
        assert!(w.node.tags.is_none());
        assert_eq!(w.user_profile.unwrap().login_name, "alice@example.com");
        assert_eq!(w.cap_map.unwrap()["tailscale.com/cap/tsidp"].len(), 1);
    }

    #[test]
    fn parses_status() {
        let j = r#"{"Version":"1.96.5","BackendState":"Running","Self":{"ID":"n1","DNSName":"idp.tn.ts.net.","TailscaleIPs":["100.64.0.9"]},"CurrentTailnet":{"Name":"example.com","MagicDNSSuffix":"tn.ts.net","MagicDNSEnabled":true}}"#;
        let s: Status = serde_json::from_str(j).unwrap();
        assert!(s.is_running());
        assert_eq!(s.dns_name().as_deref(), Some("idp.tn.ts.net"));
    }
}
