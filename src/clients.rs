//! Registered OAuth/OIDC clients ("funnel clients" in the Go code) and the
//! registry that keeps them in memory and persisted.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::store::StateStore;
use crate::util::{now_unix, random_hex, rfc3339};

pub const CLIENTS_KEY: &str = "oidc-funnel-clients.json";

pub const AUTH_METHOD_NONE: &str = "none";
pub const AUTH_METHOD_BASIC: &str = "client_secret_basic";
pub const AUTH_METHOD_POST: &str = "client_secret_post";

/// Serialised exactly like the Go `FunnelClient` so state files are portable
/// in both directions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Client {
    #[serde(rename = "client_id")]
    pub id: String,
    #[serde(
        rename = "client_secret",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub secret: String,
    #[serde(
        rename = "client_name",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_endpoint_auth_method: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_types: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_uri: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub logo_uri: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub application_type: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dynamically_registered: bool,
    /// RFC 3339; Go writes `0001-01-01T00:00:00Z` for unknown.
    #[serde(default = "zero_time")]
    pub created_at: String,
    /// Legacy single redirect URI kept for files read by older Go versions.
    #[serde(rename = "redirect_uri", default)]
    pub legacy_redirect_uri: String,
}

fn zero_time() -> String {
    "0001-01-01T00:00:00Z".to_string()
}

impl Client {
    pub fn new(name: &str, redirect_uris: Vec<String>, public: bool) -> Client {
        let first = redirect_uris.first().cloned().unwrap_or_default();
        Client {
            id: generate_client_id(),
            secret: if public {
                String::new()
            } else {
                generate_client_secret()
            },
            name: name.to_string(),
            redirect_uris,
            token_endpoint_auth_method: if public {
                AUTH_METHOD_NONE
            } else {
                AUTH_METHOD_BASIC
            }
            .to_string(),
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            scope: String::new(),
            client_uri: String::new(),
            logo_uri: String::new(),
            contacts: Vec::new(),
            application_type: "web".into(),
            dynamically_registered: false,
            created_at: rfc3339(now_unix()),
            legacy_redirect_uri: first,
        }
    }

    /// A public client authenticates with PKCE only (RFC 7636, OAuth 2.1).
    pub fn is_public(&self) -> bool {
        self.token_endpoint_auth_method == AUTH_METHOD_NONE || self.secret.is_empty()
    }

    pub fn has_secret(&self) -> bool {
        !self.secret.is_empty()
    }

    /// Copy without the secret, for API responses.
    pub fn redacted(&self) -> Client {
        let mut c = self.clone();
        c.secret.clear();
        c
    }

    /// Normalise legacy single `redirect_uri` into `redirect_uris` and keep
    /// the legacy field in sync for older readers.
    fn normalise(&mut self) -> bool {
        let mut changed = false;
        if self.redirect_uris.is_empty() && !self.legacy_redirect_uri.is_empty() {
            self.redirect_uris.push(self.legacy_redirect_uri.clone());
            changed = true;
        }
        if self.legacy_redirect_uri.is_empty() {
            if let Some(first) = self.redirect_uris.first() {
                self.legacy_redirect_uri = first.clone();
            }
        }
        changed
    }
}

pub fn generate_client_id() -> String {
    random_hex(16)
}

pub fn generate_client_secret() -> String {
    random_hex(32)
}

/// Split the admin UI's one-per-line redirect URI textarea.
pub fn split_redirect_uris(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

const DANGEROUS_SCHEMES: &[&str] = &[
    "ftp",
    "file",
    "mailto",
    "javascript",
    "data",
    "blob",
    "filesystem",
    "vbscript",
    "about",
    "chrome",
    "chrome-extension",
];

/// Validate a redirect URI: must have a scheme, http(s) must have a host, and
/// a few schemes are refused outright. Custom schemes for native apps are
/// allowed. Plain `http://` is only accepted for loopback hosts (RFC 8252
/// §7.3) unless `allow_http` is set. Returns a human readable reason when
/// invalid.
pub fn validate_redirect_uri(uri: &str, allow_http: bool) -> Result<(), String> {
    let parsed =
        url::Url::parse(uri).map_err(|_| "must be a valid URI with a scheme".to_string())?;
    let scheme = parsed.scheme();
    if DANGEROUS_SCHEMES.contains(&scheme) {
        return Err(format!("scheme {scheme:?} is not allowed"));
    }
    if (scheme == "http" || scheme == "https") && parsed.host_str().unwrap_or("").is_empty() {
        return Err("HTTP and HTTPS URLs must have a host".into());
    }
    if scheme == "http" && !allow_http && !is_loopback_host(&parsed) {
        return Err(
            "http:// redirect URIs are only allowed for localhost (start tsidp with --allow-http-redirect-uris to override)"
                .into(),
        );
    }
    if parsed.fragment().is_some() {
        return Err("redirect URIs must not contain a fragment".into());
    }
    Ok(())
}

fn is_loopback_host(u: &url::Url) -> bool {
    match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// In-memory registry persisted through a [`StateStore`].
pub struct ClientRegistry {
    clients: RwLock<HashMap<String, Client>>,
    store: Arc<dyn StateStore>,
}

impl ClientRegistry {
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        ClientRegistry {
            clients: RwLock::new(HashMap::new()),
            store,
        }
    }

    /// Load from the store, migrating legacy entries if needed.
    pub async fn load(&self) -> anyhow::Result<usize> {
        let Some(bytes) = self.store.get(CLIENTS_KEY).await? else {
            return Ok(0);
        };
        let mut map: HashMap<String, Client> = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("{} is not a valid clients file: {e}", CLIENTS_KEY))?;
        let mut migrated = false;
        for c in map.values_mut() {
            migrated |= c.normalise();
        }
        let n = map.len();
        *self.clients.write() = map;
        if migrated {
            tracing::info!("migrated clients with a single redirect_uri to redirect_uris");
            self.persist().await?;
        }
        Ok(n)
    }

    async fn persist(&self) -> anyhow::Result<()> {
        let bytes = {
            let mut snapshot = self.clients.read().clone();
            for c in snapshot.values_mut() {
                c.normalise();
            }
            serde_json::to_vec_pretty(&snapshot)?
        };
        self.store.put(CLIENTS_KEY, &bytes).await
    }

    pub fn get(&self, id: &str) -> Option<Client> {
        self.clients.read().get(id).cloned()
    }

    pub fn list(&self) -> Vec<Client> {
        let mut v: Vec<Client> = self.clients.read().values().cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        v
    }

    pub fn len(&self) -> usize {
        self.clients.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub async fn insert(&self, client: Client) -> anyhow::Result<()> {
        self.clients.write().insert(client.id.clone(), client);
        self.persist().await
    }

    /// Apply `f` to an existing client and persist. Returns false if absent.
    pub async fn update(&self, id: &str, f: impl FnOnce(&mut Client)) -> anyhow::Result<bool> {
        {
            let mut map = self.clients.write();
            let Some(c) = map.get_mut(id) else {
                return Ok(false);
            };
            f(c);
        }
        self.persist().await?;
        Ok(true)
    }

    pub async fn delete(&self, id: &str) -> anyhow::Result<bool> {
        let removed = self.clients.write().remove(id).is_some();
        if removed {
            self.persist().await?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    #[test]
    fn go_compatible_serialisation() {
        // Shape written by the Go implementation (v0.0.x), including the legacy field.
        let j = r#"{"abc":{"client_id":"abc","client_secret":"s3","client_name":"Grafana","redirect_uris":["https://g/cb"],"created_at":"2025-11-02T13:09:42.123Z","redirect_uri":"https://g/cb"}}"#;
        let map: HashMap<String, Client> = serde_json::from_str(j).unwrap();
        let c = &map["abc"];
        assert_eq!(c.secret, "s3");
        assert!(!c.is_public());
        let out = serde_json::to_value(c).unwrap();
        assert_eq!(out["client_id"], "abc");
        assert_eq!(out["redirect_uri"], "https://g/cb");
        assert!(out.get("dynamically_registered").is_none());
    }

    #[test]
    fn legacy_single_redirect_uri_is_migrated() {
        let mut c: Client = serde_json::from_str(r#"{"client_id":"x","redirect_uri":"https://old/cb","created_at":"0001-01-01T00:00:00Z"}"#).unwrap();
        assert!(c.normalise());
        assert_eq!(c.redirect_uris, vec!["https://old/cb".to_string()]);
    }

    #[test]
    fn redirect_validation() {
        assert!(validate_redirect_uri("https://app.example.com/cb", false).is_ok());
        assert!(validate_redirect_uri("myapp://callback", false).is_ok());
        assert!(validate_redirect_uri("javascript:alert(1)", false).is_err());
        assert!(validate_redirect_uri("not a uri", false).is_err());
        assert!(validate_redirect_uri("https://x/cb#frag", false).is_err());
        // plain http only for loopback unless explicitly allowed
        assert!(validate_redirect_uri("http://localhost:6274/cb", false).is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1/cb", false).is_ok());
        assert!(validate_redirect_uri("http://[::1]:8080/cb", false).is_ok());
        assert!(validate_redirect_uri("http://grafana.internal/login", false).is_err());
        assert!(validate_redirect_uri("http://grafana.internal/login", true).is_ok());
    }

    #[tokio::test]
    async fn registry_roundtrip() {
        let store = Arc::new(MemoryStore::default());
        let reg = ClientRegistry::new(store.clone());
        assert_eq!(reg.load().await.unwrap(), 0);
        let c = Client::new("App", vec!["https://a/cb".into()], false);
        reg.insert(c.clone()).await.unwrap();
        let reg2 = ClientRegistry::new(store);
        assert_eq!(reg2.load().await.unwrap(), 1);
        assert_eq!(reg2.get(&c.id).unwrap().secret, c.secret);
        assert!(reg2.delete(&c.id).await.unwrap());
        assert!(reg2.is_empty());
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;
    use crate::store::MemoryStore;

    #[tokio::test]
    async fn update_and_delete_missing_and_corrupt_file() {
        let store = Arc::new(MemoryStore::default());
        let reg = ClientRegistry::new(store.clone());
        assert!(!reg.update("nope", |_| {}).await.unwrap());
        assert!(!reg.delete("nope").await.unwrap());
        let c = Client::new("n", vec!["https://a/cb".into()], false);
        reg.insert(c.clone()).await.unwrap();
        assert!(reg.update(&c.id, |c| c.name = "m".into()).await.unwrap());
        assert_eq!(reg.list()[0].name, "m");
        assert_eq!(reg.get(&c.id).unwrap().redacted().secret, "");
        store.put(CLIENTS_KEY, b"not json").await.unwrap();
        let err = ClientRegistry::new(store)
            .load()
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a valid clients file"), "{err}");
    }

    #[test]
    fn helpers() {
        assert_eq!(
            split_redirect_uris(" https://a \n\n https://b\r\n"),
            vec!["https://a", "https://b"]
        );
        assert_eq!(generate_client_id().len(), 32);
        assert_eq!(generate_client_secret().len(), 64);
        let public = Client::new("p", vec![], true);
        assert!(
            public.is_public() && !public.has_secret() && public.legacy_redirect_uri.is_empty()
        );
        assert_eq!(public.token_endpoint_auth_method, AUTH_METHOD_NONE);
        assert!(validate_redirect_uri("http://", false).is_err());
        assert!(validate_redirect_uri("https://host.example/cb?x=1", false).is_ok());
    }
}
