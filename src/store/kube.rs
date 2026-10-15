//! State in a Kubernetes Secret, so a deployment needs no PersistentVolume.
//!
//! Uses the in-cluster service account: the API server address comes from
//! `KUBERNETES_SERVICE_HOST`/`_PORT`, the bearer token and CA from the
//! projected service account volume. The token file is re-read on every call
//! because Kubernetes rotates bound tokens.

use async_trait::async_trait;
use base64::Engine;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

use super::StateStore;

const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

#[derive(Debug)]
pub struct KubeSecretStore {
    namespace: String,
    name: String,
    api_base: String,
    token_path: PathBuf,
    client: reqwest::Client,
}

impl KubeSecretStore {
    /// Build from the in-cluster environment. `namespace` falls back to the
    /// service account's namespace. `TSIDP_KUBE_API_URL` overrides the API
    /// server address (e.g. `http://127.0.0.1:8001` behind `kubectl proxy`),
    /// and `TSIDP_KUBE_SA_DIR` the service account directory.
    pub fn from_env(name: &str, namespace: Option<String>) -> anyhow::Result<Self> {
        let api_base = match std::env::var("TSIDP_KUBE_API_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| {
                    anyhow::anyhow!(
                        "KUBERNETES_SERVICE_HOST is not set; the kubernetes state backend only works inside a pod (or set TSIDP_KUBE_API_URL)"
                    )
                })?;
                let port =
                    std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
                if host.contains(':') {
                    format!("https://[{host}]:{port}")
                } else {
                    format!("https://{host}:{port}")
                }
            }
        };
        let sa =
            PathBuf::from(std::env::var("TSIDP_KUBE_SA_DIR").unwrap_or_else(|_| SA_DIR.into()));
        Self::new(&api_base, &sa, name, namespace)
    }

    /// Build against an explicit API server and service account directory
    /// (`token`, `namespace`, and `ca.crt` for https endpoints).
    pub fn new(
        api_base: &str,
        sa_dir: &Path,
        name: &str,
        namespace: Option<String>,
    ) -> anyhow::Result<Self> {
        let namespace = match namespace {
            Some(ns) if !ns.is_empty() => ns,
            _ => std::fs::read_to_string(sa_dir.join("namespace"))
                .map(|s| s.trim().to_string())
                .map_err(|e| {
                    anyhow::anyhow!("cannot determine namespace (set --kube-namespace): {e}")
                })?,
        };
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15));
        if api_base.starts_with("https://") {
            let ca = std::fs::read(sa_dir.join("ca.crt"))
                .map_err(|e| anyhow::anyhow!("reading service account CA: {e}"))?;
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&ca)?);
        }
        Ok(KubeSecretStore {
            namespace,
            name: name.to_string(),
            api_base: api_base.trim_end_matches('/').to_string(),
            token_path: sa_dir.join("token"),
            client: builder.build()?,
        })
    }

    fn token(&self) -> anyhow::Result<String> {
        Ok(std::fs::read_to_string(&self.token_path)
            .map_err(|e| anyhow::anyhow!("reading service account token: {e}"))?
            .trim()
            .to_string())
    }

    fn secret_url(&self) -> String {
        format!(
            "{}/api/v1/namespaces/{}/secrets/{}",
            self.api_base, self.namespace, self.name
        )
    }

    fn secrets_url(&self) -> String {
        format!(
            "{}/api/v1/namespaces/{}/secrets",
            self.api_base, self.namespace
        )
    }

    async fn fetch(&self) -> anyhow::Result<Option<Value>> {
        let resp = self
            .client
            .get(self.secret_url())
            .bearer_auth(self.token()?)
            .send()
            .await?;
        match resp.status().as_u16() {
            200 => Ok(Some(resp.json().await?)),
            404 => Ok(None),
            s => Err(anyhow::anyhow!(
                "GET secret {}/{} failed: {s} {}",
                self.namespace,
                self.name,
                resp.text().await.unwrap_or_default()
            )),
        }
    }

    async fn create_empty(&self) -> anyhow::Result<()> {
        let body = json!({
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": self.name, "labels": {"app.kubernetes.io/managed-by": "tsidp"}},
            "data": {}
        });
        let resp = self
            .client
            .post(self.secrets_url())
            .bearer_auth(self.token()?)
            .json(&body)
            .send()
            .await?;
        match resp.status().as_u16() {
            200 | 201 | 409 => Ok(()),
            s => Err(anyhow::anyhow!(
                "creating secret {}/{} failed: {s} {}",
                self.namespace,
                self.name,
                resp.text().await.unwrap_or_default()
            )),
        }
    }
}

#[async_trait]
impl StateStore for KubeSecretStore {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let Some(secret) = self.fetch().await? else {
            return Ok(None);
        };
        let Some(v) = secret
            .get("data")
            .and_then(|d| d.get(key))
            .and_then(|v| v.as_str())
        else {
            return Ok(None);
        };
        Ok(Some(base64::engine::general_purpose::STANDARD.decode(v)?))
    }

    async fn put(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        if self.fetch().await?.is_none() {
            self.create_empty().await?;
        }
        let patch = json!({"data": {key: base64::engine::general_purpose::STANDARD.encode(data)}});
        let resp = self
            .client
            .patch(self.secret_url())
            .bearer_auth(self.token()?)
            .header("Content-Type", "application/merge-patch+json")
            .body(patch.to_string())
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "patching secret {}/{} failed: {} {}",
                self.namespace,
                self.name,
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        Ok(())
    }

    async fn check_writable(&self) -> anyhow::Result<()> {
        if self.fetch().await?.is_none() {
            self.create_empty().await?;
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("kubernetes secret {}/{}", self.namespace, self.name)
    }
}
