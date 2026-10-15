//! Persistent state: the signing key and the client registry.
//!
//! Two keys are stored, named after the Go implementation's files so a
//! directory written by either implementation can be read by the other:
//! `oidc-key.json` and `oidc-funnel-clients.json`.

use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;

pub mod file;
pub mod kube;

pub use file::FileStore;
pub use kube::KubeSecretStore;

#[async_trait]
pub trait StateStore: Send + Sync {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>>;
    async fn put(&self, key: &str, data: &[u8]) -> anyhow::Result<()>;
    /// Fail fast at startup if the backend cannot be written to.
    async fn check_writable(&self) -> anyhow::Result<()>;
    fn describe(&self) -> String;
}

/// Volatile store for tests and `--dev-identity` experiments.
#[derive(Default)]
pub struct MemoryStore {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

#[async_trait]
impl StateStore for MemoryStore {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.data.lock().get(key).cloned())
    }

    async fn put(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        self.data.lock().insert(key.to_string(), data.to_vec());
        Ok(())
    }

    async fn check_writable(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn describe(&self) -> String {
        "in-memory (state is lost on restart)".into()
    }
}
