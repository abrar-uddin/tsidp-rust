//! File-backed state in a directory, written atomically (temp file + rename)
//! with mode 0600.

use async_trait::async_trait;
use std::path::{Path, PathBuf};

use super::StateStore;

pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        FileStore {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }
}

#[async_trait]
impl StateStore for FileStore {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.path(key)).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", self.path(key).display())),
        }
    }

    async fn put(&self, key: &str, data: &[u8]) -> anyhow::Result<()> {
        let final_path = self.path(key);
        let tmp = self
            .dir
            .join(format!(".{key}.tmp-{}", crate::util::random_hex(4)));
        write_private(&tmp, data)
            .await
            .map_err(|e| anyhow::anyhow!("writing {}: {e}", tmp.display()))?;
        tokio::fs::rename(&tmp, &final_path).await.map_err(|e| {
            anyhow::anyhow!(
                "renaming {} to {}: {e}",
                tmp.display(),
                final_path.display()
            )
        })?;
        Ok(())
    }

    async fn check_writable(&self) -> anyhow::Result<()> {
        if !self.dir.is_dir() {
            tokio::fs::create_dir_all(&self.dir).await.map_err(|e| {
                anyhow::anyhow!(
                    "state directory {} does not exist and cannot be created: {e}",
                    self.dir.display()
                )
            })?;
        }
        let probe = self
            .dir
            .join(format!(".tsidp-write-probe-{}", crate::util::random_hex(4)));
        write_private(&probe, b"ok").await.map_err(|e| {
            anyhow::anyhow!(
                "state directory {} is not writable by uid {}: {e}. On Kubernetes set pod.spec.securityContext.fsGroup (the image runs as uid 65532); on Docker chown the volume.",
                self.dir.display(),
                current_uid()
            )
        })?;
        let _ = tokio::fs::remove_file(&probe).await;
        Ok(())
    }

    fn describe(&self) -> String {
        format!("files in {}", self.dir.display())
    }
}

async fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path).await?;
    f.write_all(data).await?;
    f.sync_all().await?;
    Ok(())
}

fn current_uid() -> String {
    #[cfg(unix)]
    {
        // Read from /proc to avoid a libc dependency; fine on Linux.
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(uid) = rest.split_whitespace().next() {
                        return uid.to_string();
                    }
                }
            }
        }
    }
    "?".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_and_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let s = FileStore::new(dir.path());
        s.check_writable().await.unwrap();
        assert!(s.get("x").await.unwrap().is_none());
        s.put("x", b"hello").await.unwrap();
        assert_eq!(s.get("x").await.unwrap().unwrap(), b"hello");
        s.put("x", b"world").await.unwrap();
        assert_eq!(s.get("x").await.unwrap().unwrap(), b"world");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    #[tokio::test]
    async fn creates_missing_dir_and_reports_unwritable() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/c");
        let s = FileStore::new(&nested);
        s.check_writable().await.unwrap();
        assert!(nested.is_dir());
        assert!(s.describe().ends_with("a/b/c"));

        // A regular file where the directory should be.
        let file = dir.path().join("plain");
        std::fs::write(&file, "x").unwrap();
        let bad = FileStore::new(&file);
        let err = bad.check_writable().await.unwrap_err().to_string();
        assert!(
            err.contains("not writable") || err.contains("cannot be created"),
            "{err}"
        );
        assert!(bad.put("k", b"v").await.is_err());
        // get on an unreadable path (a directory named like the key) is an error, not None
        let s2 = FileStore::new(dir.path());
        std::fs::create_dir(dir.path().join("dirkey")).unwrap();
        assert!(s2.get("dirkey").await.is_err());
    }
}
