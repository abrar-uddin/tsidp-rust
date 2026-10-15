//! The Kubernetes Secret state backend against a mock API server.

mod support;

use support::MockKubeApi;
use tsidp::store::{KubeSecretStore, StateStore};

#[tokio::test]
async fn creates_patches_and_reads_secret() {
    let api = MockKubeApi::start().await;
    let store = KubeSecretStore::new(&api.url, &api.sa_dir, "tsidp-state", None).unwrap();
    assert_eq!(store.describe(), "kubernetes secret tsidp/tsidp-state");

    assert!(store.get("oidc-key.json").await.unwrap().is_none());
    store.check_writable().await.unwrap();
    assert!(api.secrets.lock().contains_key("tsidp/tsidp-state"));
    assert!(
        store.get("oidc-key.json").await.unwrap().is_none(),
        "empty secret has no data"
    );

    store.put("oidc-key.json", b"{\"kid\":1}").await.unwrap();
    store.put("oidc-funnel-clients.json", b"{}").await.unwrap();
    assert_eq!(
        store.get("oidc-key.json").await.unwrap().unwrap(),
        b"{\"kid\":1}"
    );
    assert_eq!(
        store
            .get("oidc-funnel-clients.json")
            .await
            .unwrap()
            .unwrap(),
        b"{}"
    );
    store.put("oidc-key.json", b"{\"kid\":2}").await.unwrap();
    assert_eq!(
        store.get("oidc-key.json").await.unwrap().unwrap(),
        b"{\"kid\":2}"
    );
    let raw = api.secrets.lock()["tsidp/tsidp-state"]["data"]["oidc-key.json"].clone();
    assert_eq!(raw, "eyJraWQiOjJ9", "stored base64 as Kubernetes expects");
}

#[tokio::test]
async fn put_on_missing_secret_creates_it_and_namespace_override_wins() {
    let api = MockKubeApi::start().await;
    let store =
        KubeSecretStore::new(&api.url, &api.sa_dir, "other", Some("custom".into())).unwrap();
    store.put("k", b"v").await.unwrap();
    assert!(api.secrets.lock().contains_key("custom/other"));
    assert_eq!(store.get("k").await.unwrap().unwrap(), b"v");
}

#[tokio::test]
async fn api_errors_surface() {
    let api = MockKubeApi::start().await;
    let store = KubeSecretStore::new(&api.url, &api.sa_dir, "tsidp-state", None).unwrap();
    *api.fail_next.lock() = Some(500);
    let err = store.get("x").await.unwrap_err();
    assert!(err.to_string().contains("500"), "{err}");
    *api.fail_next.lock() = Some(403);
    let err = store.check_writable().await.unwrap_err();
    assert!(err.to_string().contains("403"), "{err}");

    // A bad token is rejected by the API server.
    std::fs::write(api.sa_dir.join("token"), "wrong").unwrap();
    let err = store.get("x").await.unwrap_err();
    assert!(err.to_string().contains("401"), "{err}");

    // Missing namespace file without an override.
    let dir = tempfile::tempdir().unwrap();
    let err = KubeSecretStore::new(&api.url, dir.path(), "s", None).unwrap_err();
    assert!(err.to_string().contains("namespace"), "{err}");
    // https endpoint needs a CA
    let err = KubeSecretStore::new("https://10.0.0.1:443", dir.path(), "s", Some("ns".into()))
        .unwrap_err();
    assert!(err.to_string().contains("CA"), "{err}");

    let unreachable = KubeSecretStore::new("http://127.0.0.1:1", &api.sa_dir, "s", None).unwrap();
    assert!(unreachable.get("x").await.is_err());
}
