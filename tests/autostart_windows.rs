#![cfg(windows)]
//! Exercise the GUI executable's background entry point without changing Windows startup settings.
use krot::{
    background::Client,
    config::{Config, Store},
};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn gui_background_starts_without_console_from_an_unrelated_directory() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let store = Store::new(temp.path().join("КРОТ startup").join("config.json"))?;
    store.save(&Config::default())?;
    let original = std::fs::read(&store.path)?;
    let system =
        PathBuf::from(std::env::var_os("SystemRoot").expect("Windows directory")).join("System32");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_krot"))
        .arg("--config")
        .arg(&store.path)
        .arg("serve")
        .current_dir(system)
        .creation_flags(0x0800_0000 | 0x0000_0200)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let client = Client::new(&store);
    let snapshot = timeout(Duration::from_secs(10), async {
        loop {
            anyhow::ensure!(
                child.try_wait()?.is_none(),
                "Background exited before it was ready"
            );
            if let Ok(snapshot) = client.snapshot().await {
                break Ok::<_, anyhow::Error>(snapshot);
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    assert_eq!(snapshot.version.as_deref(), Some(env!("CARGO_PKG_VERSION")));
    assert!(snapshot.config.tunnels.is_empty());
    assert!(child.try_wait()?.is_none());
    client.request("shutdown", serde_json::Value::Null).await?;
    assert!(
        timeout(Duration::from_secs(8), child.wait())
            .await??
            .success()
    );
    assert!(!store.sidecar(".background.json").exists());
    assert_eq!(std::fs::read(&store.path)?, original);
    Ok(())
}
