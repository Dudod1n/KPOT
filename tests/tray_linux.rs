#![cfg(target_os = "linux")]
//! Run only on an isolated session bus; never replace the user's tray host.
use krot::{
    background::Client,
    config::{Config, Store, Tunnel},
};
use std::{collections::HashMap, time::Duration};
use tokio::time::{sleep, timeout};
use zbus::{
    Proxy,
    proxy::CacheProperties,
    zvariant::{OwnedValue, Structure, Value},
};

type Layout = (i32, HashMap<String, OwnedValue>, Vec<OwnedValue>);
struct Watcher(tokio::sync::mpsc::UnboundedSender<String>);
#[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
impl Watcher {
    fn register_status_notifier_item(&self, service: String) {
        let _ = self.0.send(service);
    }
    #[zbus(property)]
    fn is_status_notifier_host_registered(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn registered_status_notifier_items(&self) -> Vec<String> {
        Vec::new()
    }
    #[zbus(property)]
    fn protocol_version(&self) -> i32 {
        0
    }
}

async fn menu_items(menu: &Proxy<'_>) -> anyhow::Result<Vec<(i32, String)>> {
    let (_, (_, _, children)): (u32, Layout) = menu
        .call("GetLayout", &(0i32, -1i32, Vec::<String>::new()))
        .await?;
    let mut items = Vec::new();
    for child in children {
        let mut fields = Structure::try_from(child)?.into_fields();
        let id: i32 = fields.remove(0).downcast()?;
        let props: HashMap<String, OwnedValue> = fields.remove(0).downcast()?;
        if let Some(label) = props.get("label") {
            items.push((id, <&str>::try_from(label)?.to_owned()));
        }
    }
    Ok(items)
}

#[tokio::test]
#[ignore = "dbus-run-session -- cargo test --test tray_linux -- --ignored"]
async fn daemon_registers_tray_updates_opens_existing_window_and_stops() -> anyhow::Result<()> {
    let (tx, mut registered) = tokio::sync::mpsc::unbounded_channel();
    let connection = zbus::connection::Builder::session()?
        .name("org.kde.StatusNotifierWatcher")?
        .serve_at("/StatusNotifierWatcher", Watcher(tx))?
        .build()
        .await?;
    let temp = tempfile::tempdir()?;
    let store = Store::new(temp.path().join("tray.json"))?;
    store.save(&Config::default())?;
    let client = Client::new(&store);
    let mut daemon = tokio::process::Command::new(env!("CARGO_BIN_EXE_krot-cli"))
        .arg("--config")
        .arg(&store.path)
        .arg("serve")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;
    let name = timeout(Duration::from_secs(10), registered.recv())
        .await?
        .expect("tray registered");
    let tray = zbus::proxy::Builder::<Proxy<'_>>::new(&connection)
        .destination(name.as_str())?
        .path("/StatusNotifierItem")?
        .interface("org.kde.StatusNotifierItem")?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    assert_eq!(tray.get_property::<String>("Title").await?, "КРОТ");
    let pixels: Vec<(i32, i32, Vec<u8>)> = tray.get_property("IconPixmap").await?;
    assert_eq!(
        (pixels[0].0, pixels[0].1, pixels[0].2.len()),
        (32, 32, 32 * 32 * 4)
    );
    let menu = Proxy::new(
        &connection,
        name.as_str(),
        "/MenuBar",
        "com.canonical.dbusmenu",
    )
    .await?;
    let items = menu_items(&menu).await?;
    let open = items
        .iter()
        .find(|(_, label)| label == "Открыть КРОТ")
        .unwrap()
        .0;
    let stop = items
        .iter()
        .find(|(_, label)| label == "Остановить КРОТ")
        .unwrap()
        .0;
    let _ui_lease = Store::new(store.sidecar(".ui"))?.lock()?;
    for (count, by_menu) in [(1, false), (2, true)] {
        if by_menu {
            menu.call::<_, _, ()>("Event", &(open, "clicked", Value::from(0i32), 0u32))
                .await?;
        } else {
            tray.call::<_, _, ()>("Activate", &(0i32, 0i32)).await?;
        }
        timeout(Duration::from_secs(5), async {
            loop {
                if client.snapshot().await.unwrap().activation == count {
                    break;
                }
                sleep(Duration::from_millis(30)).await;
            }
        })
        .await?;
    }
    // A closed loopback port produces a deterministic SSH error without external access.
    let free = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = free.local_addr()?.port();
    drop(free);
    let mut tunnel = Tunnel {
        name: "Tray test".into(),
        enabled: true,
        reconnect: false,
        ..Tunnel::default()
    };
    tunnel.server.host = "127.0.0.1".into();
    tunnel.server.port = port;
    tunnel.server.user = "demo".into();
    tunnel.target = "127.0.0.1".into();
    let config = Config {
        tunnels: vec![tunnel],
        ..Config::default()
    };
    client
        .request("save", serde_json::to_value(config)?)
        .await?;
    timeout(Duration::from_secs(10), async {
        loop {
            let items = menu_items(&menu).await.unwrap();
            if items.iter().any(|(_, label)| label.contains("ошибок: 1")) {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    let pixels: Vec<(i32, i32, Vec<u8>)> = tray.get_property("IconPixmap").await?;
    let offset = (26 * 32 + 26) * 4;
    assert_eq!(&pixels[0].2[offset..offset + 4], &[255, 255, 155, 145]); // Network byte order ARGB.
    let before = client.snapshot().await?;
    menu.call::<_, _, ()>("Event", &(stop, "clicked", Value::from(0i32), 0u32))
        .await?;
    assert!(
        timeout(Duration::from_secs(8), daemon.wait())
            .await??
            .success()
    );
    assert!(!store.sidecar(".background.json").exists());
    assert_eq!(
        serde_json::to_value(store.load()?)?,
        serde_json::to_value(before.config)?
    );
    assert!(tray.get_property::<String>("Title").await.is_err());
    Ok(())
}
