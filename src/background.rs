//! One owner per configuration; the desktop talks to it over authenticated loopback JSON.
use std::{
    collections::HashMap,
    fs::File,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    config::{Config, Store, atomic_json},
    ssh::{Manager, PendingPrompt, Runtime},
};

const MAX_MESSAGE: usize = 8 * 1024 * 1024;
const AUTH_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONFIG_CHANGED: &str = "Конфигурация изменилась. Обновите состояние и повторите сохранение.";

#[derive(Debug)]
struct StaleConfig;

impl std::fmt::Display for StaleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(CONFIG_CHANGED)
    }
}

impl std::error::Error for StaleConfig {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckedSave {
    before: Config,
    config: Config,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub version: Option<String>,
    pub config: Config,
    pub runtimes: HashMap<String, Runtime>,
    pub prompts: HashMap<String, PendingPrompt>,
    #[serde(default)]
    pub activation: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    port: u16,
    token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Owner(Metadata);

pub(crate) fn observe_owner(store: &Store) -> Result<Option<Owner>> {
    let stream = match std::fs::File::open(store.sidecar(".background.json")) {
        Ok(stream) => stream,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(stream, 4097), &mut raw)?;
    ensure!(raw.len() <= 4096, "Некорректный адрес фонового процесса.");
    let metadata: Metadata = serde_json::from_slice(&raw)?;
    metadata.validate()?;
    Ok(Some(Owner(metadata)))
}

impl Metadata {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.port != 0 && hex_token(&self.token),
            "Некорректный адрес фонового процесса."
        );
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    nonce: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    proof: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    token: String,
    command: String,
    #[serde(default)]
    payload: Value,
}

fn hex_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn proof(token: &str, nonce: &str) -> Hmac<Sha256> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(token.as_bytes()).expect("HMAC accepts any key size");
    mac.update(nonce.as_bytes());
    mac
}

async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    (&mut *reader)
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut data)
        .await?;
    ensure!(
        data.len() <= limit && data.last() == Some(&b'\n'),
        "Неверный размер или незавершённое сообщение."
    );
    Ok(data)
}

fn scrub_answer(command: &str, payload: &mut Value) {
    if command == "answer"
        && let Some(Value::String(secret)) = payload.get_mut("value")
    {
        secret.zeroize();
    }
}

#[derive(Clone)]
pub struct Client {
    pub path: PathBuf,
}

impl Client {
    pub fn new(store: &Store) -> Self {
        Self {
            path: store.path.clone(),
        }
    }

    pub async fn snapshot(&self) -> Result<Snapshot> {
        serde_json::from_value(self.request("snapshot", Value::Null).await?)
            .context("Некорректное состояние КРОТ.")
    }

    pub async fn request(&self, command: &str, payload: Value) -> Result<Value> {
        timeout(REQUEST_TIMEOUT, self.request_inner(command, payload, None))
            .await
            .context("Фоновый КРОТ не ответил вовремя.")?
    }

    async fn request_inner(
        &self,
        command: &str,
        mut payload: Value,
        owner: Option<&Owner>,
    ) -> Result<Value> {
        let store = Store::new(&self.path)?;
        let mut raw = Vec::new();
        tokio::fs::File::open(store.sidecar(".background.json"))
            .await?
            .take(4097)
            .read_to_end(&mut raw)
            .await?;
        ensure!(raw.len() <= 4096, "Некорректный адрес фонового процесса.");
        let metadata: Metadata =
            serde_json::from_slice(&raw).context("Некорректный адрес фонового процесса.")?;
        metadata.validate()?;
        ensure!(
            owner.is_none_or(|owner| owner.0 == metadata),
            "Предыдущий КРОТ уже сменился. Проверьте новый процесс и повторите выбор."
        );
        let mut stream = timeout(
            AUTH_TIMEOUT,
            TcpStream::connect(("127.0.0.1", metadata.port)),
        )
        .await??;
        let nonce = hex::encode(rand::random::<[u8; 32]>());
        let challenge = serde_json::to_vec(&json!({"nonce":nonce}))?;
        let mut reader = BufReader::new(&mut stream);
        timeout(AUTH_TIMEOUT, async {
            reader.get_mut().write_all(&challenge).await?;
            reader.get_mut().write_all(b"\n").await?;
            let answer: Proof = serde_json::from_slice(&read_line(&mut reader, 4096).await?)?;
            ensure!(
                hex_token(&answer.proof),
                "Не удалось подтвердить фоновый процесс КРОТ."
            );
            proof(&metadata.token, &nonce)
                .verify_slice(&hex::decode(answer.proof)?)
                .map_err(|_| anyhow::anyhow!("Не удалось подтвердить фоновый процесс КРОТ."))?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        let mut request = Request {
            token: metadata.token,
            command: command.to_owned(),
            payload: std::mem::take(&mut payload),
        };
        let encoded = serde_json::to_vec(&request);
        scrub_answer(command, &mut request.payload);
        let mut encoded = Zeroizing::new(encoded?);
        ensure!(
            encoded.len() < MAX_MESSAGE,
            "Запрос превышает допустимый размер."
        );
        encoded.push(b'\n');
        reader.get_mut().write_all(&encoded).await?;
        encoded.zeroize();
        let response: Value = serde_json::from_slice(&read_line(&mut reader, MAX_MESSAGE).await?)?;
        match response.get("ok").and_then(Value::as_bool) {
            Some(true)
                if response.as_object().is_some_and(|o| o.len() == 2)
                    && response.get("value").is_some() =>
            {
                Ok(response["value"].clone())
            }
            Some(false) if response.as_object().is_some_and(|o| o.len() == 2) => {
                let message = response
                    .get("error")
                    .and_then(Value::as_str)
                    .filter(|s| s.len() <= 4096)
                    .context("Некорректный ответ фонового процесса.")?;
                bail!("{message}")
            }
            _ => bail!("Некорректный ответ фонового процесса."),
        }
    }
}

pub(crate) fn try_lease(store: &Store) -> Result<Option<File>> {
    match store.lock() {
        Ok(lease) => Ok(Some(lease)),
        Err(error)
            if error.downcast_ref::<std::io::Error>().is_some_and(|cause| {
                cause.raw_os_error() == fs2::lock_contended_error().raw_os_error()
            }) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Stop only the authenticated owner, then wait for both the daemon and its window.
pub async fn stop_and_wait(store: &Store) -> Result<()> {
    let owner = if try_lease(store)?.is_none() {
        observe_owner(store)?
    } else {
        None
    };
    stop_selected_and_wait(store, owner.as_ref()).await
}

pub(crate) async fn stop_selected_and_wait(store: &Store, owner: Option<&Owner>) -> Result<()> {
    if try_lease(store)?.is_none() {
        let owner = owner.context(
            "Владелец конфигурации сменился или недоступен. Повторите выбор предыдущего КРОТа.",
        )?;
        timeout(
            REQUEST_TIMEOUT,
            Client::new(store).request_inner("shutdown", Value::Null, Some(owner)),
        )
        .await
        .context("Фоновый КРОТ не ответил вовремя.")?
        .context(
            "Не удалось штатно завершить предыдущий КРОТ. Процессы не остановлены принудительно.",
        )?;
    }
    let ui = Store::new(store.sidecar(".ui"))?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(_daemon) = try_lease(store)?
            && let Some(_window) = try_lease(&ui)?
        {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "Предыдущий КРОТ ещё завершает работу. Дождитесь закрытия его окна и повторите запуск."
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn ensure_running(store: &Store) -> Result<Client> {
    let guard = crate::update::startup_guard().await?;
    let client = Client::new(store);
    if timeout(Duration::from_millis(300), client.snapshot())
        .await
        .is_ok_and(|r| r.is_ok())
    {
        return Ok(client);
    }
    store.load()?;
    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    command
        .arg("--config")
        .arg(&store.path)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        command.creation_flags(0x0800_0000 | 0x0000_0200);
    }
    let mut child = command
        .spawn()
        .context("Не удалось запустить фоновый КРОТ.")?;
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    drop(guard);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if timeout(Duration::from_millis(300), client.snapshot())
            .await
            .is_ok_and(|r| r.is_ok())
        {
            return Ok(client);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if store.lock().is_err() {
        bail!(
            "Конфигурация занята другим экземпляром КРОТ. Остановите прежний процесс и повторите запуск."
        );
    }
    bail!("Не удалось запустить фоновый КРОТ. Проверьте конфигурацию и права доступа.")
}

struct Owned {
    config: Config,
    manager: Manager,
}

struct Service {
    store: Store,
    token: String,
    owned: Mutex<Owned>,
    shutdown: CancellationToken,
    closed: CancellationToken,
    activation: AtomicU64,
}

impl Service {
    async fn execute(&self, command: &str, payload: Value) -> Result<Value> {
        ensure!(
            !self.shutdown.is_cancelled(),
            "Фоновый КРОТ завершает работу."
        );
        let mut owned = self.owned.lock().await;
        match command {
            "snapshot" if payload.is_null() => {
                let (runtimes, prompts) = owned.manager.snapshot().await;
                Ok(serde_json::to_value(Snapshot {
                    version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                    config: owned.config.clone(),
                    runtimes,
                    prompts,
                    activation: self.activation.load(Ordering::Relaxed),
                })?)
            }
            "activate" if payload.is_null() => {
                self.activation.fetch_add(1, Ordering::Relaxed);
                Ok(Value::Null)
            }
            "save" | "save_checked" => {
                let next = if command == "save_checked" {
                    let update: CheckedSave =
                        serde_json::from_value(payload).context("Некорректная конфигурация.")?;
                    if update.before != owned.config {
                        return Err(StaleConfig.into());
                    }
                    update.config
                } else {
                    serde_json::from_value::<Config>(payload)
                        .context("Некорректная конфигурация.")?
                };
                next.validate()?;
                self.store.save(&next)?;
                let next = self.store.load()?;
                let changed: Vec<_> = owned
                    .config
                    .tunnels
                    .iter()
                    .filter(|old| !next.tunnels.iter().any(|new| *old == new))
                    .map(|t| t.id.clone())
                    .collect();
                for id in &changed {
                    owned.manager.stop(id).await?;
                }
                for t in &next.tunnels {
                    if t.enabled && (!owned.config.tunnels.iter().any(|old| old == t)) {
                        owned.manager.start(t.clone()).await?;
                    }
                }
                owned.config = next;
                Ok(Value::Null)
            }
            "start" | "stop" => {
                let id = payload
                    .as_str()
                    .context("Укажите ID сохранённого туннеля.")?;
                let index = owned
                    .config
                    .tunnels
                    .iter()
                    .position(|t| t.id == id)
                    .context("Сохранённый туннель не найден.")?;
                let mut next = owned.config.clone();
                next.tunnels[index].enabled = command == "start";
                self.store.save(&next)?;
                owned.config = next;
                if command == "start" {
                    owned
                        .manager
                        .start(owned.config.tunnels[index].clone())
                        .await?;
                } else {
                    owned.manager.stop(id).await?;
                }
                Ok(Value::Null)
            }
            "answer" => {
                let mut payload = payload;
                ensure!(
                    payload.as_object().is_some_and(|o| o.len() == 2),
                    "Некорректный ответ на запрос подключения."
                );
                let id = payload
                    .get("id")
                    .and_then(Value::as_str)
                    .context("Укажите ID запроса подключения.")?
                    .to_owned();
                let value = payload
                    .get_mut("value")
                    .map(std::mem::take)
                    .context("Укажите ответ на запрос подключения.")?;
                owned.manager.answer(&id, value).await?;
                Ok(Value::Null)
            }
            "shutdown" if payload.is_null() => {
                self.shutdown.cancel();
                Ok(Value::Null)
            }
            _ => bail!("Неизвестная команда или неверные параметры фонового процесса."),
        }
    }

    async fn handle(&self, stream: TcpStream) -> Result<()> {
        let mut reader = BufReader::new(stream);
        let request = timeout(AUTH_TIMEOUT, async {
            let challenge: Challenge = serde_json::from_slice(&read_line(&mut reader, 4096).await?)?;
            ensure!(hex_token(&challenge.nonce), "Некорректный запрос подтверждения.");
            let answer = json!({"proof":hex::encode(proof(&self.token, &challenge.nonce).finalize().into_bytes())});
            reader.get_mut().write_all(&serde_json::to_vec(&answer)?).await?;
            reader.get_mut().write_all(b"\n").await?;
            let request: Request = serde_json::from_slice(&read_line(&mut reader, MAX_MESSAGE).await?)?;
            ensure!(hex_token(&request.token) && bool::from(request.token.as_bytes().ct_eq(self.token.as_bytes())), "Не удалось подтвердить доступ.");
            Ok::<_, anyhow::Error>(request)
        }).await;
        let (response, shutdown) = match request {
            Ok(Ok(mut request)) => {
                let shutdown = request.command == "shutdown" && request.payload.is_null();
                let payload = std::mem::take(&mut request.payload);
                let result = self.execute(&request.command, payload).await;
                // Only locally authored messages leave this boundary, never serde/SSH/OS details.
                let response = match result {
                    Ok(value) => json!({"ok":true,"value":value}),
                    Err(error) if error.is::<StaleConfig>() => {
                        json!({"ok":false,"error":CONFIG_CHANGED})
                    }
                    Err(_) => {
                        json!({"ok":false,"error":"Не удалось выполнить команду. Проверьте данные и обновите состояние КРОТ."})
                    }
                };
                (response, shutdown)
            }
            _ => (
                json!({"ok":false,"error":"Некорректный запрос или доступ к фоновому процессу."}),
                false,
            ),
        };
        if shutdown {
            self.closed.cancelled().await;
        }
        let mut encoded = serde_json::to_vec(&response)?;
        if encoded.len() >= MAX_MESSAGE {
            encoded = serde_json::to_vec(
                &json!({"ok":false,"error":"Ответ превышает допустимый размер."}),
            )?;
        }
        encoded.push(b'\n');
        timeout(AUTH_TIMEOUT, reader.get_mut().write_all(&encoded)).await??;
        Ok(())
    }
}

pub async fn serve(store: Store) -> Result<()> {
    let guard = crate::update::startup_guard().await?;
    let _lease: File = store.lock()?;
    let config = store.load()?;
    let manager = Manager::new(store.known_hosts_path());
    let service = Arc::new(Service {
        store: store.clone(),
        token: hex::encode(rand::random::<[u8; 32]>()),
        owned: Mutex::new(Owned {
            config: config.clone(),
            manager: manager.clone(),
        }),
        shutdown: CancellationToken::new(),
        closed: CancellationToken::new(),
        activation: AtomicU64::new(0),
    });
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let metadata = Metadata {
        port: listener.local_addr()?.port(),
        token: service.token.clone(),
    };
    let endpoint = store.sidecar(".background.json");
    atomic_json(&endpoint, &metadata, Some(4096))?;
    drop(guard);
    for tunnel in config.tunnels {
        if tunnel.enabled {
            manager.start(tunnel).await?;
        }
    }
    let permits = Arc::new(Semaphore::new(64));
    let mut handlers = JoinSet::new();
    let (tray, mut tray_actions) = crate::tray::Tray::start(service.shutdown.child_token());
    let mut tray_poll = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = service.shutdown.cancelled() => break,
            _ = tokio::signal::ctrl_c() => { service.shutdown.cancel(); break; },
            Some(_) = handlers.join_next(), if !handlers.is_empty() => {},
            Some(action) = tray_actions.recv() => match action {
                crate::tray::Action::Open => {
                    if crate::app::open_desktop(&store).await.is_err() {
                        eprintln!("КРОТ: не удалось открыть окно из трея.");
                    }
                }
                crate::tray::Action::Stop => { service.shutdown.cancel(); break; }
            },
            _ = tray_poll.tick() => {
                let owned = service.owned.lock().await;
                let (runtimes, prompts) = owned.manager.snapshot().await;
                tray.update(crate::tray::Status::from_snapshot(&Snapshot {
                    version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                    config:owned.config.clone(),runtimes,prompts,
                    activation:service.activation.load(Ordering::Relaxed),
                }));
            },
            accepted = listener.accept() => {
                let (stream,_) = accepted?;
                if let Ok(permit) = permits.clone().try_acquire_owned() {
                    let service = service.clone();
                    handlers.spawn(async move { let _permit = permit; let _ = service.handle(stream).await; });
                }
            }
        }
    }
    drop(listener);
    let result = manager.close().await;
    tray.close().await;
    if std::fs::read(&endpoint)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Metadata>(&bytes).ok())
        .is_some_and(|m| m.token == service.token)
    {
        let _ = std::fs::remove_file(endpoint);
    }
    service.closed.cancel();
    if timeout(Duration::from_secs(3), async {
        while handlers.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        handlers.abort_all();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_and_messages_are_strict() {
        for invalid in ["", "a", &"g".repeat(64), &"A".repeat(64)] {
            assert!(!hex_token(invalid));
        }
        assert!(hex_token(&"a0".repeat(32)));
        assert!(
            serde_json::from_value::<Metadata>(json!({"port":0,"token":"a".repeat(64)}))
                .unwrap()
                .validate()
                .is_err()
        );
        assert!(
            serde_json::from_value::<Metadata>(json!({"port":22,"token":"a".repeat(64),"extra":0}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<Request>(json!({"token":0,"command":"shutdown"})).is_err()
        );
        assert!(
            serde_json::from_value::<Request>(
                json!({"token":"a".repeat(64),"command":"shutdown","extra":true})
            )
            .is_err()
        );
    }

    #[test]
    fn proof_pins_server_and_challenge() {
        let tag = proof("token", "nonce").finalize().into_bytes();
        assert!(proof("token", "nonce").verify_slice(&tag).is_ok());
        assert!(proof("wrong", "nonce").verify_slice(&tag).is_err());
        assert!(proof("token", "replayed").verify_slice(&tag).is_err());
        let mut answer = json!({"id":"request","value":"private-secret"});
        scrub_answer("answer", &mut answer);
        assert_eq!(answer["value"], "");
    }

    #[tokio::test]
    async fn framing_rejects_oversized_and_unterminated_input() {
        for data in [b"123456\n".as_slice(), b"abc".as_slice()] {
            let mut input = BufReader::new(data);
            assert!(read_line(&mut input, 4).await.is_err());
        }
        let mut input = BufReader::new(b"ok\nnext\n".as_slice());
        assert_eq!(&**read_line(&mut input, 4).await.unwrap(), b"ok\n");
        assert_eq!(&**read_line(&mut input, 8).await.unwrap(), b"next\n");
    }
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    #[tokio::test]
    async fn stop_waits_for_the_old_window_after_daemon_is_gone() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let ui = Store::new(store.sidecar(".ui")).unwrap().lock().unwrap();
        let waiting = tokio::spawn({
            let store = store.clone();
            async move { stop_and_wait(&store).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !waiting.is_finished(),
            "the old window still owns its lease"
        );
        drop(ui);
        waiting.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn unauthenticated_owner_is_left_running() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let owner = store.lock().unwrap();
        assert!(stop_and_wait(&store).await.is_err());
        assert!(
            store.lock().is_err(),
            "an unknown owner must keep its lease"
        );
        drop(owner);
    }

    #[test]
    fn old_snapshot_without_version_still_loads() {
        let snapshot: Snapshot = serde_json::from_value(json!({
            "config": Config::default(), "runtimes": {}, "prompts": {}
        }))
        .unwrap();
        assert!(snapshot.version.is_none());
        assert_eq!(snapshot.activation, 0);
    }

    #[tokio::test]
    async fn authenticated_stop_releases_the_daemon_before_returning() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let daemon = tokio::spawn(serve(store.clone()));
        let client = Client::new(&store);
        timeout(Duration::from_secs(3), async {
            while client.snapshot().await.is_err() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        stop_and_wait(&store).await.unwrap();
        assert!(store.lock().is_ok());
        daemon.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_old_replacement_choice_cannot_stop_a_new_owner() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let client = Client::new(&store);
        let first = tokio::spawn(serve(store.clone()));
        timeout(Duration::from_secs(3), async {
            while client.snapshot().await.is_err() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let previous = observe_owner(&store).unwrap();
        stop_and_wait(&store).await.unwrap();
        first.await.unwrap().unwrap();
        let second = tokio::spawn(serve(store.clone()));
        timeout(Duration::from_secs(3), async {
            while client.snapshot().await.is_err() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            stop_selected_and_wait(&store, previous.as_ref())
                .await
                .is_err()
        );
        assert!(
            client.snapshot().await.is_ok(),
            "a fresh owner needs a fresh replacement choice"
        );
        stop_and_wait(&store).await.unwrap();
        second.await.unwrap().unwrap();
    }
}
