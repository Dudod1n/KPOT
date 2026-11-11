//! One owner per configuration; the desktop talks to it over authenticated loopback JSON.
use std::{
    collections::{HashMap, HashSet},
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
    apps::{AppRule, AppRuntime, Apps, DivertReport, DivertStats, Interceptor},
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
    #[serde(default)]
    pub apps: Vec<AppRule>,
    #[serde(default)]
    pub app_runtimes: HashMap<String, AppRuntime>,
    /// Why application traffic cannot be intercepted; empty when it can.
    #[serde(default)]
    pub apps_unavailable: String,
    /// The elevated helper is running and intercepts traffic.
    #[serde(default)]
    pub divert_attached: bool,
    /// Why the helper last failed to start.
    #[serde(default)]
    pub divert_error: String,
    /// The user's UDP choices: relay consent per tunnel, QUIC per rule.
    #[serde(default)]
    pub udp: crate::udp::consent::UdpSettings,
    /// Why the UDP settings file could not be read; UDP stays off meanwhile.
    #[serde(default)]
    pub udp_error: String,
    #[serde(default)]
    pub udp_runtimes: HashMap<String, crate::ssh::UdpRuntime>,
    #[serde(default)]
    pub udp_metrics: HashMap<String, crate::udp::transport::TransportMetrics>,
    /// Background-side routing metrics per tunnel.
    #[serde(default)]
    pub udp_routing: HashMap<String, crate::udp::router::TunnelRouting>,
    /// UDP traffic per rule through the tunnel.
    #[serde(default)]
    pub udp_rules: HashMap<String, crate::udp::router::RuleMetrics>,
    /// The helper's part of each rule's UDP path, while it is attached.
    #[serde(default)]
    pub udp_helper: HashMap<String, crate::divert::link::HelperUdpStats>,
}

const DIVERT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_APP_LOGS: usize = 200;

/// The last word from the elevated helper and what it has reported so far.
#[derive(Default)]
struct Divert {
    seen: Option<Instant>,
    stats: HashMap<String, DivertStats>,
    udp: HashMap<String, crate::divert::link::HelperUdpStats>,
    logs: HashMap<String, Vec<String>>,
    error: String,
}

impl Divert {
    fn attached(&self) -> bool {
        self.seen
            .is_some_and(|seen| seen.elapsed() < DIVERT_TIMEOUT)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckedApps {
    before: Vec<AppRule>,
    rules: Vec<AppRule>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    port: u16,
    token: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Owner(Metadata);

/// Shared by the client and the owner check, so both read the address the same way.
fn read_metadata(store: &Store) -> Result<Option<Metadata>> {
    let stream = match std::fs::File::open(store.sidecar(".background.json")) {
        Ok(stream) => stream,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(stream, 4097), &mut raw)?;
    ensure!(raw.len() <= 4096, "Некорректный адрес фонового процесса.");
    let metadata: Metadata =
        serde_json::from_slice(&raw).context("Некорректный адрес фонового процесса.")?;
    metadata.validate()?;
    Ok(Some(metadata))
}

pub(crate) fn observe_owner(store: &Store) -> Result<Option<Owner>> {
    Ok(read_metadata(store)?.map(Owner))
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

/// Test helper: waits up to 3 s until the daemon answers.
#[cfg(test)]
pub(crate) async fn wait_until_serving(client: &Client) {
    timeout(Duration::from_secs(3), async {
        while client.snapshot().await.is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the daemon did not start");
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

    /// Opens the helper's binary UDP channel: an authenticated request whose connection then
    /// carries frames in both directions.
    pub async fn attach_udp(&self) -> Result<BufReader<TcpStream>> {
        let version = json!({"version": krot_udp_proto::VERSION});
        let (value, stream) = timeout(
            REQUEST_TIMEOUT,
            self.exchange("udp_attach", version.clone(), None),
        )
        .await
        .context("Фоновый КРОТ не ответил вовремя.")??;
        ensure!(value == version, "Фоновый КРОТ другой версии.");
        Ok(stream)
    }

    async fn request_inner(
        &self,
        command: &str,
        payload: Value,
        owner: Option<&Owner>,
    ) -> Result<Value> {
        Ok(self.exchange(command, payload, owner).await?.0)
    }

    async fn exchange(
        &self,
        command: &str,
        mut payload: Value,
        owner: Option<&Owner>,
    ) -> Result<(Value, BufReader<TcpStream>)> {
        let metadata =
            read_metadata(&Store::new(&self.path)?)?.context("Фоновый КРОТ не запущен.")?;
        ensure!(
            owner.is_none_or(|owner| owner.0 == metadata),
            "Предыдущий КРОТ уже сменился. Проверьте новый процесс и повторите выбор."
        );
        let stream = timeout(
            AUTH_TIMEOUT,
            TcpStream::connect(("127.0.0.1", metadata.port)),
        )
        .await??;
        stream.set_nodelay(true)?;
        let nonce = hex::encode(rand::random::<[u8; 32]>());
        let challenge = serde_json::to_vec(&json!({"nonce":nonce}))?;
        let mut reader = BufReader::new(stream);
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
                Ok((response["value"].clone(), reader))
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
    // The elevated helper runs the old executable until it notices the daemon is gone.
    let divert = Store::new(store.sidecar(".divert"))?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(_daemon) = try_lease(store)?
            && let Some(_window) = try_lease(&ui)?
            && let Some(_helper) = try_lease(&divert)?
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
    apps: Apps,
    divert: Divert,
    manager: Manager,
    udp: crate::udp::consent::UdpSettings,
    udp_error: String,
}

const UDP_BROKEN: &str = "Файл настроек UDP повреждён. Исправьте или удалите его, затем повторите.";

impl Owned {
    /// SOCKS tunnels whose user agreed to the relay.
    fn udp_tunnels(&self) -> HashSet<String> {
        self.config
            .tunnels
            .iter()
            .filter(|tunnel| tunnel.kind == "D" && self.udp.tunnel_enabled(&tunnel.id))
            .map(|tunnel| tunnel.id.clone())
            .collect()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UdpTunnelChoice {
    id: String,
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UdpRuleChoice {
    id: String,
    quic: bool,
}

struct Service {
    store: Store,
    token: String,
    router: Arc<crate::udp::router::Router>,
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
                let states = runtimes
                    .iter()
                    .map(|(id, runtime)| (id.clone(), runtime.state.clone()))
                    .collect();
                let unavailable = crate::apps::unavailable();
                let attached = owned.divert.attached();
                let interceptor = if attached {
                    Interceptor::Attached
                } else if unavailable.is_empty() {
                    Interceptor::Detached
                } else {
                    Interceptor::Unavailable
                };
                let app_runtimes = owned
                    .apps
                    .rules
                    .iter()
                    .map(|rule| {
                        let state =
                            crate::apps::state(rule, &owned.config.tunnels, &states, interceptor);
                        let stats = owned
                            .divert
                            .stats
                            .get(&rule.id)
                            .filter(|_| attached)
                            .cloned()
                            .unwrap_or_default();
                        (
                            rule.id.clone(),
                            AppRuntime {
                                state: state.into(),
                                connections: stats.connections,
                                total: stats.total,
                                sent: stats.sent,
                                received: stats.received,
                                logs: owned.divert.logs.get(&rule.id).cloned().unwrap_or_default(),
                            },
                        )
                    })
                    .collect();
                let mut udp_runtimes = HashMap::new();
                let mut udp_metrics = HashMap::new();
                for (id, (runtime, metrics)) in owned.manager.udp_snapshot().await {
                    if let Some(metrics) = metrics {
                        udp_metrics.insert(id.clone(), metrics);
                    }
                    udp_runtimes.insert(id, runtime);
                }
                Ok(serde_json::to_value(Snapshot {
                    udp_routing: self.router.tunnel_metrics(),
                    udp_rules: self.router.rule_metrics(),
                    udp_helper: if attached {
                        owned.divert.udp.clone()
                    } else {
                        HashMap::new()
                    },
                    udp: owned.udp.clone(),
                    udp_error: owned.udp_error.clone(),
                    udp_runtimes,
                    udp_metrics,
                    apps: owned.apps.rules.clone(),
                    app_runtimes,
                    apps_unavailable: unavailable.into(),
                    divert_attached: attached,
                    divert_error: owned.divert.error.clone(),
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
                let udp = owned.udp_tunnels();
                owned.manager.set_udp(udp).await;
                Ok(Value::Null)
            }
            "udp_tunnel" => {
                let choice: UdpTunnelChoice =
                    serde_json::from_value(payload).context("Некорректный выбор UDP.")?;
                ensure!(owned.udp_error.is_empty(), UDP_BROKEN);
                ensure!(
                    owned
                        .config
                        .tunnels
                        .iter()
                        .any(|tunnel| tunnel.id == choice.id && tunnel.kind == "D"),
                    "UDP через сервер доступен только для сохранённого туннеля типа D."
                );
                let mut next = owned.udp.clone();
                next.tunnels.insert(
                    choice.id,
                    crate::udp::consent::TunnelUdp {
                        enabled: choice.enabled,
                    },
                );
                next.retain_known(
                    owned.config.tunnels.iter().map(|tunnel| tunnel.id.as_str()),
                    owned.apps.rules.iter().map(|rule| rule.id.as_str()),
                );
                crate::udp::consent::save(&self.store, &next)?;
                owned.udp = next;
                let udp = owned.udp_tunnels();
                owned.manager.set_udp(udp).await;
                Ok(Value::Null)
            }
            "udp_rule" => {
                let choice: UdpRuleChoice =
                    serde_json::from_value(payload).context("Некорректный выбор UDP.")?;
                ensure!(owned.udp_error.is_empty(), UDP_BROKEN);
                ensure!(
                    owned.apps.rules.iter().any(|rule| rule.id == choice.id),
                    "Сохранённое правило не найдено."
                );
                let mut next = owned.udp.clone();
                next.rules.insert(
                    choice.id,
                    crate::udp::consent::RuleUdp { quic: choice.quic },
                );
                next.retain_known(
                    owned.config.tunnels.iter().map(|tunnel| tunnel.id.as_str()),
                    owned.apps.rules.iter().map(|rule| rule.id.as_str()),
                );
                crate::udp::consent::save(&self.store, &next)?;
                owned.udp = next;
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
            "apps_save" => {
                let update: CheckedApps =
                    serde_json::from_value(payload).context("Некорректные правила приложений.")?;
                if update.before != owned.apps.rules {
                    return Err(StaleConfig.into());
                }
                for rule in &update.rules {
                    // Untouched rules may wait for a deleted tunnel; new and edited ones may not.
                    if !owned.apps.rules.contains(rule) {
                        crate::apps::validate_rule(rule, &update.rules, &owned.config.tunnels)?;
                    }
                }
                let next = Apps {
                    version: 1,
                    rules: update.rules,
                };
                crate::apps::save(&self.store, &next)?;
                owned.apps = crate::apps::load(&self.store)?;
                Ok(Value::Null)
            }
            "divert_sync" => {
                let report: DivertReport =
                    serde_json::from_value(payload).context("Некорректный отчёт перехвата.")?;
                ensure!(
                    report.error.chars().count() <= 400 && report.logs.len() <= 1000,
                    "Отчёт перехвата превышает допустимый размер."
                );
                if report.version != env!("CARGO_PKG_VERSION") {
                    return Ok(json!({"rules": [], "stop": true}));
                }
                let divert = &mut owned.divert;
                if !report.error.is_empty() {
                    divert.error = report.error;
                    divert.seen = None;
                    return Ok(json!({"rules": []}));
                }
                divert.error.clear();
                divert.seen = Some(Instant::now());
                divert.stats = report.stats;
                divert.udp = report.udp;
                for (rule, line) in report.logs {
                    if owned.apps.rules.iter().any(|saved| saved.id == rule) {
                        let lines = owned.divert.logs.entry(rule).or_default();
                        lines.push(line.chars().take(200).collect());
                        if lines.len() > MAX_APP_LOGS {
                            lines.drain(..lines.len() - MAX_APP_LOGS);
                        }
                    }
                }
                let (states, _) = owned.manager.states().await;
                let udp_tunnels = owned.udp_tunnels();
                self.router.set_rules(
                    owned
                        .apps
                        .rules
                        .iter()
                        .filter(|rule| rule.enabled && udp_tunnels.contains(&rule.tunnel_id))
                        .map(|rule| (rule.id.clone(), rule.tunnel_id.clone()))
                        .collect(),
                );
                let udp_up: HashSet<String> = udp_tunnels
                    .into_iter()
                    .filter(|tunnel| self.router.up(tunnel))
                    .collect();
                let rules = crate::apps::divert_rules(
                    &owned.apps.rules,
                    &owned.config.tunnels,
                    &states,
                    &udp_up,
                    &owned.udp,
                );
                Ok(json!({"rules": rules}))
            }
            "app_start" | "app_stop" => {
                let id = payload
                    .as_str()
                    .context("Укажите ID сохранённого правила.")?;
                let mut next = owned.apps.clone();
                let rule = next
                    .rules
                    .iter_mut()
                    .find(|rule| rule.id == id)
                    .context("Сохранённое правило не найдено.")?;
                rule.enabled = command == "app_start";
                crate::apps::save(&self.store, &next)?;
                owned.apps = next;
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
        if let Ok(Ok(request)) = &request
            && request.command == "udp_attach"
        {
            ensure!(
                request.payload == json!({"version": krot_udp_proto::VERSION})
                    && reader.buffer().is_empty(),
                "Некорректный запрос UDP-канала."
            );
            let answer = json!({"ok": true, "value": {"version": krot_udp_proto::VERSION}});
            let mut encoded = serde_json::to_vec(&answer)?;
            encoded.push(b'\n');
            timeout(AUTH_TIMEOUT, reader.get_mut().write_all(&encoded)).await??;
            let stream = reader.into_inner();
            stream.set_nodelay(true)?;
            let (read, write) = stream.into_split();
            self.router.clone().serve(read, write).await;
            return Ok(());
        }
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
    // Broken application rules must not keep the tunnels from starting.
    let apps = crate::apps::load(&store).unwrap_or_default();
    // Broken UDP settings keep UDP off and the file untouched; tunnels still start.
    let (udp, udp_error) = match crate::udp::consent::load(&store) {
        Ok(udp) => (udp, String::new()),
        Err(error) => (Default::default(), format!("{error:#}")),
    };
    let manager = Manager::new(store.known_hosts_path());
    let router = Arc::new(crate::udp::router::Router::default());
    let (notices, notices_receive) = tokio::sync::mpsc::unbounded_channel();
    manager.set_udp_sink(notices);
    tokio::spawn(router.clone().run(notices_receive));
    let service = Arc::new(Service {
        store: store.clone(),
        token: hex::encode(rand::random::<[u8; 32]>()),
        router,
        owned: Mutex::new(Owned {
            config: config.clone(),
            apps,
            divert: Divert::default(),
            manager: manager.clone(),
            udp,
            udp_error,
        }),
        shutdown: CancellationToken::new(),
        closed: CancellationToken::new(),
        activation: AtomicU64::new(0),
    });
    // SIGTERM closes tunnels like Ctrl+C; registered before the address is published.
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let metadata = Metadata {
        port: listener.local_addr()?.port(),
        token: service.token.clone(),
    };
    let endpoint = store.sidecar(".background.json");
    atomic_json(&endpoint, &metadata, Some(4096))?;
    drop(guard);
    {
        let owned = service.owned.lock().await;
        manager.set_udp(owned.udp_tunnels()).await;
    }
    for tunnel in config.tunnels {
        if tunnel.enabled {
            manager.start(tunnel).await?;
        }
    }
    let permits = Arc::new(Semaphore::new(64));
    let mut handlers = JoinSet::new();
    let (tray, mut tray_actions) = crate::tray::Tray::start(service.shutdown.child_token());
    let mut tray_poll = tokio::time::interval(Duration::from_secs(1));
    let mut backoff = crate::ssh::AcceptBackoff::default();
    loop {
        let terminated = async {
            #[cfg(unix)]
            terminate.recv().await;
            #[cfg(not(unix))]
            std::future::pending::<()>().await;
        };
        tokio::select! {
            _ = service.shutdown.cancelled() => break,
            _ = tokio::signal::ctrl_c() => { service.shutdown.cancel(); break; },
            _ = terminated => { service.shutdown.cancel(); break; },
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
                // Keep the previous icon while a command holds the state.
                if let Ok(owned) = service.owned.try_lock() {
                    let (states, waiting) = owned.manager.states().await;
                    tray.update(crate::tray::Status::count(&owned.config.tunnels, &states, &waiting));
                }
            },
            _ = tokio::time::sleep_until(backoff.resume_at()), if !backoff.ready() => backoff.resume(),
            accepted = listener.accept(), if backoff.ready() => match accepted {
                Ok((stream, _)) => {
                    backoff.succeeded();
                    if let Ok(permit) = permits.clone().try_acquire_owned() {
                        let service = service.clone();
                        handlers.spawn(async move { let _permit = permit; let _ = service.handle(stream).await; });
                    }
                }
                // A transient accept error must not stop the daemon.
                Err(_) => { backoff.failed(); }
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

        // The helper is waited for in the same way: an update must not start beside it.
        let helper = Store::new(store.sidecar(".divert"))
            .unwrap()
            .lock()
            .unwrap();
        let waiting = tokio::spawn({
            let store = store.clone();
            async move { stop_and_wait(&store).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiting.is_finished(), "the helper still owns its lease");
        drop(helper);
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
        wait_until_serving(&client).await;
        stop_and_wait(&store).await.unwrap();
        assert!(store.lock().is_ok());
        daemon.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn the_helper_udp_channel_is_authenticated_and_carries_frames() {
        use krot_udp_proto::{self as proto, CloseReason, Frame};
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let daemon = tokio::spawn(serve(store.clone()));
        let client = Client::new(&store);
        wait_until_serving(&client).await;

        let mut channel = client.attach_udp().await.unwrap();
        // No tunnel carries UDP: a new flow is refused at once, in frames.
        let mut open = Vec::new();
        proto::encode(
            &Frame::Open {
                flow: 3,
                rule: "r1",
            },
            &mut open,
        );
        channel.get_mut().write_all(&open).await.unwrap();
        let mut answer = vec![0u8; 10];
        timeout(Duration::from_secs(3), channel.read_exact(&mut answer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            proto::parse(&answer).unwrap().unwrap().0,
            Frame::Close {
                flow: 3,
                reason: CloseReason::Socket,
            }
        );
        let snapshot = client.snapshot().await.unwrap();
        assert_eq!(snapshot.udp_rules["r1"].flows_refused, 1);

        // A wrong protocol version gets the usual refusal and no binary channel.
        let refused = client
            .request(
                "udp_attach",
                json!({"version": krot_udp_proto::VERSION + 1}),
            )
            .await;
        assert!(refused.is_err());
        drop(channel);
        stop_and_wait(&store).await.unwrap();
        daemon.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_old_replacement_choice_cannot_stop_a_new_owner() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let client = Client::new(&store);
        let first = tokio::spawn(serve(store.clone()));
        wait_until_serving(&client).await;
        let previous = observe_owner(&store).unwrap();
        stop_and_wait(&store).await.unwrap();
        first.await.unwrap().unwrap();
        let second = tokio::spawn(serve(store.clone()));
        wait_until_serving(&client).await;
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

    #[tokio::test]
    async fn app_rules_are_saved_beside_the_config_and_survive_their_tunnel() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path().join("tunnels.json")).unwrap();
        let socks = crate::config::Tunnel {
            id: "socks".into(),
            name: "socks".into(),
            kind: "D".into(),
            ..Default::default()
        };
        let config = Config {
            tunnels: vec![socks],
            ..Default::default()
        };
        let service = Service {
            store: store.clone(),
            token: String::new(),
            router: Default::default(),
            owned: Mutex::new(Owned {
                config: config.clone(),
                apps: Apps::default(),
                divert: Divert::default(),
                manager: Manager::new(store.known_hosts_path()),
                udp: Default::default(),
                udp_error: String::new(),
            }),
            shutdown: CancellationToken::new(),
            closed: CancellationToken::new(),
            activation: AtomicU64::new(0),
        };
        let rule = AppRule {
            id: "rule".into(),
            name: "curl".into(),
            path: "/usr/bin/curl".into(),
            tunnel_id: "socks".into(),
            ..Default::default()
        };
        let stray = AppRule {
            id: "stray".into(),
            path: "/usr/bin/wget".into(),
            tunnel_id: "missing".into(),
            ..rule.clone()
        };
        assert!(
            service
                .execute("apps_save", json!({"before": [], "rules": [stray]}))
                .await
                .is_err(),
            "a new rule needs an existing SOCKS5 tunnel"
        );
        service
            .execute("apps_save", json!({"before": [], "rules": [rule]}))
            .await
            .unwrap();
        let stale = service
            .execute("apps_save", json!({"before": [], "rules": []}))
            .await
            .unwrap_err();
        assert!(stale.is::<StaleConfig>());
        service.execute("app_start", json!("rule")).await.unwrap();
        assert!(service.execute("app_start", json!("gone")).await.is_err());
        let saved = crate::apps::load(&store).unwrap();
        assert!(saved.rules[0].enabled);
        assert!(
            !store.path.exists(),
            "the main configuration is not rewritten"
        );

        // Deleting the tunnel keeps the rule and reports why it does nothing.
        service
            .execute(
                "save_checked",
                json!({"before": config, "config": Config::default()}),
            )
            .await
            .unwrap();
        let snapshot: Snapshot =
            serde_json::from_value(service.execute("snapshot", Value::Null).await.unwrap())
                .unwrap();
        assert_eq!(snapshot.apps, saved.rules);
        assert_eq!(snapshot.apps_unavailable, crate::apps::unavailable());
        assert!(!snapshot.divert_attached);
        assert_ne!(snapshot.app_runtimes["rule"].state, "running");
        // An untouched orphan does not block saving the rest.
        service
            .execute(
                "apps_save",
                json!({"before": saved.rules, "rules": saved.rules}),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn helper_reports_attach_it_and_carry_counters_journal_and_start_errors() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path().join("tunnels.json")).unwrap();
        let socks = crate::config::Tunnel {
            id: "socks".into(),
            name: "socks".into(),
            kind: "D".into(),
            ..Default::default()
        };
        let rule = AppRule {
            id: "rule".into(),
            name: "curl".into(),
            path: "/usr/bin/curl".into(),
            tunnel_id: "socks".into(),
            enabled: true,
            ..Default::default()
        };
        let service = Service {
            store: store.clone(),
            token: String::new(),
            router: Default::default(),
            owned: Mutex::new(Owned {
                config: Config {
                    tunnels: vec![socks],
                    ..Default::default()
                },
                apps: Apps {
                    version: 1,
                    rules: vec![rule],
                },
                divert: Divert::default(),
                manager: Manager::new(store.known_hosts_path()),
                udp: Default::default(),
                udp_error: String::new(),
            }),
            shutdown: CancellationToken::new(),
            closed: CancellationToken::new(),
            activation: AtomicU64::new(0),
        };
        async fn snapshot(service: &Service) -> Snapshot {
            serde_json::from_value(service.execute("snapshot", Value::Null).await.unwrap()).unwrap()
        }
        let version = env!("CARGO_PKG_VERSION");
        // A helper left over from another version is told to stop and never attaches.
        let stale = json!({"version": "0.0.1", "stats": {}});
        let reply = service.execute("divert_sync", stale).await.unwrap();
        assert_eq!(reply, json!({"rules": [], "stop": true}));
        assert!(!snapshot(&service).await.divert_attached);
        let failed = json!({"version": version, "error": "Драйвер не загрузился."});
        service.execute("divert_sync", failed).await.unwrap();
        let state = snapshot(&service).await;
        assert!(!state.divert_attached);
        assert_eq!(state.divert_error, "Драйвер не загрузился.");

        let report = json!({
            "version": version,
            "stats": {"rule": {"connections": 2, "total": 9, "sent": 10, "received": 20}},
            "logs": [["rule", "10:00:00 10.0.0.1:443 через туннель"], ["gone", "x"]],
        });
        let reply = service.execute("divert_sync", report).await.unwrap();
        // The tunnel is not running, so the application is cut off rather than proxied.
        assert_eq!(
            reply["rules"],
            json!([{"id": "rule", "path": "/usr/bin/curl", "children": true, "direct": false,
                     "proxy": null, "udp": false, "quic": false}])
        );
        let state = snapshot(&service).await;
        assert!(state.divert_attached && state.divert_error.is_empty());
        assert!(state.udp_helper.is_empty());
        let runtime = &state.app_runtimes["rule"];
        assert_eq!(runtime.state, "blocked");
        assert_eq!((runtime.connections, runtime.total), (2, 9));
        assert_eq!(runtime.logs, ["10:00:00 10.0.0.1:443 через туннель"]);

        // A helper that stopped reporting no longer counts as intercepting.
        service.owned.lock().await.divert.seen = Instant::now().checked_sub(DIVERT_TIMEOUT * 2);
        let state = snapshot(&service).await;
        assert!(!state.divert_attached);
        assert_eq!(state.app_runtimes["rule"].connections, 0);
        assert!(
            service
                .execute("divert_sync", json!({"unknown": 1}))
                .await
                .is_err()
        );
    }
}
