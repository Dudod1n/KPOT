//! Native SSH transport, forwarding, and application-owned connection lifetime.
use crate::config::{Endpoint, Tunnel, atomic_json, unbracket, validate_tunnel};
use anyhow::{Result, anyhow, bail};
use russh::client::{self, ChannelOpenHandle};
use russh::keys::{self, HashAlg, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelOpenFailure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use zeroize::Zeroizing;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const ACCEPT_RETRY: Duration = Duration::from_millis(100);
/// About five seconds of consecutive accept errors.
const ACCEPT_ATTEMPTS: u32 = 50;
const ACCEPT_FAILED: Problem = Problem {
    message: "Локальный порт перестал принимать соединения.",
    retryable: true,
};

/// Paces retries after accept errors without blocking the surrounding `select!`.
#[derive(Default)]
pub(crate) struct AcceptBackoff {
    failures: u32,
    resume: Option<tokio::time::Instant>,
}
impl AcceptBackoff {
    pub(crate) fn ready(&self) -> bool {
        self.resume.is_none()
    }
    pub(crate) fn resume_at(&self) -> tokio::time::Instant {
        self.resume.unwrap_or_else(tokio::time::Instant::now)
    }
    pub(crate) fn resume(&mut self) {
        self.resume = None;
    }
    pub(crate) fn succeeded(&mut self) {
        self.failures = 0;
    }
    /// Pauses accepting and returns the number of consecutive failures.
    pub(crate) fn failed(&mut self) -> u32 {
        self.failures = self.failures.saturating_add(1);
        self.resume = Some(tokio::time::Instant::now() + ACCEPT_RETRY);
        self.failures
    }
}
const CANCELLED: Problem = Problem {
    message: "Подключение отменено.",
    retryable: false,
};
const NETWORK: Problem = Problem {
    message: "SSH-соединение прервано или узел недоступен.",
    retryable: true,
};
const AUTH: Problem = Problem {
    message: "SSH-сервер отклонил авторизацию. Проверьте пользователя и способ входа.",
    retryable: false,
};
/// A connection that may not ask the user needed an answer: a password or a host key check.
const NEEDS_USER: Problem =
    Problem::terminal("Для этого подключения нужен ввод пароля или проверка ключа узла.");
const KEY_FILE: Problem = Problem {
    message: "Не удалось открыть SSH-ключ: проверьте файл и пароль ключа.",
    retryable: false,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Runtime {
    pub state: String,
    pub message: String,
    pub hop: String,
    pub started_at: Option<f64>,
    pub logs: VecDeque<String>,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            message: String::new(),
            hop: String::new(),
            started_at: None,
            logs: VecDeque::new(),
        }
    }
}
/// State of a tunnel's UDP through the server relay.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct UdpRuntime {
    /// `off`, `waiting`, `starting`, `running` or `unavailable`.
    pub state: String,
    /// Why UDP is unavailable, or what it waits for.
    pub message: String,
    /// Transport level; 1 while only the separate SSH connection exists.
    pub level: u8,
    pub since: Option<f64>,
    pub starts: u64,
    pub uploads: u64,
}

/// Transports of running UDP relays, for the background process to route datagrams.
pub enum UdpNotice {
    Up {
        tunnel: String,
        transport: Arc<crate::udp::transport::Transport>,
        events: mpsc::Receiver<crate::udp::transport::Event>,
    },
    Down {
        tunnel: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Prompt {
    pub kind: String,
    pub tunnel_id: String,
    pub tunnel_name: String,
    pub endpoint: Endpoint,
    pub hop: String,
    pub message: String,
    pub old_fingerprint: String,
    pub new_fingerprint: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingPrompt {
    pub id: String,
    pub request: Prompt,
}
struct WaitingPrompt {
    prompt: PendingPrompt,
    answer: oneshot::Sender<Answer>,
}
enum Answer {
    Trust(bool),
    Credential(Zeroizing<String>),
    Cancel,
}
struct Task {
    cancel: CancellationToken,
    join: JoinHandle<()>,
}
#[derive(Default)]
struct State {
    closed: bool,
    runtimes: HashMap<String, Runtime>,
    prompts: HashMap<String, WaitingPrompt>,
    tasks: HashMap<String, Task>,
    /// Tunnels whose user agreed to the UDP relay.
    udp_enabled: HashSet<String>,
    udp: HashMap<String, UdpRuntime>,
    udp_links: HashMap<String, Arc<crate::udp::transport::Transport>>,
}
struct Inner {
    known_hosts: PathBuf,
    state: Mutex<State>,
    lifecycle: Mutex<()>,
    trust_write: Mutex<()>,
    udp_sink: StdMutex<Option<mpsc::UnboundedSender<UdpNotice>>>,
    udp_changed: watch::Sender<u64>,
}
#[derive(Clone)]
pub struct Manager(Arc<Inner>);
impl Manager {
    pub fn new(known_hosts_path: PathBuf) -> Self {
        Self(Arc::new(Inner {
            known_hosts: known_hosts_path,
            state: Mutex::new(State::default()),
            lifecycle: Mutex::new(()),
            trust_write: Mutex::new(()),
            udp_sink: StdMutex::new(None),
            udp_changed: watch::channel(0).0,
        }))
    }
    /// Where transports of running relays are announced.
    pub fn set_udp_sink(&self, sink: mpsc::UnboundedSender<UdpNotice>) {
        *self.0.udp_sink.lock().unwrap() = Some(sink);
    }
    /// Tunnels that may run the UDP relay; the others stop theirs.
    pub async fn set_udp(&self, enabled: HashSet<String>) {
        let mut state = self.0.state.lock().await;
        if state.udp_enabled != enabled {
            state.udp_enabled = enabled;
            drop(state);
            self.0
                .udp_changed
                .send_modify(|generation| *generation += 1);
        }
    }
    /// UDP state of every tunnel that has one, with the metrics of running transports.
    pub async fn udp_snapshot(
        &self,
    ) -> HashMap<String, (UdpRuntime, Option<crate::udp::transport::TransportMetrics>)> {
        let state = self.0.state.lock().await;
        state
            .udp
            .iter()
            .map(|(id, runtime)| {
                (
                    id.clone(),
                    (
                        runtime.clone(),
                        state.udp_links.get(id).map(|transport| transport.metrics()),
                    ),
                )
            })
            .collect()
    }
    fn announce(&self, notice: UdpNotice) {
        if let Some(sink) = self.0.udp_sink.lock().unwrap().as_ref() {
            let _ = sink.send(notice);
        }
    }
    async fn udp_state(&self, id: &str, status: &str, message: &str) {
        let mut state = self.0.state.lock().await;
        let runtime = state.udp.entry(id.into()).or_default();
        if runtime.state == status && runtime.message == message {
            return;
        }
        runtime.since = (status == "running").then(now);
        if status == "running" {
            runtime.starts += 1;
            runtime.level = 1;
        } else {
            runtime.level = 0;
        }
        runtime.state = status.into();
        runtime.message = message.into();
        let line = match status {
            "running" => Some("UDP: помощник на сервере работает, уровень 1.".to_owned()),
            "unavailable" => Some(format!("UDP недоступен: {message}")),
            "off" => Some("UDP выключен.".to_owned()),
            _ => None,
        };
        if let Some(line) = line
            && let Some(tunnel) = state.runtimes.get_mut(id)
        {
            push_log(tunnel, &line);
        }
    }
    pub async fn start(&self, tunnel: Tunnel) -> Result<()> {
        validate_tunnel(&tunnel, &[])?;
        let _operation = self.0.lifecycle.lock().await;
        let mut state = self.0.state.lock().await;
        if state.closed {
            bail!("Менеджер SSH завершил работу.");
        }
        if state
            .tasks
            .get(&tunnel.id)
            .is_some_and(|task| !task.join.is_finished())
        {
            return Ok(());
        }
        let runtime = state.runtimes.entry(tunnel.id.clone()).or_default();
        runtime.started_at = None;
        runtime.hop.clear();
        update(runtime, "connecting", "Подключение…");
        let cancel = CancellationToken::new();
        let manager = self.clone();
        let task_cancel = cancel.clone();
        let id = tunnel.id.clone();
        let join = tokio::spawn(async move {
            manager.run(tunnel, task_cancel).await;
        });
        state.tasks.insert(id, Task { cancel, join });
        Ok(())
    }
    pub async fn stop(&self, id: &str) -> Result<()> {
        let _operation = self.0.lifecycle.lock().await;
        let task = {
            let mut state = self.0.state.lock().await;
            state
                .prompts
                .retain(|_, p| p.prompt.request.tunnel_id != id);
            state.tasks.remove(id)
        };
        if let Some(task) = task {
            task.cancel.cancel();
            let _ = task.join.await;
        }
        let mut state = self.0.state.lock().await;
        let runtime = state.runtimes.entry(id.into()).or_default();
        runtime.started_at = None;
        runtime.hop.clear();
        update(runtime, "stopped", "Туннель остановлен");
        Ok(())
    }
    pub async fn close(&self) -> Result<()> {
        let _operation = self.0.lifecycle.lock().await;
        let tasks = {
            let mut state = self.0.state.lock().await;
            state.closed = true;
            state.prompts.clear();
            std::mem::take(&mut state.tasks)
        };
        for task in tasks.values() {
            task.cancel.cancel();
        }
        for (id, task) in tasks {
            let _ = task.join.await;
            let mut state = self.0.state.lock().await;
            let runtime = state.runtimes.entry(id).or_default();
            runtime.started_at = None;
            runtime.hop.clear();
            update(runtime, "stopped", "Туннель остановлен");
        }
        Ok(())
    }
    pub async fn snapshot(&self) -> (HashMap<String, Runtime>, HashMap<String, PendingPrompt>) {
        let state = self.0.state.lock().await;
        (
            state.runtimes.clone(),
            state
                .prompts
                .values()
                .map(|p| (p.prompt.request.tunnel_id.clone(), p.prompt.clone()))
                .collect(),
        )
    }
    /// Tunnel states and the tunnels waiting for an answer, without copying logs.
    pub async fn states(&self) -> (HashMap<String, String>, HashSet<String>) {
        let state = self.0.state.lock().await;
        (
            state
                .runtimes
                .iter()
                .map(|(id, runtime)| (id.clone(), runtime.state.clone()))
                .collect(),
            state
                .prompts
                .values()
                .map(|p| p.prompt.request.tunnel_id.clone())
                .collect(),
        )
    }
    pub async fn answer(&self, request_id: &str, value: Value) -> Result<()> {
        let value = match value {
            Value::String(secret) => Answer::Credential(Zeroizing::new(secret)),
            Value::Bool(accepted) => Answer::Trust(accepted),
            Value::Null => Answer::Cancel,
            _ => bail!("Недопустимый ответ на запрос SSH."),
        };
        let mut state = self.0.state.lock().await;
        let pending = state
            .prompts
            .get(request_id)
            .ok_or_else(|| anyhow!("Запрос больше не ожидает ответа."))?;
        if !valid_answer(&pending.prompt.request.kind, &value) {
            bail!("Недопустимый ответ на запрос SSH.");
        }
        if let Some(pending) = state.prompts.remove(request_id) {
            let _ = pending.answer.send(value);
        }
        Ok(())
    }
    async fn ask(
        &self,
        prompt: Prompt,
        cancel: &CancellationToken,
    ) -> std::result::Result<Answer, Problem> {
        let id = uuid::Uuid::new_v4().to_string();
        let (answer, receive) = oneshot::channel();
        {
            let mut state = self.0.state.lock().await;
            if cancel.is_cancelled() || state.closed {
                return Err(CANCELLED);
            }
            state.prompts.insert(
                id.clone(),
                WaitingPrompt {
                    prompt: PendingPrompt {
                        id: id.clone(),
                        request: prompt,
                    },
                    answer,
                },
            );
        }
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(CANCELLED),
            value = receive => value.map_err(|_| CANCELLED),
        };
        self.0.state.lock().await.prompts.remove(&id);
        result
    }
    async fn credential(
        &self,
        kind: &str,
        tunnel: &Tunnel,
        endpoint: &Endpoint,
        hop: &str,
        cancel: &CancellationToken,
    ) -> std::result::Result<Zeroizing<String>, Problem> {
        match self
            .ask(prompt(kind, tunnel, endpoint, hop), cancel)
            .await?
        {
            Answer::Credential(secret) => Ok(secret),
            _ => Err(Problem::terminal("Ввод учётных данных отменён.")),
        }
    }
    async fn trust(
        &self,
        tunnel: &Tunnel,
        endpoint: &Endpoint,
        hop: &str,
        key: &PublicKey,
        cancel: &CancellationToken,
        interactive: bool,
    ) -> std::result::Result<(), Problem> {
        let identity = format!(
            "[{}]:{}",
            unbracket(&endpoint.host).to_lowercase(),
            endpoint.port
        );
        let exported = key
            .to_openssh()
            .map_err(|_| Problem::terminal("SSH-сервер предоставил неподдерживаемый ключ узла."))?;
        loop {
            let old = {
                let _write = self.0.trust_write.lock().await;
                read_trust(&self.0.known_hosts)?.get(&identity).cloned()
            };
            if old.as_deref().is_some_and(|s| same_key(s, key)) {
                return Ok(());
            }
            if !interactive {
                return Err(NEEDS_USER);
            }
            let mut request = prompt(
                if old.is_some() {
                    "hostchanged"
                } else {
                    "trust"
                },
                tunnel,
                endpoint,
                hop,
            );
            request.message =
                "Сверьте отпечаток по независимому каналу перед подтверждением.".into();
            request.old_fingerprint = old
                .as_deref()
                .and_then(|s| PublicKey::from_openssh(s).ok())
                .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
                .unwrap_or_default();
            request.new_fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
            if !matches!(self.ask(request, cancel).await?, Answer::Trust(true)) {
                return Err(Problem::terminal(
                    "Ключ узла не принят. Подключение отменено.",
                ));
            }
            let _write = self.0.trust_write.lock().await;
            let mut trust = read_trust(&self.0.known_hosts)?;
            if trust.get(&identity) != old.as_ref() {
                continue;
            }
            if cancel.is_cancelled() {
                return Err(CANCELLED);
            }
            trust.insert(identity.clone(), exported.clone());
            atomic_json(&self.0.known_hosts, &trust, None).map_err(|_| {
                Problem::terminal("Не удалось сохранить ключ узла; подключение отменено.")
            })?;
            return Ok(());
        }
    }
    async fn log(&self, id: &str, message: &str) {
        let mut state = self.0.state.lock().await;
        push_log(state.runtimes.entry(id.into()).or_default(), message);
    }
    async fn state(&self, id: &str, status: &str, message: &str, hop: Option<&str>) {
        let mut state = self.0.state.lock().await;
        let runtime = state.runtimes.entry(id.into()).or_default();
        if let Some(hop) = hop {
            runtime.hop = hop.into();
        }
        runtime.started_at = if status == "running" {
            Some(now())
        } else {
            None
        };
        update(runtime, status, message);
    }
    async fn run(&self, tunnel: Tunnel, cancel: CancellationToken) {
        let credentials = Credentials::default();
        let udp = (tunnel.kind == "D").then(|| {
            let manager = self.clone();
            let tunnel = tunnel.clone();
            let cancel = cancel.child_token();
            let credentials = credentials.clone();
            tokio::spawn(async move { manager.udp_run(tunnel, cancel, credentials).await })
        });
        let mut delay = 1;
        loop {
            let mut attempt = Attempt::new(cancel.child_token());
            let result = {
                let forward = self.forward(&tunnel, &mut attempt, &credentials);
                tokio::pin!(forward);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => tokio::time::timeout(Duration::from_secs(5), &mut forward).await.unwrap_or(Err(CANCELLED)),
                    result = &mut forward => result,
                }
            };
            attempt.cleanup().await;
            if attempt.started {
                delay = 1;
            }
            if cancel.is_cancelled() {
                break;
            }
            let problem = result.err().unwrap_or(NETWORK);
            if !tunnel.reconnect || !problem.retryable {
                self.state(&tunnel.id, "error", problem.message, None).await;
                break;
            }
            self.state(
                &tunnel.id,
                "reconnecting",
                &format!("{} Повтор через {delay} с.", problem.message),
                None,
            )
            .await;
            tokio::select! { _ = cancel.cancelled() => break, _ = tokio::time::sleep(Duration::from_secs(delay)) => {} }
            delay = (delay * 2).min(30);
        }
        if let Some(udp) = udp {
            // The token is a child of `cancel`; a tunnel that stopped on an error cancels it here.
            udp.abort();
            let _ = udp.await;
            self.udp_down(&tunnel.id).await;
            self.udp_state(&tunnel.id, "off", "").await;
        }
        self.0
            .state
            .lock()
            .await
            .prompts
            .retain(|_, p| p.prompt.request.tunnel_id != tunnel.id);
    }
    async fn udp_down(&self, id: &str) {
        if self.0.state.lock().await.udp_links.remove(id).is_some() {
            self.announce(UdpNotice::Down { tunnel: id.into() });
        }
    }
    /// Keeps the tunnel's UDP relay running on its own SSH connection while UDP is enabled
    /// and the tunnel runs. Its failures never touch the tunnel itself.
    async fn udp_run(&self, tunnel: Tunnel, cancel: CancellationToken, credentials: Credentials) {
        let mut changes = self.0.udp_changed.subscribe();
        let mut delay = 1u64;
        loop {
            loop {
                let (enabled, running) = {
                    let state = self.0.state.lock().await;
                    (
                        state.udp_enabled.contains(&tunnel.id),
                        state
                            .runtimes
                            .get(&tunnel.id)
                            .is_some_and(|runtime| runtime.state == "running"),
                    )
                };
                match (enabled, running) {
                    (false, _) => self.udp_state(&tunnel.id, "off", "").await,
                    (true, false) => {
                        self.udp_state(&tunnel.id, "waiting", "Ждёт подключения туннеля.")
                            .await
                    }
                    (true, true) => break,
                }
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = changes.changed() => {},
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {},
                }
            }
            self.udp_state(&tunnel.id, "starting", "Запуск помощника на сервере…")
                .await;
            let mut attempt = Attempt::new(cancel.child_token());
            let result = self
                .udp_session(&tunnel, &mut attempt, &credentials, &mut changes)
                .await;
            self.udp_down(&tunnel.id).await;
            attempt.cleanup().await;
            if cancel.is_cancelled() {
                return;
            }
            let wait = match result {
                // Switched off: back to waiting for it, without delay.
                Ok(()) => continue,
                Err((message, retryable)) => {
                    self.udp_state(&tunnel.id, "unavailable", message).await;
                    if retryable {
                        let wait = delay;
                        delay = (delay * 2).min(60);
                        wait
                    } else {
                        300
                    }
                }
            };
            // A changed setting is a reason to try at once.
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = changes.changed() => delay = 1,
                _ = tokio::time::sleep(Duration::from_secs(wait)) => {},
            }
        }
    }
    /// One UDP connection with its relay, until it fails or UDP is switched off (`Ok`).
    async fn udp_session(
        &self,
        tunnel: &Tunnel,
        attempt: &mut Attempt,
        credentials: &Credentials,
        changes: &mut watch::Receiver<u64>,
    ) -> std::result::Result<(), (&'static str, bool)> {
        self.connect(tunnel, attempt, credentials, Purpose::Udp)
            .await
            .map_err(|problem| (problem.message, problem.retryable))?;
        let connection = attempt
            .sessions
            .last()
            .cloned()
            .ok_or((NETWORK.message, true))?;
        let launched = tokio::select! {
            _ = attempt.cancel.cancelled() => return Err((CANCELLED.message, false)),
            launched = crate::udp::deliver::launch(&connection, crate::udp::transport::default_settings()) => launched,
        }
        .map_err(|problem| (problem.message(), problem.retryable()))?;
        let transport = Arc::new(launched.transport);
        {
            let mut state = self.0.state.lock().await;
            if launched.uploaded {
                state.udp.entry(tunnel.id.clone()).or_default().uploads += 1;
                if let Some(runtime) = state.runtimes.get_mut(&tunnel.id) {
                    push_log(runtime, "UDP: помощник загружен на сервер.");
                }
            }
            state.udp_links.insert(tunnel.id.clone(), transport.clone());
        }
        self.announce(UdpNotice::Up {
            tunnel: tunnel.id.clone(),
            transport: transport.clone(),
            events: launched.events,
        });
        self.udp_state(&tunnel.id, "running", "").await;
        let mut check = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = attempt.cancel.cancelled() => return Err((CANCELLED.message, false)),
                failure = transport.failed() => {
                    return Err((match failure {
                        crate::udp::transport::Failure::Timeout => "Помощник UDP на сервере перестал отвечать.",
                        crate::udp::transport::Failure::Protocol => "Помощник UDP на сервере ответил некорректно.",
                        _ => crate::udp::deliver::Problem::Failed.message(),
                    }, true));
                },
                _ = changes.changed() => {
                    if !self.0.state.lock().await.udp_enabled.contains(&tunnel.id) {
                        return Ok(());
                    }
                },
                _ = check.tick() => {
                    if connection.is_closed() {
                        return Err((NETWORK.message, true));
                    }
                },
            }
        }
    }
    async fn forward(
        &self,
        tunnel: &Tunnel,
        attempt: &mut Attempt,
        credentials: &Credentials,
    ) -> std::result::Result<(), Problem> {
        let (remote_send, mut remote_receive) = mpsc::channel(64);
        let expected = Arc::new(StdMutex::new(None));
        self.connect(
            tunnel,
            attempt,
            credentials,
            Purpose::Tunnel {
                remote: remote_send,
                expected: expected.clone(),
            },
        )
        .await?;
        let connection = attempt.sessions.last().cloned().ok_or(NETWORK)?;
        if tunnel.kind == "R" {
            *expected.lock().unwrap() = Some(RemoteRoute {
                address: tunnel.bind.clone(),
                port: tunnel.port,
            });
            timed(connection.tcpip_forward(unbracket(&tunnel.bind), u32::from(tunnel.port)))
                .await?
                .map_err(|error| match error {
                    russh::Error::RequestDenied => Problem::terminal(
                        "SSH-сервер не разрешил удалённый порт или порт уже занят.",
                    ),
                    _ => NETWORK,
                })?;
        } else {
            attempt.listener = Some(
                timed(TcpListener::bind((unbracket(&tunnel.bind), tunnel.port)))
                    .await?
                    .map_err(bind_problem)?,
            );
        }
        self.state(&tunnel.id, "running", "Туннель работает", None)
            .await;
        attempt.started = true;
        let mut check = tokio::time::interval(Duration::from_millis(100));
        let mut backoff = AcceptBackoff::default();
        loop {
            tokio::select! {
                _ = attempt.cancel.cancelled() => return Err(CANCELLED),
                _ = check.tick() => if attempt.sessions.iter().any(|session| session.is_closed()) { return Err(attempt.failure.lock().unwrap().take().unwrap_or(NETWORK)); },
                Some(_) = attempt.copies.join_next(), if !attempt.copies.is_empty() => {},
                _ = tokio::time::sleep_until(backoff.resume_at()), if !backoff.ready() => backoff.resume(),
                accepted = accept_optional(attempt.listener.as_ref()), if attempt.listener.is_some() && backoff.ready() => {
                    let Ok((socket, origin)) = accepted else {
                        // Retry a transient error; reconnect with a new listener if it persists.
                        match backoff.failed() {
                            1 => self.log(&tunnel.id, "Ошибка приёма соединения на локальном порту; повторяем.").await,
                            ACCEPT_ATTEMPTS.. => return Err(ACCEPT_FAILED),
                            _ => {}
                        }
                        continue;
                    };
                    backoff.succeeded();
                    let connection = connection.clone();
                    let target = tunnel.target.clone();
                    let port = tunnel.target_port;
                    let dynamic = tunnel.kind == "D";
                    attempt.copies.spawn(async move {
                        let _ = local_connection(socket, origin, connection, dynamic, target, port).await;
                    });
                },
                Some((channel, reply)) = remote_receive.recv(), if tunnel.kind == "R" => {
                    let target = tunnel.target.clone();
                    let port = tunnel.target_port;
                    attempt.copies.spawn(async move {
                        match timed(TcpStream::connect((unbracket(&target), port))).await {
                            Ok(Ok(mut socket)) => {
                                reply.accept().await;
                                let mut stream = channel.into_stream();
                                let _ = tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
                            },
                            _ => reply.reject(ChannelOpenFailure::ConnectFailed).await,
                        }
                    });
                },
            }
        }
    }
    /// Opens the SSH session to the tunnel's server through its jump hosts and logs in.
    /// The session ends up last in `attempt.sessions`.
    async fn connect(
        &self,
        tunnel: &Tunnel,
        attempt: &mut Attempt,
        credentials: &Credentials,
        purpose: Purpose,
    ) -> std::result::Result<(), Problem> {
        if attempt.cancel.is_cancelled() {
            return Err(CANCELLED);
        }
        let interactive = matches!(purpose, Purpose::Tunnel { .. });
        let (remote, expected) = match purpose {
            Purpose::Tunnel { remote, expected } => (Some(remote), expected),
            Purpose::Udp => (None, Arc::new(StdMutex::new(None))),
        };
        let jumps = if tunnel.jumps_enabled {
            tunnel.jumps.as_slice()
        } else {
            &[]
        };
        for (index, endpoint) in jumps
            .iter()
            .chain(std::iter::once(&tunnel.server))
            .enumerate()
        {
            if attempt.cancel.is_cancelled() {
                return Err(CANCELLED);
            }
            let hop = if index < jumps.len() {
                format!("Jump host {}/{}", index + 1, jumps.len())
            } else {
                "Конечный SSH-сервер".into()
            };
            if interactive {
                self.state(
                    &tunnel.id,
                    "connecting",
                    &format!("{hop}: {}", endpoint.address()),
                    Some(&hop),
                )
                .await;
            }
            let stream: Box<dyn Transport> = if let Some(previous) = attempt.sessions.last() {
                let channel = interruptible(
                    &attempt.cancel,
                    previous.channel_open_direct_tcpip(
                        unbracket(&endpoint.host),
                        u32::from(endpoint.port),
                        "127.0.0.1",
                        0,
                    ),
                )
                .await??;
                Box::new(channel.into_stream())
            } else {
                // DNS and TCP connect do not see the transport token.
                Box::new(
                    interruptible(
                        &attempt.cancel,
                        first_hop(unbracket(&endpoint.host), endpoint.port, interactive),
                    )
                    .await?
                    .map_err(|_| NETWORK)?,
                )
            };
            let (waiting_send, waiting_receive) = watch::channel(false);
            let handler = Handler {
                manager: self.clone(),
                tunnel: tunnel.clone(),
                endpoint: endpoint.clone(),
                hop: hop.clone(),
                cancel: attempt.cancel.clone(),
                waiting: waiting_send,
                pinned: None,
                remote: if index == jumps.len() {
                    remote.clone()
                } else {
                    None
                },
                expected: expected.clone(),
                failure: attempt.failure.clone(),
                interactive,
            };
            let stream = CancelIo::new(stream, attempt.cancel.clone());
            let config = Arc::new(client::Config {
                nodelay: true,
                keepalive_interval: Some(Duration::from_secs(15)),
                keepalive_max: 3,
                ..Default::default()
            });
            let session = connecting(
                client::connect_stream(config, stream, handler),
                waiting_receive,
                &attempt.cancel,
            )
            .await?;
            // Keep ownership before authentication, so a failed login closes its transport too.
            attempt.sessions.push(Arc::new(session));
            let session =
                Arc::get_mut(attempt.sessions.last_mut().ok_or(NETWORK)?).ok_or(NETWORK)?;
            self.authenticate(
                session,
                tunnel,
                endpoint,
                &hop,
                credentials,
                &attempt.cancel,
                interactive,
            )
            .await?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    async fn authenticate(
        &self,
        session: &mut client::Handle<Handler>,
        tunnel: &Tunnel,
        endpoint: &Endpoint,
        hop: &str,
        credentials: &Credentials,
        cancel: &CancellationToken,
        interactive: bool,
    ) -> std::result::Result<(), Problem> {
        if timed(session.authenticate_none(&endpoint.user))
            .await??
            .success()
        {
            return Ok(());
        }
        let identity = serde_json::to_string(endpoint).map_err(|_| AUTH)?;
        let known = credentials.lock().await.get(&identity).cloned();
        let success = if endpoint.auth == "password" {
            let secret = match known {
                Some(Credential::Password(secret)) => secret,
                _ if !interactive => return Err(NEEDS_USER),
                _ => {
                    let secret = self
                        .credential("password", tunnel, endpoint, hop, cancel)
                        .await?;
                    credentials
                        .lock()
                        .await
                        .insert(identity.clone(), Credential::Password(secret.clone()));
                    secret
                }
            };
            timed(session.authenticate_password(&endpoint.user, secret.as_str()))
                .await??
                .success()
        } else if endpoint.auth == "key" {
            let key = match known {
                Some(Credential::Key(key)) => key,
                _ => {
                    let path = expand_key_path(&endpoint.key);
                    let encoded = Zeroizing::new(
                        tokio::fs::read_to_string(path)
                            .await
                            .map_err(|_| KEY_FILE)?,
                    );
                    let first = keys::decode_secret_key(&encoded, None);
                    let key = match first {
                        Ok(key) => key,
                        Err(error) if encrypted_key(&error, &encoded) => {
                            if !interactive {
                                return Err(NEEDS_USER);
                            }
                            let passphrase = self
                                .credential("passphrase", tunnel, endpoint, hop, cancel)
                                .await?;
                            tokio::task::spawn_blocking(move || {
                                keys::decode_secret_key(&encoded, Some(&passphrase))
                            })
                            .await
                            .map_err(|_| KEY_FILE)?
                            .map_err(|_| KEY_FILE)?
                        }
                        Err(_) => return Err(KEY_FILE),
                    };
                    let key = Arc::new(key);
                    credentials
                        .lock()
                        .await
                        .insert(identity.clone(), Credential::Key(key.clone()));
                    key
                }
            };
            let hash = timed(session.best_supported_rsa_hash()).await??.flatten();
            timed(session.authenticate_publickey(
                &endpoint.user,
                keys::key::PrivateKeyWithHashAlg::new(key, hash),
            ))
            .await??
            .success()
        } else {
            timed(agent_auth(session, &endpoint.user)).await??
        };
        if success { Ok(()) } else { Err(AUTH) }
    }
}
fn valid_answer(kind: &str, value: &Answer) -> bool {
    if matches!(kind, "trust" | "hostchanged") {
        matches!(value, Answer::Trust(_) | Answer::Cancel)
    } else {
        matches!(value, Answer::Credential(_) | Answer::Cancel)
    }
}
fn prompt(kind: &str, tunnel: &Tunnel, endpoint: &Endpoint, hop: &str) -> Prompt {
    Prompt {
        kind: kind.into(),
        tunnel_id: tunnel.id.clone(),
        tunnel_name: tunnel.name.clone(),
        endpoint: endpoint.clone(),
        hop: hop.into(),
        message: String::new(),
        old_fingerprint: String::new(),
        new_fingerprint: String::new(),
    }
}
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
fn update(runtime: &mut Runtime, state: &str, message: &str) {
    runtime.state = state.into();
    runtime.message = message.into();
    push_log(runtime, message);
}
fn push_log(runtime: &mut Runtime, message: &str) {
    runtime
        .logs
        .push_back(log_line(&chrono::Local::now(), message));
    while runtime.logs.len() > 300 {
        runtime.logs.pop_front();
    }
}
fn log_line<Zone: chrono::TimeZone>(time: &chrono::DateTime<Zone>, message: &str) -> String
where
    Zone::Offset: std::fmt::Display,
{
    format!("{}  {message}", time.format("%H:%M:%S"))
}
fn read_trust(path: &Path) -> std::result::Result<HashMap<String, String>, Problem> {
    let problem =
        Problem::terminal("Не удалось прочитать хранилище ключей узлов; файл не изменён.");
    let content = match std::fs::read(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(_) => return Err(problem),
    };
    let trust: HashMap<String, String> = serde_json::from_slice(&content).map_err(|_| problem)?;
    for key in trust.values() {
        PublicKey::from_openssh(key).map_err(|_| problem)?;
    }
    Ok(trust)
}
fn same_key(encoded: &str, key: &PublicKey) -> bool {
    PublicKey::from_openssh(encoded).is_ok_and(|old| old.key_data() == key.key_data())
}
#[derive(Clone, Copy, Debug)]
struct Problem {
    message: &'static str,
    retryable: bool,
}
impl Problem {
    const fn terminal(message: &'static str) -> Self {
        Self {
            message,
            retryable: false,
        }
    }
}
impl std::fmt::Display for Problem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}
impl std::error::Error for Problem {}
impl From<russh::Error> for Problem {
    fn from(_: russh::Error) -> Self {
        NETWORK
    }
}
async fn timed<T>(operation: impl Future<Output = T>) -> std::result::Result<T, Problem> {
    tokio::time::timeout(NETWORK_TIMEOUT, operation)
        .await
        .map_err(|_| Problem {
            message: "Истекло время ожидания SSH-соединения.",
            retryable: true,
        })
}
async fn interruptible<T>(
    cancel: &CancellationToken,
    operation: impl Future<Output = T>,
) -> std::result::Result<T, Problem> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(CANCELLED),
        value = timed(operation) => value,
    }
}
fn bind_problem(_: io::Error) -> Problem {
    Problem::terminal(
        "Не удалось открыть локальный порт. Проверьте адрес, права и занятость порта.",
    )
}
#[derive(Clone)]
enum Credential {
    Password(Zeroizing<String>),
    Key(Arc<PrivateKey>),
}
/// Secrets entered for one tunnel, shared by all of its connections and kept in memory only.
type Credentials = Arc<Mutex<HashMap<String, Credential>>>;
pub(crate) fn expand_key_path(path: &str) -> PathBuf {
    if (path == "~" || path.starts_with("~/") || path.starts_with("~\\"))
        && let Some(home) = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
    {
        return PathBuf::from(home).join(path.get(2..).unwrap_or(""));
    }
    PathBuf::from(path)
}
fn encrypted_key(error: &keys::Error, encoded: &str) -> bool {
    matches!(error, keys::Error::KeyIsEncrypted)
        || encoded.contains("BEGIN ENCRYPTED PRIVATE KEY")
        || encoded.contains("Proc-Type: 4,ENCRYPTED")
        || encoded.starts_with("PuTTY-User-Key-File-")
}

trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
// Dropping a russh Handle detaches its task. Cancelling its transport closes that task too.
struct CancelIo {
    stream: Box<dyn Transport>,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}
impl CancelIo {
    fn new(stream: Box<dyn Transport>, cancel: CancellationToken) -> Self {
        Self {
            stream,
            cancelled: Box::pin(cancel.cancelled_owned()),
        }
    }
    fn cancelled(&mut self, cx: &mut Context<'_>) -> bool {
        self.cancelled.as_mut().poll(cx).is_ready()
    }
}
impl AsyncRead for CancelIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.cancelled(cx) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for CancelIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.cancelled(cx) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        Pin::new(&mut self.stream).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.cancelled(cx) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.cancelled(cx) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
struct Attempt {
    cancel: CancellationToken,
    sessions: Vec<Arc<client::Handle<Handler>>>,
    listener: Option<TcpListener>,
    copies: JoinSet<()>,
    started: bool,
    failure: Arc<StdMutex<Option<Problem>>>,
}
impl Attempt {
    fn new(cancel: CancellationToken) -> Self {
        Self {
            cancel,
            sessions: vec![],
            listener: None,
            copies: JoinSet::new(),
            started: false,
            failure: Arc::new(StdMutex::new(None)),
        }
    }
    async fn cleanup(&mut self) {
        self.listener.take();
        self.cancel.cancel();
        self.copies.abort_all();
        while self.copies.join_next().await.is_some() {}
        while let Some(session) = self.sessions.pop() {
            if let Ok(handle) = Arc::try_unwrap(session) {
                let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
            }
        }
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.copies.abort_all();
    }
}
async fn connecting<T>(
    operation: impl Future<Output = std::result::Result<T, Problem>>,
    mut waiting: watch::Receiver<bool>,
    cancel: &CancellationToken,
) -> std::result::Result<T, Problem> {
    tokio::pin!(operation);
    let deadline = tokio::time::sleep(NETWORK_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        let paused = *waiting.borrow();
        tokio::select! {
            biased;
            result = &mut operation => return result,
            _ = cancel.cancelled() => {
                let _ = tokio::time::timeout(Duration::from_secs(5), &mut operation).await;
                return Err(CANCELLED);
            },
            changed = waiting.changed() => {
                if changed.is_err() { cancel.cancel(); return Err(NETWORK); }
                if !*waiting.borrow() { deadline.as_mut().reset(tokio::time::Instant::now() + NETWORK_TIMEOUT); }
            },
            _ = &mut deadline, if !paused => {
                cancel.cancel();
                let _ = tokio::time::timeout(Duration::from_secs(5), &mut operation).await;
                return Err(Problem { message: "Истекло время ожидания SSH-соединения.", retryable: true });
            },
        }
    }
}
/// What a connection is for.
enum Purpose {
    /// The tunnel itself: it reports progress and may ask the user.
    Tunnel {
        remote: mpsc::Sender<RemoteChannel>,
        expected: Arc<StdMutex<Option<RemoteRoute>>>,
    },
    /// The separate UDP connection: silent, never asks, small send buffer.
    Udp,
}

/// Send buffer of the UDP connection's TCP socket: bytes beyond the in-flight window would only
/// add delay there. Tuned on the stand.
const UDP_SEND_BUFFER: u32 = 256 * 1024;

async fn first_hop(host: &str, port: u16, interactive: bool) -> io::Result<TcpStream> {
    if interactive {
        return TcpStream::connect((host, port)).await;
    }
    let mut last = io::Error::from(io::ErrorKind::NotFound);
    for address in tokio::net::lookup_host((host, port)).await? {
        let socket = if address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        let _ = socket.set_send_buffer_size(UDP_SEND_BUFFER);
        socket.set_nodelay(true)?;
        match socket.connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[derive(Clone)]
struct RemoteRoute {
    address: String,
    port: u16,
}
type RemoteChannel = (Channel<client::Msg>, ChannelOpenHandle);
struct Handler {
    manager: Manager,
    tunnel: Tunnel,
    endpoint: Endpoint,
    hop: String,
    cancel: CancellationToken,
    waiting: watch::Sender<bool>,
    pinned: Option<PublicKey>,
    remote: Option<mpsc::Sender<RemoteChannel>>,
    expected: Arc<StdMutex<Option<RemoteRoute>>>,
    failure: Arc<StdMutex<Option<Problem>>>,
    /// Whether the user may be asked; the UDP connection never asks.
    interactive: bool,
}
impl client::Handler for Handler {
    type Error = Problem;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Problem> {
        let key = key.public_key();
        if let Some(pinned) = &self.pinned {
            if pinned.key_data() == key.key_data() {
                return Ok(true);
            }
            let problem = Problem::terminal(
                "Ключ SSH-узла изменился при подключении. Запустите туннель снова для проверки.",
            );
            *self.failure.lock().unwrap() = Some(problem);
            return Err(problem);
        }
        self.waiting.send_replace(true);
        let trusted = self
            .manager
            .trust(
                &self.tunnel,
                &self.endpoint,
                &self.hop,
                &key,
                &self.cancel,
                self.interactive,
            )
            .await;
        self.waiting.send_replace(false);
        trusted?;
        self.pinned = Some(key);
        Ok(true)
    }
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        address: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> std::result::Result<(), Problem> {
        let accepted = !self.cancel.is_cancelled()
            && self
                .expected
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|route| remote_matches(route, address, port));
        if accepted && let Some(remote) = &self.remote {
            let _ = remote.try_send((channel, reply));
        }
        Ok(())
    }
    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _: Channel<client::Msg>,
        _: &str,
        _: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> std::result::Result<(), Problem> {
        Ok(())
    }
    async fn server_channel_open_agent_forward(
        &mut self,
        _: Channel<client::Msg>,
        _: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> std::result::Result<(), Problem> {
        Ok(())
    }
    async fn server_channel_open_session(
        &mut self,
        _: Channel<client::Msg>,
        _: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> std::result::Result<(), Problem> {
        Ok(())
    }
    async fn server_channel_open_direct_tcpip(
        &mut self,
        _: Channel<client::Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        _: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> std::result::Result<(), Problem> {
        Ok(())
    }
    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _: Channel<client::Msg>,
        _: &str,
        _: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> std::result::Result<(), Problem> {
        Ok(())
    }
    async fn server_channel_open_x11(
        &mut self,
        _: Channel<client::Msg>,
        _: &str,
        _: u32,
        _: ChannelOpenHandle,
        _: &mut client::Session,
    ) -> std::result::Result<(), Problem> {
        Ok(())
    }
}
fn remote_matches(route: &RemoteRoute, address: &str, port: u32) -> bool {
    if port != u32::from(route.port) {
        return false;
    }
    let configured = unbracket(&route.address).to_lowercase();
    let address = unbracket(address).to_lowercase();
    configured == address
        || (configured == "localhost" && address.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()))
}
async fn agent_auth(
    session: &mut client::Handle<Handler>,
    user: &str,
) -> std::result::Result<bool, Problem> {
    use keys::agent::client::AgentClient;
    #[cfg(unix)]
    let mut agent = AgentClient::connect_env()
        .await
        .map_err(|_| {
            Problem::terminal("SSH-agent недоступен. Проверьте SSH_AUTH_SOCK и загруженные ключи.")
        })?
        .dynamic();
    #[cfg(windows)]
    let mut agent = match AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
        Ok(agent) => agent.dynamic(),
        Err(_) => AgentClient::connect_pageant()
            .await
            .map_err(|_| {
                Problem::terminal(
                    "SSH-agent недоступен. Запустите OpenSSH agent или Pageant и загрузите ключ.",
                )
            })?
            .dynamic(),
    };
    #[cfg(not(any(unix, windows)))]
    return Err(Problem::terminal("SSH-agent недоступен на этой платформе."));
    #[cfg(any(unix, windows))]
    {
        let identities = agent.request_identities().await.map_err(|_| AUTH)?;
        let hash = session.best_supported_rsa_hash().await?.flatten();
        for identity in identities {
            let unsigned = AtomicBool::new(false);
            let mut signer = SkippingSigner {
                signer: &mut agent,
                unsigned: &unsigned,
            };
            let outcome = match identity {
                keys::agent::AgentIdentity::PublicKey { key, .. } => {
                    skip_unsigned(
                        session.authenticate_publickey_with(user, key, hash, &mut signer),
                        &unsigned,
                    )
                    .await
                }
                keys::agent::AgentIdentity::Certificate { certificate, .. } => {
                    skip_unsigned(
                        session.authenticate_certificate_with(user, certificate, hash, &mut signer),
                        &unsigned,
                    )
                    .await
                }
            };
            match outcome {
                Some(Ok(result)) if result.success() => return Ok(true),
                Some(Err(_)) => return Err(AUTH),
                // Rejected or unsigned: try the next key.
                _ => {}
            }
        }
        Ok(false)
    }
}
/// Hands back the unsigned request so russh skips a key the agent cannot sign with.
#[cfg(any(unix, windows))]
struct SkippingSigner<'a, S> {
    signer: &'a mut S,
    unsigned: &'a AtomicBool,
}
#[cfg(any(unix, windows))]
impl<S: russh::Signer + Send> russh::Signer for SkippingSigner<'_, S> {
    type Error = S::Error;
    async fn auth_sign(
        &mut self,
        key: &keys::agent::AgentIdentity,
        hash: Option<HashAlg>,
        request: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, S::Error> {
        let untouched = request.clone();
        match self.signer.auth_sign(key, hash, request).await {
            Ok(signed) => Ok(signed),
            Err(_) => {
                self.unsigned.store(true, Ordering::Release);
                Ok(untouched)
            }
        }
    }
}
/// Ends with `None` once the signer has given up on this key.
#[cfg(any(unix, windows))]
async fn skip_unsigned<T>(attempt: impl Future<Output = T>, unsigned: &AtomicBool) -> Option<T> {
    tokio::pin!(attempt);
    let mut delivered = false;
    std::future::poll_fn(|cx| match attempt.as_mut().poll(cx) {
        Poll::Ready(value) => Poll::Ready(Some(value)),
        Poll::Pending if !unsigned.load(Ordering::Acquire) => Poll::Pending,
        Poll::Pending if delivered => Poll::Ready(None),
        Poll::Pending => {
            // One more poll lets the pending channel send complete.
            delivered = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}
async fn accept_optional(
    listener: Option<&TcpListener>,
) -> io::Result<(TcpStream, std::net::SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}
async fn local_connection(
    mut socket: TcpStream,
    origin: std::net::SocketAddr,
    connection: Arc<client::Handle<Handler>>,
    dynamic: bool,
    target: String,
    port: u16,
) -> std::result::Result<(), Problem> {
    let (target, port) = if dynamic {
        timed(socks_destination(&mut socket))
            .await?
            .map_err(|_| Problem::terminal("Недопустимый запрос SOCKS5."))?
    } else {
        (target, port)
    };
    let channel = match timed(connection.channel_open_direct_tcpip(
        unbracket(&target),
        u32::from(port),
        origin.ip().to_string(),
        u32::from(origin.port()),
    ))
    .await
    {
        Ok(Ok(channel)) => channel,
        error => {
            if dynamic {
                let _ = socket.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            }
            return Err(error.err().unwrap_or(NETWORK));
        }
    };
    if dynamic {
        socket
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .map_err(|_| NETWORK)?;
    }
    let mut stream = channel.into_stream();
    tokio::io::copy_bidirectional(&mut socket, &mut stream)
        .await
        .map_err(|_| NETWORK)?;
    Ok(())
}
async fn socks_destination(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> io::Result<(String, u16)> {
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 || greeting[1] == 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut methods = vec![0; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 255]).await?;
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    stream.write_all(&[5, 0]).await?;
    let mut request = [0; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    if request[1] != 1 {
        stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let host = match request[3] {
        1 => {
            let mut ip = [0; 4];
            stream.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip).await?;
            Ipv6Addr::from(ip).to_string()
        }
        3 => {
            let length = stream.read_u8().await?;
            if length == 0 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let mut host = vec![0; usize::from(length)];
            stream.read_exact(&mut host).await?;
            let host =
                String::from_utf8(host).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            if host.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            host
        }
        _ => {
            stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
    };
    let port = stream.read_u16().await?;
    if port == 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel() -> Tunnel {
        serde_json::from_value(serde_json::json!({
            "id":"test", "name":"Test", "kind":"L", "server": {
                "host":"example.test", "port":22, "user":"user", "auth":"password", "key":""
            }, "bind":"127.0.0.1", "port":12345, "target":"localhost", "target_port":80,
            "reconnect":false, "jumps_enabled":false, "jumps":[], "enabled":true
        }))
        .unwrap()
    }
    #[tokio::test]
    async fn prompts_are_independent_typed_and_secret_free() {
        let directory = tempfile::tempdir().unwrap();
        let manager = Manager::new(directory.path().join("hosts.json"));
        let cancel = CancellationToken::new();
        let mut tasks = vec![];
        for id in ["first", "second"] {
            let manager = manager.clone();
            let cancel = cancel.clone();
            let mut tunnel = tunnel();
            tunnel.id = id.into();
            tasks.push(tokio::spawn(async move {
                manager
                    .credential("password", &tunnel, &tunnel.server, "server", &cancel)
                    .await
            }));
        }
        let prompts = loop {
            let (_, prompts) = manager.snapshot().await;
            if prompts.len() == 2 {
                break prompts;
            }
            tokio::task::yield_now().await;
        };
        let first = prompts.get("first").unwrap();
        assert!(manager.answer(&first.id, Value::Bool(true)).await.is_err());
        manager
            .answer(&first.id, Value::String("secret-never-in-snapshot".into()))
            .await
            .unwrap();
        assert_eq!(
            tasks.remove(0).await.unwrap().unwrap().as_str(),
            "secret-never-in-snapshot"
        );
        assert!(
            !serde_json::to_string(&manager.snapshot().await)
                .unwrap()
                .contains("secret-never-in-snapshot")
        );
        assert_eq!(manager.snapshot().await.1.len(), 1);
        cancel.cancel();
        assert!(tasks.remove(0).await.unwrap().is_err());
        assert!(manager.snapshot().await.1.is_empty());
        assert!(!directory.path().join("hosts.json").exists());
    }
    #[tokio::test]
    async fn cleanup_releases_listener_and_copy_tasks() {
        let mut attempt = Attempt::new(CancellationToken::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        attempt.listener = Some(listener);
        let (send, receive) = oneshot::channel::<()>();
        attempt.copies.spawn(async move {
            let _send = send;
            std::future::pending::<()>().await;
        });
        attempt.cleanup().await;
        assert!(receive.await.is_err());
        assert!(TcpListener::bind(address).await.is_ok());
        assert!(attempt.copies.is_empty());
    }
    #[tokio::test]
    async fn cancellation_interrupts_blocked_transport() {
        let (client, _server) = tokio::io::duplex(64);
        let cancel = CancellationToken::new();
        let mut transport = CancelIo::new(Box::new(client), cancel.clone());
        let read = tokio::spawn(async move { transport.read_u8().await });
        tokio::task::yield_now().await;
        cancel.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), read)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }
    #[tokio::test]
    async fn socks_reads_ipv4_domain_and_ipv6_without_consuming_payload() {
        for (encoded, expected) in [
            (vec![1, 127, 0, 0, 1], "127.0.0.1"),
            (
                vec![
                    3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                ],
                "example.com",
            ),
            (
                vec![4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "::1",
            ),
        ] {
            let (mut client, mut server) = tokio::io::duplex(1024);
            let parse = tokio::spawn(async move {
                let destination = socks_destination(&mut server).await.unwrap();
                assert_eq!(server.read_u8().await.unwrap(), 99);
                destination
            });
            client.write_all(&[5, 2, 2, 0]).await.unwrap();
            assert_eq!(client.read_u16().await.unwrap(), 0x0500);
            let mut request = vec![5, 1, 0];
            request.extend(encoded);
            request.extend([0x01, 0xbb, 99]);
            client.write_all(&request).await.unwrap();
            assert_eq!(parse.await.unwrap(), (expected.into(), 443));
        }
    }
    #[tokio::test]
    async fn socks_rejects_unsupported_authentication_and_commands() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let parse = tokio::spawn(async move { socks_destination(&mut server).await });
        client.write_all(&[5, 1, 2]).await.unwrap();
        assert_eq!(client.read_u16().await.unwrap(), 0x05ff);
        assert!(parse.await.unwrap().is_err());
        let (mut client, mut server) = tokio::io::duplex(64);
        let parse = tokio::spawn(async move { socks_destination(&mut server).await });
        client.write_all(&[5, 1, 0, 5, 2, 0, 1]).await.unwrap();
        let mut response = [0; 12];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[3], 7);
        assert!(parse.await.unwrap().is_err());
    }
    #[test]
    fn unsolicited_remote_routes_and_string_trust_answers_are_rejected() {
        let route = RemoteRoute {
            address: "127.0.0.1".into(),
            port: 8080,
        };
        assert!(remote_matches(&route, "127.0.0.1", 8080));
        assert!(!remote_matches(&route, "127.0.0.1", 8081));
        assert!(!remote_matches(&route, "192.0.2.1", 8080));
        assert!(!valid_answer(
            "trust",
            &Answer::Credential(Zeroizing::new("true".into()))
        ));
        assert!(valid_answer("trust", &Answer::Trust(true)));
        assert!(!valid_answer("password", &Answer::Trust(true)));
    }
    #[test]
    fn corrupt_trust_store_is_not_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hosts.json");
        std::fs::write(&path, r#"{"[example.com]:22":"invalid"}"#).unwrap();
        assert!(read_trust(&path).is_err());
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            r#"{"[example.com]:22":"invalid"}"#
        );
    }
    #[tokio::test]
    async fn concurrent_host_confirmations_merge_and_require_new_consent_after_change() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hosts.json");
        let manager = Manager::new(path.clone());
        let key = PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ",
        )
        .unwrap();
        let other_key = PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X",
        )
        .unwrap();
        let mut tasks = vec![];
        for host in ["first.example", "second.example"] {
            let manager = manager.clone();
            let key = key.clone();
            let mut tunnel = tunnel();
            tunnel.id = host.into();
            tunnel.server.host = host.into();
            tasks.push(tokio::spawn(async move {
                manager
                    .trust(
                        &tunnel,
                        &tunnel.server,
                        "server",
                        &key,
                        &CancellationToken::new(),
                        true,
                    )
                    .await
            }));
        }
        let prompts = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let prompts = manager.snapshot().await.1;
                if prompts.len() == 2 {
                    break prompts;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for pending in prompts.values() {
            manager
                .answer(&pending.id, Value::Bool(true))
                .await
                .unwrap();
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(read_trust(&path).unwrap().len(), 2);
        // A connection that may not ask accepts only an already trusted key, without a prompt.
        let mut silent = tunnel();
        silent.server.host = "first.example".into();
        let trusted = read_trust(&path).unwrap()["[first.example]:22"].clone();
        let trusted = PublicKey::from_openssh(&trusted).unwrap();
        assert!(
            manager
                .trust(
                    &silent,
                    &silent.server,
                    "server",
                    &trusted,
                    &CancellationToken::new(),
                    false
                )
                .await
                .is_ok()
        );
        let refused = manager
            .trust(
                &silent,
                &silent.server,
                "server",
                &other_key,
                &CancellationToken::new(),
                false,
            )
            .await;
        assert_eq!(
            refused.err().map(|problem| problem.message),
            Some(NEEDS_USER.message)
        );
        assert!(manager.snapshot().await.1.is_empty());
        let changed_manager = manager.clone();
        let task = tokio::spawn(async move {
            let mut tunnel = tunnel();
            tunnel.server.host = "first.example".into();
            changed_manager
                .trust(
                    &tunnel,
                    &tunnel.server,
                    "server",
                    &other_key,
                    &CancellationToken::new(),
                    true,
                )
                .await
        });
        let changed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(request) = manager.snapshot().await.1.into_values().next() {
                    break request;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(changed.request.kind, "hostchanged");
        assert_ne!(
            changed.request.old_fingerprint,
            changed.request.new_fingerprint
        );
        manager
            .answer(&changed.id, Value::Bool(false))
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());
        assert!(same_key(
            &read_trust(&path).unwrap()["[first.example]:22"],
            &key
        ));
    }
    #[test]
    fn log_lines_use_the_wall_clock_of_the_given_time_zone() {
        use chrono::TimeZone;
        let moscow = chrono::FixedOffset::east_opt(3 * 3600).unwrap();
        let time = moscow.timestamp_opt(11 * 3600 + 5 * 60 + 7, 0).unwrap();
        assert_eq!(log_line(&time, "Подключение…"), "14:05:07  Подключение…");
        assert_eq!(
            log_line(&time.with_timezone(&chrono::Utc), "x"),
            "11:05:07  x"
        );
    }
    #[tokio::test]
    async fn cancellation_interrupts_an_operation_that_ignores_the_transport() {
        let cancel = CancellationToken::new();
        let waiting = tokio::spawn({
            let cancel = cancel.clone();
            async move { interruptible(&cancel, std::future::pending::<()>()).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        cancel.cancel();
        let problem = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(!problem.retryable);
        assert_eq!(
            interruptible(&CancellationToken::new(), async { 7 })
                .await
                .unwrap(),
            7
        );
    }
    #[tokio::test]
    async fn stop_returns_promptly_while_a_silent_server_holds_the_connection() {
        let directory = tempfile::tempdir().unwrap();
        let manager = Manager::new(directory.path().join("hosts.json"));
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut tunnel = tunnel();
        tunnel.server.host = "127.0.0.1".into();
        tunnel.server.port = silent.local_addr().unwrap().port();
        manager.start(tunnel.clone()).await.unwrap();
        // Hold the socket open without an SSH banner.
        let (_held, _) = tokio::time::timeout(Duration::from_secs(3), silent.accept())
            .await
            .unwrap()
            .unwrap();
        let (states, waiting) = manager.states().await;
        assert_eq!(states[&tunnel.id], "connecting");
        assert!(waiting.is_empty());
        tokio::time::timeout(Duration::from_secs(2), manager.stop(&tunnel.id))
            .await
            .expect("stop must not wait for the network timeout")
            .unwrap();
        assert_eq!(manager.states().await.0[&tunnel.id], "stopped");
    }
    #[tokio::test]
    async fn accept_backoff_pauses_counts_and_resets() {
        let mut backoff = AcceptBackoff::default();
        assert!(backoff.ready());
        assert_eq!(backoff.failed(), 1);
        assert!(!backoff.ready());
        let start = tokio::time::Instant::now();
        tokio::time::sleep_until(backoff.resume_at()).await;
        assert!(start.elapsed() >= ACCEPT_RETRY);
        backoff.resume();
        assert!(backoff.ready());
        assert_eq!(backoff.failed(), 2);
        backoff.resume();
        backoff.succeeded();
        assert_eq!(backoff.failed(), 1, "a success starts a new series");
    }
    #[test]
    fn log_entries_keep_the_tunnel_state() {
        let mut runtime = Runtime::default();
        update(&mut runtime, "running", "Туннель работает");
        push_log(&mut runtime, "Ошибка приёма соединения");
        assert_eq!(
            (runtime.state.as_str(), runtime.message.as_str()),
            ("running", "Туннель работает")
        );
        assert_eq!(runtime.logs.len(), 2);
    }
    #[test]
    fn runtime_log_is_bounded() {
        let mut runtime = Runtime::default();
        for _ in 0..350 {
            update(&mut runtime, "connecting", "test");
        }
        assert_eq!(runtime.logs.len(), 300);
    }
}
