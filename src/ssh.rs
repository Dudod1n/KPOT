//! Native SSH transport, forwarding, and application-owned connection lifetime.
use crate::config::{Endpoint, Tunnel, atomic_json, validate_tunnel};
use anyhow::{Result, anyhow, bail};
use russh::client::{self, ChannelOpenHandle};
use russh::keys::{self, HashAlg, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelOpenFailure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
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
}
struct Inner {
    known_hosts: PathBuf,
    state: Mutex<State>,
    lifecycle: Mutex<()>,
    trust_write: Mutex<()>,
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
        }))
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
    ) -> std::result::Result<(), Problem> {
        let identity = format!(
            "[{}]:{}",
            endpoint.host.trim_matches(['[', ']']).to_lowercase(),
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
        let mut credentials = HashMap::new();
        let mut delay = 1;
        loop {
            let mut attempt = Attempt::new(cancel.child_token());
            let result = {
                let forward = self.forward(&tunnel, &mut attempt, &mut credentials);
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
        self.0
            .state
            .lock()
            .await
            .prompts
            .retain(|_, p| p.prompt.request.tunnel_id != tunnel.id);
    }
    async fn forward(
        &self,
        tunnel: &Tunnel,
        attempt: &mut Attempt,
        credentials: &mut HashMap<String, Credential>,
    ) -> std::result::Result<(), Problem> {
        if attempt.cancel.is_cancelled() {
            return Err(CANCELLED);
        }
        let jumps = if tunnel.jumps_enabled {
            tunnel.jumps.as_slice()
        } else {
            &[]
        };
        let (remote_send, mut remote_receive) = mpsc::channel(64);
        let expected = Arc::new(StdMutex::new(None));
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
            self.state(
                &tunnel.id,
                "connecting",
                &format!("{hop}: {}", endpoint.address()),
                Some(&hop),
            )
            .await;
            let stream: Box<dyn Transport> = if let Some(previous) = attempt.sessions.last() {
                let channel = timed(previous.channel_open_direct_tcpip(
                    endpoint.host.trim_matches(['[', ']']),
                    u32::from(endpoint.port),
                    "127.0.0.1",
                    0,
                ))
                .await??;
                Box::new(channel.into_stream())
            } else {
                Box::new(
                    timed(TcpStream::connect((
                        endpoint.host.trim_matches(['[', ']']),
                        endpoint.port,
                    )))
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
                    Some(remote_send.clone())
                } else {
                    None
                },
                expected: expected.clone(),
                failure: attempt.failure.clone(),
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
            )
            .await?;
        }
        let connection = attempt.sessions.last().cloned().ok_or(NETWORK)?;
        if tunnel.kind == "R" {
            *expected.lock().unwrap() = Some(RemoteRoute {
                address: tunnel.bind.clone(),
                port: tunnel.port,
            });
            timed(
                connection
                    .tcpip_forward(tunnel.bind.trim_matches(['[', ']']), u32::from(tunnel.port)),
            )
            .await?
            .map_err(|error| match error {
                russh::Error::RequestDenied => {
                    Problem::terminal("SSH-сервер не разрешил удалённый порт или порт уже занят.")
                }
                _ => NETWORK,
            })?;
        } else {
            attempt.listener = Some(
                timed(TcpListener::bind((
                    tunnel.bind.trim_matches(['[', ']']),
                    tunnel.port,
                )))
                .await?
                .map_err(bind_problem)?,
            );
        }
        self.state(&tunnel.id, "running", "Туннель работает", None)
            .await;
        attempt.started = true;
        let mut check = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = attempt.cancel.cancelled() => return Err(CANCELLED),
                _ = check.tick() => if attempt.sessions.iter().any(|session| session.is_closed()) { return Err(attempt.failure.lock().unwrap().take().unwrap_or(NETWORK)); },
                Some(_) = attempt.copies.join_next(), if !attempt.copies.is_empty() => {},
                accepted = accept_optional(attempt.listener.as_ref()), if attempt.listener.is_some() => {
                    let (socket, origin) = accepted.map_err(|_| NETWORK)?;
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
                        match timed(TcpStream::connect((target.trim_matches(['[', ']']), port))).await {
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
    async fn authenticate(
        &self,
        session: &mut client::Handle<Handler>,
        tunnel: &Tunnel,
        endpoint: &Endpoint,
        hop: &str,
        credentials: &mut HashMap<String, Credential>,
        cancel: &CancellationToken,
    ) -> std::result::Result<(), Problem> {
        if timed(session.authenticate_none(&endpoint.user))
            .await??
            .success()
        {
            return Ok(());
        }
        let identity = serde_json::to_string(endpoint).map_err(|_| AUTH)?;
        let success = if endpoint.auth == "password" {
            if !credentials.contains_key(&identity) {
                let secret = self
                    .credential("password", tunnel, endpoint, hop, cancel)
                    .await?;
                credentials.insert(identity.clone(), Credential::Password(secret));
            }
            let Some(Credential::Password(secret)) = credentials.get(&identity) else {
                return Err(AUTH);
            };
            timed(session.authenticate_password(&endpoint.user, secret.as_str()))
                .await??
                .success()
        } else if endpoint.auth == "key" {
            if !credentials.contains_key(&identity) {
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
                credentials.insert(identity.clone(), Credential::Key(Arc::new(key)));
            }
            let Some(Credential::Key(key)) = credentials.get(&identity) else {
                return Err(KEY_FILE);
            };
            let hash = timed(session.best_supported_rsa_hash()).await??.flatten();
            timed(session.authenticate_publickey(
                &endpoint.user,
                keys::key::PrivateKeyWithHashAlg::new(key.clone(), hash),
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
    let seconds = now() as u64 % 86400;
    runtime.logs.push_back(format!(
        "{:02}:{:02}:{:02}  {message}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    ));
    while runtime.logs.len() > 300 {
        runtime.logs.pop_front();
    }
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
fn bind_problem(_: io::Error) -> Problem {
    Problem::terminal(
        "Не удалось открыть локальный порт. Проверьте адрес, права и занятость порта.",
    )
}
enum Credential {
    Password(Zeroizing<String>),
    Key(Arc<PrivateKey>),
}
fn expand_key_path(path: &str) -> PathBuf {
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
            .trust(&self.tunnel, &self.endpoint, &self.hop, &key, &self.cancel)
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
    let configured = route.address.trim_matches(['[', ']']).to_lowercase();
    let address = address.trim_matches(['[', ']']).to_lowercase();
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
            let result = match identity {
                keys::agent::AgentIdentity::PublicKey { key, .. } => {
                    session
                        .authenticate_publickey_with(user, key, hash, &mut agent)
                        .await
                }
                keys::agent::AgentIdentity::Certificate { certificate, .. } => {
                    session
                        .authenticate_certificate_with(user, certificate, hash, &mut agent)
                        .await
                }
            }
            .map_err(|_| AUTH)?;
            if result.success() {
                return Ok(true);
            }
        }
        Ok(false)
    }
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
        target.trim_matches(['[', ']']),
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
    fn runtime_log_is_bounded() {
        let mut runtime = Runtime::default();
        for _ in 0..350 {
            update(&mut runtime, "connecting", "test");
        }
        assert_eq!(runtime.logs.len(), 300);
    }
}
