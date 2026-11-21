//! On-demand tests of a running tunnel's SSH session: the speed test (about 25 seconds) and the
//! stability test (minutes). They use the session the forwardings use, so they measure what the
//! applications get, and share its bandwidth with them. Downloads read `/dev/urandom` from an
//! exec channel, uploads go to `wc -c`; without a shell on the server only the delay is
//! measured. A test's channels never touch the session: a failed channel ends the step, a
//! cancelled test closes its channel, and a stopped tunnel ends its test.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use krot_udp_proto::metrics::Histogram;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::link::bytes_text;
use crate::metrics::Summary;

pub mod cli;
mod history;
pub mod report;
mod session;

pub use report::{Direction, Event, Kind, Sample, Stall, TestReport, TestStatus};
pub use session::{Access, BoxFuture, Gate, Pipe, Session};

/// A ping without an answer in this time is lost; the session stays as it is.
const PING_TIMEOUT: Duration = crate::link::PING_TIMEOUT;
const IDLE_PINGS: u32 = 10;
const IDLE_PING_GAP: Duration = Duration::from_millis(200);
/// Pause between pings while the speed test transfers.
const LOADED_PING_GAP: Duration = Duration::from_millis(500);
/// How long each direction of the speed test transfers at most.
const SPEED_PHASE: Duration = Duration::from_secs(10);
/// A transfer that makes no progress for longer has stalled.
const STALL_GAP: Duration = Duration::from_secs(2);
/// How long the server may take to confirm what it received, after the upload.
const CONFIRM: Duration = Duration::from_secs(10);
const STABILITY_PING_GAP: Duration = Duration::from_secs(2);
const MINUTE: Duration = Duration::from_secs(60);
/// The stability test's transfer in each direction, once a minute.
pub const STABILITY_TRANSFER: u64 = 256 * 1024;
const STABILITY_PHASE: Duration = Duration::from_secs(20);
pub const DEFAULT_LIMIT_MB: u64 = 100;
pub const MAX_LIMIT_MB: u64 = 10_000;
pub const MIN_STABILITY: Duration = Duration::from_secs(10);
pub const MAX_STABILITY: Duration = Duration::from_secs(24 * 3600);
const MIB: u64 = 1024 * 1024;

const NOT_FOUND: &str = "Тест не найден.";
const MARKER: &str = "KROT-TEST-OK";
const PROBE: &str = "echo KROT-TEST-OK";
/// `head -c` of GNU, BusyBox and BSD; random data, so that SSH compression changes nothing.
const DOWNLOAD: &str = "exec head -c \"$1\" /dev/urandom";
const UPLOAD: &str = "exec wc -c";

/// `test_start`: which test to run on which tunnel.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// ID of the tunnel.
    pub id: String,
    pub kind: Kind,
    /// Seconds of the stability test.
    #[serde(default)]
    pub duration: Option<u64>,
    #[serde(default)]
    pub limit_mb: Option<u64>,
}

/// A refusal worded by КРОТ itself for the user; the background process passes it on.
#[derive(Debug)]
pub struct Refusal(pub &'static str);

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for Refusal {}

fn refuse(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Refusal(message).into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestId {
    id: String,
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// One minute of the stability test.
#[derive(Default)]
struct Minute {
    rtt: Histogram,
    sent: u64,
    lost: u64,
    down_bps: Option<u64>,
    up_bps: Option<u64>,
}

/// Everything a running test has observed, kept behind a lock so that its status can be read
/// at any moment.
struct Run {
    origin: Instant,
    ended: Option<Instant>,
    report: TestReport,
    state: &'static str,
    phase: String,
    error: String,
    /// Bytes of the transfer going on, while there is one.
    moving: Option<Arc<AtomicU64>>,
    idle: Histogram,
    loaded: Histogram,
    transfers: u32,
    losses_in_row: u32,
    ping_stall: Option<Instant>,
    minutes: Vec<Minute>,
    down_rates: Vec<u64>,
    up_rates: Vec<u64>,
}

impl Run {
    fn new(origin: Instant, report: TestReport) -> Self {
        Self {
            origin,
            ended: None,
            report,
            state: "running",
            phase: String::new(),
            error: String::new(),
            moving: None,
            idle: Histogram::default(),
            loaded: Histogram::default(),
            transfers: 0,
            losses_in_row: 0,
            ping_stall: None,
            minutes: Vec::new(),
            down_rates: Vec::new(),
            up_rates: Vec::new(),
        }
    }
    fn offset(&self, at: Instant) -> f64 {
        at.saturating_duration_since(self.origin).as_secs_f64()
    }
    fn minute(&mut self, at: Instant) -> &mut Minute {
        let index = (at.saturating_duration_since(self.origin).as_secs() / 60) as usize;
        while self.minutes.len() <= index {
            self.minutes.push(Minute::default());
        }
        &mut self.minutes[index]
    }
    fn answered(&mut self, at: Instant, rtt: Duration) {
        self.report.ping_sent += 1;
        if self.transfers > 0 {
            self.loaded.record(rtt);
        } else {
            self.idle.record(rtt);
        }
        let minute = self.minute(at);
        minute.sent += 1;
        minute.rtt.record(rtt);
        self.end_ping_stall(at);
    }
    fn lost(&mut self, sent: Instant) {
        self.report.ping_sent += 1;
        self.report.ping_lost += 1;
        let minute = self.minute(sent);
        minute.sent += 1;
        minute.lost += 1;
        self.losses_in_row += 1;
        if self.losses_in_row == 1 {
            self.ping_stall.get_or_insert(sent);
        }
    }
    /// Two lost pings in a row and more were a stall, from the first lost ping on.
    fn end_ping_stall(&mut self, at: Instant) {
        let lost = std::mem::take(&mut self.losses_in_row);
        if let Some(since) = self.ping_stall.take()
            && lost >= crate::link::STALL_LOSSES
        {
            self.report.stalls.push(Stall {
                at_s: self.offset(since),
                direction: Direction::Ping,
                at_byte: None,
                duration_ms: at.saturating_duration_since(since).as_millis() as u64,
            });
        }
    }
    fn session_event(&mut self, at: Instant, kind: &str) {
        self.end_ping_stall(at);
        if kind == "reconnected" {
            self.report.reconnects += 1;
        }
        let at_s = self.offset(at);
        self.report.events.push(Event {
            at_s,
            kind: kind.into(),
        });
    }
    fn transferred(&mut self, direction: Direction, transfer: &Transfer) {
        for stall in &transfer.stalls {
            self.report.stalls.push(stall.clone());
        }
        match direction {
            Direction::Down => self.report.down_bytes += transfer.bytes,
            _ => self.report.up_bytes += transfer.bytes,
        }
    }
    fn skip(&mut self, reason: &str) {
        if !self.report.skipped.iter().any(|known| known == reason) {
            self.report.skipped.push(reason.into());
        }
    }
    fn note(&mut self, note: String) {
        self.report.notes.push(note);
    }
    /// The report as it stands, with the summaries computed.
    fn report(&self, now: Instant) -> TestReport {
        let now = self.ended.unwrap_or(now);
        let mut report = self.report.clone();
        report.duration_s = now.saturating_duration_since(self.origin).as_secs();
        report.idle_rtt = Summary::of(&self.idle);
        report.loaded_rtt = Summary::of(&self.loaded);
        if report.kind == Kind::Stability {
            let mean = |rates: &[u64]| {
                (!rates.is_empty()).then(|| rates.iter().sum::<u64>() / rates.len() as u64)
            };
            report.down_bps = mean(&self.down_rates);
            report.up_bps = mean(&self.up_rates);
            report.samples = self
                .minutes
                .iter()
                .enumerate()
                .map(|(index, minute)| Sample {
                    minute: index as u64,
                    rtt_p50_us: minute.rtt.quantile_us(0.50),
                    rtt_p95_us: minute.rtt.quantile_us(0.95),
                    sent: minute.sent,
                    lost: minute.lost,
                    down_bps: minute.down_bps,
                    up_bps: minute.up_bps,
                })
                .collect();
        }
        report
    }
    fn status(&self, id: &str, now: Instant) -> TestStatus {
        let mut phase = self.phase.clone();
        if let Some(bytes) = &self.moving {
            phase += &format!(": {}", bytes_text(bytes.load(Ordering::Relaxed)));
        }
        TestStatus {
            id: id.into(),
            state: self.state.into(),
            phase,
            elapsed_s: self
                .ended
                .unwrap_or(now)
                .saturating_duration_since(self.origin)
                .as_secs(),
            error: self.error.clone(),
            report: self.report(now),
        }
    }
}

type Shared = Arc<Mutex<Run>>;

fn lock(run: &Shared) -> std::sync::MutexGuard<'_, Run> {
    run.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Why a test cannot go on.
#[derive(Debug, PartialEq, Eq)]
enum Stop {
    /// The session ended in the middle of a step.
    Session,
    /// The tunnel stopped.
    Tunnel,
}

impl Stop {
    fn message(&self) -> &'static str {
        match self {
            Self::Session => "Сессия туннеля оборвалась во время теста.",
            Self::Tunnel => "Туннель остановлен.",
        }
    }
}

/// The current session; `Stop::Session` while the tunnel reconnects.
fn current(sessions: &watch::Receiver<Option<Access>>) -> Result<Access, Stop> {
    sessions.borrow().clone().ok_or(Stop::Session)
}

/// One ping: its round-trip time, `None` without an answer in time. `Err` once the session is
/// gone.
async fn ping(access: &Access) -> Result<Option<Duration>, Stop> {
    let answer = access
        .run(|session| async move {
            let sent = Instant::now();
            match tokio::time::timeout(PING_TIMEOUT, session.ping()).await {
                Ok(true) => Some(Some(sent.elapsed())),
                Ok(false) => None,
                Err(_) => Some(None),
            }
        })
        .await;
    answer.flatten().ok_or(Stop::Session)
}

/// Pings and records the answer; a ping lost to a gone session is not counted.
async fn ping_once(access: &Access, run: &Shared) -> Result<(), Stop> {
    let sent = Instant::now();
    match ping(access).await? {
        Some(rtt) => lock(run).answered(Instant::now(), rtt),
        None => lock(run).lost(sent),
    }
    Ok(())
}

/// Whether the server runs the test's commands: `None` when it refuses exec channels,
/// `Some(false)` when it runs something else, such as a `ForceCommand`.
async fn probe_shell(access: &Access) -> Result<Option<bool>, Stop> {
    let command = crate::udp::deliver::command(PROBE, &[]);
    access
        .run(|session| async move {
            let mut pipe = session.exec(command).await?;
            let mut output = Vec::new();
            let read = async {
                let mut buffer = [0u8; 256];
                while output.len() < 256 {
                    match pipe.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => output.extend_from_slice(&buffer[..read]),
                    }
                }
            };
            let _ = tokio::time::timeout(Duration::from_secs(10), read).await;
            Some(
                String::from_utf8_lossy(&output)
                    .lines()
                    .any(|line| line.trim() == MARKER),
            )
        })
        .await
        .ok_or(Stop::Session)
}

/// How a transfer ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Limit,
    Deadline,
    /// The server closed the channel before the limit.
    Closed,
    /// The server refused the command.
    Refused,
}

#[derive(Debug)]
struct Transfer {
    bytes: u64,
    elapsed: Duration,
    stalls: Vec<Stall>,
    end: End,
    /// The upload's byte count as the server saw it.
    confirmed: Option<u64>,
}

impl Transfer {
    fn refused() -> Self {
        Self {
            bytes: 0,
            elapsed: Duration::ZERO,
            stalls: Vec::new(),
            end: End::Refused,
            confirmed: None,
        }
    }
    fn bps(&self) -> Option<u64> {
        let seconds = self.elapsed.as_secs_f64();
        (self.bytes > 0 && seconds > 0.0).then(|| (self.bytes as f64 * 8.0 / seconds) as u64)
    }
}

/// Progress of a transfer, with the pauses longer than `STALL_GAP`.
struct Watch {
    origin: Instant,
    direction: Direction,
    last: Instant,
    bytes: u64,
    stalls: Vec<Stall>,
    shared: Arc<AtomicU64>,
}

impl Watch {
    fn new(origin: Instant, direction: Direction, shared: Arc<AtomicU64>) -> Self {
        Self {
            origin,
            direction,
            last: Instant::now(),
            bytes: 0,
            stalls: Vec::new(),
            shared,
        }
    }
    fn pause_until(&mut self, now: Instant) {
        let pause = now.saturating_duration_since(self.last);
        if pause > STALL_GAP {
            self.stalls.push(Stall {
                at_s: self
                    .last
                    .saturating_duration_since(self.origin)
                    .as_secs_f64(),
                direction: self.direction,
                at_byte: Some(self.bytes),
                duration_ms: pause.as_millis() as u64,
            });
        }
    }
    fn moved(&mut self, bytes: usize) {
        let now = Instant::now();
        self.pause_until(now);
        self.last = now;
        self.bytes += bytes as u64;
        self.shared.store(self.bytes, Ordering::Relaxed);
    }
}

/// Reads up to `limit` random bytes from the server for at most `time`.
async fn download(
    session: Arc<dyn Session>,
    limit: u64,
    time: Duration,
    origin: Instant,
    shared: Arc<AtomicU64>,
) -> Transfer {
    let command = crate::udp::deliver::command(DOWNLOAD, &[&limit.to_string()]);
    let Some(mut pipe) = session.exec(command).await else {
        return Transfer::refused();
    };
    let mut watch = Watch::new(origin, Direction::Down, shared);
    let start = watch.last;
    let deadline = start + time;
    let mut buffer = vec![0u8; 64 * 1024];
    let end = loop {
        let left = limit - watch.bytes;
        if left == 0 {
            break End::Limit;
        }
        let size = buffer
            .len()
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        match tokio::time::timeout_at(deadline, pipe.read(&mut buffer[..size])).await {
            Err(_) => break End::Deadline,
            Ok(Ok(0) | Err(_)) => break End::Closed,
            Ok(Ok(read)) => watch.moved(read),
        }
    };
    let finished = if end == End::Deadline {
        watch.pause_until(deadline);
        deadline
    } else {
        watch.last
    };
    Transfer {
        bytes: watch.bytes,
        elapsed: finished.saturating_duration_since(start),
        stalls: watch.stalls,
        end,
        confirmed: None,
    }
}

/// Sends up to `limit` bytes to the server for at most `time`, then waits for the server's count.
async fn upload(
    session: Arc<dyn Session>,
    limit: u64,
    time: Duration,
    origin: Instant,
    shared: Arc<AtomicU64>,
) -> Transfer {
    let command = crate::udp::deliver::command(UPLOAD, &[]);
    let Some(mut pipe) = session.exec(command).await else {
        return Transfer::refused();
    };
    // Random data, longer than the window of SSH compression.
    let mut data = vec![0u8; 64 * 1024];
    rand::fill(&mut data[..]);
    let mut watch = Watch::new(origin, Direction::Up, shared);
    let start = watch.last;
    let deadline = start + time;
    let end = loop {
        let left = limit - watch.bytes;
        if left == 0 {
            break End::Limit;
        }
        let size = data.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        match tokio::time::timeout_at(deadline, pipe.write(&data[..size])).await {
            Err(_) => break End::Deadline,
            Ok(Ok(0) | Err(_)) => break End::Closed,
            Ok(Ok(written)) => watch.moved(written),
        }
    };
    if end == End::Deadline {
        watch.pause_until(deadline);
    }
    let mut confirmed = None;
    if end != End::Closed {
        let confirm = async {
            pipe.shutdown().await.ok()?;
            let mut output = Vec::new();
            let mut buffer = [0u8; 64];
            while output.len() < 64 {
                match pipe.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => output.extend_from_slice(&buffer[..read]),
                }
            }
            String::from_utf8_lossy(&output).trim().parse::<u64>().ok()
        };
        confirmed = tokio::time::timeout(CONFIRM, confirm).await.ok().flatten();
    }
    // Written bytes may still wait in buffers; the server's count arrives after all of them.
    let finished = if confirmed.is_some() {
        Instant::now()
    } else {
        watch.last.max(start)
    };
    Transfer {
        bytes: confirmed.unwrap_or(watch.bytes).min(watch.bytes),
        elapsed: finished.saturating_duration_since(start),
        stalls: watch.stalls,
        end,
        confirmed,
    }
}

/// Runs a transfer on the session while the run counts it as load.
async fn transfer(
    access: &Access,
    run: &Shared,
    direction: Direction,
    limit: u64,
    time: Duration,
) -> Result<Transfer, Stop> {
    let shared = Arc::new(AtomicU64::new(0));
    let origin = {
        let mut run = lock(run);
        run.transfers += 1;
        run.moving = Some(shared.clone());
        run.origin
    };
    let result = access
        .run(move |session| async move {
            match direction {
                Direction::Down => download(session, limit, time, origin, shared).await,
                _ => upload(session, limit, time, origin, shared).await,
            }
        })
        .await;
    let mut locked = lock(run);
    locked.transfers -= 1;
    locked.moving = None;
    result.ok_or(Stop::Session)
}

/// Pings every `gap` while `work` runs, and returns what `work` returns.
async fn with_pings<T>(
    access: &Access,
    run: &Shared,
    gap: Duration,
    work: impl std::future::Future<Output = T>,
) -> T {
    let pinging = async {
        loop {
            let next = Instant::now() + gap;
            if ping_once(access, run).await.is_err() {
                std::future::pending::<()>().await;
            }
            tokio::time::sleep_until(next).await;
        }
    };
    tokio::select! {
        result = work => result,
        () = pinging => unreachable!("pings run until the work ends"),
    }
}

fn mib(bytes: u64) -> String {
    bytes_text(bytes)
}

/// Notes what is worth noting about a finished transfer.
fn note_transfer(run: &Shared, direction: Direction, transfer: &Transfer, limit: u64) {
    let mut run = lock(run);
    run.transferred(direction, transfer);
    let what = if direction == Direction::Down {
        "Скачивание"
    } else {
        "Отдача"
    };
    match transfer.end {
        End::Closed if direction == Direction::Down => run.note(format!(
            "Скачивание остановилось на {}: сервер закрыл канал теста раньше лимита {}.",
            mib(transfer.bytes),
            mib(limit)
        )),
        End::Closed => run.note(format!(
            "Отдача остановилась на {}: сервер закрыл канал теста.",
            mib(transfer.bytes)
        )),
        End::Deadline
            if direction == Direction::Down
                && transfer.stalls.last().is_some_and(|stall| {
                    stall.at_byte == Some(transfer.bytes) && transfer.bytes < limit
                }) =>
        {
            run.note(format!(
                "Скачивание остановилось на {} и не возобновилось до конца шага.",
                mib(transfer.bytes)
            ))
        }
        End::Limit | End::Deadline
            if direction == Direction::Up && transfer.confirmed.is_none() =>
        {
            run.note(format!(
                "{what}: сервер не подтвердил полученный объём, скорость оценена по отправленному."
            ))
        }
        _ => {}
    }
}

const NO_EXEC: &str = "скорость не измерена: SSH-сервер не разрешает выполнять команды.";
const NO_SHELL: &str = "скорость не измерена: SSH-сервер не выполняет команды оболочки (например, задан ForceCommand).";

/// Whether to transfer: notes the reason when not.
async fn shell_ready(access: &Access, run: &Shared) -> Result<bool, Stop> {
    lock(run).phase = "Проверка команд на сервере".into();
    let shell = probe_shell(access).await?;
    match shell {
        Some(true) => Ok(true),
        Some(false) => {
            lock(run).skip(NO_SHELL);
            Ok(false)
        }
        None => {
            lock(run).skip(NO_EXEC);
            Ok(false)
        }
    }
}

async fn speed(
    sessions: watch::Receiver<Option<Access>>,
    run: Shared,
    limit: u64,
) -> Result<(), Stop> {
    let access = current(&sessions)?;
    lock(&run).phase = "Задержка без нагрузки".into();
    for _ in 0..IDLE_PINGS {
        let next = Instant::now() + IDLE_PING_GAP;
        ping_once(&access, &run).await?;
        tokio::time::sleep_until(next).await;
    }
    if !shell_ready(&access, &run).await? {
        return Ok(());
    }
    for (direction, phase) in [(Direction::Down, "Скачивание"), (Direction::Up, "Отдача")]
    {
        lock(&run).phase = phase.into();
        let work = transfer(&access, &run, direction, limit, SPEED_PHASE);
        let result = with_pings(&access, &run, LOADED_PING_GAP, work).await?;
        if result.end == End::Refused {
            lock(&run).note(format!("{phase}: сервер отказал в канале теста."));
            continue;
        }
        note_transfer(&run, direction, &result, limit);
        let mut locked = lock(&run);
        match direction {
            Direction::Down => locked.report.down_bps = result.bps(),
            _ => locked.report.up_bps = result.bps(),
        }
    }
    Ok(())
}

/// Follows the tunnel's sessions: records disconnects and reconnects. Returns when the
/// tunnel stops.
async fn follow(mut sessions: watch::Receiver<Option<Access>>, run: Shared) -> Stop {
    let mut last = sessions.borrow().as_ref().map(|access| access.session);
    let mut connected = last.is_some();
    loop {
        if sessions.changed().await.is_err() {
            return Stop::Tunnel;
        }
        let now = sessions
            .borrow_and_update()
            .as_ref()
            .map(|access| access.session);
        match now {
            None if connected => {
                connected = false;
                lock(&run).session_event(Instant::now(), "disconnected");
            }
            Some(number) if Some(number) != last => {
                if connected {
                    // The new session came before the old one was seen to go.
                    lock(&run).session_event(Instant::now(), "disconnected");
                }
                connected = true;
                last = Some(number);
                lock(&run).session_event(Instant::now(), "reconnected");
            }
            _ => {}
        }
    }
}

async fn stability(
    sessions: watch::Receiver<Option<Access>>,
    run: Shared,
    duration: Duration,
) -> Result<(), Stop> {
    let origin = lock(&run).origin;
    current(&sessions)?;
    lock(&run).phase = "Проверка стабильности".into();
    let pinging = async {
        let mut next = origin;
        loop {
            if let Ok(access) = current(&sessions) {
                let _ = ping_once(&access, &run).await;
            }
            next += STABILITY_PING_GAP;
            tokio::time::sleep_until(next.max(Instant::now())).await;
        }
    };
    let transferring = async {
        let mut shell = None;
        let mut minute = 0u32;
        loop {
            let at = origin + MINUTE * minute;
            if at >= origin + duration {
                // No transfer starts as the test ends.
                std::future::pending::<()>().await;
            }
            tokio::time::sleep_until(at).await;
            minute += 1;
            let Ok(access) = current(&sessions) else {
                continue;
            };
            if shell.is_none() {
                match shell_ready(&access, &run).await {
                    Ok(ready) => shell = Some(ready),
                    Err(_) => continue,
                }
                lock(&run).phase = "Проверка стабильности".into();
            }
            if shell != Some(true) {
                std::future::pending::<()>().await;
            }
            let at = Instant::now();
            let mut rates = [None, None];
            for (slot, direction) in [Direction::Down, Direction::Up].into_iter().enumerate() {
                let Ok(result) = transfer(
                    &access,
                    &run,
                    direction,
                    STABILITY_TRANSFER,
                    STABILITY_PHASE,
                )
                .await
                else {
                    break;
                };
                if result.end == End::Refused {
                    continue;
                }
                note_transfer(&run, direction, &result, STABILITY_TRANSFER);
                rates[slot] = result.bps();
            }
            let mut locked = lock(&run);
            if let Some(rate) = rates[0] {
                locked.down_rates.push(rate);
            }
            if let Some(rate) = rates[1] {
                locked.up_rates.push(rate);
            }
            let sample = locked.minute(at);
            sample.down_bps = rates[0];
            sample.up_bps = rates[1];
        }
    };
    tokio::select! {
        () = tokio::time::sleep_until(origin + duration) => {
            lock(&run).end_ping_stall(Instant::now());
            Ok(())
        },
        stop = follow(sessions.clone(), run.clone()) => Err(stop),
        () = pinging => unreachable!("pings run until the test ends"),
        () = transferring => unreachable!("transfers run until the test ends"),
    }
}

/// One test: its state for the status, and the way to cancel it.
struct Job {
    id: String,
    run: Shared,
    cancel: CancellationToken,
}

/// The tests of the background process: at most one per tunnel, the last one kept with its
/// result after it ends.
pub struct Tests {
    jobs: Mutex<HashMap<String, Job>>,
    history: Option<PathBuf>,
}

impl Tests {
    /// `history` is the file that keeps the results of finished tests.
    pub fn new(history: Option<PathBuf>) -> Self {
        Self {
            jobs: Mutex::default(),
            history,
        }
    }
    fn jobs(&self) -> std::sync::MutexGuard<'_, HashMap<String, Job>> {
        self.jobs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    /// Starts a test on the tunnel whose sessions `gate` publishes.
    pub fn start(&self, gate: &Gate, request: Request) -> Result<String> {
        let limit_mb = request.limit_mb.unwrap_or(DEFAULT_LIMIT_MB);
        refuse(
            (1..=MAX_LIMIT_MB).contains(&limit_mb),
            "Лимит объёма теста — от 1 до 10000 МБ.",
        )?;
        let duration = match request.kind {
            Kind::Speed => Duration::ZERO,
            Kind::Stability => {
                let duration = Duration::from_secs(request.duration.unwrap_or(30 * 60));
                refuse(
                    (MIN_STABILITY..=MAX_STABILITY).contains(&duration),
                    "Длительность теста стабильности — от 10 секунд до 24 часов.",
                )?;
                duration
            }
        };
        let sessions = gate.subscribe();
        refuse(
            sessions.borrow().is_some(),
            "Туннель не подключён. Дождитесь подключения и повторите тест.",
        )?;
        let mut jobs = self.jobs();
        if let Some(job) = jobs.get(&request.id) {
            refuse(
                lock(&job.run).state != "running",
                "Тест этого туннеля уже идёт.",
            )?;
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        let report = TestReport {
            tunnel: request.id.clone(),
            kind: request.kind,
            started_at: unix_now(),
            planned_s: (request.kind == Kind::Stability).then_some(duration.as_secs()),
            limit_bytes: limit_mb * MIB,
            ..Default::default()
        };
        let run: Shared = Arc::new(Mutex::new(Run::new(Instant::now(), report)));
        let cancel = CancellationToken::new();
        let task = {
            let (run, cancel) = (run.clone(), cancel.clone());
            let history = self.history.clone();
            let limit = limit_mb * MIB;
            let id = id.clone();
            async move {
                let test = async {
                    match request.kind {
                        Kind::Speed => speed(sessions, run.clone(), limit).await,
                        Kind::Stability => stability(sessions, run.clone(), duration).await,
                    }
                };
                let outcome = tokio::select! {
                    outcome = test => Some(outcome),
                    () = cancel.cancelled() => None,
                };
                let finished = {
                    let mut locked = lock(&run);
                    let now = Instant::now();
                    locked.end_ping_stall(now);
                    locked.ended = Some(now);
                    locked.moving = None;
                    locked.phase.clear();
                    match outcome {
                        Some(Ok(())) => locked.state = "done",
                        Some(Err(stop)) => {
                            locked.state = "failed";
                            locked.error = stop.message().into();
                        }
                        None => locked.state = "cancelled",
                    }
                    locked.status(&id, now)
                };
                if let Some(path) = history {
                    let _ =
                        tokio::task::spawn_blocking(move || history::append(&path, finished)).await;
                }
            }
        };
        jobs.insert(
            request.id.clone(),
            Job {
                id: id.clone(),
                run,
                cancel,
            },
        );
        tokio::spawn(task);
        Ok(id)
    }
    fn find<T>(&self, id: &str, then: impl FnOnce(&Job) -> T) -> Option<T> {
        self.jobs().values().find(|job| job.id == id).map(then)
    }
    pub fn status(&self, id: &str) -> Option<TestStatus> {
        self.find(id, |job| lock(&job.run).status(&job.id, Instant::now()))
    }
    /// Cancels a running test; `false` for an unknown one.
    pub fn cancel(&self, id: &str) -> bool {
        self.find(id, |job| job.cancel.cancel()).is_some()
    }
    /// The last test of every tunnel, by tunnel, without the minutes: the snapshot is read
    /// several times a second, and `test_status` has them.
    pub fn snapshot(&self) -> HashMap<String, TestStatus> {
        let now = Instant::now();
        self.jobs()
            .iter()
            .map(|(tunnel, job)| {
                let mut status = lock(&job.run).status(&job.id, now);
                status.report.samples.clear();
                (tunnel.clone(), status)
            })
            .collect()
    }
    /// Commands of the local protocol: `test_start`, `test_status` and `test_cancel`.
    pub async fn execute(
        &self,
        manager: &crate::ssh::Manager,
        command: &str,
        payload: Value,
    ) -> Result<Value> {
        match command {
            "test_start" => {
                let request: Request =
                    serde_json::from_value(payload).context("Некорректный запрос теста.")?;
                let Some(link) = manager.link(&request.id).await else {
                    return Err(Refusal("Туннель не запущен.").into());
                };
                let id = self.start(link.gate(), request)?;
                Ok(json!({ "id": id }))
            }
            "test_status" | "test_cancel" => {
                let TestId { id } = serde_json::from_value(payload).context("Укажите ID теста.")?;
                if command == "test_cancel" {
                    refuse(self.cancel(&id), NOT_FOUND)?;
                    return Ok(Value::Null);
                }
                match self.status(&id) {
                    Some(status) => Ok(serde_json::to_value(status)?),
                    None => Err(Refusal(NOT_FOUND).into()),
                }
            }
            _ => bail!("Неизвестная команда теста."),
        }
    }
}

impl Drop for Tests {
    fn drop(&mut self) {
        for job in self.jobs().values() {
            job.cancel.cancel();
        }
    }
}

#[cfg(test)]
mod tests;
