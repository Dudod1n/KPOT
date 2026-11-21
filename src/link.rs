//! Constant measurement of a running tunnel's SSH session: round-trip time of `keepalive@openssh.com`
//! pings, lost pings, stalls, reconnects and the traffic of its forwardings. It costs about ten
//! bytes per second, never closes the session (keepalive does that) and keeps a lock off the
//! data path: the forwardings only add to two atomic counters.
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, MissedTickBehavior};

use crate::metrics::{Summary, Windowed};

/// Pause between pings, and how long a ping may wait for its answer before it counts as lost.
pub const PING_INTERVAL: Duration = Duration::from_secs(10);
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// The first ping goes out soon after connecting, so that the delay shows at once.
const FIRST_PING: Duration = Duration::from_secs(1);
/// How often the traffic counters are read, and the span the current rate is measured over.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
pub const RATE_WINDOW: Duration = Duration::from_secs(5);
/// Lost pings in a row that make a stall.
pub const STALL_LOSSES: u32 = 2;
/// Silence of incoming data while the applications keep sending and no ping got through that
/// makes a stall. A ping answered during the silence shows the session alive: the other side
/// just has nothing to say.
pub const STALL_SILENCE: Duration = Duration::from_secs(15);
/// The RTT histogram rolls once a minute; its window covers the last ten minutes.
const RTT_INTERVAL: Duration = Duration::from_secs(60);
/// Round-trip times the jitter is averaged over: the last ten minutes of pings.
const JITTER_SAMPLES: usize = 60;
const EVENTS: usize = 32;

/// What the snapshot and `krot-cli metrics` show about a running tunnel's session. Every
/// field is optional on the wire, so older and newer clients read each other's snapshots.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LinkStats {
    /// Unix time the current session connected; empty while the tunnel reconnects.
    pub connected_since: Option<f64>,
    /// Seconds the current session has been up.
    pub uptime_s: u64,
    /// Sessions after the first one since the tunnel was started.
    pub reconnects: u64,
    /// The latest connects, disconnects with their reasons, and stalls, oldest first.
    pub events: Vec<LinkEvent>,
    /// Ping round-trip time over the last ten minutes.
    pub rtt: Summary,
    /// Mean difference between consecutive round-trip times.
    pub jitter_us: Option<u64>,
    pub ping_sent: u64,
    /// Pings without an answer within five seconds.
    pub ping_lost: u64,
    pub stalls: u64,
    /// A stall is going on now.
    pub stalled: bool,
    /// Current rate over the last five seconds, in bits per second.
    pub rx_bps: u64,
    pub tx_bps: u64,
    /// Bytes through the forwardings since the tunnel was started.
    pub rx_total: u64,
    pub tx_total: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LinkEvent {
    /// Unix time.
    pub at: f64,
    /// `connected`, `reconnected`, `disconnected`, `stall` or `recovered`.
    pub kind: String,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    Losses,
    Silence,
}

/// The measurement itself, fed with the time of every observation so that it can be tested
/// without a session or a clock.
#[derive(Debug)]
pub struct Meter {
    origin: (Instant, f64),
    connected: Option<Instant>,
    sessions: u64,
    events: VecDeque<LinkEvent>,
    rtt: Windowed,
    rolled: Instant,
    recent: VecDeque<u64>,
    ping_sent: u64,
    ping_lost: u64,
    losses_in_row: u32,
    stalls: u64,
    stall: Option<(Instant, Cause)>,
    /// Counter readings `(at, rx, tx)` of the last `RATE_WINDOW`.
    samples: VecDeque<(Instant, u64, u64)>,
    received_at: Option<Instant>,
    sent_at: Option<Instant>,
    answered_at: Option<Instant>,
}

impl Meter {
    /// `wall` is the Unix time at `now`; event times are counted from it.
    pub fn new(now: Instant, wall: f64) -> Self {
        Self {
            origin: (now, wall),
            connected: None,
            sessions: 0,
            events: VecDeque::new(),
            rtt: Windowed::default(),
            rolled: now,
            recent: VecDeque::new(),
            ping_sent: 0,
            ping_lost: 0,
            losses_in_row: 0,
            stalls: 0,
            stall: None,
            samples: VecDeque::new(),
            received_at: None,
            sent_at: None,
            answered_at: None,
        }
    }
    fn wall(&self, at: Instant) -> f64 {
        self.origin.1 + at.saturating_duration_since(self.origin.0).as_secs_f64()
    }
    fn event(&mut self, at: Instant, kind: &str, detail: String) {
        if self.events.len() == EVENTS {
            self.events.pop_front();
        }
        let at = self.wall(at);
        self.events.push_back(LinkEvent {
            at,
            kind: kind.into(),
            detail,
        });
    }
    pub fn connected(&mut self, at: Instant) {
        self.sessions += 1;
        self.connected = Some(at);
        self.losses_in_row = 0;
        self.stall = None;
        self.samples.clear();
        self.received_at = None;
        self.sent_at = None;
        self.answered_at = None;
        if self.sessions == 1 {
            self.event(at, "connected", "Сессия установлена.".into());
        } else {
            let detail = format!("Переподключение № {}.", self.sessions - 1);
            self.event(at, "reconnected", detail);
        }
    }
    pub fn disconnected(&mut self, at: Instant, reason: &str) {
        if self.connected.take().is_none() {
            return;
        }
        self.stall = None;
        self.samples.clear();
        self.event(at, "disconnected", reason.into());
    }
    pub fn ping_answered(&mut self, at: Instant, rtt: Duration) {
        if self.connected.is_none() {
            return;
        }
        self.ping_sent += 1;
        self.rtt.record(rtt);
        if self.recent.len() == JITTER_SAMPLES {
            self.recent.pop_front();
        }
        self.recent
            .push_back(u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX));
        self.losses_in_row = 0;
        self.answered_at = Some(at);
        self.recover(at);
    }
    pub fn ping_lost(&mut self, at: Instant) {
        if self.connected.is_none() {
            return;
        }
        self.ping_sent += 1;
        self.ping_lost += 1;
        self.losses_in_row += 1;
        if self.losses_in_row >= STALL_LOSSES {
            self.stall_begins(at, Cause::Losses);
        }
    }
    /// Reads the forwardings' byte counters, once a second.
    pub fn sample(&mut self, at: Instant, rx: u64, tx: u64) {
        if self.connected.is_none() {
            return;
        }
        if at.saturating_duration_since(self.rolled) >= RTT_INTERVAL {
            self.rtt.roll();
            self.rolled = at;
        }
        if let Some(&(_, last_rx, last_tx)) = self.samples.back() {
            if rx > last_rx {
                self.received_at = Some(at);
                self.recover(at);
            }
            if tx > last_tx {
                self.sent_at = Some(at);
            }
        }
        self.samples.push_back((at, rx, tx));
        while self
            .samples
            .front()
            .is_some_and(|(first, ..)| at.saturating_duration_since(*first) > RATE_WINDOW)
        {
            self.samples.pop_front();
        }
        if let (Some(received), Some(sent)) = (self.received_at, self.sent_at) {
            let silent = at.saturating_duration_since(received) >= STALL_SILENCE;
            let sending = at.saturating_duration_since(sent) <= 2 * SAMPLE_INTERVAL;
            let unanswered = self.answered_at.is_none_or(|answered| answered <= received);
            if silent && sending && unanswered {
                self.stall_begins(at, Cause::Silence);
            }
        }
    }
    fn stall_begins(&mut self, at: Instant, cause: Cause) {
        if self.stall.is_some() {
            return;
        }
        self.stalls += 1;
        self.stall = Some((at, cause));
        let detail = match cause {
            Cause::Losses => format!("{STALL_LOSSES} ping подряд без ответа."),
            Cause::Silence => format!(
                "Нет входящих данных {} с при активной передаче.",
                STALL_SILENCE.as_secs()
            ),
        };
        self.event(at, "stall", detail);
    }
    fn recover(&mut self, at: Instant) {
        if let Some((since, _)) = self.stall.take() {
            let seconds = at.saturating_duration_since(since).as_secs();
            self.event(
                at,
                "recovered",
                format!("Замирание прошло через {seconds} с."),
            );
        }
    }
    /// Bits per second received and sent over the last `RATE_WINDOW`; zero without fresh readings.
    fn rates(&self, at: Instant) -> (u64, u64) {
        let (Some(&(first, rx0, tx0)), Some(&(last, rx1, tx1))) =
            (self.samples.front(), self.samples.back())
        else {
            return (0, 0);
        };
        let span = last.saturating_duration_since(first).as_secs_f64();
        if span <= 0.0 || at.saturating_duration_since(last) > 3 * SAMPLE_INTERVAL {
            return (0, 0);
        }
        let rate = |from: u64, to: u64| (to.saturating_sub(from) as f64 * 8.0 / span) as u64;
        (rate(rx0, rx1), rate(tx0, tx1))
    }
    fn jitter_us(&self) -> Option<u64> {
        if self.recent.len() < 2 {
            return None;
        }
        let differences: u64 = self
            .recent
            .iter()
            .zip(self.recent.iter().skip(1))
            .map(|(a, b)| a.abs_diff(*b))
            .sum();
        Some(differences / (self.recent.len() as u64 - 1))
    }
    pub fn stats(&self, at: Instant, rx_total: u64, tx_total: u64) -> LinkStats {
        let (rx_bps, tx_bps) = self.rates(at);
        LinkStats {
            connected_since: self.connected.map(|since| self.wall(since)),
            uptime_s: self
                .connected
                .map_or(0, |since| at.saturating_duration_since(since).as_secs()),
            reconnects: self.sessions.saturating_sub(1),
            events: self.events.iter().cloned().collect(),
            rtt: self.rtt.summary(),
            jitter_us: self.jitter_us(),
            ping_sent: self.ping_sent,
            ping_lost: self.ping_lost,
            stalls: self.stalls,
            stalled: self.stall.is_some(),
            rx_bps,
            tx_bps,
            rx_total,
            tx_total,
        }
    }
}

/// Bytes through a tunnel's forwardings. Shared by every forwarded connection, so it holds
/// only atomics.
#[derive(Debug, Default)]
pub struct Counters {
    rx: AtomicU64,
    tx: AtomicU64,
}

impl Counters {
    pub fn totals(&self) -> (u64, u64) {
        (
            self.rx.load(Ordering::Relaxed),
            self.tx.load(Ordering::Relaxed),
        )
    }
}

/// A forwarded SSH stream that counts what it reads as received and what it writes as sent.
pub struct Counted<S> {
    inner: S,
    counters: Arc<Counters>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, counters: Arc<Counters>) -> Self {
        Self { inner, counters }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let read = buf.filled().len().saturating_sub(before);
        if read > 0 {
            self.counters.rx.fetch_add(read as u64, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result {
            self.counters
                .tx
                .fetch_add(written as u64, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The measurement of one tunnel from its start to its stop, across reconnects.
#[derive(Debug)]
pub struct Link {
    counters: Arc<Counters>,
    meter: Mutex<Meter>,
    /// The current session for the speed and stability tests.
    gate: crate::quality::Gate,
}

impl Default for Link {
    fn default() -> Self {
        Self::new()
    }
}

impl Link {
    pub fn new() -> Self {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self {
            counters: Arc::default(),
            meter: Mutex::new(Meter::new(Instant::now(), wall)),
            gate: crate::quality::Gate::default(),
        }
    }
    pub fn gate(&self) -> &crate::quality::Gate {
        &self.gate
    }
    pub fn counters(&self) -> Arc<Counters> {
        self.counters.clone()
    }
    fn meter(&self) -> std::sync::MutexGuard<'_, Meter> {
        self.meter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    pub fn connected(&self) {
        self.meter().connected(Instant::now());
    }
    pub fn disconnected(&self, reason: &str) {
        self.meter().disconnected(Instant::now(), reason);
    }
    pub fn stats(&self) -> LinkStats {
        let (rx, tx) = self.counters.totals();
        self.meter().stats(Instant::now(), rx, tx)
    }
    /// Pings the session and reads the counters until `ping` reports the session gone. `ping`
    /// resolves `true` on an answer; one without an answer in `PING_TIMEOUT` counts as lost
    /// and leaves the session alone.
    pub async fn probe<P, F>(&self, mut ping: P)
    where
        P: FnMut() -> F,
        F: Future<Output = bool>,
    {
        let pinging = async {
            let mut next = Instant::now() + FIRST_PING;
            loop {
                tokio::time::sleep_until(next).await;
                next += PING_INTERVAL;
                let sent = Instant::now();
                match tokio::time::timeout(PING_TIMEOUT, ping()).await {
                    Ok(true) => {
                        let now = Instant::now();
                        self.meter().ping_answered(now, now - sent);
                    }
                    Ok(false) => return,
                    Err(_) => self.meter().ping_lost(Instant::now()),
                }
            }
        };
        let sampling = async {
            let mut tick = tokio::time::interval(SAMPLE_INTERVAL);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let (rx, tx) = self.counters.totals();
                self.meter().sample(Instant::now(), rx, tx);
            }
        };
        tokio::select! {
            () = pinging => {},
            () = sampling => {},
        }
    }
}

/// A rate in words: `4,2 Мбит/с`.
pub fn rate_text(bits_per_second: u64) -> String {
    const UNITS: [&str; 4] = ["бит/с", "кбит/с", "Мбит/с", "Гбит/с"];
    let mut amount = bits_per_second as f64;
    let mut unit = 0;
    while amount >= 1000.0 && unit < UNITS.len() - 1 {
        amount /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bits_per_second} {}", UNITS[0])
    } else {
        format!("{amount:.1} {}", UNITS[unit]).replace('.', ",")
    }
}

/// A duration in words: `2 ч 05 мин`, `3 мин 07 с`, `42 с`.
pub fn duration_text(seconds: u64) -> String {
    let (hours, minutes, seconds) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    match (hours, minutes) {
        (0, 0) => format!("{seconds} с"),
        (0, _) => format!("{minutes} мин {seconds:02} с"),
        _ => format!("{hours} ч {minutes:02} мин"),
    }
}

fn milliseconds(us: u64) -> String {
    if us < 10_000 {
        format!("{:.1}", us as f64 / 1000.0).replace('.', ",")
    } else {
        (us / 1000).to_string()
    }
}

/// The lines of a running tunnel's card: delay, speed, uptime and trouble.
pub fn card_lines(stats: &LinkStats) -> Vec<String> {
    let delay = match (stats.rtt.p50_us, stats.rtt.p95_us) {
        (Some(p50), Some(p95)) => {
            let mut line = format!(
                "Задержка {} мс, p95 {} мс",
                milliseconds(p50),
                milliseconds(p95)
            );
            if let Some(jitter) = stats.jitter_us {
                line += &format!(" · джиттер {} мс", milliseconds(jitter));
            }
            line
        }
        _ if stats.ping_lost > 0 => "Задержка: сервер не ответил на ping".into(),
        _ => "Задержка: измеряется…".into(),
    };
    let delay = format!(
        "{delay} · потеряно ping {} из {}",
        stats.ping_lost, stats.ping_sent
    );
    let speed = format!(
        "Скорость ↓ {} · ↑ {} · всего ↓ {} · ↑ {}",
        rate_text(stats.rx_bps),
        rate_text(stats.tx_bps),
        bytes_text(stats.rx_total),
        bytes_text(stats.tx_total)
    );
    let mut health = format!(
        "Сессия {} · переподключений {} · замираний {}",
        duration_text(stats.uptime_s),
        stats.reconnects,
        stats.stalls
    );
    if stats.stalled {
        health += " · сейчас замирание";
    }
    vec![delay, speed, health]
}

/// A byte count in words: `1,5 МБ`.
pub fn bytes_text(value: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit < UNITS.len() - 1 {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} Б")
    } else {
        format!("{amount:.1} {}", UNITS[unit]).replace('.', ",")
    }
}

#[cfg(test)]
mod tests;
