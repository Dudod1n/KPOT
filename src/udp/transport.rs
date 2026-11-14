//! Level 1 of the UDP transport: the client side of the frame protocol over one byte stream,
//! normally the exec channel that runs `krot-relay`.
//!
//! `send` never blocks: it queues the datagram and returns. A writer task takes datagrams in
//! order, drops those older than `DATAGRAM_EXPIRY`, and stops once `IN_FLIGHT_WINDOW` bytes
//! are unacknowledged by the relay, so delay builds up only in this queue, where it is seen and
//! bounded, and not in SSH or TCP buffers. Control frames (acknowledgements, pings, closes)
//! bypass the window, so the two directions can never wait for each other.
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use krot_udp_proto::{
    self as proto, CloseReason, Frame, Refusal, RelayStats, Settings, VERSION,
    limits::{
        ACK_INTERVAL, CHANNEL_QUEUE_BYTES, CHANNEL_QUEUE_DATAGRAMS, DATAGRAM_EXPIRY, DEFAULT_IDLE,
        DEFAULT_IDLE_BIDIRECTIONAL, DEFAULT_MAX_FLOWS, DELIVERY_QUEUE_DATAGRAMS, IN_FLIGHT_WINDOW,
        REPORT_INTERVAL, SILENCE_TIMEOUT, WRITE_BATCH,
    },
    metrics::{DropReason, Drops},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Notify, mpsc, watch},
    task::JoinSet,
};

use super::metrics::{Summary, Traffic, Windowed, drops_map};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_CHUNK: usize = 128 * 1024;
/// Round-trip samples kept for jitter.
const RTT_SAMPLES: usize = 16;

pub fn default_settings() -> Settings {
    Settings {
        max_flows: DEFAULT_MAX_FLOWS,
        idle_ms: DEFAULT_IDLE.as_millis() as u32,
        idle_bidirectional_ms: DEFAULT_IDLE_BIDIRECTIONAL.as_millis() as u32,
    }
}

/// Why the transport did not start or stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The relay speaks another protocol version.
    Version(u16),
    /// The relay did not answer in time, or went silent.
    Timeout,
    /// The relay sent something that is not a valid frame.
    Protocol,
    /// The stream ended or failed.
    Closed,
}

/// What the relay sends to the consumer.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Datagram {
        flow: u32,
        peer: SocketAddr,
        data: Vec<u8>,
    },
    Closed {
        flow: u32,
        reason: CloseReason,
        counters: FlowCounters,
    },
}

/// Traffic and losses of one flow on this side of the channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowCounters {
    pub sent: Traffic,
    pub received: Traffic,
    pub drops: Drops,
}

/// Everything measured for one transport, as the snapshot and the CLI show it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TransportMetrics {
    pub sent: Traffic,
    pub received: Traffic,
    /// Datagrams dropped on this side, by reason.
    pub drops: std::collections::BTreeMap<String, u64>,
    pub flows_active: u64,
    pub queue_datagrams: u64,
    pub queue_bytes: u64,
    /// Time a datagram waited before it was written to the channel.
    pub to_channel_delay: Summary,
    /// Round trip to the relay measured by pings.
    pub rtt: Summary,
    pub rtt_jitter_us: Option<u64>,
    pub relay: RelayMetrics,
}

/// What the relay reported about its side.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RelayMetrics {
    pub flows_active: u64,
    pub flows_opened: u64,
    pub flows_refused: u64,
    pub to_network: Traffic,
    pub from_network: Traffic,
    pub drops: std::collections::BTreeMap<String, u64>,
    pub to_network_delay: Summary,
    pub to_client_delay: Summary,
}

struct Queued {
    flow: u32,
    peer: SocketAddr,
    data: Vec<u8>,
    at: Instant,
}

struct State {
    outbox: VecDeque<Queued>,
    outbox_bytes: usize,
    control: Vec<u8>,
    /// Datagram frame bytes written to the relay and acknowledged by it.
    sent_bytes: u64,
    acked_bytes: u64,
    /// Datagram frame bytes received from the relay, and the value last acknowledged.
    received_bytes: u64,
    acknowledged: u64,
    ack_at: Instant,
    heard_at: Instant,
    pings: u32,
    flows: HashMap<u32, FlowCounters>,
    sent: Traffic,
    received: Traffic,
    drops: Drops,
    to_channel_delay: Windowed,
    rtt: Windowed,
    rtt_samples: VecDeque<u64>,
    relay: RelayStats,
    relay_to_network_delay: Windowed,
    relay_to_client_delay: Windowed,
}

impl State {
    fn drop_datagram(&mut self, flow: u32, reason: DropReason) {
        self.drops.add(reason);
        if let Some(counters) = self.flows.get_mut(&flow) {
            counters.drops.add(reason);
        }
    }
}

struct Shared {
    state: Mutex<State>,
    wake: Notify,
    failure: watch::Sender<Option<Failure>>,
    started: Instant,
}

impl Shared {
    fn fail(&self, failure: Failure) {
        self.failure.send_if_modified(|current| {
            if current.is_none() {
                *current = Some(failure);
                true
            } else {
                false
            }
        });
        self.wake.notify_one();
    }
}

pub struct Transport {
    shared: Arc<Shared>,
    failure: watch::Receiver<Option<Failure>>,
    settings: Settings,
    _tasks: JoinSet<()>,
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> Result<Vec<u8>, Failure> {
    loop {
        match proto::parse(buffer) {
            Ok(Some((_, used))) => return Ok(buffer.drain(..used).collect()),
            Ok(None) => {}
            Err(_) => return Err(Failure::Protocol),
        }
        let mut chunk = [0u8; 4096];
        let count = reader.read(&mut chunk).await.map_err(|_| Failure::Closed)?;
        if count == 0 {
            return Err(Failure::Closed);
        }
        buffer.extend_from_slice(&chunk[..count]);
    }
}

impl Transport {
    /// Greets the relay and starts the reader and writer tasks.
    pub async fn start<R, W>(
        mut reader: R,
        mut writer: W,
        settings: Settings,
    ) -> Result<(Self, mpsc::Receiver<Event>), Failure>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let mut hello = Vec::new();
        proto::encode(
            &Frame::Hello {
                version: VERSION,
                settings,
            },
            &mut hello,
        );
        let mut buffer = Vec::new();
        let accepted = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            writer
                .write_all(&hello)
                .await
                .map_err(|_| Failure::Closed)?;
            writer.flush().await.map_err(|_| Failure::Closed)?;
            let frame = read_frame(&mut reader, &mut buffer).await?;
            match proto::parse(&frame) {
                Ok(Some((
                    Frame::HelloOk {
                        version: VERSION,
                        settings,
                    },
                    _,
                ))) => Ok(settings),
                Ok(Some((
                    Frame::Refuse {
                        reason: Refusal::Version,
                        supported,
                    },
                    _,
                ))) => Err(Failure::Version(supported)),
                _ => Err(Failure::Protocol),
            }
        })
        .await
        .map_err(|_| Failure::Timeout)??;

        let now = Instant::now();
        let (failure_send, failure) = watch::channel(None);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                outbox: VecDeque::new(),
                outbox_bytes: 0,
                control: Vec::new(),
                sent_bytes: 0,
                acked_bytes: 0,
                received_bytes: 0,
                acknowledged: 0,
                ack_at: now,
                heard_at: now,
                pings: 0,
                flows: HashMap::new(),
                sent: Traffic::default(),
                received: Traffic::default(),
                drops: Drops::default(),
                to_channel_delay: Windowed::default(),
                rtt: Windowed::default(),
                rtt_samples: VecDeque::new(),
                relay: RelayStats::default(),
                relay_to_network_delay: Windowed::default(),
                relay_to_client_delay: Windowed::default(),
            }),
            wake: Notify::new(),
            failure: failure_send,
            started: now,
        });
        let (events_send, events) = mpsc::channel(DELIVERY_QUEUE_DATAGRAMS);
        let mut tasks = JoinSet::new();
        let reading = shared.clone();
        tasks.spawn(async move {
            let failure = read_loop(&mut reader, buffer, &reading, events_send).await;
            reading.fail(failure);
        });
        let writing = shared.clone();
        tasks.spawn(async move {
            let failure = write_loop(&mut writer, &writing).await;
            writing.fail(failure);
            // Closing our side tells the relay to end at once.
            let _ = writer.shutdown().await;
        });
        Ok((
            Self {
                shared,
                failure,
                settings: accepted,
                _tasks: tasks,
            },
            events,
        ))
    }

    /// Settings the relay accepted.
    pub fn settings(&self) -> Settings {
        self.settings
    }

    /// Queues a datagram of `flow` for `peer`; the oldest queued datagram makes room if needed.
    pub fn send(&self, flow: u32, peer: SocketAddr, data: &[u8]) {
        if data.len() > proto::MAX_PAYLOAD {
            let mut state = self.shared.state.lock().unwrap();
            state.flows.entry(flow).or_default();
            state.drop_datagram(flow, DropReason::Size);
            return;
        }
        {
            let mut state = self.shared.state.lock().unwrap();
            state.flows.entry(flow).or_default();
            while state.outbox.len() >= CHANNEL_QUEUE_DATAGRAMS
                || state.outbox_bytes + data.len() > CHANNEL_QUEUE_BYTES
            {
                let Some(old) = state.outbox.pop_front() else {
                    break;
                };
                state.outbox_bytes -= old.data.len();
                state.drop_datagram(old.flow, DropReason::Overflow);
            }
            state.outbox_bytes += data.len();
            state.outbox.push_back(Queued {
                flow,
                peer,
                data: data.to_vec(),
                at: Instant::now(),
            });
        }
        self.shared.wake.notify_one();
    }

    /// Ends `flow` here and asks the relay to close its socket; returns its counters.
    pub fn close(&self, flow: u32) -> Option<FlowCounters> {
        let counters = {
            let mut state = self.shared.state.lock().unwrap();
            let counters = state.flows.remove(&flow)?;
            let mut outbox = std::mem::take(&mut state.outbox);
            outbox.retain(|queued| queued.flow != flow);
            state.outbox_bytes = outbox.iter().map(|queued| queued.data.len()).sum();
            state.outbox = outbox;
            proto::encode(
                &Frame::Close {
                    flow,
                    reason: CloseReason::Client,
                },
                &mut state.control,
            );
            counters
        };
        self.shared.wake.notify_one();
        Some(counters)
    }

    pub fn flow(&self, flow: u32) -> Option<FlowCounters> {
        self.shared.state.lock().unwrap().flows.get(&flow).copied()
    }

    pub fn failure(&self) -> Option<Failure> {
        *self.failure.borrow()
    }

    /// Waits until the transport stops and tells why.
    pub async fn failed(&self) -> Failure {
        let mut failure = self.failure.clone();
        loop {
            if let Some(failure) = *failure.borrow_and_update() {
                return failure;
            }
            if failure.changed().await.is_err() {
                return Failure::Closed;
            }
        }
    }

    pub fn metrics(&self) -> TransportMetrics {
        let state = self.shared.state.lock().unwrap();
        let jitter = (state.rtt_samples.len() > 1).then(|| {
            let samples: Vec<u64> = state.rtt_samples.iter().copied().collect();
            let total: u64 = samples
                .windows(2)
                .map(|pair| pair[0].abs_diff(pair[1]))
                .sum();
            total / (samples.len() as u64 - 1)
        });
        TransportMetrics {
            sent: state.sent,
            received: state.received,
            drops: drops_map(&state.drops),
            flows_active: state.flows.len() as u64,
            queue_datagrams: state.outbox.len() as u64,
            queue_bytes: state.outbox_bytes as u64,
            to_channel_delay: state.to_channel_delay.summary(),
            rtt: state.rtt.summary(),
            rtt_jitter_us: jitter,
            relay: RelayMetrics {
                flows_active: u64::from(state.relay.flows_active),
                flows_opened: state.relay.flows_opened,
                flows_refused: state.relay.flows_refused,
                to_network: Traffic {
                    datagrams: state.relay.to_network_datagrams,
                    bytes: state.relay.to_network_bytes,
                },
                from_network: Traffic {
                    datagrams: state.relay.from_network_datagrams,
                    bytes: state.relay.from_network_bytes,
                },
                drops: drops_map(&state.relay.drops),
                to_network_delay: state.relay_to_network_delay.summary(),
                to_client_delay: state.relay_to_client_delay.summary(),
            },
        }
    }
}

async fn read_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut buffer: Vec<u8>,
    shared: &Shared,
    events: mpsc::Sender<Event>,
) -> Failure {
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        let mut start = 0;
        loop {
            let parsed = match proto::parse(&buffer[start..]) {
                Ok(parsed) => parsed,
                Err(_) => return Failure::Protocol,
            };
            let Some((frame, used)) = parsed else {
                break;
            };
            start += used;
            if let Err(failure) = handle(frame, used, shared, &events) {
                return failure;
            }
        }
        buffer.drain(..start);
        let count = match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => return Failure::Closed,
            Ok(count) => count,
        };
        buffer.extend_from_slice(&chunk[..count]);
        shared.state.lock().unwrap().heard_at = Instant::now();
    }
}

fn handle(
    frame: Frame<'_>,
    used: usize,
    shared: &Shared,
    events: &mpsc::Sender<Event>,
) -> Result<(), Failure> {
    let mut state = shared.state.lock().unwrap();
    match frame {
        Frame::Recv { flow, peer, data } => {
            state.received_bytes += used as u64;
            // Answers for a flow closed here are no longer wanted.
            let Some(counters) = state.flows.get_mut(&flow) else {
                return Ok(());
            };
            counters.received.add(data.len());
            state.received.add(data.len());
            let event = Event::Datagram {
                flow,
                peer,
                data: data.to_vec(),
            };
            if events.try_send(event).is_err() {
                state.drop_datagram(flow, DropReason::Overflow);
            }
            if state.received_bytes - state.acknowledged >= IN_FLIGHT_WINDOW / 4 {
                drop(state);
                shared.wake.notify_one();
            }
        }
        Frame::Close { flow, reason } => {
            if let Some(counters) = state.flows.remove(&flow) {
                let mut outbox = std::mem::take(&mut state.outbox);
                outbox.retain(|queued| queued.flow != flow);
                state.outbox_bytes = outbox.iter().map(|queued| queued.data.len()).sum();
                state.outbox = outbox;
                let _ = events.try_send(Event::Closed {
                    flow,
                    reason,
                    counters,
                });
            }
        }
        Frame::Ack { received } => {
            let acked = received.min(state.sent_bytes);
            if acked > state.acked_bytes {
                state.acked_bytes = acked;
                drop(state);
                shared.wake.notify_one();
            }
        }
        Frame::Pong { time_us, .. } => {
            let now_us = shared.started.elapsed().as_micros() as u64;
            if time_us <= now_us {
                let rtt = now_us - time_us;
                state.rtt.record(Duration::from_micros(rtt));
                if state.rtt_samples.len() == RTT_SAMPLES {
                    state.rtt_samples.pop_front();
                }
                state.rtt_samples.push_back(rtt);
            }
            state.pings = 0;
        }
        Frame::Stats(stats) => {
            state
                .relay_to_network_delay
                .push_interval(stats.to_network_delay);
            state
                .relay_to_client_delay
                .push_interval(stats.to_client_delay);
            state.relay = *stats;
        }
        _ => return Err(Failure::Protocol),
    }
    Ok(())
}

async fn write_loop<W: AsyncWrite + Unpin>(writer: &mut W, shared: &Shared) -> Failure {
    let mut batch = Vec::with_capacity(WRITE_BATCH + proto::MAX_FRAME);
    let mut ping_at = Instant::now();
    let mut roll_at = Instant::now() + REPORT_INTERVAL;
    let mut sequence = 0u32;
    let mut failure = shared.failure.subscribe();
    loop {
        if let Some(failure) = *failure.borrow_and_update() {
            return failure;
        }
        let now = Instant::now();
        batch.clear();
        let wait = {
            let mut state = shared.state.lock().unwrap();
            if now.duration_since(state.heard_at) > SILENCE_TIMEOUT {
                return Failure::Timeout;
            }
            if now >= roll_at {
                roll_at = now + REPORT_INTERVAL;
                state.to_channel_delay.roll();
                state.rtt.roll();
            }
            if now >= ping_at {
                ping_at = now + REPORT_INTERVAL;
                sequence = sequence.wrapping_add(1);
                state.pings += 1;
                let time_us = now.duration_since(shared.started).as_micros() as u64;
                proto::encode(&Frame::Ping { sequence, time_us }, &mut batch);
            }
            if state.received_bytes != state.acknowledged
                && (now.duration_since(state.ack_at) >= ACK_INTERVAL
                    || state.received_bytes - state.acknowledged >= IN_FLIGHT_WINDOW / 4)
            {
                state.acknowledged = state.received_bytes;
                state.ack_at = now;
                let received = state.received_bytes;
                proto::encode(&Frame::Ack { received }, &mut batch);
            }
            batch.append(&mut state.control);
            while batch.len() < WRITE_BATCH {
                let Some(front) = state.outbox.front() else {
                    break;
                };
                let waited = now.saturating_duration_since(front.at);
                let size = proto::datagram_frame_size(&front.peer, front.data.len()) as u64;
                if waited <= DATAGRAM_EXPIRY
                    && state.sent_bytes - state.acked_bytes + size > IN_FLIGHT_WINDOW
                {
                    break;
                }
                let Some(queued) = state.outbox.pop_front() else {
                    break;
                };
                state.outbox_bytes -= queued.data.len();
                if waited > DATAGRAM_EXPIRY {
                    state.drop_datagram(queued.flow, DropReason::Expired);
                    continue;
                }
                proto::encode(
                    &Frame::Send {
                        flow: queued.flow,
                        peer: queued.peer,
                        data: &queued.data,
                    },
                    &mut batch,
                );
                state.sent_bytes += size;
                state.to_channel_delay.record(waited);
                state.sent.add(queued.data.len());
                if let Some(counters) = state.flows.get_mut(&queued.flow) {
                    counters.sent.add(queued.data.len());
                }
            }
            // Wake for the next timed duty: ping, metrics roll, acknowledgement or expiry.
            let mut next = ping_at.min(roll_at);
            if state.received_bytes != state.acknowledged {
                next = next.min(state.ack_at + ACK_INTERVAL);
            }
            if let Some(front) = state.outbox.front() {
                next = next.min(front.at + DATAGRAM_EXPIRY);
            }
            next
        };
        if !batch.is_empty() {
            if writer.write_all(&batch).await.is_err() || writer.flush().await.is_err() {
                return Failure::Closed;
            }
            continue;
        }
        tokio::select! {
            _ = shared.wake.notified() => {}
            _ = tokio::time::sleep_until(wait.into()) => {}
            _ = failure.changed() => {}
        }
    }
}

#[cfg(test)]
mod tests;
