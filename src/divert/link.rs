//! The elevated helper's UDP channel to the background process. Platform-neutral: the packet
//! loop hands captured datagrams to `Link::send`, and answers come out of `Link::run` for the
//! platform to inject.
//!
//! Like every other part of the path, the queue is bounded, drops its oldest datagram when
//! full and never sends a datagram older than `DATAGRAM_EXPIRY`.
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    future::Future,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use krot_udp_proto::{
    self as proto, Frame,
    limits::{
        CHANNEL_QUEUE_BYTES, CHANNEL_QUEUE_DATAGRAMS, DATAGRAM_EXPIRY, DELIVERY_QUEUE_DATAGRAMS,
        REPORT_INTERVAL, SILENCE_TIMEOUT, WRITE_BATCH,
    },
    metrics::{DropReason, Drops},
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Notify, mpsc},
};

use crate::udp::metrics::{Summary, Traffic, Windowed, drops_map};

/// Pause before connecting again after the channel failed.
const RECONNECT: Duration = Duration::from_secs(1);

/// What the helper reports per rule about its part of the UDP path.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct HelperUdpStats {
    pub flows: u64,
    /// Datagrams of the application taken off the network.
    pub captured: Traffic,
    /// Answers injected back to the application.
    pub injected: Traffic,
    pub drops: BTreeMap<String, u64>,
    /// Time a datagram waited in the helper before it reached the background process.
    pub to_background_delay: Summary,
}

/// What the background process sends back.
#[derive(Debug, PartialEq, Eq)]
pub enum Inbound {
    Datagram {
        id: u32,
        peer: SocketAddr,
        data: Vec<u8>,
    },
    /// The flow ended on the far side; its next datagram opens it again.
    Closed { id: u32 },
    /// The channel was lost: every flow is gone.
    Lost,
}

struct Queued {
    frame: Vec<u8>,
    rule: Option<String>,
    payload: usize,
    at: Instant,
}

#[derive(Default)]
struct RuleState {
    flows: u64,
    captured: Traffic,
    injected: Traffic,
    drops: Drops,
    delay: Windowed,
}

#[derive(Default)]
struct State {
    queue: VecDeque<Queued>,
    queue_bytes: usize,
    rules: HashMap<String, RuleState>,
    flow_rules: HashMap<u32, String>,
}

impl State {
    fn rule(&mut self, rule: &str) -> &mut RuleState {
        self.rules.entry(rule.to_owned()).or_default()
    }
}

#[derive(Default)]
pub struct Link {
    state: Mutex<State>,
    wake: Notify,
    up: AtomicBool,
}

impl Link {
    /// The channel to the background process works right now.
    pub fn up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }

    /// Queues a datagram of flow `id`; `opened` tells that the flow is new and needs `OPEN`.
    pub fn send(&self, rule: &str, id: u32, opened: bool, peer: SocketAddr, payload: &[u8]) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let counters = state.rule(rule);
        counters.captured.add(payload.len());
        if payload.len() > proto::MAX_PAYLOAD {
            counters.drops.add(DropReason::Size);
            return;
        }
        if opened {
            counters.flows += 1;
            state.flow_rules.insert(id, rule.to_owned());
            let mut frame = Vec::new();
            proto::encode(&Frame::Open { flow: id, rule }, &mut frame);
            state.queue.push_back(Queued {
                frame,
                rule: None,
                payload: 0,
                at: now,
            });
        }
        while state.queue.len() >= CHANNEL_QUEUE_DATAGRAMS
            || state.queue_bytes + payload.len() > CHANNEL_QUEUE_BYTES
        {
            // Control frames are tiny; only datagrams are given up.
            let Some(index) = state.queue.iter().position(|queued| queued.rule.is_some()) else {
                break;
            };
            let Some(old) = state.queue.remove(index) else {
                break;
            };
            state.queue_bytes -= old.payload;
            if let Some(rule) = old.rule {
                state.rule(&rule).drops.add(DropReason::Overflow);
            }
        }
        let mut frame = Vec::with_capacity(proto::datagram_frame_size(&peer, payload.len()));
        proto::encode(
            &Frame::Send {
                flow: id,
                peer,
                data: payload,
            },
            &mut frame,
        );
        state.queue_bytes += payload.len();
        state.queue.push_back(Queued {
            frame,
            rule: Some(rule.to_owned()),
            payload: payload.len(),
            at: now,
        });
        drop(state);
        self.wake.notify_one();
    }

    /// Ends flow `id` on the far side too.
    pub fn close(&self, id: u32) {
        let mut state = self.state.lock().unwrap();
        state.flow_rules.remove(&id);
        let mut frame = Vec::new();
        proto::encode(
            &Frame::Close {
                flow: id,
                reason: proto::CloseReason::Client,
            },
            &mut frame,
        );
        state.queue.push_back(Queued {
            frame,
            rule: None,
            payload: 0,
            at: Instant::now(),
        });
        drop(state);
        self.wake.notify_one();
    }

    /// A datagram of `rule` that did not go anywhere, for a reason the platform found.
    pub fn dropped(&self, rule: &str, reason: DropReason) {
        self.state.lock().unwrap().rule(rule).drops.add(reason);
    }

    /// An answer was injected back to the application.
    pub fn injected(&self, rule: &str, bytes: usize) {
        self.state.lock().unwrap().rule(rule).injected.add(bytes);
    }

    pub fn stats(&self) -> HashMap<String, HelperUdpStats> {
        let state = self.state.lock().unwrap();
        state
            .rules
            .iter()
            .map(|(rule, counters)| {
                (
                    rule.clone(),
                    HelperUdpStats {
                        flows: counters.flows,
                        captured: counters.captured,
                        injected: counters.injected,
                        drops: drops_map(&counters.drops),
                        to_background_delay: counters.delay.summary(),
                    },
                )
            })
            .collect()
    }

    /// Keeps the channel open with `connect`, and hands answers to `inbound`.
    pub async fn run<F, Fut, R, W>(self: Arc<Self>, connect: F, inbound: mpsc::Sender<Inbound>)
    where
        F: Fn() -> Fut,
        Fut: Future<Output = anyhow::Result<(R, W)>>,
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            if let Ok((reader, writer)) = connect().await {
                self.up.store(true, Ordering::Release);
                self.serve(reader, writer, &inbound).await;
                self.up.store(false, Ordering::Release);
                {
                    let mut state = self.state.lock().unwrap();
                    state.flow_rules.clear();
                    // Nothing queued can reach a channel that no longer knows its flows.
                    for queued in std::mem::take(&mut state.queue) {
                        if let Some(rule) = queued.rule {
                            state.rule(&rule).drops.add(DropReason::Channel);
                        }
                    }
                    state.queue_bytes = 0;
                }
                if inbound.send(Inbound::Lost).await.is_err() {
                    return;
                }
            }
            tokio::time::sleep(RECONNECT).await;
        }
    }

    /// Reads and writes at the same time: a side that cannot write must still read, or two
    /// full buffers would wait for each other forever. A write that stays blocked for
    /// `SILENCE_TIMEOUT` ends the channel like silence does.
    async fn serve<R, W>(&self, reader: R, writer: W, inbound: &mpsc::Sender<Inbound>)
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let heard = Heard::new();
        tokio::select! {
            _ = self.write_loop(writer, &heard) => {}
            _ = self.read_loop(reader, inbound, &heard) => {}
        }
    }

    async fn write_loop<W: AsyncWrite + Unpin>(&self, mut writer: W, heard: &Heard) {
        let mut batch = Vec::with_capacity(WRITE_BATCH + proto::MAX_FRAME);
        let mut ping = tokio::time::interval(REPORT_INTERVAL);
        let mut sequence = 0u32;
        loop {
            batch.clear();
            {
                let now = Instant::now();
                let mut state = self.state.lock().unwrap();
                while batch.len() < WRITE_BATCH {
                    let Some(queued) = state.queue.pop_front() else {
                        break;
                    };
                    state.queue_bytes -= queued.payload;
                    let waited = now.duration_since(queued.at);
                    if let Some(rule) = &queued.rule {
                        let counters = state.rule(rule);
                        if waited > DATAGRAM_EXPIRY {
                            counters.drops.add(DropReason::Expired);
                            continue;
                        }
                        counters.delay.record(waited);
                    }
                    batch.extend_from_slice(&queued.frame);
                }
            }
            if !batch.is_empty() {
                let written = tokio::time::timeout(SILENCE_TIMEOUT, async {
                    writer.write_all(&batch).await?;
                    writer.flush().await
                })
                .await;
                if !matches!(written, Ok(Ok(()))) {
                    return;
                }
                continue;
            }
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = ping.tick() => {
                    if heard.silent_for() > SILENCE_TIMEOUT {
                        return;
                    }
                    sequence = sequence.wrapping_add(1);
                    let mut state = self.state.lock().unwrap();
                    for counters in state.rules.values_mut() {
                        counters.delay.roll();
                    }
                    let mut frame = Vec::new();
                    proto::encode(&Frame::Ping { sequence, time_us: 0 }, &mut frame);
                    state.queue.push_front(Queued { frame, rule: None, payload: 0, at: Instant::now() });
                }
            }
        }
    }

    async fn read_loop<R: AsyncRead + Unpin>(
        &self,
        mut reader: R,
        inbound: &mpsc::Sender<Inbound>,
        heard: &Heard,
    ) {
        let mut buffer = Vec::new();
        let mut chunk = vec![0u8; 128 * 1024];
        loop {
            let count = match reader.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(count) => count,
            };
            heard.now();
            buffer.extend_from_slice(&chunk[..count]);
            let mut start = 0;
            loop {
                let parsed = match proto::parse(&buffer[start..]) {
                    Ok(parsed) => parsed,
                    Err(_) => return,
                };
                let Some((frame, used)) = parsed else { break };
                start += used;
                let message = match frame {
                    Frame::Recv { flow, peer, data } => Inbound::Datagram {
                        id: flow,
                        peer,
                        data: data.to_vec(),
                    },
                    Frame::Close { flow, .. } => {
                        self.state.lock().unwrap().flow_rules.remove(&flow);
                        Inbound::Closed { id: flow }
                    }
                    Frame::Pong { .. } => continue,
                    _ => return,
                };
                // Never wait for the consumer here: answers that do not fit are dropped.
                if let Err(mpsc::error::TrySendError::Full(Inbound::Datagram { id, .. })) =
                    inbound.try_send(message)
                {
                    let mut state = self.state.lock().unwrap();
                    if let Some(rule) = state.flow_rules.get(&id).cloned() {
                        state.rule(&rule).drops.add(DropReason::Overflow);
                    }
                }
            }
            buffer.drain(..start);
        }
    }
}

/// When the channel last delivered bytes, shared by its reading and writing halves.
struct Heard {
    start: Instant,
    micros: std::sync::atomic::AtomicU64,
}

impl Heard {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            micros: std::sync::atomic::AtomicU64::new(0),
        }
    }
    fn now(&self) {
        let micros = self.start.elapsed().as_micros() as u64;
        self.micros.store(micros, Ordering::Relaxed);
    }
    fn silent_for(&self) -> Duration {
        let last = Duration::from_micros(self.micros.load(Ordering::Relaxed));
        self.start.elapsed().saturating_sub(last)
    }
}

/// Answers waiting for injection.
pub const INBOUND_QUEUE: usize = DELIVERY_QUEUE_DATAGRAMS;

#[cfg(test)]
mod tests;
