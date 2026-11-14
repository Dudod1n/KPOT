//! Routes datagrams between the elevated helper and the UDP transports of tunnels.
//!
//! The helper names a flow by its own id and says in `OPEN` which rule it belongs to. The
//! router picks the transport of that rule's tunnel and gives the flow an id of its own there,
//! so answers find their way back and counters add up per rule.
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use krot_udp_proto::{
    self as proto, CloseReason, Frame,
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

use super::{
    metrics::{Summary, Traffic, Windowed, drops_map, merge_drops},
    transport::{Event, FlowCounters, Transport},
};
use crate::ssh::UdpNotice;

/// Per-rule UDP traffic on the background side, as the snapshot and the CLI show it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RuleMetrics {
    pub flows_active: u64,
    pub flows_total: u64,
    /// Flows the router could not open because the tunnel had no running relay.
    pub flows_refused: u64,
    pub sent: Traffic,
    pub received: Traffic,
    pub drops: std::collections::BTreeMap<String, u64>,
}

/// Background-side metrics of one tunnel's UDP that are not the transport's own.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TunnelRouting {
    /// Time an answer waited before it was written to the helper.
    pub to_helper_delay: Summary,
    pub to_helper_drops: std::collections::BTreeMap<String, u64>,
}

enum Delivery {
    Datagram {
        tunnel: String,
        flow: u32,
        peer: SocketAddr,
        data: Vec<u8>,
        at: Instant,
    },
    Closed {
        tunnel: String,
        flow: u32,
        reason: CloseReason,
    },
    Down {
        tunnel: String,
    },
}

#[derive(Default)]
struct RuleTotals {
    closed: FlowCounters,
    flows_total: u64,
    flows_refused: u64,
}

#[derive(Default)]
struct TunnelTotals {
    to_helper_delay: Windowed,
    to_helper_drops: Drops,
}

#[derive(Default)]
struct State {
    links: HashMap<String, Arc<Transport>>,
    /// Rule id → tunnel id, for rules whose tunnel may carry UDP.
    rules: HashMap<String, String>,
    /// (tunnel, transport flow) → rule, for every open flow.
    flows: HashMap<(String, u32), String>,
    channel: Option<(u64, mpsc::Sender<Delivery>)>,
    generation: u64,
    next_flow: u32,
    totals: HashMap<String, RuleTotals>,
    tunnels: HashMap<String, TunnelTotals>,
}

impl State {
    fn add_closed(&mut self, rule: &str, counters: &FlowCounters) {
        let totals = self.totals.entry(rule.to_owned()).or_default();
        totals.closed.sent.merge(&counters.sent);
        totals.closed.received.merge(&counters.received);
        merge_drops(&mut totals.closed.drops, &counters.drops);
    }
}

#[derive(Default)]
pub struct Router {
    state: Mutex<State>,
}

impl Router {
    /// Follows relays as they start and stop. Ends when the manager drops its sender.
    pub async fn run(self: Arc<Self>, mut notices: mpsc::UnboundedReceiver<UdpNotice>) {
        let mut roll = tokio::time::interval(REPORT_INTERVAL);
        loop {
            tokio::select! {
                notice = notices.recv() => match notice {
                    None => return,
                    Some(UdpNotice::Up { tunnel, transport, mut events }) => {
                        self.state.lock().unwrap().links.insert(tunnel.clone(), transport);
                        let router = self.clone();
                        tokio::spawn(async move {
                            while let Some(event) = events.recv().await {
                                router.event(&tunnel, event);
                            }
                        });
                    }
                    Some(UdpNotice::Down { tunnel }) => self.down(&tunnel),
                },
                _ = roll.tick() => {
                    for totals in self.state.lock().unwrap().tunnels.values_mut() {
                        totals.to_helper_delay.roll();
                    }
                }
            }
        }
    }

    /// Rules that may use UDP through their tunnel; called whenever rules or tunnels change.
    pub fn set_rules(&self, rules: HashMap<String, String>) {
        let mut state = self.state.lock().unwrap();
        // Open flows whose rule now goes through another tunnel, or none, end here: the
        // helper opens them again with the next datagram, on the current route.
        let moved: Vec<(String, u32, String)> = state
            .flows
            .iter()
            .filter(|((tunnel, _), rule)| rules.get(*rule) != Some(tunnel))
            .map(|((tunnel, flow), rule)| (tunnel.clone(), *flow, rule.clone()))
            .collect();
        state.rules = rules;
        for (tunnel, flow, rule) in moved {
            state.flows.remove(&(tunnel.clone(), flow));
            if let Some(counters) = state.links.get(&tunnel).and_then(|link| link.close(flow)) {
                state.add_closed(&rule, &counters);
            }
            if let Some((_, channel)) = &state.channel {
                let _ = channel.try_send(Delivery::Closed {
                    tunnel,
                    flow,
                    reason: CloseReason::Client,
                });
            }
        }
    }

    /// Whether the tunnel has a running relay.
    pub fn up(&self, tunnel: &str) -> bool {
        self.state.lock().unwrap().links.contains_key(tunnel)
    }

    fn event(&self, tunnel: &str, event: Event) {
        let mut state = self.state.lock().unwrap();
        let delivery = match event {
            Event::Datagram { flow, peer, data } => Delivery::Datagram {
                tunnel: tunnel.to_owned(),
                flow,
                peer,
                data,
                at: Instant::now(),
            },
            Event::Closed {
                flow,
                reason,
                counters,
            } => {
                if let Some(rule) = state.flows.remove(&(tunnel.to_owned(), flow)) {
                    state.add_closed(&rule, &counters);
                }
                Delivery::Closed {
                    tunnel: tunnel.to_owned(),
                    flow,
                    reason,
                }
            }
        };
        let sent = state
            .channel
            .as_ref()
            .map(|(_, channel)| channel.try_send(delivery));
        if let Some(Err(mpsc::error::TrySendError::Full(Delivery::Datagram { .. }))) = sent {
            state
                .tunnels
                .entry(tunnel.to_owned())
                .or_default()
                .to_helper_drops
                .add(DropReason::Overflow);
        }
    }

    fn down(&self, tunnel: &str) {
        let mut state = self.state.lock().unwrap();
        // The transport still holds the counters of its flows.
        if let Some(transport) = state.links.remove(tunnel) {
            let open: Vec<(u32, String)> = state
                .flows
                .iter()
                .filter(|((owner, _), _)| owner == tunnel)
                .map(|((_, flow), rule)| (*flow, rule.clone()))
                .collect();
            for (flow, rule) in open {
                state.flows.remove(&(tunnel.to_owned(), flow));
                if let Some(counters) = transport.flow(flow) {
                    state.add_closed(&rule, &counters);
                }
            }
        }
        if let Some((_, channel)) = &state.channel {
            let _ = channel.try_send(Delivery::Down {
                tunnel: tunnel.to_owned(),
            });
        }
    }

    /// Per-rule metrics: closed flows plus the live counters of open ones.
    pub fn rule_metrics(&self) -> HashMap<String, RuleMetrics> {
        let state = self.state.lock().unwrap();
        let mut metrics: HashMap<String, (FlowCounters, u64)> = HashMap::new();
        for ((tunnel, flow), rule) in &state.flows {
            let entry = metrics.entry(rule.clone()).or_default();
            entry.1 += 1;
            if let Some(counters) = state.links.get(tunnel).and_then(|link| link.flow(*flow)) {
                entry.0.sent.merge(&counters.sent);
                entry.0.received.merge(&counters.received);
                merge_drops(&mut entry.0.drops, &counters.drops);
            }
        }
        let mut rules: Vec<&String> = state.totals.keys().collect();
        rules.extend(metrics.keys());
        rules.sort();
        rules.dedup();
        rules
            .into_iter()
            .map(|rule| {
                let (live, active) = metrics.get(rule).copied().unwrap_or_default();
                let totals = state.totals.get(rule);
                let mut sent = live.sent;
                let mut received = live.received;
                let mut drops = live.drops;
                if let Some(totals) = totals {
                    sent.merge(&totals.closed.sent);
                    received.merge(&totals.closed.received);
                    merge_drops(&mut drops, &totals.closed.drops);
                }
                (
                    rule.clone(),
                    RuleMetrics {
                        flows_active: active,
                        flows_total: totals.map_or(0, |totals| totals.flows_total),
                        flows_refused: totals.map_or(0, |totals| totals.flows_refused),
                        sent,
                        received,
                        drops: drops_map(&drops),
                    },
                )
            })
            .collect()
    }

    pub fn tunnel_metrics(&self) -> HashMap<String, TunnelRouting> {
        self.state
            .lock()
            .unwrap()
            .tunnels
            .iter()
            .map(|(tunnel, totals)| {
                (
                    tunnel.clone(),
                    TunnelRouting {
                        to_helper_delay: totals.to_helper_delay.summary(),
                        to_helper_drops: drops_map(&totals.to_helper_drops),
                    },
                )
            })
            .collect()
    }

    /// Serves the helper's binary channel until it ends. A newer channel replaces this one.
    pub async fn serve<R, W>(self: Arc<Self>, mut reader: R, writer: W)
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (deliveries_send, mut deliveries) = mpsc::channel(DELIVERY_QUEUE_DATAGRAMS);
        let generation = {
            let mut state = self.state.lock().unwrap();
            state.generation += 1;
            state.channel = Some((state.generation, deliveries_send));
            state.generation
        };
        let (frames_send, mut frames) = mpsc::channel::<Result<Vec<u8>, ()>>(1024);
        let reading = tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut chunk = vec![0u8; 128 * 1024];
            loop {
                let mut start = 0;
                loop {
                    match proto::parse(&buffer[start..]) {
                        Ok(Some((_, used))) => {
                            let frame = buffer[start..start + used].to_vec();
                            start += used;
                            if frames_send.send(Ok(frame)).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            let _ = frames_send.send(Err(())).await;
                            return;
                        }
                    }
                }
                buffer.drain(..start);
                match reader.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(count) => buffer.extend_from_slice(&chunk[..count]),
                }
            }
        });
        // helper flow → (tunnel, transport flow, rule, transport)
        let mut flows: HashMap<u32, (String, u32, String, Arc<Transport>)> = HashMap::new();
        let mut back: HashMap<(String, u32), u32> = HashMap::new();
        // Writing runs apart from reading: a helper that does not read for a while must never
        // stop this side from reading what the helper sends.
        let outbox = Arc::new(Outbox::default());
        let mut writing = tokio::spawn(write_out(self.clone(), outbox.clone(), writer));
        let mut out = Outgoing::default();
        loop {
            tokio::select! {
                _ = &mut writing => break,
                frame = frames.recv() => {
                    let Some(Ok(frame)) = frame else { break };
                    let Ok(Some((frame, _))) = proto::parse(&frame) else { break };
                    match frame {
                        Frame::Open { flow, rule } => {
                            if let Some((tunnel, tflow, rule, transport)) = flows.remove(&flow) {
                                self.close_flow(&tunnel, tflow, &rule, &transport);
                                back.remove(&(tunnel, tflow));
                            }
                            match self.open(rule) {
                                Some((tunnel, tflow, transport)) => {
                                    back.insert((tunnel.clone(), tflow), flow);
                                    flows.insert(flow, (tunnel, tflow, rule.to_owned(), transport));
                                }
                                None => out.control(&Frame::Close { flow, reason: CloseReason::Socket }),
                            }
                        }
                        Frame::Send { flow, peer, data } => {
                            if let Some((_, tflow, _, transport)) = flows.get(&flow) {
                                transport.send(*tflow, peer, data);
                            }
                        }
                        Frame::Close { flow, .. } => {
                            if let Some((tunnel, tflow, rule, transport)) = flows.remove(&flow) {
                                self.close_flow(&tunnel, tflow, &rule, &transport);
                                back.remove(&(tunnel, tflow));
                            }
                        }
                        // Pings keep the local channel's liveness visible to the helper.
                        Frame::Ping { sequence, time_us } => {
                            out.control(&Frame::Pong { sequence, time_us, held_us: 0 });
                        }
                        _ => break,
                    }
                }
                delivery = deliveries.recv() => {
                    let Some(delivery) = delivery else { break };
                    self.write_delivery(delivery, &mut flows, &mut back, &mut out);
                    // Take whatever else is ready.
                    while out.0.len() < 256 {
                        let Ok(delivery) = deliveries.try_recv() else { break };
                        self.write_delivery(delivery, &mut flows, &mut back, &mut out);
                    }
                }
            }
            if !out.0.is_empty() {
                outbox.push(&self, std::mem::take(&mut out.0));
            }
        }
        reading.abort();
        writing.abort();
        for (_, (tunnel, tflow, rule, transport)) in flows {
            self.close_flow(&tunnel, tflow, &rule, &transport);
        }
        let mut state = self.state.lock().unwrap();
        if state
            .channel
            .as_ref()
            .is_some_and(|(current, _)| *current == generation)
        {
            state.channel = None;
        }
    }

    fn open(&self, rule: &str) -> Option<(String, u32, Arc<Transport>)> {
        let mut state = self.state.lock().unwrap();
        let tunnel = state.rules.get(rule).cloned();
        let transport = tunnel
            .as_ref()
            .and_then(|tunnel| state.links.get(tunnel).cloned());
        let totals = state.totals.entry(rule.to_owned()).or_default();
        let (Some(tunnel), Some(transport)) = (tunnel, transport) else {
            totals.flows_refused += 1;
            return None;
        };
        totals.flows_total += 1;
        state.next_flow = state.next_flow.wrapping_add(1);
        let flow = state.next_flow;
        state.flows.insert((tunnel.clone(), flow), rule.to_owned());
        Some((tunnel, flow, transport))
    }

    fn close_flow(&self, tunnel: &str, flow: u32, rule: &str, transport: &Transport) {
        let counters = transport.close(flow);
        let mut state = self.state.lock().unwrap();
        if state.flows.remove(&(tunnel.to_owned(), flow)).is_some()
            && let Some(counters) = counters
        {
            state.add_closed(rule, &counters);
        }
    }

    fn write_delivery(
        &self,
        delivery: Delivery,
        flows: &mut HashMap<u32, (String, u32, String, Arc<Transport>)>,
        back: &mut HashMap<(String, u32), u32>,
        out: &mut Outgoing,
    ) {
        match delivery {
            Delivery::Datagram {
                tunnel,
                flow,
                peer,
                data,
                at,
            } => {
                let Some(helper) = back.get(&(tunnel.clone(), flow)) else {
                    return;
                };
                let mut frame = Vec::with_capacity(proto::datagram_frame_size(&peer, data.len()));
                proto::encode(
                    &Frame::Recv {
                        flow: *helper,
                        peer,
                        data: &data,
                    },
                    &mut frame,
                );
                out.0.push(Out::Data { frame, tunnel, at });
            }
            Delivery::Closed {
                tunnel,
                flow,
                reason,
            } => {
                if let Some(helper) = back.remove(&(tunnel, flow)) {
                    flows.remove(&helper);
                    out.control(&Frame::Close {
                        flow: helper,
                        reason,
                    });
                }
            }
            Delivery::Down { tunnel } => {
                let gone: Vec<u32> = flows
                    .iter()
                    .filter(|(_, (owner, ..))| *owner == tunnel)
                    .map(|(helper, _)| *helper)
                    .collect();
                for helper in gone {
                    if let Some((tunnel, tflow, ..)) = flows.remove(&helper) {
                        back.remove(&(tunnel, tflow));
                    }
                    out.control(&Frame::Close {
                        flow: helper,
                        reason: CloseReason::Socket,
                    });
                }
            }
        }
    }
}

/// Frames for the helper. Control frames are never given up; answers are, when they wait too
/// long or do not fit.
enum Out {
    Control(Vec<u8>),
    Data {
        frame: Vec<u8>,
        tunnel: String,
        at: Instant,
    },
}

#[derive(Default)]
struct Outgoing(Vec<Out>);

impl Outgoing {
    fn control(&mut self, frame: &Frame<'_>) {
        let mut bytes = Vec::new();
        proto::encode(frame, &mut bytes);
        self.0.push(Out::Control(bytes));
    }
}

#[derive(Default)]
struct OutboxState {
    items: VecDeque<Out>,
    data: usize,
    data_bytes: usize,
}

#[derive(Default)]
struct Outbox {
    state: Mutex<OutboxState>,
    wake: Notify,
}

impl Outbox {
    fn push(&self, router: &Router, items: Vec<Out>) {
        let mut state = self.state.lock().unwrap();
        for item in items {
            if let Out::Data { frame, .. } = &item {
                state.data += 1;
                state.data_bytes += frame.len();
            }
            state.items.push_back(item);
        }
        while state.data > CHANNEL_QUEUE_DATAGRAMS || state.data_bytes > CHANNEL_QUEUE_BYTES {
            let Some(index) = state
                .items
                .iter()
                .position(|item| matches!(item, Out::Data { .. }))
            else {
                break;
            };
            if let Some(Out::Data { frame, tunnel, .. }) = state.items.remove(index) {
                state.data -= 1;
                state.data_bytes -= frame.len();
                router.count_to_helper(&tunnel, Err(DropReason::Overflow));
            }
        }
        drop(state);
        self.wake.notify_one();
    }
}

impl Router {
    fn count_to_helper(&self, tunnel: &str, outcome: Result<std::time::Duration, DropReason>) {
        let mut state = self.state.lock().unwrap();
        let totals = state.tunnels.entry(tunnel.to_owned()).or_default();
        match outcome {
            Ok(waited) => totals.to_helper_delay.record(waited),
            Err(reason) => totals.to_helper_drops.add(reason),
        }
    }
}

/// Writes queued frames to the helper; a write blocked for `SILENCE_TIMEOUT` ends the channel.
async fn write_out<W: AsyncWrite + Unpin>(router: Arc<Router>, outbox: Arc<Outbox>, mut writer: W) {
    let mut batch = Vec::with_capacity(WRITE_BATCH + proto::MAX_FRAME);
    loop {
        batch.clear();
        {
            let now = Instant::now();
            let mut state = outbox.state.lock().unwrap();
            while batch.len() < WRITE_BATCH {
                let Some(item) = state.items.pop_front() else {
                    break;
                };
                match item {
                    Out::Control(frame) => batch.extend_from_slice(&frame),
                    Out::Data { frame, tunnel, at } => {
                        state.data -= 1;
                        state.data_bytes -= frame.len();
                        let waited = now.saturating_duration_since(at);
                        if waited > DATAGRAM_EXPIRY {
                            router.count_to_helper(&tunnel, Err(DropReason::Expired));
                            continue;
                        }
                        router.count_to_helper(&tunnel, Ok(waited));
                        batch.extend_from_slice(&frame);
                    }
                }
            }
        }
        if batch.is_empty() {
            outbox.wake.notified().await;
            continue;
        }
        let written = tokio::time::timeout(SILENCE_TIMEOUT, async {
            writer.write_all(&batch).await?;
            writer.flush().await
        })
        .await;
        if !matches!(written, Ok(Ok(()))) {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
