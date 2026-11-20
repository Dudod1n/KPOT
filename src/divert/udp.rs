//! UDP of covered applications through the tunnel's relay: the flow table and the packets the
//! helper builds for answers. Platform-neutral and tested everywhere.
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use krot_udp_proto::limits::{DEFAULT_IDLE, DEFAULT_IDLE_BIDIRECTIONAL};

const UDP: u8 = 17;
/// Hop limit of injected answers: they never cross a router.
const TTL: u8 = 64;

/// How a rule's UDP is handled right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// The tunnel is down or carries no UDP: only name resolution passes, as in 0.5.8.
    Block,
    /// The tunnel is down and the rule lets the application go around it.
    Direct,
    /// Datagrams go through the tunnel's relay; UDP 443 too when `quic` is set.
    Tunnel { quic: bool },
}

/// The local and remote endpoints of an outbound UDP packet and its payload.
pub fn outbound(data: &[u8]) -> Option<(SocketAddr, SocketAddr, &[u8])> {
    let (source, destination, transport, end) = match data.first()? >> 4 {
        4 => {
            let header = usize::from(data[0] & 0x0f) * 4;
            if header < 20 || data.len() < header || data[9] != UDP {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([data[2], data[3]]));
            let address =
                |at: usize| IpAddr::from([data[at], data[at + 1], data[at + 2], data[at + 3]]);
            (address(12), address(16), header, total.min(data.len()))
        }
        6 if data.len() >= 40 && data[6] == UDP => {
            let address = |at: usize| {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[at..at + 16]);
                IpAddr::from(octets)
            };
            let payload = usize::from(u16::from_be_bytes([data[4], data[5]]));
            (address(8), address(24), 40, (40 + payload).min(data.len()))
        }
        _ => return None,
    };
    let header = data.get(transport..transport + 8)?;
    let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if length < 8 || transport + length > end {
        return None;
    }
    Some((
        SocketAddr::new(source, u16::from_be_bytes([header[0], header[1]])),
        SocketAddr::new(destination, u16::from_be_bytes([header[2], header[3]])),
        &data[transport + 8..transport + length],
    ))
}

fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn add(sum: &mut u32, bytes: &[u8]) {
    for pair in bytes.chunks(2) {
        *sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
}

/// An inbound IPv4 or IPv6 packet carrying `payload` from `source` to the application at
/// `destination`, with valid checksums. `None` when the families differ or it is too large.
pub fn inbound(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    ident: u16,
) -> Option<Vec<u8>> {
    let udp_length = u16::try_from(8 + payload.len()).ok()?;
    let mut udp = Vec::with_capacity(usize::from(udp_length));
    udp.extend_from_slice(&source.port().to_be_bytes());
    udp.extend_from_slice(&destination.port().to_be_bytes());
    udp.extend_from_slice(&udp_length.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let mut pseudo = 0u32;
    let mut packet = match (source.ip(), destination.ip()) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            let total = u16::try_from(20 + udp.len()).ok()?;
            let mut header = vec![0x45, 0];
            header.extend_from_slice(&total.to_be_bytes());
            header.extend_from_slice(&ident.to_be_bytes());
            header.extend_from_slice(&[0, 0, TTL, UDP, 0, 0]);
            header.extend_from_slice(&from.octets());
            header.extend_from_slice(&to.octets());
            let mut sum = 0;
            add(&mut sum, &header);
            header[10..12].copy_from_slice(&fold(sum).to_be_bytes());
            add(&mut pseudo, &from.octets());
            add(&mut pseudo, &to.octets());
            header
        }
        (IpAddr::V6(from), IpAddr::V6(to)) => {
            let mut header = vec![0x60, 0, 0, 0];
            header.extend_from_slice(&udp_length.to_be_bytes());
            header.extend_from_slice(&[UDP, TTL]);
            header.extend_from_slice(&from.octets());
            header.extend_from_slice(&to.octets());
            add(&mut pseudo, &from.octets());
            add(&mut pseudo, &to.octets());
            header
        }
        _ => return None,
    };
    pseudo += u32::from(UDP) + u32::from(udp_length);
    add(&mut pseudo, &udp);
    // An all-zero result is sent as all ones; zero means "no checksum" in IPv4.
    let checksum = match fold(pseudo) {
        0 => 0xffff,
        value => value,
    };
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&udp);
    Some(packet)
}

/// Identifies the fragments of one datagram: its addresses and the identification field.
pub type FragmentKey = (IpAddr, IpAddr, u32);

/// A fragment of a UDP datagram, IPv4 or IPv6: its key and, for the first fragment, where
/// its UDP header starts. Later fragments carry no UDP header.
pub fn fragment(data: &[u8]) -> Option<(FragmentKey, Option<usize>)> {
    match data.first()? >> 4 {
        4 => {
            let header = usize::from(data[0] & 0x0f) * 4;
            if data.len() < 20 || header < 20 || data[9] != UDP {
                return None;
            }
            let field = u16::from_be_bytes([data[6], data[7]]);
            let (more, offset) = (field & 0x2000 != 0, field & 0x1fff);
            if !more && offset == 0 {
                return None;
            }
            let address =
                |at: usize| IpAddr::from([data[at], data[at + 1], data[at + 2], data[at + 3]]);
            let id = u16::from_be_bytes([data[4], data[5]]);
            Some((
                (address(12), address(16), u32::from(id)),
                (offset == 0).then_some(header),
            ))
        }
        6 if data.len() >= 40 => {
            let at = ipv6_fragment_header(data)?;
            let header = &data[at..at + 8];
            if header[0] != UDP {
                return None;
            }
            // An atomic fragment (offset 0, no more fragments) is a whole datagram behind a
            // fragment header; it is treated as a first fragment and never captured.
            let offset = u16::from_be_bytes([header[2], header[3]]) >> 3;
            let address = |at: usize| {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[at..at + 16]);
                IpAddr::from(octets)
            };
            let id = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
            Some((
                (address(8), address(24), id),
                (offset == 0).then_some(at + 8),
            ))
        }
        _ => None,
    }
}

/// Where the fragment header of an IPv6 packet starts, past the extension headers that may
/// precede it.
fn ipv6_fragment_header(data: &[u8]) -> Option<usize> {
    const HOP_BY_HOP: u8 = 0;
    const ROUTING: u8 = 43;
    const FRAGMENT: u8 = 44;
    const DESTINATION: u8 = 60;
    let (mut next, mut at) = (data[6], 40);
    loop {
        match next {
            FRAGMENT => return (data.len() >= at + 8).then_some(at),
            HOP_BY_HOP | ROUTING | DESTINATION => {
                let header = data.get(at..at + 2)?;
                next = header[0];
                at += (usize::from(header[1]) + 1) * 8;
            }
            _ => return None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Flow<M> {
    pub id: u32,
    pub rule: String,
    /// What the platform needs to inject answers, from the latest outbound packet.
    pub meta: M,
    seen: Instant,
    received: bool,
}

/// Flows of covered sockets, keyed by the application's local address.
pub struct Flows<M> {
    by_local: HashMap<SocketAddr, Flow<M>>,
    by_id: HashMap<u32, SocketAddr>,
    next: u32,
}

impl<M> Default for Flows<M> {
    fn default() -> Self {
        Self {
            by_local: HashMap::new(),
            by_id: HashMap::new(),
            next: 0,
        }
    }
}

/// What an outbound datagram did to the table.
#[derive(Debug, PartialEq, Eq)]
pub struct Outbound {
    pub id: u32,
    /// The flow is new: the relay must learn its rule first.
    pub opened: bool,
    /// A flow of the same socket under another rule that has to be closed.
    pub replaced: Option<u32>,
}

impl<M> Flows<M> {
    pub fn outbound(&mut self, local: SocketAddr, rule: &str, meta: M, now: Instant) -> Outbound {
        let mut replaced = None;
        if let Some(flow) = self.by_local.get_mut(&local) {
            if flow.rule == rule {
                flow.meta = meta;
                flow.seen = now;
                return Outbound {
                    id: flow.id,
                    opened: false,
                    replaced: None,
                };
            }
            replaced = Some(flow.id);
            self.by_id.remove(&flow.id);
        }
        self.next = self.next.wrapping_add(1).max(1);
        let id = self.next;
        self.by_id.insert(id, local);
        self.by_local.insert(
            local,
            Flow {
                id,
                rule: rule.to_owned(),
                meta,
                seen: now,
                received: false,
            },
        );
        Outbound {
            id,
            opened: true,
            replaced,
        }
    }

    /// The application socket an answer for `id` goes to.
    pub fn inbound(&mut self, id: u32, now: Instant) -> Option<(SocketAddr, &Flow<M>)> {
        let local = *self.by_id.get(&id)?;
        let flow = self.by_local.get_mut(&local)?;
        flow.seen = now;
        flow.received = true;
        Some((local, flow))
    }

    pub fn close(&mut self, id: u32) -> Option<Flow<M>> {
        let local = self.by_id.remove(&id)?;
        self.by_local.remove(&local)
    }

    /// Removes idle flows, with the relay's timeouts, and returns their ids.
    pub fn purge(&mut self, now: Instant) -> Vec<u32> {
        self.purge_after(now, DEFAULT_IDLE, DEFAULT_IDLE_BIDIRECTIONAL)
    }

    fn purge_after(&mut self, now: Instant, idle: Duration, both: Duration) -> Vec<u32> {
        let gone: Vec<SocketAddr> = self
            .by_local
            .iter()
            .filter(|(_, flow)| {
                now.duration_since(flow.seen) > if flow.received { both } else { idle }
            })
            .map(|(local, _)| *local)
            .collect();
        gone.into_iter()
            .filter_map(|local| self.by_local.remove(&local))
            .map(|flow| {
                self.by_id.remove(&flow.id);
                flow.id
            })
            .collect()
    }

    /// Ends every flow, e.g. when the channel to the background process is lost.
    pub fn clear(&mut self) -> Vec<u32> {
        self.by_id.clear();
        self.by_local.drain().map(|(_, flow)| flow.id).collect()
    }

    pub fn len(&self) -> usize {
        self.by_local.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_local.is_empty()
    }
}

#[cfg(test)]
mod tests;
