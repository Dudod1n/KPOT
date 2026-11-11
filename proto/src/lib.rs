//! Frames of the UDP channel between КРОТ and `krot-relay`, and the metrics both sides share.
//!
//! The channel is a byte stream (the stdin/stdout of an SSH exec channel). Every frame is
//! `length: u32 BE` (bytes after the length field), `type: u8`, body. All integers are
//! big-endian. Parsing never reads past the given buffer and never panics: a malformed
//! frame is an error that ends the session.
#![forbid(unsafe_code)]

pub mod limits;
pub mod metrics;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// First bytes of `HELLO` and `HELLO_OK`.
pub const MAGIC: [u8; 4] = *b"KRUD";
/// Protocol version; both sides refuse any other.
pub const VERSION: u16 = 1;
/// The largest UDP payload over IPv4, used for both families.
pub const MAX_PAYLOAD: usize = 65_507;
/// Type byte, flow, family, IPv6 address and port in front of the largest payload.
pub const MAX_FRAME: usize = 1 + 4 + 1 + 16 + 2 + MAX_PAYLOAD;
/// Length field.
pub const LENGTH_SIZE: usize = 4;

pub mod kind {
    pub const HELLO: u8 = 0x01;
    pub const HELLO_OK: u8 = 0x02;
    pub const REFUSE: u8 = 0x03;
    pub const SEND: u8 = 0x10;
    pub const RECV: u8 = 0x11;
    pub const CLOSE: u8 = 0x12;
    pub const PING: u8 = 0x20;
    pub const PONG: u8 = 0x21;
    pub const ACK: u8 = 0x22;
    pub const STATS: u8 = 0x30;
    pub const OPEN: u8 = 0x40;
}

/// Why `REFUSE` was sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Version,
    Other(u8),
}

impl Refusal {
    fn code(self) -> u8 {
        match self {
            Self::Version => 1,
            Self::Other(code) => code,
        }
    }
    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Version,
            code => Self::Other(code),
        }
    }
}

/// Why a flow ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The client no longer needs the flow.
    Client,
    Idle,
    /// The relay already holds as many flows as allowed.
    Limit,
    /// The socket of the flow failed.
    Socket,
    Other(u8),
}

impl CloseReason {
    fn code(self) -> u8 {
        match self {
            Self::Client => 0,
            Self::Idle => 1,
            Self::Limit => 2,
            Self::Socket => 3,
            Self::Other(code) => code,
        }
    }
    fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Client,
            1 => Self::Idle,
            2 => Self::Limit,
            3 => Self::Socket,
            code => Self::Other(code),
        }
    }
}

/// Settings the client asks for in `HELLO`; the relay clamps them and answers with its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub max_flows: u16,
    pub idle_ms: u32,
    pub idle_bidirectional_ms: u32,
}

/// Counters and per-interval histograms the relay reports once a second.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayStats {
    pub flows_active: u32,
    pub flows_opened: u64,
    pub flows_refused: u64,
    pub to_network_datagrams: u64,
    pub to_network_bytes: u64,
    pub from_network_datagrams: u64,
    pub from_network_bytes: u64,
    pub drops: metrics::Drops,
    /// Time a datagram waited in the relay before `sendto`.
    pub to_network_delay: metrics::Histogram,
    /// Time a datagram waited in the relay before it was written to the client.
    pub to_client_delay: metrics::Histogram,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    Hello {
        version: u16,
        settings: Settings,
    },
    HelloOk {
        version: u16,
        settings: Settings,
    },
    Refuse {
        reason: Refusal,
        supported: u16,
    },
    /// A datagram of `flow` to `peer`.
    Send {
        flow: u32,
        peer: SocketAddr,
        data: &'a [u8],
    },
    /// A datagram for `flow` from `peer`.
    Recv {
        flow: u32,
        peer: SocketAddr,
        data: &'a [u8],
    },
    Close {
        flow: u32,
        reason: CloseReason,
    },
    Ping {
        sequence: u32,
        time_us: u64,
    },
    /// Echo of `PING`; `held_us` is how long the ping waited in the relay.
    Pong {
        sequence: u32,
        time_us: u64,
        held_us: u32,
    },
    /// Bytes of `SEND`/`RECV` frames received so far, for the sender's in-flight limit.
    Ack {
        received: u64,
    },
    Stats(Box<RelayStats>),
    /// Local channel only: the rule a new flow belongs to.
    Open {
        flow: u32,
        rule: &'a str,
    },
}

/// Why a byte stream is not a valid sequence of frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The length field is zero or above `MAX_FRAME`.
    Length,
    UnknownKind(u8),
    /// The body does not match its type.
    Malformed,
    Magic,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length => formatter.write_str("invalid frame length"),
            Self::UnknownKind(kind) => write!(formatter, "unknown frame type {kind:#04x}"),
            Self::Malformed => formatter.write_str("malformed frame"),
            Self::Magic => formatter.write_str("not a KROT UDP channel"),
        }
    }
}

impl std::error::Error for Error {}

/// Reads one frame from the start of `buffer`. `Ok(None)` means more bytes are needed;
/// otherwise the frame and the number of bytes it took are returned.
pub fn parse(buffer: &[u8]) -> Result<Option<(Frame<'_>, usize)>, Error> {
    let Some(length) = buffer.get(..LENGTH_SIZE) else {
        return Ok(None);
    };
    let length = u32::from_be_bytes([length[0], length[1], length[2], length[3]]) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(Error::Length);
    }
    let Some(body) = buffer.get(LENGTH_SIZE..LENGTH_SIZE + length) else {
        return Ok(None);
    };
    let mut reader = Reader(&body[1..]);
    let frame = match body[0] {
        kind::HELLO => {
            let (version, settings) = reader.hello()?;
            Frame::Hello { version, settings }
        }
        kind::HELLO_OK => {
            let (version, settings) = reader.hello()?;
            Frame::HelloOk { version, settings }
        }
        kind::REFUSE => Frame::Refuse {
            reason: Refusal::from_code(reader.u8()?),
            supported: reader.u16()?,
        },
        kind::SEND | kind::RECV => {
            let flow = reader.u32()?;
            let peer = reader.address()?;
            let data = reader.rest();
            if data.len() > MAX_PAYLOAD {
                return Err(Error::Malformed);
            }
            if body[0] == kind::SEND {
                Frame::Send { flow, peer, data }
            } else {
                Frame::Recv { flow, peer, data }
            }
        }
        kind::CLOSE => Frame::Close {
            flow: reader.u32()?,
            reason: CloseReason::from_code(reader.u8()?),
        },
        kind::PING => Frame::Ping {
            sequence: reader.u32()?,
            time_us: reader.u64()?,
        },
        kind::PONG => Frame::Pong {
            sequence: reader.u32()?,
            time_us: reader.u64()?,
            held_us: reader.u32()?,
        },
        kind::ACK => Frame::Ack {
            received: reader.u64()?,
        },
        kind::STATS => Frame::Stats(Box::new(reader.stats()?)),
        kind::OPEN => {
            let flow = reader.u32()?;
            let length = usize::from(reader.u8()?);
            let rule = std::str::from_utf8(reader.take(length)?).map_err(|_| Error::Malformed)?;
            if rule.is_empty() {
                return Err(Error::Malformed);
            }
            Frame::Open { flow, rule }
        }
        other => return Err(Error::UnknownKind(other)),
    };
    if !reader.0.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(Some((frame, LENGTH_SIZE + length)))
}

/// Appends `frame` to `output`. Panics only on a frame this module would refuse to parse:
/// an oversized payload or an empty or over-long rule name.
pub fn encode(frame: &Frame<'_>, output: &mut Vec<u8>) {
    let start = output.len();
    output.extend_from_slice(&[0; LENGTH_SIZE]);
    match frame {
        Frame::Hello { version, settings } => {
            output.push(kind::HELLO);
            put_hello(output, *version, settings);
        }
        Frame::HelloOk { version, settings } => {
            output.push(kind::HELLO_OK);
            put_hello(output, *version, settings);
        }
        Frame::Refuse { reason, supported } => {
            output.push(kind::REFUSE);
            output.push(reason.code());
            output.extend_from_slice(&supported.to_be_bytes());
        }
        Frame::Send { flow, peer, data } | Frame::Recv { flow, peer, data } => {
            assert!(data.len() <= MAX_PAYLOAD, "datagram above the UDP limit");
            output.push(if matches!(frame, Frame::Send { .. }) {
                kind::SEND
            } else {
                kind::RECV
            });
            output.extend_from_slice(&flow.to_be_bytes());
            put_address(output, peer);
            output.extend_from_slice(data);
        }
        Frame::Close { flow, reason } => {
            output.push(kind::CLOSE);
            output.extend_from_slice(&flow.to_be_bytes());
            output.push(reason.code());
        }
        Frame::Ping { sequence, time_us } => {
            output.push(kind::PING);
            output.extend_from_slice(&sequence.to_be_bytes());
            output.extend_from_slice(&time_us.to_be_bytes());
        }
        Frame::Pong {
            sequence,
            time_us,
            held_us,
        } => {
            output.push(kind::PONG);
            output.extend_from_slice(&sequence.to_be_bytes());
            output.extend_from_slice(&time_us.to_be_bytes());
            output.extend_from_slice(&held_us.to_be_bytes());
        }
        Frame::Ack { received } => {
            output.push(kind::ACK);
            output.extend_from_slice(&received.to_be_bytes());
        }
        Frame::Stats(stats) => {
            output.push(kind::STATS);
            put_stats(output, stats);
        }
        Frame::Open { flow, rule } => {
            let length = u8::try_from(rule.len()).expect("rule name above 255 bytes");
            assert!(length > 0, "empty rule name");
            output.push(kind::OPEN);
            output.extend_from_slice(&flow.to_be_bytes());
            output.push(length);
            output.extend_from_slice(rule.as_bytes());
        }
    }
    let length = (output.len() - start - LENGTH_SIZE) as u32;
    output[start..start + LENGTH_SIZE].copy_from_slice(&length.to_be_bytes());
}

/// Size of the encoded `SEND`/`RECV` frame, without building it.
pub fn datagram_frame_size(peer: &SocketAddr, payload: usize) -> usize {
    LENGTH_SIZE + 1 + 4 + address_size(peer) + payload
}

fn address_size(peer: &SocketAddr) -> usize {
    match peer {
        SocketAddr::V4(_) => 1 + 4 + 2,
        SocketAddr::V6(_) => 1 + 16 + 2,
    }
}

fn put_hello(output: &mut Vec<u8>, version: u16, settings: &Settings) {
    output.extend_from_slice(&MAGIC);
    output.extend_from_slice(&version.to_be_bytes());
    output.extend_from_slice(&settings.max_flows.to_be_bytes());
    output.extend_from_slice(&settings.idle_ms.to_be_bytes());
    output.extend_from_slice(&settings.idle_bidirectional_ms.to_be_bytes());
}

fn put_address(output: &mut Vec<u8>, peer: &SocketAddr) {
    match peer.ip() {
        IpAddr::V4(ip) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(6);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&peer.port().to_be_bytes());
}

fn put_histogram(output: &mut Vec<u8>, histogram: &metrics::Histogram) {
    for count in histogram.buckets {
        output.extend_from_slice(&count.to_be_bytes());
    }
    output.extend_from_slice(&histogram.sum_us.to_be_bytes());
    output.extend_from_slice(&histogram.max_us.to_be_bytes());
}

fn put_stats(output: &mut Vec<u8>, stats: &RelayStats) {
    output.extend_from_slice(&stats.flows_active.to_be_bytes());
    for value in [
        stats.flows_opened,
        stats.flows_refused,
        stats.to_network_datagrams,
        stats.to_network_bytes,
        stats.from_network_datagrams,
        stats.from_network_bytes,
    ] {
        output.extend_from_slice(&value.to_be_bytes());
    }
    for value in stats.drops.0 {
        output.extend_from_slice(&value.to_be_bytes());
    }
    put_histogram(output, &stats.to_network_delay);
    put_histogram(output, &stats.to_client_delay);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < count {
            return Err(Error::Malformed);
        }
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut array = [0; N];
        array.copy_from_slice(self.take(N)?);
        Ok(array)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }
    fn hello(&mut self) -> Result<(u16, Settings), Error> {
        if self.array::<4>()? != MAGIC {
            return Err(Error::Magic);
        }
        Ok((
            self.u16()?,
            Settings {
                max_flows: self.u16()?,
                idle_ms: self.u32()?,
                idle_bidirectional_ms: self.u32()?,
            },
        ))
    }
    fn address(&mut self) -> Result<SocketAddr, Error> {
        let ip = match self.u8()? {
            4 => IpAddr::V4(Ipv4Addr::from(self.array::<4>()?)),
            6 => IpAddr::V6(Ipv6Addr::from(self.array::<16>()?)),
            _ => return Err(Error::Malformed),
        };
        Ok(SocketAddr::new(ip, self.u16()?))
    }
    fn histogram(&mut self) -> Result<metrics::Histogram, Error> {
        let mut histogram = metrics::Histogram::default();
        for count in &mut histogram.buckets {
            *count = self.u64()?;
        }
        histogram.sum_us = self.u64()?;
        histogram.max_us = self.u64()?;
        Ok(histogram)
    }
    fn stats(&mut self) -> Result<RelayStats, Error> {
        let mut stats = RelayStats {
            flows_active: self.u32()?,
            flows_opened: self.u64()?,
            flows_refused: self.u64()?,
            to_network_datagrams: self.u64()?,
            to_network_bytes: self.u64()?,
            from_network_datagrams: self.u64()?,
            from_network_bytes: self.u64()?,
            ..Default::default()
        };
        for value in &mut stats.drops.0 {
            *value = self.u64()?;
        }
        stats.to_network_delay = self.histogram()?;
        stats.to_client_delay = self.histogram()?;
        Ok(stats)
    }
}

#[cfg(test)]
mod tests;
