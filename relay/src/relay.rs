//! A single-threaded `poll` loop over stdin, stdout and one UDP socket per flow.
//!
//! Delay must not build up anywhere: every queue is bounded by count and bytes and drops its
//! oldest datagram when full, a datagram older than `DATAGRAM_EXPIRY` is dropped instead of
//! being sent, and datagrams towards the client stop once `IN_FLIGHT_WINDOW` bytes are
//! unacknowledged, so they wait here, where expiry applies, and not in SSH or TCP buffers.
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    time::{Duration, Instant},
};

use krot_udp_proto::{
    self as proto, CloseReason, Frame, Refusal, RelayStats, Settings, VERSION,
    limits::{
        ACK_INTERVAL, CHANNEL_QUEUE_BYTES, CHANNEL_QUEUE_DATAGRAMS, DATAGRAM_EXPIRY,
        FLOW_QUEUE_BYTES, FLOW_QUEUE_DATAGRAMS, HELLO_TIMEOUT, IN_FLIGHT_WINDOW, MAX_IDLE,
        MIN_IDLE, RELAY_MAX_FLOWS, REPORT_INTERVAL, WRITE_BATCH,
    },
    metrics::DropReason,
};

const STDIN: RawFd = 0;
const STDOUT: RawFd = 1;
const READ_CHUNK: usize = 256 * 1024;
/// Datagrams read from one flow socket per loop round, so one busy flow cannot starve others.
const READS_PER_ROUND: usize = 64;
/// Control frames waiting for stdout; a client that makes more is not following the protocol.
const MAX_CONTROL: usize = 8192;

enum Exit {
    /// stdin closed: the SSH channel is gone.
    Done,
    /// The client sent something that is not a valid frame sequence.
    Protocol,
    /// stdin or stdout failed.
    Io,
    /// The client speaks another protocol version.
    Refused,
}

pub fn run() -> i32 {
    let result = Relay::new().and_then(|mut relay| relay.serve());
    match result {
        Ok(()) | Err(Exit::Done) => 0,
        Err(Exit::Protocol) => 3,
        Err(Exit::Io) => 4,
        Err(Exit::Refused) => 5,
    }
}

struct Outgoing {
    peer: SocketAddr,
    data: Vec<u8>,
    at: Instant,
}

struct Flow {
    socket: UdpSocket,
    /// The socket is IPv6 with IPv4-mapped addresses enabled.
    dual: bool,
    queue: VecDeque<Outgoing>,
    queued_bytes: usize,
    last: Instant,
    sent: bool,
    received: bool,
}

/// A datagram frame for the client and when it was queued.
struct Pending {
    frame: Vec<u8>,
    at: Instant,
}

enum Control {
    Frame(Vec<u8>),
    /// Encoded when written, so that it reports how long it waited.
    Pong {
        sequence: u32,
        time_us: u64,
        at: Instant,
    },
}

struct Relay {
    settings: Option<Settings>,
    started: Instant,
    input: Vec<u8>,
    input_start: usize,
    flows: HashMap<u32, Flow>,
    control: VecDeque<Control>,
    data: VecDeque<Pending>,
    data_bytes: usize,
    /// The batch being written to stdout and how much of it is written.
    output: Vec<u8>,
    written: usize,
    /// Datagram frame bytes written to and acknowledged by the client.
    sent_bytes: u64,
    acked_bytes: u64,
    /// Datagram frame bytes received from the client and the value last acknowledged.
    received_bytes: u64,
    acknowledged: u64,
    ack_at: Instant,
    report_at: Instant,
    stats: RelayStats,
    scratch: Vec<u8>,
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor this process owns; no memory is passed.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: as above.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(last_error());
    }
    Ok(())
}

fn read_fd(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the buffer is valid for writes of its whole length.
    let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if count < 0 {
        Err(last_error())
    } else {
        Ok(count as usize)
    }
}

fn write_fd(fd: RawFd, buffer: &[u8]) -> io::Result<usize> {
    // SAFETY: the buffer is valid for reads of its whole length.
    let count = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
    if count < 0 {
        Err(last_error())
    } else {
        Ok(count as usize)
    }
}

/// A non-blocking UDP socket on an ephemeral port: dual-stack where the server has IPv6.
fn open_socket() -> io::Result<(UdpSocket, bool)> {
    // SAFETY: plain socket creation; the descriptor is owned by the `UdpSocket` right away.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd >= 0 {
        // SAFETY: `fd` is a fresh socket owned by nobody else.
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        let off: libc::c_int = 0;
        // SAFETY: zeroed `sockaddr_in6` is the unspecified address with port 0.
        let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        // SAFETY: the option value and the address are valid for the sizes passed.
        let dual = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                (&off as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            ) == 0
                && libc::bind(
                    fd,
                    (&address as *const libc::sockaddr_in6).cast(),
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                ) == 0
        };
        if dual {
            return Ok((socket, true));
        }
    }
    // Without IPv6 the flow reaches IPv4 only.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;
    Ok((socket, false))
}

fn target(peer: SocketAddr, dual: bool) -> SocketAddr {
    match peer.ip() {
        IpAddr::V4(ip) if dual => SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), peer.port()),
        _ => peer,
    }
}

fn would_block(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn send_error(error: &io::Error) -> DropReason {
    if error.raw_os_error() == Some(libc::EMSGSIZE) {
        DropReason::Size
    } else {
        DropReason::Channel
    }
}

impl Relay {
    fn new() -> Result<Self, Exit> {
        set_nonblocking(STDIN).map_err(|_| Exit::Io)?;
        set_nonblocking(STDOUT).map_err(|_| Exit::Io)?;
        let now = Instant::now();
        Ok(Self {
            settings: None,
            started: now,
            input: Vec::with_capacity(READ_CHUNK),
            input_start: 0,
            flows: HashMap::new(),
            control: VecDeque::new(),
            data: VecDeque::new(),
            data_bytes: 0,
            output: Vec::with_capacity(WRITE_BATCH + proto::MAX_FRAME),
            written: 0,
            sent_bytes: 0,
            acked_bytes: 0,
            received_bytes: 0,
            acknowledged: 0,
            ack_at: now,
            report_at: now + REPORT_INTERVAL,
            stats: RelayStats::default(),
            scratch: vec![0; 65_536],
        })
    }

    fn serve(&mut self) -> Result<(), Exit> {
        let mut descriptors: Vec<libc::pollfd> = Vec::new();
        let mut owners: Vec<u32> = Vec::new();
        loop {
            let now = Instant::now();
            if self.settings.is_none() && now.duration_since(self.started) > HELLO_TIMEOUT {
                return Err(Exit::Protocol);
            }
            self.tick(now);
            self.flush()?;

            descriptors.clear();
            owners.clear();
            descriptors.push(libc::pollfd {
                fd: STDIN,
                events: libc::POLLIN,
                revents: 0,
            });
            descriptors.push(libc::pollfd {
                fd: STDOUT,
                events: if self.written < self.output.len() {
                    libc::POLLOUT
                } else {
                    0
                },
                revents: 0,
            });
            for (id, flow) in &self.flows {
                owners.push(*id);
                descriptors.push(libc::pollfd {
                    fd: flow.socket.as_raw_fd(),
                    events: libc::POLLIN
                        | if flow.queue.is_empty() {
                            0
                        } else {
                            libc::POLLOUT
                        },
                    revents: 0,
                });
            }
            let timeout = self.timeout(now);
            // SAFETY: the array holds `descriptors.len()` initialised entries.
            let ready = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    timeout,
                )
            };
            if ready < 0 {
                if would_block(&last_error()) {
                    continue;
                }
                return Err(Exit::Io);
            }
            if descriptors[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(Exit::Io);
            }
            if descriptors[0].revents != 0 {
                self.read_input()?;
            }
            for (descriptor, id) in descriptors[2..].iter().zip(&owners) {
                if descriptor.revents & libc::POLLOUT != 0 {
                    self.drain_flow(*id);
                }
                if descriptor.revents & (libc::POLLIN | libc::POLLERR) != 0 {
                    self.receive(*id);
                }
            }
        }
    }

    /// Milliseconds until the next timed duty, at most one report interval.
    fn timeout(&self, now: Instant) -> libc::c_int {
        let mut until = self.report_at.saturating_duration_since(now);
        if self.received_bytes != self.acknowledged {
            until = until.min((self.ack_at + ACK_INTERVAL).saturating_duration_since(now));
        }
        until.as_millis().min(1000) as libc::c_int
    }

    fn tick(&mut self, now: Instant) {
        if self.received_bytes != self.acknowledged
            && (now.duration_since(self.ack_at) >= ACK_INTERVAL
                || self.received_bytes - self.acknowledged >= IN_FLIGHT_WINDOW / 4)
        {
            self.acknowledged = self.received_bytes;
            self.ack_at = now;
            self.push_control(&Frame::Ack {
                received: self.received_bytes,
            });
        }
        if now < self.report_at {
            return;
        }
        self.report_at = now + REPORT_INTERVAL;
        if let Some(settings) = self.settings {
            let idle = Duration::from_millis(u64::from(settings.idle_ms));
            let idle_both = Duration::from_millis(u64::from(settings.idle_bidirectional_ms));
            let expired: Vec<u32> = self
                .flows
                .iter()
                .filter(|(_, flow)| {
                    let limit = if flow.sent && flow.received {
                        idle_both
                    } else {
                        idle
                    };
                    now.duration_since(flow.last) > limit
                })
                .map(|(id, _)| *id)
                .collect();
            for flow in expired {
                self.flows.remove(&flow);
                self.push_control(&Frame::Close {
                    flow,
                    reason: CloseReason::Idle,
                });
            }
            self.stats.flows_active = self.flows.len() as u32;
            let stats = self.stats.clone();
            self.stats.to_network_delay = Default::default();
            self.stats.to_client_delay = Default::default();
            self.push_control(&Frame::Stats(Box::new(stats)));
        }
    }

    fn push_control(&mut self, frame: &Frame<'_>) {
        let mut encoded = Vec::new();
        proto::encode(frame, &mut encoded);
        self.control.push_back(Control::Frame(encoded));
    }

    fn read_input(&mut self) -> Result<(), Exit> {
        if self.input_start > 0 {
            self.input.drain(..self.input_start);
            self.input_start = 0;
        }
        let length = self.input.len();
        self.input.resize(length + READ_CHUNK, 0);
        let result = read_fd(STDIN, &mut self.input[length..]);
        let count = match result {
            Ok(0) => return Err(Exit::Done),
            Ok(count) => count,
            Err(error) if would_block(&error) => 0,
            Err(_) => return Err(Exit::Io),
        };
        self.input.truncate(length + count);
        let input = std::mem::take(&mut self.input);
        let result = self.consume(&input);
        self.input = input;
        result?;
        if self.control.len() > MAX_CONTROL {
            return Err(Exit::Protocol);
        }
        Ok(())
    }

    fn consume(&mut self, input: &[u8]) -> Result<(), Exit> {
        loop {
            let parsed = proto::parse(&input[self.input_start..]).map_err(|_| Exit::Protocol)?;
            let Some((frame, used)) = parsed else {
                return Ok(());
            };
            self.input_start += used;
            let now = Instant::now();
            match (self.settings, frame) {
                (None, Frame::Hello { version, settings }) => {
                    if version != VERSION {
                        self.push_control(&Frame::Refuse {
                            reason: Refusal::Version,
                            supported: VERSION,
                        });
                        self.flush_all();
                        return Err(Exit::Refused);
                    }
                    let clamp = |ms: u32| {
                        Duration::from_millis(u64::from(ms))
                            .clamp(MIN_IDLE, MAX_IDLE)
                            .as_millis() as u32
                    };
                    let settings = Settings {
                        max_flows: settings.max_flows.clamp(1, RELAY_MAX_FLOWS),
                        idle_ms: clamp(settings.idle_ms),
                        idle_bidirectional_ms: clamp(settings.idle_bidirectional_ms),
                    };
                    self.settings = Some(settings);
                    self.push_control(&Frame::HelloOk {
                        version: VERSION,
                        settings,
                    });
                }
                (None, _) | (Some(_), Frame::Hello { .. }) => return Err(Exit::Protocol),
                (Some(settings), Frame::Send { flow, peer, data }) => {
                    self.received_bytes += used as u64;
                    self.send(settings, flow, peer, data, now);
                }
                (Some(_), Frame::Close { flow, .. }) => {
                    self.flows.remove(&flow);
                }
                (Some(_), Frame::Ping { sequence, time_us }) => {
                    self.control.push_back(Control::Pong {
                        sequence,
                        time_us,
                        at: now,
                    });
                }
                (Some(_), Frame::Ack { received }) => {
                    // Never more than was sent, whatever the client claims.
                    self.acked_bytes = self.acked_bytes.max(received.min(self.sent_bytes));
                }
                // Frames only the relay sends, or the local channel uses.
                (Some(_), _) => return Err(Exit::Protocol),
            }
        }
    }

    fn send(&mut self, settings: Settings, id: u32, peer: SocketAddr, data: &[u8], now: Instant) {
        if !self.flows.contains_key(&id) {
            if self.flows.len() >= usize::from(settings.max_flows) {
                self.stats.flows_refused += 1;
                self.push_control(&Frame::Close {
                    flow: id,
                    reason: CloseReason::Limit,
                });
                return;
            }
            let Ok((socket, dual)) = open_socket() else {
                self.stats.drops.add(DropReason::Channel);
                self.push_control(&Frame::Close {
                    flow: id,
                    reason: CloseReason::Socket,
                });
                return;
            };
            self.stats.flows_opened += 1;
            self.flows.insert(
                id,
                Flow {
                    socket,
                    dual,
                    queue: VecDeque::new(),
                    queued_bytes: 0,
                    last: now,
                    sent: false,
                    received: false,
                },
            );
        }
        let Some(flow) = self.flows.get_mut(&id) else {
            return;
        };
        flow.last = now;
        flow.sent = true;
        if flow.queue.is_empty() {
            match flow.socket.send_to(data, target(peer, flow.dual)) {
                Ok(_) => {
                    self.stats.to_network_datagrams += 1;
                    self.stats.to_network_bytes += data.len() as u64;
                    self.stats.to_network_delay.record(now.elapsed());
                    return;
                }
                Err(error) if would_block(&error) => {}
                Err(error) => {
                    self.stats.drops.add(send_error(&error));
                    return;
                }
            }
        }
        while flow.queue.len() >= FLOW_QUEUE_DATAGRAMS
            || flow.queued_bytes + data.len() > FLOW_QUEUE_BYTES
        {
            let Some(old) = flow.queue.pop_front() else {
                break;
            };
            flow.queued_bytes -= old.data.len();
            self.stats.drops.add(DropReason::Overflow);
        }
        flow.queued_bytes += data.len();
        flow.queue.push_back(Outgoing {
            peer,
            data: data.to_vec(),
            at: now,
        });
    }

    fn drain_flow(&mut self, id: u32) {
        let Some(flow) = self.flows.get_mut(&id) else {
            return;
        };
        while let Some(datagram) = flow.queue.pop_front() {
            let waited = datagram.at.elapsed();
            if waited > DATAGRAM_EXPIRY {
                flow.queued_bytes -= datagram.data.len();
                self.stats.drops.add(DropReason::Expired);
                continue;
            }
            match flow
                .socket
                .send_to(&datagram.data, target(datagram.peer, flow.dual))
            {
                Ok(_) => {
                    self.stats.to_network_datagrams += 1;
                    self.stats.to_network_bytes += datagram.data.len() as u64;
                    self.stats.to_network_delay.record(waited);
                }
                Err(error) if would_block(&error) => {
                    flow.queue.push_front(datagram);
                    return;
                }
                Err(error) => self.stats.drops.add(send_error(&error)),
            }
            flow.queued_bytes -= datagram.data.len();
        }
    }

    fn receive(&mut self, id: u32) {
        for _ in 0..READS_PER_ROUND {
            let Some(flow) = self.flows.get_mut(&id) else {
                return;
            };
            let (length, peer) = match flow.socket.recv_from(&mut self.scratch) {
                Ok(received) => received,
                Err(error) if would_block(&error) => return,
                // An ICMP error reported on the socket; the next datagram may still arrive.
                Err(_) => continue,
            };
            let now = Instant::now();
            flow.last = now;
            flow.received = true;
            let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
            let data = &self.scratch[..length.min(proto::MAX_PAYLOAD)];
            self.stats.from_network_datagrams += 1;
            self.stats.from_network_bytes += data.len() as u64;
            let mut frame = Vec::with_capacity(proto::datagram_frame_size(&peer, data.len()));
            proto::encode(
                &Frame::Recv {
                    flow: id,
                    peer,
                    data,
                },
                &mut frame,
            );
            while self.data.len() >= CHANNEL_QUEUE_DATAGRAMS
                || self.data_bytes + frame.len() > CHANNEL_QUEUE_BYTES
            {
                let Some(old) = self.data.pop_front() else {
                    break;
                };
                self.data_bytes -= old.frame.len();
                self.stats.drops.add(DropReason::Overflow);
            }
            self.data_bytes += frame.len();
            self.data.push_back(Pending { frame, at: now });
        }
    }

    /// Fills the next batch: control frames first, then datagrams the window allows.
    fn fill(&mut self) {
        self.output.clear();
        self.written = 0;
        let now = Instant::now();
        while let Some(control) = self.control.pop_front() {
            match control {
                Control::Frame(frame) => self.output.extend_from_slice(&frame),
                Control::Pong {
                    sequence,
                    time_us,
                    at,
                } => proto::encode(
                    &Frame::Pong {
                        sequence,
                        time_us,
                        held_us: now.duration_since(at).as_micros().min(u32::MAX as u128) as u32,
                    },
                    &mut self.output,
                ),
            }
        }
        while self.output.len() < WRITE_BATCH {
            let Some(pending) = self.data.front() else {
                break;
            };
            let waited = now.duration_since(pending.at);
            let size = pending.frame.len() as u64;
            if waited <= DATAGRAM_EXPIRY
                && self.sent_bytes - self.acked_bytes + size > IN_FLIGHT_WINDOW
            {
                break;
            }
            let Some(pending) = self.data.pop_front() else {
                break;
            };
            self.data_bytes -= pending.frame.len();
            if waited > DATAGRAM_EXPIRY {
                self.stats.drops.add(DropReason::Expired);
                continue;
            }
            self.stats.to_client_delay.record(waited);
            self.sent_bytes += size;
            self.output.extend_from_slice(&pending.frame);
        }
    }

    /// Writes until stdout would block or nothing is left to write.
    fn flush(&mut self) -> Result<(), Exit> {
        loop {
            if self.written == self.output.len() {
                self.fill();
                if self.output.is_empty() {
                    return Ok(());
                }
            }
            match write_fd(STDOUT, &self.output[self.written..]) {
                Ok(count) => self.written += count,
                Err(error) if would_block(&error) => return Ok(()),
                Err(_) => return Err(Exit::Io),
            }
        }
    }

    /// Best effort before exiting: the client should learn why the relay stopped.
    fn flush_all(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if self.flush().is_err() {
                return;
            }
            if self.written == self.output.len() && self.control.is_empty() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
