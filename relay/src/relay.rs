//! A single-threaded `poll` loop over stdin, stdout and one UDP socket per flow.
//!
//! Delay must not build up anywhere: every queue is bounded by count and bytes and drops its
//! oldest datagram when full, a datagram older than `DATAGRAM_EXPIRY` is dropped instead of
//! being sent, and datagrams towards the client stop once `IN_FLIGHT_WINDOW` bytes are
//! unacknowledged, so they wait here, where expiry applies, and not in SSH or TCP buffers.
//!
//! Answers wait for the client in one queue per flow. The flows are served in turn and a full
//! queue drops from the flow that holds most, so a flood into the port of one flow, which
//! needs no credentials, costs the other flows neither their place nor their turn. Expired
//! answers of any flow leave first, and finding the flow that holds most does not search all
//! flows for every datagram dropped.
use std::{
    collections::{BinaryHeap, HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    ops::Range,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    time::{Duration, Instant},
};

use krot_udp_proto::{
    self as proto, CloseReason, Frame, Refusal, RelayStats, Settings, VERSION,
    limits::{
        ACK_INTERVAL, CHANNEL_QUEUE_BYTES, CHANNEL_QUEUE_DATAGRAMS, DATAGRAM_EXPIRY,
        FLOW_QUEUE_BYTES, FLOW_QUEUE_DATAGRAMS, HELLO_TIMEOUT, IN_FLIGHT_WINDOW, MAX_IDLE,
        MIN_IDLE, RELAY_MAX_FLOWS, RELAY_QUEUE_BYTES, RELAY_RESERVED_DESCRIPTORS, REPORT_INTERVAL,
        WRITE_BATCH,
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
/// Peers a flow remembers having sent to; answers from them keep the flow alive.
const MAX_PEERS: usize = 32;
/// Flow ids the relay closed itself, remembered so that each is answered by one `CLOSE` only.
const MAX_REFUSED: usize = 65_536;
/// How long a closed id stays refused. The client does not answer a `CLOSE` of the relay and
/// may give the id to a new flow later, so the id is held only while datagrams sent before the
/// client read the `CLOSE` can still arrive.
const REFUSED_HOLD: Duration = Duration::from_secs(10);
/// Bytes a flow may write to the client before the next flow with answers takes its turn.
const TURN_BYTES: usize = 2048;

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
    match Relay::new().serve() {
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
    /// The last datagram of the application, or answer from a peer it sent to.
    last: Instant,
    sent: bool,
    /// A peer the flow sent to has answered.
    received: bool,
    peers: Vec<SocketAddr>,
}

/// A datagram frame for the client and when it was queued.
struct Pending {
    frame: Vec<u8>,
    at: Instant,
    /// Order among all answers, filled in when queued.
    seq: u64,
}

/// An answer in `Relay::arrivals`; it may have left its queue already.
struct Arrival {
    flow: u32,
    seq: u64,
    at: Instant,
}

/// Answers of one flow waiting for the client.
struct Replies {
    queue: VecDeque<Pending>,
    bytes: usize,
    /// Bytes the flow may still write in its turn.
    credit: usize,
}

/// The position and original enqueue time of a datagram in the stdout batch.
struct OutputDatagram {
    bytes: Range<usize>,
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
    /// Answers for the client by flow. An entry emptied by a drop stays until its turn comes.
    data: HashMap<u32, Replies>,
    /// The flows in `data`, each once, in the order of their turns.
    turns: VecDeque<u32>,
    data_count: usize,
    data_bytes: usize,
    /// Answers in the order they were queued, which is the order of their times, so expired
    /// answers of every flow are found from the front.
    arrivals: VecDeque<Arrival>,
    next_seq: u64,
    /// Flows by datagrams and by bytes held, with stale entries: each flow holding answers
    /// has an entry at least as large as what it holds, and an entry is checked when on top.
    by_count: BinaryHeap<(usize, u32)>,
    by_bytes: BinaryHeap<(usize, u32)>,
    /// Heap entries and flows looked at to find the flow that holds most.
    #[cfg(test)]
    examined: usize,
    /// The batch being written to stdout and how much of it is written.
    output: Vec<u8>,
    written: usize,
    output_datagrams: VecDeque<OutputDatagram>,
    /// Bytes in complete datagram frames written to stdout and acknowledged by the client.
    sent_bytes: u64,
    acked_bytes: u64,
    /// Datagram frame bytes received from the client and the value last acknowledged.
    received_bytes: u64,
    acknowledged: u64,
    ack_at: Instant,
    report_at: Instant,
    stats: RelayStats,
    scratch: Vec<u8>,
    chunk: Vec<u8>,
    /// Flows refused with `CLOSE` and when: their datagrams are dropped quietly for
    /// `REFUSED_HOLD`.
    refused: HashMap<u32, Instant>,
    /// Bytes waiting in all flow queues together.
    flow_bytes: usize,
    /// Flows the descriptor limit allows, besides the relay's own descriptors.
    descriptor_flows: u16,
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

/// Raises the soft limit of open files to the hard one and tells how many flow sockets fit.
fn descriptor_flows() -> u16 {
    // SAFETY: plain value structures passed to getrlimit/setrlimit.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return RELAY_MAX_FLOWS;
    }
    if limit.rlim_cur < limit.rlim_max {
        let raised = libc::rlimit {
            rlim_cur: limit.rlim_max,
            rlim_max: limit.rlim_max,
        };
        // SAFETY: as above.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            limit = raised;
        }
    }
    // `rlim_t` is narrower than `u64` on some 32-bit targets.
    #[allow(clippy::unnecessary_cast)]
    let usable = (limit.rlim_cur as u64).saturating_sub(RELAY_RESERVED_DESCRIPTORS);
    usable.min(u64::from(RELAY_MAX_FLOWS)) as u16
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
    fn new() -> Self {
        let now = Instant::now();
        Self {
            settings: None,
            started: now,
            input: Vec::with_capacity(READ_CHUNK),
            input_start: 0,
            flows: HashMap::new(),
            control: VecDeque::new(),
            data: HashMap::new(),
            turns: VecDeque::new(),
            data_count: 0,
            data_bytes: 0,
            arrivals: VecDeque::new(),
            next_seq: 0,
            by_count: BinaryHeap::new(),
            by_bytes: BinaryHeap::new(),
            #[cfg(test)]
            examined: 0,
            output: Vec::with_capacity(WRITE_BATCH + proto::MAX_FRAME),
            written: 0,
            output_datagrams: VecDeque::new(),
            sent_bytes: 0,
            acked_bytes: 0,
            received_bytes: 0,
            acknowledged: 0,
            ack_at: now,
            report_at: now + REPORT_INTERVAL,
            stats: RelayStats::default(),
            scratch: vec![0; 65_536],
            chunk: vec![0; READ_CHUNK],
            refused: HashMap::new(),
            flow_bytes: 0,
            descriptor_flows: RELAY_MAX_FLOWS,
        }
    }

    fn serve(&mut self) -> Result<(), Exit> {
        self.descriptor_flows = descriptor_flows();
        set_nonblocking(STDIN).map_err(|_| Exit::Io)?;
        set_nonblocking(STDOUT).map_err(|_| Exit::Io)?;
        let mut descriptors: Vec<libc::pollfd> = Vec::new();
        let mut owners: Vec<u32> = Vec::new();
        loop {
            let now = Instant::now();
            if self.settings.is_none() && now.duration_since(self.started) > HELLO_TIMEOUT {
                return Err(Exit::Protocol);
            }
            self.tick(now);
            self.flush(STDOUT)?;

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

    /// Milliseconds until the next timed duty, at most one report interval. Rounded up: a
    /// wait rounded down to zero would spin the loop until the duty is due.
    fn timeout(&self, now: Instant) -> libc::c_int {
        let mut until = self.report_at.saturating_duration_since(now);
        if self.received_bytes != self.acknowledged {
            until = until.min((self.ack_at + ACK_INTERVAL).saturating_duration_since(now));
        }
        until.as_micros().div_ceil(1000).min(1000) as libc::c_int
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
            // Stale datagrams leave the queues without waiting for their socket to drain.
            let mut stale = 0;
            for flow in self.flows.values_mut() {
                while flow.queue.front().is_some_and(|queued| {
                    now.saturating_duration_since(queued.at) > DATAGRAM_EXPIRY
                }) {
                    if let Some(old) = flow.queue.pop_front() {
                        flow.queued_bytes -= old.data.len();
                        self.flow_bytes -= old.data.len();
                        stale += 1;
                    }
                }
            }
            for _ in 0..stale {
                self.stats.drops.add(DropReason::Expired);
            }
            // A datagram of the client that crosses this `CLOSE` must not open the flow again:
            // the client forgets the id once it reads the `CLOSE`.
            for flow in expired {
                self.remove_flow(flow);
                self.refuse(flow, CloseReason::Idle, now);
            }
            self.stats.flows_active = self.flows.len() as u32;
            let stats = self.stats.clone();
            self.stats.to_network_delay = Default::default();
            self.stats.to_client_delay = Default::default();
            self.push_control(&Frame::Stats(Box::new(stats)));
        }
    }

    fn remove_flow(&mut self, id: u32) {
        if let Some(flow) = self.flows.remove(&id) {
            self.flow_bytes -= flow.queued_bytes;
        }
    }

    fn push_control(&mut self, frame: &Frame<'_>) {
        let mut encoded = Vec::new();
        proto::encode(frame, &mut encoded);
        self.control.push_back(Control::Frame(encoded));
    }

    /// Closes a flow from this side; further datagrams of it are dropped quietly.
    fn refuse(&mut self, flow: u32, reason: CloseReason, now: Instant) {
        if self.refused.len() >= MAX_REFUSED {
            self.refused
                .retain(|_, at| now.saturating_duration_since(*at) < REFUSED_HOLD);
            if self.refused.len() >= MAX_REFUSED {
                self.refused.clear();
            }
        }
        self.refused.insert(flow, now);
        self.push_control(&Frame::Close { flow, reason });
    }

    fn read_input(&mut self) -> Result<(), Exit> {
        if self.input_start > 0 {
            self.input.drain(..self.input_start);
            self.input_start = 0;
        }
        let count = match read_fd(STDIN, &mut self.chunk) {
            Ok(0) => return Err(Exit::Done),
            Ok(count) => count,
            Err(error) if would_block(&error) => 0,
            Err(_) => return Err(Exit::Io),
        };
        self.input.extend_from_slice(&self.chunk[..count]);
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
                        max_flows: settings
                            .max_flows
                            .min(RELAY_MAX_FLOWS)
                            .min(self.descriptor_flows)
                            .max(1),
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
                    self.remove_flow(flow);
                    self.refused.remove(&flow);
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
            // One `CLOSE` per closed flow, not one per datagram: datagrams that were already
            // on their way are dropped quietly.
            match self.refused.get(&id) {
                Some(at) if now.saturating_duration_since(*at) < REFUSED_HOLD => {
                    self.stats.drops.add(DropReason::Channel);
                    return;
                }
                // The hold is over: the client may have given the id to a new flow.
                Some(_) => {
                    self.refused.remove(&id);
                }
                None => {}
            }
            if self.flows.len() >= usize::from(settings.max_flows) {
                self.stats.flows_refused += 1;
                self.refuse(id, CloseReason::Limit, now);
                return;
            }
            let Ok((socket, dual)) = open_socket() else {
                self.stats.drops.add(DropReason::Channel);
                self.refuse(id, CloseReason::Socket, now);
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
                    peers: Vec::new(),
                },
            );
        }
        let Some(flow) = self.flows.get_mut(&id) else {
            return;
        };
        flow.last = now;
        flow.sent = true;
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        if !flow.peers.contains(&peer) {
            if flow.peers.len() == MAX_PEERS {
                flow.peers.remove(0);
            }
            flow.peers.push(peer);
        }
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
            || self.flow_bytes + data.len() > RELAY_QUEUE_BYTES
        {
            let Some(old) = flow.queue.pop_front() else {
                break;
            };
            flow.queued_bytes -= old.data.len();
            self.flow_bytes -= old.data.len();
            self.stats.drops.add(DropReason::Overflow);
        }
        // The shared budget is held by other flows: this datagram does not fit.
        if self.flow_bytes + data.len() > RELAY_QUEUE_BYTES {
            self.stats.drops.add(DropReason::Overflow);
            return;
        }
        flow.queued_bytes += data.len();
        self.flow_bytes += data.len();
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
                self.flow_bytes -= datagram.data.len();
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
            self.flow_bytes -= datagram.data.len();
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
            // Unsolicited datagrams still reach the client, as STUN needs, but only answers
            // from peers the flow sent to keep it alive: strangers cannot hold it open.
            let canonical = SocketAddr::new(peer.ip().to_canonical(), peer.port());
            if flow.peers.contains(&canonical) {
                flow.last = now;
                flow.received = true;
            }
            self.stats.from_network_datagrams += 1;
            self.stats.from_network_bytes += length as u64;
            if length > proto::MAX_PAYLOAD {
                self.stats.drops.add(DropReason::Size);
                continue;
            }
            let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
            let data = &self.scratch[..length];
            let mut frame = Vec::with_capacity(proto::datagram_frame_size(&peer, data.len()));
            proto::encode(
                &Frame::Recv {
                    flow: id,
                    peer,
                    data,
                },
                &mut frame,
            );
            self.queue_reply(
                id,
                Pending {
                    frame,
                    at: now,
                    seq: 0,
                },
            );
        }
    }

    /// Queues an answer of `flow` for the client, making room when the queue is full: expired
    /// answers leave first, then the oldest of the flow that holds most.
    fn queue_reply(&mut self, flow: u32, mut pending: Pending) {
        if self.data_count >= CHANNEL_QUEUE_DATAGRAMS
            || self.data_bytes + pending.frame.len() > CHANNEL_QUEUE_BYTES
        {
            self.expire_replies(pending.at);
        }
        while self.data_count >= CHANNEL_QUEUE_DATAGRAMS
            || self.data_bytes + pending.frame.len() > CHANNEL_QUEUE_BYTES
        {
            let by_count = self.data_count >= CHANNEL_QUEUE_DATAGRAMS;
            if !self.drop_reply(flow, by_count) {
                break;
            }
        }
        pending.seq = self.next_seq;
        self.next_seq += 1;
        self.arrivals.push_back(Arrival {
            flow,
            seq: pending.seq,
            at: pending.at,
        });
        self.data_count += 1;
        self.data_bytes += pending.frame.len();
        let replies = self.data.entry(flow).or_insert_with(|| {
            self.turns.push_back(flow);
            Replies {
                queue: VecDeque::new(),
                bytes: 0,
                credit: TURN_BYTES,
            }
        });
        replies.bytes += pending.frame.len();
        replies.queue.push_back(pending);
        self.by_count.push((replies.queue.len(), flow));
        self.by_bytes.push((replies.bytes, flow));
        self.compact();
    }

    /// Forgets answers that have left once their entries outnumber those queued, so the
    /// work is paid for by the answers queued since.
    fn compact(&mut self) {
        let limit = 2 * self.data_count + 64;
        if self.arrivals.len() > limit {
            let data = &self.data;
            self.arrivals.retain(|arrival| {
                data.get(&arrival.flow)
                    .and_then(|replies| replies.queue.front())
                    .is_some_and(|front| front.seq <= arrival.seq)
            });
        }
        let limit = 2 * self.data.len() + 64;
        if self.by_count.len() > limit || self.by_bytes.len() > limit {
            #[cfg(test)]
            {
                self.examined += self.data.len();
            }
            let held = self
                .data
                .iter()
                .filter(|(_, replies)| !replies.queue.is_empty());
            self.by_count = held
                .clone()
                .map(|(flow, replies)| (replies.queue.len(), *flow))
                .collect();
            self.by_bytes = held.map(|(flow, replies)| (replies.bytes, *flow)).collect();
        }
    }

    /// Takes the oldest answer of `flow` and leaves its entry, even empty, in its turn.
    fn pop_reply(&mut self, flow: u32) -> Option<Pending> {
        let replies = self.data.get_mut(&flow)?;
        let pending = replies.queue.pop_front()?;
        replies.bytes -= pending.frame.len();
        self.data_count -= 1;
        self.data_bytes -= pending.frame.len();
        Some(pending)
    }

    /// Drops the answers of all flows that waited longer than `DATAGRAM_EXPIRY`.
    fn expire_replies(&mut self, now: Instant) {
        while let Some(arrival) = self.arrivals.front() {
            if now.saturating_duration_since(arrival.at) <= DATAGRAM_EXPIRY {
                break;
            }
            let (flow, seq) = (arrival.flow, arrival.seq);
            self.arrivals.pop_front();
            // A flow sends and drops from the front, so an answer still queued is its first.
            let queued = self
                .data
                .get(&flow)
                .and_then(|replies| replies.queue.front())
                .is_some_and(|front| front.seq == seq);
            if queued && self.pop_reply(flow).is_some() {
                self.stats.drops.add(DropReason::Expired);
            }
        }
    }

    /// The flow that holds most datagrams with `by_count`, bytes otherwise.
    fn largest(&mut self, by_count: bool) -> Option<u32> {
        let heap = if by_count {
            &mut self.by_count
        } else {
            &mut self.by_bytes
        };
        while let Some(&(entry, flow)) = heap.peek() {
            #[cfg(test)]
            {
                self.examined += 1;
            }
            let held = self.data.get(&flow).map_or(0, |replies| {
                if by_count {
                    replies.queue.len()
                } else {
                    replies.bytes
                }
            });
            if held == entry {
                return Some(flow);
            }
            heap.pop();
            // The flow shrank since and goes back at its size. An entry below its size is a
            // leftover: a larger one exists.
            if held > 0 && held < entry {
                heap.push((held, flow));
            }
        }
        None
    }

    /// Drops the oldest answer of the flow that holds most of what ran out: datagrams with
    /// `by_count`, bytes otherwise, so a flood of small datagrams pays for the places it takes.
    /// `false` when none waits.
    fn drop_reply(&mut self, arriving: u32, by_count: bool) -> bool {
        let total = if by_count {
            self.data_count
        } else {
            self.data_bytes
        };
        // A flow that holds half of everything holds most: no search while it floods.
        let held = self.data.get(&arriving).map_or(0, |replies| {
            if by_count {
                replies.queue.len()
            } else {
                replies.bytes
            }
        });
        let largest = if held * 2 >= total && held > 0 {
            arriving
        } else {
            let Some(flow) = self.largest(by_count) else {
                return false;
            };
            flow
        };
        if self.pop_reply(largest).is_none() {
            return false;
        }
        self.stats.drops.add(DropReason::Overflow);
        true
    }

    /// Fills the next batch: control frames first, then datagrams the window allows, taken
    /// from the flows in turn.
    fn fill(&mut self, now: Instant) {
        self.output.clear();
        self.written = 0;
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
        // Also while the window is full: expired answers must not hold places of fresh ones.
        self.expire_replies(now);
        let mut in_flight = self.sent_bytes - self.acked_bytes;
        while self.output.len() < WRITE_BATCH {
            let Some(&flow) = self.turns.front() else {
                break;
            };
            let Some(replies) = self.data.get_mut(&flow) else {
                self.turns.pop_front();
                continue;
            };
            let Some(size) = replies.queue.front().map(|pending| pending.frame.len()) else {
                self.data.remove(&flow);
                self.turns.pop_front();
                continue;
            };
            if in_flight + size as u64 > IN_FLIGHT_WINDOW {
                break;
            }
            // The turn ends; the credit grows until it covers a datagram of any size.
            if replies.credit < size {
                replies.credit += TURN_BYTES;
                self.turns.rotate_left(1);
                continue;
            }
            replies.credit -= size;
            let Some(pending) = self.pop_reply(flow) else {
                break;
            };
            if self
                .data
                .get(&flow)
                .is_some_and(|replies| replies.queue.is_empty())
            {
                self.data.remove(&flow);
                self.turns.pop_front();
            }
            let start = self.output.len();
            self.output.extend_from_slice(&pending.frame);
            self.output_datagrams.push_back(OutputDatagram {
                bytes: start..self.output.len(),
                at: pending.at,
            });
            in_flight += size as u64;
        }
    }

    fn drop_expired_output(&mut self, now: Instant) {
        // Finish a partially written frame to preserve framing. The remaining datagrams
        // follow in enqueue order, so the expired ones occupy a single contiguous range.
        let first_unstarted = usize::from(
            self.output_datagrams
                .front()
                .is_some_and(|datagram| datagram.bytes.start < self.written),
        );
        let expired = self
            .output_datagrams
            .iter()
            .skip(first_unstarted)
            .take_while(|datagram| now.duration_since(datagram.at) > DATAGRAM_EXPIRY)
            .count();
        if expired == 0 {
            return;
        }
        let end = first_unstarted + expired;
        let removed = self.output_datagrams[first_unstarted].bytes.start
            ..self.output_datagrams[end - 1].bytes.end;
        let removed_bytes = removed.len();
        self.output.drain(removed);
        for _ in self.output_datagrams.drain(first_unstarted..end) {
            self.stats.drops.add(DropReason::Expired);
        }
        for datagram in self.output_datagrams.iter_mut().skip(first_unstarted) {
            datagram.bytes.start -= removed_bytes;
            datagram.bytes.end -= removed_bytes;
        }
    }

    fn record_write(&mut self, count: usize, now: Instant) {
        let end = self.written + count;
        while let Some(datagram) = self.output_datagrams.front() {
            if datagram.bytes.start >= end {
                break;
            }
            if datagram.bytes.start >= self.written {
                self.stats
                    .to_client_delay
                    .record(now.duration_since(datagram.at));
            }
            if datagram.bytes.end > end {
                break;
            }
            self.sent_bytes += datagram.bytes.len() as u64;
            self.output_datagrams.pop_front();
        }
        self.written = end;
    }

    /// Writes until stdout would block or nothing is left to write.
    fn flush(&mut self, stdout: RawFd) -> Result<(), Exit> {
        loop {
            if self.written == self.output.len() {
                self.fill(Instant::now());
                if self.output.is_empty() {
                    return Ok(());
                }
            }
            let now = Instant::now();
            self.drop_expired_output(now);
            if self.written == self.output.len() {
                continue;
            }
            match write_fd(stdout, &self.output[self.written..]) {
                Ok(0) => return Err(Exit::Io),
                Ok(count) => self.record_write(count, now),
                Err(error) if would_block(&error) => return Ok(()),
                Err(_) => return Err(Exit::Io),
            }
        }
    }

    /// Best effort before exiting: the client should learn why the relay stopped.
    fn flush_all(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if self.flush(STDOUT).is_err() {
                return;
            }
            if self.written == self.output.len() && self.control.is_empty() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn queue_reply(relay: &mut Relay, data: &[u8], at: Instant) -> Vec<u8> {
        queue_flow_reply(relay, 1, data, at)
    }

    fn queue_flow_reply(relay: &mut Relay, flow: u32, data: &[u8], at: Instant) -> Vec<u8> {
        let mut frame = Vec::new();
        proto::encode(
            &Frame::Recv {
                flow,
                peer: "127.0.0.1:9".parse().unwrap(),
                data,
            },
            &mut frame,
        );
        relay.queue_reply(
            flow,
            Pending {
                frame: frame.clone(),
                at,
                seq: 0,
            },
        );
        frame
    }

    /// The flows of the `RECV` frames in the batch, in order.
    fn batch_flows(relay: &Relay) -> Vec<u32> {
        let mut flows = Vec::new();
        let mut rest = &relay.output[..];
        while let Some((frame, used)) = proto::parse(rest).unwrap() {
            if let Frame::Recv { flow, .. } = frame {
                flows.push(flow);
            }
            rest = &rest[used..];
        }
        flows
    }

    #[test]
    fn a_flood_into_one_flow_keeps_the_answers_of_another() {
        let mut relay = Relay::new();
        let now = Instant::now();
        let junk = [0u8; 1200];
        for _ in 0..CHANNEL_QUEUE_DATAGRAMS {
            queue_flow_reply(&mut relay, 2, &junk, now);
        }
        let voice = queue_flow_reply(&mut relay, 1, b"voice", now);
        // The flood goes on: room is made at its own expense.
        for _ in 0..CHANNEL_QUEUE_DATAGRAMS {
            queue_flow_reply(&mut relay, 2, &junk, now);
        }
        assert!(relay.data_count <= CHANNEL_QUEUE_DATAGRAMS);
        assert!(relay.data_bytes <= CHANNEL_QUEUE_BYTES);
        assert_eq!(relay.data[&1].queue.len(), 1);
        assert_eq!(
            relay.stats.drops.get(DropReason::Overflow) as usize,
            2 * CHANNEL_QUEUE_DATAGRAMS + 1 - relay.data_count
        );

        // The answer does not wait behind the flood either.
        relay.fill(now);
        let flows = batch_flows(&relay);
        let place = flows.iter().position(|flow| *flow == 1).unwrap();
        assert!(place <= 2, "after {place} datagrams of the flood");
        assert!(relay.output.windows(voice.len()).any(|part| part == voice));
        assert!(!relay.data.contains_key(&1));
        assert_eq!(relay.turns, [2]);
    }

    #[test]
    fn a_flood_of_small_datagrams_pays_for_the_places_it_takes() {
        let mut relay = Relay::new();
        let now = Instant::now();
        // Fewer datagrams, but more bytes than the whole flood.
        for _ in 0..200 {
            queue_flow_reply(&mut relay, 1, &[0u8; 1200], now);
        }
        for _ in 0..2 * CHANNEL_QUEUE_DATAGRAMS {
            queue_flow_reply(&mut relay, 2, &[0u8; 1], now);
        }
        assert_eq!(relay.data_count, CHANNEL_QUEUE_DATAGRAMS);
        assert_eq!(relay.data[&1].queue.len(), 200);
    }

    /// A full window; flow 1 is first in turns with a fresh answer behind an expired one, and
    /// flow 2 fills the rest of the queue with answers expired at the returned time.
    fn full_window_with_expired_answers() -> (Relay, Instant) {
        let mut relay = Relay::new();
        let start = Instant::now();
        queue_flow_reply(&mut relay, 1, b"old", start);
        for _ in 0..CHANNEL_QUEUE_DATAGRAMS - 2 {
            queue_flow_reply(&mut relay, 2, b"stale", start + Duration::from_millis(1));
        }
        queue_flow_reply(&mut relay, 1, b"fresh", start + DATAGRAM_EXPIRY);
        assert_eq!(relay.data_count, CHANNEL_QUEUE_DATAGRAMS);
        relay.sent_bytes = IN_FLIGHT_WINDOW;
        (relay, start + DATAGRAM_EXPIRY + Duration::from_millis(2))
    }

    #[test]
    fn a_full_window_still_drops_expired_answers_of_every_flow() {
        let (mut relay, now) = full_window_with_expired_answers();
        relay.fill(now);
        assert!(batch_flows(&relay).is_empty());
        assert_eq!(
            relay.stats.drops.get(DropReason::Expired) as usize,
            CHANNEL_QUEUE_DATAGRAMS - 1
        );
        assert_eq!((relay.data_count, relay.data[&1].queue.len()), (1, 1));
        assert_eq!(relay.turns.front(), Some(&1));
    }

    #[test]
    fn expired_answers_make_room_before_fresh_ones() {
        let (mut relay, now) = full_window_with_expired_answers();
        for _ in 0..100 {
            queue_flow_reply(&mut relay, 3, b"new", now);
        }
        assert_eq!(relay.stats.drops.get(DropReason::Overflow), 0);
        assert_eq!(
            relay.stats.drops.get(DropReason::Expired) as usize,
            CHANNEL_QUEUE_DATAGRAMS - 1
        );
        assert_eq!(relay.data[&1].queue.len(), 1);
        assert_eq!(relay.data[&3].queue.len(), 100);
        assert_eq!(relay.data_count, 101);
    }

    #[test]
    fn a_flood_into_many_flows_does_not_search_them_all_for_each_drop() {
        let mut relay = Relay::new();
        let now = Instant::now();
        let flows = u32::from(RELAY_MAX_FLOWS);
        let junk = [0u8; 1200];
        for round in 0..20 * CHANNEL_QUEUE_DATAGRAMS as u32 {
            queue_flow_reply(&mut relay, round % flows, &junk, now);
        }
        let drops = relay.stats.drops.get(DropReason::Overflow) as usize;
        assert!(drops > 10 * CHANNEL_QUEUE_DATAGRAMS, "{drops} drops");
        // A search of all flows would look at about `RELAY_MAX_FLOWS` of them per drop.
        let per_drop = relay.examined as f64 / drops as f64;
        assert!(per_drop < 8.0, "{per_drop} looked at per drop");
        // The flood is still shared evenly: every flow keeps its part.
        let held: Vec<usize> = relay.data.values().map(|r| r.queue.len()).collect();
        assert_eq!(held.len(), flows as usize);
        let (least, most) = (held.iter().min().unwrap(), held.iter().max().unwrap());
        assert!(most - least <= 1, "from {least} to {most}");
        assert!(relay.arrivals.len() <= 2 * relay.data_count + 64);
        assert!(relay.by_bytes.len() <= 2 * relay.data.len() + 64);
    }

    #[test]
    fn flows_take_turns_by_bytes_and_keep_their_order() {
        let mut relay = Relay::new();
        let now = Instant::now();
        let large = [0u8; 1500];
        for _ in 0..4 {
            queue_flow_reply(&mut relay, 1, &large, now);
        }
        for _ in 0..12 {
            queue_flow_reply(&mut relay, 2, &[0u8; 100], now);
        }
        relay.fill(now);
        let flows = batch_flows(&relay);
        assert_eq!(flows.len(), 16);
        // Twelve small datagrams take about as many bytes as one large one.
        let small_before_second_large = flows
            .iter()
            .scan(0, |large, flow| {
                *large += usize::from(*flow == 1);
                Some(*large)
            })
            .zip(&flows)
            .filter(|(large, flow)| *large < 2 && **flow == 2)
            .count();
        assert_eq!(small_before_second_large, 12);
        assert!(relay.data.is_empty() && relay.turns.is_empty());
        assert_eq!((relay.data_count, relay.data_bytes), (0, 0));
    }

    #[test]
    fn an_id_closed_by_the_relay_opens_a_new_flow_after_the_hold() {
        let mut relay = Relay::new();
        let settings = Settings {
            max_flows: 4,
            idle_ms: 1000,
            idle_bidirectional_ms: 1000,
        };
        let peer = "127.0.0.1:9".parse().unwrap();
        let closed = Instant::now();
        relay.refuse(7, CloseReason::Idle, closed);

        // A datagram that crossed the `CLOSE` is dropped.
        relay.send(settings, 7, peer, b"late", closed + REFUSED_HOLD / 2);
        assert!(!relay.flows.contains_key(&7));
        assert_eq!(relay.stats.drops.get(DropReason::Channel), 1);

        // The client never answers the `CLOSE`; a later flow with the same id still opens.
        relay.send(settings, 7, peer, b"new", closed + REFUSED_HOLD);
        assert!(relay.flows.contains_key(&7));
        assert!(!relay.refused.contains_key(&7));
        assert_eq!(relay.stats.flows_opened, 1);
    }

    #[test]
    fn full_stdout_drops_an_expired_datagram_before_writing_it() {
        let (mut reader, writer) = io::pipe().unwrap();
        let stdout = writer.as_raw_fd();
        set_nonblocking(stdout).unwrap();
        set_nonblocking(reader.as_raw_fd()).unwrap();
        // SAFETY: the pipe writer is open and F_GETPIPE_SZ takes no additional argument.
        let capacity = unsafe { libc::fcntl(stdout, libc::F_GETPIPE_SZ) };
        assert!(capacity > 0);
        let mut filler = vec![0; capacity as usize];
        assert_eq!(write_fd(stdout, &filler).unwrap(), filler.len());

        let mut relay = Relay::new();
        let expired = queue_reply(&mut relay, b"stale", Instant::now());
        assert!(relay.flush(stdout).is_ok());
        assert_eq!(relay.output, expired);
        assert_eq!(relay.written, 0);

        std::thread::sleep(DATAGRAM_EXPIRY * 2);
        reader.read_exact(&mut filler).unwrap();
        assert!(relay.flush(stdout).is_ok());
        assert!(
            matches!(reader.read(&mut [0; 1]), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "expired datagram reached stdout"
        );
        assert_eq!(relay.stats.drops.get(DropReason::Expired), 1);
        assert_eq!(relay.sent_bytes, 0);
        assert_eq!(relay.stats.to_client_delay.count(), 0);

        let fresh = queue_reply(&mut relay, b"fresh", Instant::now());
        assert!(relay.flush(stdout).is_ok());
        let mut received = vec![0; fresh.len()];
        reader.read_exact(&mut received).unwrap();
        assert_eq!(received, fresh);
        assert_eq!(relay.sent_bytes, fresh.len() as u64);
        assert_eq!(relay.stats.to_client_delay.count(), 1);
    }

    #[test]
    fn dropping_expired_output_preserves_partial_and_fresh_frames() {
        let mut relay = Relay::new();
        let queued = Instant::now();
        let first_write = queued + DATAGRAM_EXPIRY / 2;
        let retry = queued + DATAGRAM_EXPIRY + Duration::from_millis(1);

        let control = Frame::Ack { received: 42 };
        relay.push_control(&control);
        let started = queue_reply(&mut relay, b"started", queued);
        queue_reply(&mut relay, b"stale", queued);
        let fresh = queue_reply(&mut relay, b"fresh", first_write);
        relay.fill(first_write);

        let mut expected = Vec::new();
        proto::encode(&control, &mut expected);
        let written = expected.len() + 1;
        relay.record_write(written, first_write);
        assert_eq!(relay.sent_bytes, 0);
        assert_eq!(relay.stats.to_client_delay.count(), 1);

        relay.drop_expired_output(retry);
        expected.extend_from_slice(&started);
        expected.extend_from_slice(&fresh);
        assert_eq!(relay.output, expected);
        assert_eq!(relay.written, written);
        assert_eq!(relay.stats.drops.get(DropReason::Expired), 1);

        relay.record_write(expected.len() - written, retry);
        assert_eq!(relay.sent_bytes, (started.len() + fresh.len()) as u64);
        assert_eq!(relay.stats.to_client_delay.count(), 2);
        assert!(relay.output_datagrams.is_empty());
    }
}
