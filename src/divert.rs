//! Elevated helper: reflects the TCP connections of chosen executables into a local relay
//! that carries them through a SOCKS5 tunnel. Packet logic is platform-neutral and tested
//! everywhere; capturing and injecting packets is Windows-only (WinDivert).
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use crate::apps::{DivertRule, path_key};

#[cfg(windows)]
mod windows;

/// Official WinDivert 2.2.2-A x64 files; anything else is refused before it is loaded.
pub const DLL_SHA256: &str = "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2";
pub const SYS_SHA256: &str = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2";

/// A driver file that must sit next to the executable.
#[derive(Debug, PartialEq, Eq)]
pub struct Component {
    pub name: &'static str,
    pub sha256: &'static str,
    pub size: u64,
}

pub const COMPONENTS: [Component; 2] = [
    Component {
        name: "WinDivert.dll",
        sha256: DLL_SHA256,
        size: 47_616,
    },
    Component {
        name: "WinDivert64.sys",
        sha256: SYS_SHA256,
        size: 94_144,
    },
];

/// Components that are absent from `directory` or are not the pinned build.
pub fn missing_components(directory: &std::path::Path) -> Vec<&'static Component> {
    use sha2::Digest;
    COMPONENTS
        .iter()
        .filter(|component| {
            std::fs::read(directory.join(component.name))
                .map(|bytes| hex::encode(sha2::Sha256::digest(&bytes)) != component.sha256)
                .unwrap_or(true)
        })
        .collect()
}

const TCP: u8 = 6;
const UDP: u8 = 17;
const DNS_PORT: u16 = 53;
const CLOSED_FLOW: Duration = Duration::from_secs(60);
const IDLE_FLOW: Duration = Duration::from_secs(2 * 60 * 60);
const DECISION_TTL: Duration = Duration::from_secs(5);
const MAX_ANCESTORS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Reinject unchanged.
    Pass,
    Drop,
    /// The packet was rewritten in place and must be injected as inbound.
    Reflect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Packet {
    protocol: u8,
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    /// Offset of the IP addresses and of the transport header.
    addresses: usize,
    transport: usize,
    flags: u8,
}

fn parse(data: &[u8]) -> Option<Packet> {
    let (protocol, source, destination, addresses, transport) = match data.first()? >> 4 {
        4 => {
            let header = usize::from(data[0] & 0x0f) * 4;
            // Later fragments carry no transport header.
            if header < 20
                || data.len() < header
                || u16::from_be_bytes([data[6], data[7]]) & 0x1fff != 0
            {
                return None;
            }
            let address = |at: usize| {
                IpAddr::V4(Ipv4Addr::new(
                    data[at],
                    data[at + 1],
                    data[at + 2],
                    data[at + 3],
                ))
            };
            (data[9], address(12), address(16), 12, header)
        }
        6 if data.len() >= 40 => {
            let address = |at: usize| {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[at..at + 16]);
                IpAddr::V6(Ipv6Addr::from(octets))
            };
            // Extension headers are left alone: such packets pass unchanged.
            (data[6], address(8), address(24), 8, 40)
        }
        _ => return None,
    };
    let needed = match protocol {
        TCP => 20,
        UDP => 8,
        _ => return None,
    };
    let header = data.get(transport..transport + needed)?;
    Some(Packet {
        protocol,
        source,
        destination,
        source_port: u16::from_be_bytes([header[0], header[1]]),
        destination_port: u16::from_be_bytes([header[2], header[3]]),
        addresses,
        transport,
        flags: if protocol == TCP { header[13] } else { 0 },
    })
}

fn rewrite(data: &mut [u8], packet: &Packet, source: (IpAddr, u16), destination: (IpAddr, u16)) {
    let mut at = packet.addresses;
    for address in [source.0, destination.0] {
        match address {
            IpAddr::V4(ip) => data[at..at + 4].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => data[at..at + 16].copy_from_slice(&ip.octets()),
        }
        at += if address.is_ipv4() { 4 } else { 16 };
    }
    data[packet.transport..packet.transport + 2].copy_from_slice(&source.1.to_be_bytes());
    data[packet.transport + 2..packet.transport + 4].copy_from_slice(&destination.1.to_be_bytes());
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    pub remote_port: u16,
    pub rule: String,
    seen: Instant,
    app_finished: bool,
    relay_finished: bool,
    closed: Option<Instant>,
}

/// Reflected connections, keyed by the remote address and the application's local port:
/// exactly what the relay sees as the peer of an accepted connection.
#[derive(Default)]
pub struct Nat {
    flows: HashMap<(IpAddr, u16), Flow>,
}

impl Nat {
    pub fn get(&self, remote: IpAddr, local_port: u16) -> Option<&Flow> {
        self.flows.get(&(remote, local_port))
    }
    fn touch(&mut self, key: (IpAddr, u16), flags: u8, from_app: bool, now: Instant) {
        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };
        flow.seen = now;
        if flags & 0x01 != 0 {
            if from_app {
                flow.app_finished = true;
            } else {
                flow.relay_finished = true;
            }
        }
        if (flags & 0x04 != 0 || (flow.app_finished && flow.relay_finished))
            && flow.closed.is_none()
        {
            flow.closed = Some(now);
        }
    }
    pub fn purge(&mut self, now: Instant) {
        self.flows.retain(|_, flow| match flow.closed {
            Some(closed) => now.duration_since(closed) < CLOSED_FLOW,
            None => now.duration_since(flow.seen) < IDLE_FLOW,
        });
    }
    pub fn len(&self) -> usize {
        self.flows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

/// Decides what happens to one outbound packet. `owner` names the rule of the process that
/// owns a local port, or `None` when the process is not covered by any rule. `direct` tells
/// whether a rule lets its application bypass a tunnel that is not running.
pub fn handle(
    data: &mut [u8],
    relay_port: u16,
    nat: &mut Nat,
    now: Instant,
    owner: &mut dyn FnMut(u8, &Origin) -> Option<String>,
    direct: &dyn Fn(&str) -> bool,
) -> Verdict {
    let Some(packet) = parse(data) else {
        return Verdict::Pass;
    };
    let view = Origin {
        local: SocketAddr::new(packet.source, packet.source_port),
        remote: packet.destination,
        remote_port: packet.destination_port,
    };
    if packet.protocol == UDP {
        // Names are resolved by this computer; everything else would bypass the tunnel,
        // unless the rule sends the application around a tunnel that is down anyway.
        if packet.destination_port == DNS_PORT {
            return Verdict::Pass;
        }
        return match owner(UDP, &view) {
            Some(rule) if !direct(&rule) => Verdict::Drop,
            _ => Verdict::Pass,
        };
    }
    if packet.source_port == relay_port {
        let key = (packet.destination, packet.destination_port);
        let Some(remote_port) = nat.flows.get(&key).map(|flow| flow.remote_port) else {
            return Verdict::Drop;
        };
        nat.touch(key, packet.flags, false, now);
        rewrite(
            data,
            &packet,
            (packet.destination, remote_port),
            (packet.source, packet.destination_port),
        );
        return Verdict::Reflect;
    }
    let key = (packet.destination, packet.source_port);
    if packet.flags & 0x12 == 0x02 {
        match owner(TCP, &view) {
            Some(rule) => {
                nat.flows.insert(
                    key,
                    Flow {
                        remote_port: packet.destination_port,
                        rule,
                        seen: now,
                        app_finished: false,
                        relay_finished: false,
                        closed: None,
                    },
                );
            }
            None => {
                // The port now belongs to another process.
                nat.flows.remove(&key);
                return Verdict::Pass;
            }
        }
    } else if nat
        .flows
        .get(&key)
        .is_none_or(|flow| flow.remote_port != packet.destination_port)
    {
        return Verdict::Pass;
    }
    nat.touch(key, packet.flags, true, now);
    rewrite(
        data,
        &packet,
        (packet.destination, packet.source_port),
        (packet.source, relay_port),
    );
    Verdict::Reflect
}

/// What the owner lookup needs to know about a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    pub local: SocketAddr,
    pub remote: IpAddr,
    pub remote_port: u16,
}

pub trait Processes {
    fn path(&self, pid: u32) -> Option<String>;
    fn parent(&self, pid: u32) -> Option<u32>;
}

/// Maps a process to the rule that covers it, remembering recent answers.
pub struct Matcher {
    rules: Vec<(String, String, bool)>,
    own_path: String,
    decisions: HashMap<u32, (Option<String>, Instant)>,
}

impl Matcher {
    pub fn new(own_path: &str) -> Self {
        Self {
            rules: Vec::new(),
            own_path: path_key(own_path),
            decisions: HashMap::new(),
        }
    }
    pub fn set_rules(&mut self, rules: &[DivertRule]) -> bool {
        let next: Vec<_> = rules
            .iter()
            .map(|rule| (rule.id.clone(), path_key(&rule.path), rule.children))
            // КРОТ itself carries the tunnels and must never be captured.
            .filter(|(_, path, _)| *path != self.own_path)
            .collect();
        if next != self.rules {
            self.rules = next;
            self.decisions.clear();
            return true;
        }
        false
    }
    pub fn decide(&mut self, pid: u32, now: Instant, processes: &dyn Processes) -> Option<String> {
        if self.rules.is_empty() {
            return None;
        }
        if let Some((rule, at)) = self.decisions.get(&pid)
            && now.duration_since(*at) < DECISION_TTL
        {
            return rule.clone();
        }
        let rule = self.resolve(pid, processes);
        if self.decisions.len() > 4096 {
            self.decisions
                .retain(|_, (_, at)| now.duration_since(*at) < DECISION_TTL);
        }
        self.decisions.insert(pid, (rule.clone(), now));
        rule
    }
    fn resolve(&self, pid: u32, processes: &dyn Processes) -> Option<String> {
        let path = path_key(&processes.path(pid)?);
        if path == self.own_path {
            return None;
        }
        if let Some((id, _, _)) = self.rules.iter().find(|(_, rule, _)| *rule == path) {
            return Some(id.clone());
        }
        if !self.rules.iter().any(|(_, _, children)| *children) {
            return None;
        }
        let mut current = pid;
        for _ in 0..MAX_ANCESTORS {
            let parent = processes.parent(current)?;
            if parent == current || parent == 0 {
                return None;
            }
            if let Some(path) = processes.path(parent) {
                let path = path_key(&path);
                if let Some((id, _, _)) = self
                    .rules
                    .iter()
                    .find(|(_, rule, children)| *children && *rule == path)
                {
                    return Some(id.clone());
                }
            }
            current = parent;
        }
        None
    }
}

// Windows OWNER_PID tables contain a row count followed by fixed-size rows.
#[cfg(any(windows, test))]
fn owner_rows(table: &[u8], row_size: usize) -> impl Iterator<Item = &[u8]> {
    let (count, rows) = table.split_first_chunk::<4>().unwrap_or((&[0; 4], &[]));
    rows.chunks_exact(row_size)
        .take(u32::from_le_bytes(*count) as usize)
}

#[cfg(any(windows, test))]
fn table_port(row: &[u8], offset: usize) -> u16 {
    // The network-order port occupies the first two bytes of the 32-bit field.
    u16::from_be_bytes([row[offset], row[offset + 1]])
}

#[cfg(any(windows, test))]
fn table_pid(row: &[u8]) -> u32 {
    u32::from_le_bytes(*row.last_chunk::<4>().unwrap())
}

/// A TCP row that also matches the remote port wins over one that shares only the local port.
#[cfg(any(windows, test))]
fn tcp_table_owner(table: &[u8], v6: bool, local_port: u16, remote_port: u16) -> Option<u32> {
    let (size, local, remote) = if v6 { (56, 20, 44) } else { (24, 8, 16) };
    let mut fallback = None;
    for row in owner_rows(table, size) {
        if table_port(row, local) != local_port {
            continue;
        }
        let owner = table_pid(row);
        if table_port(row, remote) == remote_port {
            return Some(owner);
        }
        fallback.get_or_insert(owner);
    }
    fallback
}

/// Windows reports the bound UDP address, which can be unspecified for a wildcard socket.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct UdpSocket {
    pid: u32,
    created_at: u64,
    address: IpAddr,
    scope: [u8; 4],
}

#[cfg(any(windows, test))]
impl UdpSocket {
    fn matches(self, local: SocketAddr, allow_ipv6_wildcard: bool) -> bool {
        let source = local.ip().to_canonical();
        match self.address {
            IpAddr::V4(ip) => source.is_ipv4() && (ip.is_unspecified() || self.address == source),
            IpAddr::V6(ip) if ip.is_unspecified() => source.is_ipv6() || allow_ipv6_wildcard,
            IpAddr::V6(ip) => {
                self.address == source
                    && (!ip.is_unicast_link_local()
                        || matches!(local, SocketAddr::V6(addr) if udp_scope_matches(self.scope, addr.scope_id())))
            }
        }
    }
}

#[cfg(any(windows, test))]
const UDP_TABLE_HEADER: usize = 8;
#[cfg(any(windows, test))]
const UDP4_ROW_SIZE: usize = 160;
#[cfg(any(windows, test))]
const UDP6_ROW_SIZE: usize = 176;

#[cfg(any(windows, test))]
fn udp_table_owners(
    table: &[u8],
    local: SocketAddr,
    allow_ipv6_wildcard: bool,
) -> impl Iterator<Item = UdpSocket> + '_ {
    udp_sockets(table, local.is_ipv6()).filter_map(move |(port, socket)| {
        (port == local.port() && socket.matches(local, allow_ipv6_wildcard)).then_some(socket)
    })
}

#[cfg(any(windows, test))]
fn udp_sockets(table: &[u8], v6: bool) -> impl Iterator<Item = (u16, UdpSocket)> + '_ {
    let (size, port_offset, time_offset) = if v6 {
        (UDP6_ROW_SIZE, 20, 32)
    } else {
        (UDP4_ROW_SIZE, 4, 16)
    };
    let count = table
        .first_chunk::<4>()
        .copied()
        .map_or(0, u32::from_le_bytes);
    table
        .get(UDP_TABLE_HEADER..)
        .unwrap_or_default()
        .chunks_exact(size)
        .take(count as usize)
        .filter_map(move |row| {
            let pid = u32::from_le_bytes(*row[port_offset + 4..].first_chunk::<4>().unwrap());
            let created_at = u64::from_le_bytes(*row[time_offset..].first_chunk::<8>().unwrap());
            let (address, scope) = if v6 {
                let ip = Ipv6Addr::from(*row.first_chunk::<16>().unwrap());
                (
                    IpAddr::V6(ip).to_canonical(),
                    row[16..20].try_into().unwrap(),
                )
            } else {
                (
                    Ipv4Addr::from(*row.first_chunk::<4>().unwrap()).into(),
                    [0; 4],
                )
            };
            let socket = UdpSocket {
                pid,
                created_at,
                address,
                scope,
            };
            (pid != 0).then(|| (table_port(row, port_offset), socket))
        })
}

#[cfg(any(windows, test))]
fn udp_scope_matches(bytes: [u8; 4], interface: u32) -> bool {
    // Accept both network and native byte order for the low 28 bits of SCOPE_ID.
    const ZONE_MASK: u32 = 0x0fff_ffff;
    interface == 0
        || bytes == [0; 4]
        || u32::from_be_bytes(bytes) & ZONE_MASK == interface
        || u32::from_ne_bytes(bytes) & ZONE_MASK == interface
}

/// FILETIME interval bracketing the capture, accounting for scheduling between clock reads.
#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
struct CaptureTime {
    earliest: u64,
    latest: u64,
}

#[cfg(any(windows, test))]
#[derive(Default)]
struct UdpDecision {
    owners: Vec<(UdpSocket, Option<String>)>,
    complete: bool,
}

#[cfg(any(windows, test))]
impl UdpDecision {
    fn add(
        &mut self,
        owners: impl Iterator<Item = UdpSocket>,
        captured: CaptureTime,
        blocking_rule: &mut impl FnMut(u32) -> Option<String>,
    ) {
        self.owners.extend(owners.map(|owner| {
            let rule = if owner.created_at <= captured.latest {
                blocking_rule(owner.pid)
            } else {
                None
            };
            (owner, rule)
        }));
    }
}

/// Retain individually observed blocked bindings for datagrams already in the driver queue.
#[cfg(any(windows, test))]
#[derive(Default)]
struct UdpHistory {
    ports: HashMap<u16, Vec<UdpBinding>>,
}

#[cfg(any(windows, test))]
struct UdpBinding {
    socket: UdpSocket,
    observed_at: u64,
    ended_by: Option<u64>,
    rule: String,
    seen_on_ipv4: bool,
}

#[cfg(any(windows, test))]
impl UdpHistory {
    // FILETIME counts 100-nanosecond intervals. WinDivert's default queue time is 2 seconds.
    const QUEUE_AGE: u64 = 20_000_000;

    #[cfg(windows)]
    fn allow_bypassing(&mut self, bypassing: &std::collections::HashSet<String>) {
        self.ports.retain(|_, bindings| {
            bindings.retain(|binding| !bypassing.contains(&binding.rule));
            !bindings.is_empty()
        });
    }
    fn prune(
        &mut self,
        now: u64,
        observed: u64,
        live: &std::collections::HashSet<(u16, UdpSocket)>,
    ) {
        self.ports.retain(|port, bindings| {
            for binding in bindings.iter_mut() {
                if !live.contains(&(*port, binding.socket)) {
                    binding.ended_by.get_or_insert(observed);
                }
            }
            bindings.retain(|binding| {
                binding
                    .ended_by
                    .is_none_or(|end| now.saturating_sub(end) <= Self::QUEUE_AGE)
            });
            !bindings.is_empty()
        });
    }

    fn decide(
        &mut self,
        local: SocketAddr,
        captured: CaptureTime,
        observed: u64,
        current: UdpDecision,
    ) -> Option<String> {
        let mut rule = current.owners.iter().find_map(|(_, rule)| rule.clone());
        if let Some(bindings) = self.ports.get_mut(&local.port()) {
            for binding in bindings
                .iter_mut()
                .filter(|binding| binding.socket.matches(local, binding.seen_on_ipv4))
            {
                if current
                    .owners
                    .iter()
                    .any(|(socket, _)| *socket == binding.socket)
                {
                    binding.observed_at = observed;
                    continue;
                }
                if current.complete {
                    // A newer observed bind can delimit reuse. A socket already present in the
                    // previous snapshot can overlap this binding, for example via a wildcard.
                    let end = current
                        .owners
                        .iter()
                        .filter(|(socket, _)| {
                            socket.address == binding.socket.address
                                && socket.scope == binding.socket.scope
                        })
                        .map(|(socket, _)| socket.created_at)
                        .filter(|time| *time > binding.observed_at)
                        .min()
                        .map_or(observed, |time| time.saturating_sub(1));
                    binding.ended_by = Some(binding.ended_by.map_or(end, |old| old.min(end)));
                }
                if rule.is_none()
                    && binding.socket.created_at <= captured.latest
                    && binding.ended_by.is_none_or(|end| captured.earliest <= end)
                {
                    rule = Some(binding.rule.clone());
                }
            }
        }
        for (socket, blocked_by) in current.owners {
            if let Some(blocked_by) = blocked_by {
                self.remember(local, socket, blocked_by, observed);
            }
        }
        rule
    }

    fn remember(&mut self, local: SocketAddr, socket: UdpSocket, rule: String, observed_at: u64) {
        let port = local.port();
        if let Some(binding) = self
            .ports
            .get_mut(&port)
            .and_then(|bindings| bindings.iter_mut().find(|binding| binding.socket == socket))
        {
            binding.observed_at = observed_at;
            binding.ended_by = None;
            binding.rule = rule;
            binding.seen_on_ipv4 |= local.is_ipv4();
            return;
        }
        self.ports.entry(port).or_default().push(UdpBinding {
            socket,
            observed_at,
            ended_by: None,
            rule,
            seen_on_ipv4: local.is_ipv4(),
        });
    }
}

/// Starts the helper with administrator rights; the system asks the user for consent.
pub fn launch(config: &std::path::Path) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows::launch(config)
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        anyhow::bail!("Перехват трафика приложений работает только в Windows.")
    }
}

/// Runs the helper until the background КРОТ goes away.
pub fn run(store: crate::config::Store) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows::run(store)
    }
    #[cfg(not(windows))]
    {
        let _ = store;
        anyhow::bail!("Перехват трафика приложений работает только в Windows.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: u16 = 40000;

    fn tcp(source: &str, destination: &str, flags: u8) -> Vec<u8> {
        let source: std::net::SocketAddr = source.parse().unwrap();
        let destination: std::net::SocketAddr = destination.parse().unwrap();
        let mut data = match (source.ip(), destination.ip()) {
            (IpAddr::V4(from), IpAddr::V4(to)) => {
                let mut ip = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, TCP, 0, 0];
                ip.extend(from.octets());
                ip.extend(to.octets());
                ip
            }
            (IpAddr::V6(from), IpAddr::V6(to)) => {
                let mut ip = vec![0x60, 0, 0, 0, 0, 20, TCP, 64];
                ip.extend(from.octets());
                ip.extend(to.octets());
                ip
            }
            _ => unreachable!(),
        };
        data.extend(source.port().to_be_bytes());
        data.extend(destination.port().to_be_bytes());
        data.extend([0; 9]);
        data.push(flags);
        data.extend([0; 6]);
        data
    }
    fn endpoints(data: &[u8]) -> (String, String) {
        let packet = parse(data).unwrap();
        (
            std::net::SocketAddr::new(packet.source, packet.source_port).to_string(),
            std::net::SocketAddr::new(packet.destination, packet.destination_port).to_string(),
        )
    }
    fn covered(_: u8, _: &Origin) -> Option<String> {
        Some("rule".into())
    }
    fn foreign(_: u8, _: &Origin) -> Option<String> {
        None
    }
    fn tunneled(_: &str) -> bool {
        false
    }
    fn bypassing(_: &str) -> bool {
        true
    }

    #[test]
    fn covered_connection_is_reflected_into_the_relay_and_back_for_both_families() {
        for (app, remote, relay) in [
            (
                "192.168.1.5:50000",
                "93.184.216.34:443",
                "192.168.1.5:40000",
            ),
            ("[fd00::5]:50000", "[2001:db8::1]:443", "[fd00::5]:40000"),
        ] {
            let remote_ip = remote.parse::<std::net::SocketAddr>().unwrap().ip();
            let as_peer = std::net::SocketAddr::new(remote_ip, 50000).to_string();
            let (mut nat, now) = (Nat::default(), Instant::now());
            let mut syn = tcp(app, remote, 0x02);
            assert_eq!(
                handle(&mut syn, RELAY, &mut nat, now, &mut covered, &tunneled),
                Verdict::Reflect
            );
            // The relay accepts a connection that seems to come from the remote address.
            assert_eq!(endpoints(&syn), (as_peer.clone(), relay.to_owned()));
            let flow = nat.get(remote_ip, 50000).unwrap();
            assert_eq!((flow.remote_port, flow.rule.as_str()), (443, "rule"));

            let mut answer = tcp(relay, &as_peer, 0x12);
            assert_eq!(
                handle(&mut answer, RELAY, &mut nat, now, &mut foreign, &tunneled),
                Verdict::Reflect
            );
            // The application sees the answer as coming from the real destination.
            assert_eq!(endpoints(&answer), (remote.to_owned(), app.to_owned()));

            // Later packets follow the table, not the process lookup.
            let mut data = tcp(app, remote, 0x18);
            assert_eq!(
                handle(&mut data, RELAY, &mut nat, now, &mut foreign, &tunneled),
                Verdict::Reflect
            );
            assert_eq!(endpoints(&data).1, relay);
        }
    }

    #[test]
    fn foreign_traffic_passes_untouched_and_stray_relay_packets_are_dropped() {
        let (mut nat, now) = (Nat::default(), Instant::now());
        for flags in [0x02, 0x10, 0x18] {
            let original = tcp("192.168.1.5:50001", "10.0.0.1:22", flags);
            let mut packet = original.clone();
            assert_eq!(
                handle(&mut packet, RELAY, &mut nat, now, &mut foreign, &tunneled),
                Verdict::Pass
            );
            assert_eq!(packet, original);
        }
        assert!(nat.is_empty());
        let mut stray = tcp("192.168.1.5:40000", "10.0.0.1:50001", 0x12);
        assert_eq!(
            handle(&mut stray, RELAY, &mut nat, now, &mut covered, &tunneled),
            Verdict::Drop
        );
        // A reused local port that now belongs to a foreign process leaves the table.
        let mut syn = tcp("192.168.1.5:50002", "10.0.0.1:80", 0x02);
        handle(&mut syn, RELAY, &mut nat, now, &mut covered, &tunneled);
        let mut reused = tcp("192.168.1.5:50002", "10.0.0.1:80", 0x02);
        assert_eq!(
            handle(&mut reused, RELAY, &mut nat, now, &mut foreign, &tunneled),
            Verdict::Pass
        );
        assert!(nat.is_empty());
        // Same port and address, other destination port: not this flow.
        handle(
            &mut syn.clone(),
            RELAY,
            &mut nat,
            now,
            &mut covered,
            &tunneled,
        );
        let mut syn = tcp("192.168.1.5:50002", "10.0.0.1:80", 0x02);
        handle(&mut syn, RELAY, &mut nat, now, &mut covered, &tunneled);
        let mut other = tcp("192.168.1.5:50002", "10.0.0.1:8080", 0x10);
        assert_eq!(
            handle(&mut other, RELAY, &mut nat, now, &mut foreign, &tunneled),
            Verdict::Pass
        );
        for garbage in [&[][..], &[0x45, 0, 0], &[0x10; 40]] {
            let mut packet = garbage.to_vec();
            assert_eq!(
                handle(&mut packet, RELAY, &mut nat, now, &mut covered, &tunneled),
                Verdict::Pass
            );
        }
    }

    #[test]
    fn covered_udp_is_dropped_except_name_resolution() {
        let (mut nat, now) = (Nat::default(), Instant::now());
        let udp = |port: u16| {
            let mut packet = tcp("192.168.1.5:50003", &format!("8.8.8.8:{port}"), 0);
            packet[9] = UDP;
            packet
        };
        assert_eq!(
            handle(&mut udp(443), RELAY, &mut nat, now, &mut covered, &tunneled),
            Verdict::Drop
        );
        assert_eq!(
            handle(&mut udp(53), RELAY, &mut nat, now, &mut covered, &tunneled),
            Verdict::Pass
        );
        assert_eq!(
            handle(&mut udp(443), RELAY, &mut nat, now, &mut foreign, &tunneled),
            Verdict::Pass
        );
    }

    #[test]
    fn covered_udp_goes_direct_while_the_rule_bypasses_a_stopped_tunnel() {
        let (mut nat, now) = (Nat::default(), Instant::now());
        for (source, destination) in [
            ("192.168.1.5:50003", "8.8.8.8:443"),
            ("[fd00::5]:50003", "[2001:db8::8]:3478"),
        ] {
            let mut packet = tcp(source, destination, 0);
            packet[if source.starts_with('[') { 6 } else { 9 }] = UDP;
            let original = packet.clone();
            assert_eq!(
                handle(&mut packet, RELAY, &mut nat, now, &mut covered, &bypassing),
                Verdict::Pass
            );
            assert_eq!(packet, original);
            assert_eq!(
                handle(&mut packet, RELAY, &mut nat, now, &mut covered, &tunneled),
                Verdict::Drop
            );
        }
        assert!(nat.is_empty());
    }

    #[test]
    fn udp_rules_follow_local_bindings_and_port_reuse() {
        let tree = Tree(HashMap::from([
            (10, (r"C:\Apps\direct.exe", 1)),
            (20, (r"C:\Apps\blocked.exe", 1)),
        ]));
        let mut matcher = Matcher::new(r"C:\KROT\krot.exe");
        matcher.set_rules(&[
            rule("direct", r"C:\Apps\direct.exe", false),
            rule("blocked", r"C:\Apps\blocked.exe", false),
        ]);

        let (mut nat, now) = (Nat::default(), Instant::now());
        for (direct, blocked, other, wildcard, destination) in [
            (
                "192.168.1.5:50003",
                "192.168.1.6:50003",
                "192.168.1.7:50003",
                "0.0.0.0:50003",
                "8.8.8.8:443",
            ),
            (
                "[fd00::5]:50003",
                "[fd00::6]:50003",
                "[fd00::7]:50003",
                "[::]:50003",
                "[2001:db8::8]:3478",
            ),
            (
                "[fe80::5%3]:50003",
                "[fe80::5%8]:50003",
                "[fe80::5%4]:50003",
                "[::]:50003",
                "[fe80::8]:3478",
            ),
        ] {
            let row = |endpoint: &str, pid| udp_row(endpoint.parse().unwrap(), pid, 1);
            let bypass = |rule: &str| rule == "direct";
            let mut check = |source: &str, table: &[u8], pids: &[u32], expected| {
                let mut packet = tcp(source, destination, 0);
                packet[if source.starts_with('[') { 6 } else { 9 }] = UDP;
                assert_eq!(
                    handle(
                        &mut packet,
                        RELAY,
                        &mut nat,
                        now,
                        &mut |protocol, origin| {
                            assert_eq!(protocol, UDP);
                            let mut local = origin.local;
                            if let (SocketAddr::V6(addr), SocketAddr::V6(bound)) =
                                (&mut local, source.parse::<SocketAddr>().unwrap())
                            {
                                addr.set_scope_id(bound.scope_id());
                            }
                            let owners: Vec<_> = udp_table_owners(table, local, true)
                                .map(|owner| owner.pid)
                                .collect();
                            assert_eq!(owners, pids, "{source}");
                            owners.into_iter().find_map(|pid| {
                                matcher.decide(pid, now, &tree).filter(|rule| !bypass(rule))
                            })
                        },
                        &bypass,
                    ),
                    expected,
                    "{source}",
                );
            };
            let separate = udp_table(&[row(direct, 10), row(blocked, 20)]);
            check(direct, &separate, &[10], Verdict::Pass);
            check(blocked, &separate, &[20], Verdict::Drop);
            check(other, &separate, &[], Verdict::Pass);

            // The same endpoint changes PID within the lifetime of the process cache.
            let reused = udp_table(&[row(direct, 20)]);
            check(direct, &reused, &[20], Verdict::Drop);

            // Both the exact and wildcard sockets could send from this address.
            let overlapping = udp_table(&[row(direct, 10), row(wildcard, 20)]);
            check(direct, &overlapping, &[10, 20], Verdict::Drop);
            check(other, &overlapping, &[20], Verdict::Drop);
        }
    }

    #[test]
    fn finished_and_idle_connections_leave_the_table() {
        let (mut nat, start) = (Nat::default(), Instant::now());
        let open = |nat: &mut Nat, port: u16| {
            let mut syn = tcp(&format!("192.168.1.5:{port}"), "10.0.0.1:443", 0x02);
            handle(&mut syn, RELAY, nat, start, &mut covered, &tunneled);
        };
        open(&mut nat, 1);
        open(&mut nat, 2);
        open(&mut nat, 3);
        // 1: both sides finish. 2: reset. 3: stays idle.
        let mut fin = tcp("192.168.1.5:1", "10.0.0.1:443", 0x11);
        handle(&mut fin, RELAY, &mut nat, start, &mut foreign, &tunneled);
        nat.purge(start + CLOSED_FLOW * 2);
        assert_eq!(nat.len(), 3, "a half-closed connection is still alive");
        let mut fin = tcp("192.168.1.5:40000", "10.0.0.1:1", 0x11);
        handle(&mut fin, RELAY, &mut nat, start, &mut foreign, &tunneled);
        let mut reset = tcp("192.168.1.5:2", "10.0.0.1:443", 0x04);
        handle(&mut reset, RELAY, &mut nat, start, &mut foreign, &tunneled);
        nat.purge(start + CLOSED_FLOW / 2);
        assert_eq!(nat.len(), 3);
        nat.purge(start + CLOSED_FLOW * 2);
        assert_eq!(nat.len(), 1);
        nat.purge(start + IDLE_FLOW * 2);
        assert!(nat.is_empty());
    }

    struct Tree(HashMap<u32, (&'static str, u32)>);
    impl Processes for Tree {
        fn path(&self, pid: u32) -> Option<String> {
            self.0.get(&pid).map(|(path, _)| (*path).to_owned())
        }
        fn parent(&self, pid: u32) -> Option<u32> {
            self.0.get(&pid).map(|(_, parent)| *parent)
        }
    }
    fn rule(id: &str, path: &str, children: bool) -> DivertRule {
        DivertRule {
            id: id.into(),
            path: path.into(),
            children,
            direct: false,
            proxy: None,
        }
    }

    #[test]
    fn matcher_follows_paths_children_and_never_captures_krot_itself() {
        let tree = Tree(HashMap::from([
            (10, (r"C:\Apps\Browser.exe", 1)),
            (11, (r"C:\Apps\helper.exe", 10)),
            (12, (r"C:\Apps\deep.exe", 11)),
            (20, (r"C:\Apps\solo.exe", 1)),
            (21, (r"C:\Apps\child.exe", 20)),
            (30, (r"C:\KROT\krot.exe", 1)),
            (31, (r"C:\Apps\spawned.exe", 30)),
            (40, (r"C:\Apps\loop.exe", 40)),
        ]));
        let now = Instant::now();
        let mut matcher = Matcher::new(r"c:\krot\KROT.exe");
        assert_eq!(matcher.decide(10, now, &tree), None, "no rules, no capture");
        matcher.set_rules(&[
            rule("browser", r"c:\apps\browser.exe", true),
            rule("solo", r"C:\Apps\solo.exe", false),
            rule("self", r"C:\KROT\krot.exe", true),
        ]);
        for (pid, expected) in [
            (10, Some("browser")),
            (11, Some("browser")),
            (12, Some("browser")),
            (20, Some("solo")),
            (21, None),
            (30, None),
            (31, None),
            (40, None),
            (99, None),
        ] {
            assert_eq!(
                matcher.decide(pid, now, &tree).as_deref(),
                expected,
                "pid {pid}"
            );
        }
        // Answers are remembered briefly and forgotten when the rules change.
        let empty = Tree(HashMap::new());
        assert_eq!(matcher.decide(10, now, &empty).as_deref(), Some("browser"));
        assert_eq!(matcher.decide(10, now + DECISION_TTL * 2, &empty), None);
        assert_eq!(matcher.decide(11, now, &empty).as_deref(), Some("browser"));
        matcher.set_rules(&[rule("solo", r"C:\Apps\solo.exe", false)]);
        assert_eq!(matcher.decide(11, now, &tree), None);
    }

    #[test]
    fn only_the_pinned_driver_files_count_as_present() {
        let directory = tempfile::tempdir().unwrap();
        let names = |missing: Vec<&Component>| -> Vec<_> {
            missing.iter().map(|component| component.name).collect()
        };
        assert_eq!(
            names(missing_components(directory.path())),
            ["WinDivert.dll", "WinDivert64.sys"]
        );
        // A file with the right name and other content is still missing.
        std::fs::write(directory.path().join("WinDivert.dll"), b"other build").unwrap();
        assert_eq!(missing_components(directory.path()).len(), 2);
    }

    fn owner_table(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut table = (rows.len() as u32).to_le_bytes().to_vec();
        table.extend(rows.iter().flatten());
        table
    }

    fn udp_table(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut table = (rows.len() as u32).to_le_bytes().to_vec();
        table.resize(UDP_TABLE_HEADER, 0);
        table.extend(rows.iter().flatten());
        table
    }

    fn udp_row(endpoint: SocketAddr, pid: u32, created_at: u64) -> Vec<u8> {
        let mut row = match endpoint {
            SocketAddr::V4(addr) => addr.ip().octets().to_vec(),
            SocketAddr::V6(addr) => {
                let mut row = addr.ip().octets().to_vec();
                row.extend(addr.scope_id().to_be_bytes());
                row
            }
        };
        row.extend(endpoint.port().to_be_bytes());
        row.extend([0; 2]);
        row.extend(pid.to_le_bytes());
        let (size, time_offset) = if endpoint.is_ipv6() {
            (UDP6_ROW_SIZE, 32)
        } else {
            (UDP4_ROW_SIZE, 16)
        };
        row.resize(time_offset, 0);
        row.extend(created_at.to_le_bytes());
        row.resize(size, 0);
        row
    }

    #[test]
    fn tcp_owner_is_read_from_both_system_table_layouts() {
        fn row(size: usize, fields: &[(usize, u32)], ports: &[(usize, u16)]) -> Vec<u8> {
            let mut row = vec![0u8; size];
            for (at, value) in fields {
                row[*at..*at + 4].copy_from_slice(&value.to_le_bytes());
            }
            for (at, port) in ports {
                row[*at..*at + 2].copy_from_slice(&port.to_be_bytes());
            }
            row
        }
        let tcp4 = owner_table(&[
            row(24, &[(20, 100)], &[(8, 50000), (16, 80)]),
            row(24, &[(20, 200)], &[(8, 50000), (16, 443)]),
            row(24, &[(20, 300)], &[(8, 50001), (16, 443)]),
        ]);
        assert_eq!(tcp_table_owner(&tcp4, false, 50000, 443), Some(200));
        assert_eq!(tcp_table_owner(&tcp4, false, 50000, 22), Some(100));
        assert_eq!(tcp_table_owner(&tcp4, false, 50002, 443), None);
        let tcp6 = owner_table(&[row(56, &[(52, 400)], &[(20, 50000), (44, 443)])]);
        assert_eq!(tcp_table_owner(&tcp6, true, 50000, 443), Some(400));
        // A count larger than the buffer and a truncated buffer are both harmless.
        let mut short = tcp4.clone();
        short[0] = 200;
        short.truncate(4 + 24 + 10);
        assert_eq!(tcp_table_owner(&short, false, 50000, 80), Some(100));
        assert_eq!(tcp_table_owner(&[1, 0], false, 1, 1), None);
    }

    #[test]
    fn ipv4_mapped_udp_lookup_matches_compatible_bindings() {
        let row = |addr: &str, pid| udp_row(addr.parse().unwrap(), pid, 1);
        let mapped = "[::ffff:192.0.2.1]:50000".parse().unwrap();
        let table = udp_table(&[
            row("[::]:50000", 10),
            row("[fd00::1]:50000", 20),
            row("[::ffff:192.0.2.2]:50000", 30),
            row("[::ffff:192.0.2.1]:50001", 40),
            udp_row(mapped, 0, 1),
            udp_row(mapped, 50, 1),
            row("[::ffff:0.0.0.0]:50000", 60),
        ]);
        assert_eq!(
            udp_table_owners(&table, mapped, false)
                .map(|owner| owner.pid)
                .collect::<Vec<_>>(),
            [50, 60],
        );
        let fallback = udp_table(&[row("[::]:50000", 10)]);
        assert_eq!(
            udp_table_owners(&fallback, mapped, true)
                .map(|owner| owner.pid)
                .collect::<Vec<_>>(),
            [10],
        );
        assert!(udp_table_owners(&fallback, mapped, false).next().is_none());
    }

    #[test]
    fn queued_udp_keeps_the_old_rule_across_close_and_rebind() {
        for (source, remote, protocol_offset) in [
            ("192.168.1.5:50003", "8.8.8.8:443", 9),
            ("[fd00::5]:50003", "[2001:db8::8]:443", 6),
        ] {
            let local = source.parse().unwrap();
            let mut history = UdpHistory::default();
            let (mut nat, now) = (Nat::default(), Instant::now());
            let blocked = udp_table(&[udp_row(local, 10, 1)]);
            let replacement = udp_table(&[udp_row(local, 20, 30)]);
            let empty = udp_table(&[]);
            let mut check = |table: &[u8], captured, observed| {
                let captured = at(captured);
                let mut packet = tcp(source, remote, 0);
                packet[protocol_offset] = UDP;
                handle(
                    &mut packet,
                    RELAY,
                    &mut nat,
                    now,
                    &mut |_, origin| {
                        let mut decision = UdpDecision {
                            complete: true,
                            ..UdpDecision::default()
                        };
                        decision.add(
                            udp_table_owners(table, origin.local, true),
                            captured,
                            &mut |pid| (pid == 10).then(|| "blocked".to_owned()),
                        );
                        history.decide(origin.local, captured, observed, decision)
                    },
                    &tunneled,
                )
            };
            assert_eq!(check(&blocked, 10, 11), Verdict::Drop);
            assert_eq!(check(&empty, 20, 25), Verdict::Drop);
            assert_eq!(check(&replacement, 22, 32), Verdict::Drop);
            assert_eq!(check(&replacement, 31, 33), Verdict::Pass);
            // The queue can deliver older packets after seeing the replacement.
            assert_eq!(check(&replacement, 23, 34), Verdict::Drop);
            assert_eq!(check(&empty, 35, 36), Verdict::Pass);
            assert_eq!(check(&empty, 39, 40), Verdict::Pass);
            history.prune(40 + UdpHistory::QUEUE_AGE + 1, 41, &Default::default());
            assert!(history.ports.is_empty());
        }
    }

    fn at(time: u64) -> CaptureTime {
        CaptureTime {
            earliest: time,
            latest: time,
        }
    }

    #[test]
    fn known_udp_wildcard_keeps_its_block_across_sources_and_overlapping_binds() {
        let first: SocketAddr = "192.0.2.1:50003".parse().unwrap();
        let second: SocketAddr = "192.0.2.2:50003".parse().unwrap();
        let wildcard = udp_row("0.0.0.0:50003".parse().unwrap(), 10, 1);
        let direct = udp_row(second, 20, 12);
        let both = udp_table(&[wildcard, direct.clone()]);
        let after_close = udp_table(&[direct]);
        let mut history = UdpHistory::default();
        let mut decide = |local, table, captured, observed| {
            let mut decision = UdpDecision {
                complete: true,
                ..UdpDecision::default()
            };
            decision.add(
                udp_table_owners(table, local, true),
                at(captured),
                &mut |pid| (pid == 10).then(|| "blocked".into()),
            );
            history.decide(local, at(captured), observed, decision)
        };
        assert!(decide(first, &both, 10, 11).is_some());
        assert!(decide(second, &after_close, 13, 14).is_some());
        assert!(decide(second, &after_close, 15, 16).is_none());
    }

    #[test]
    fn bind_in_capture_clock_interval_can_still_block() {
        let local: SocketAddr = "192.0.2.1:50003".parse().unwrap();
        let table = udp_table(&[udp_row(local, 10, 50)]);
        let captured = CaptureTime {
            earliest: 40,
            latest: 60,
        };
        let mut decision = UdpDecision::default();
        decision.add(udp_table_owners(&table, local, true), captured, &mut |_| {
            Some("blocked".into())
        });
        assert!(
            UdpHistory::default()
                .decide(local, captured, 70, decision)
                .is_some()
        );
    }

    #[test]
    fn failed_udp_snapshot_does_not_expire_a_known_block() {
        let local = "192.0.2.1:50003".parse().unwrap();
        let mut history = UdpHistory::default();
        let blocked = UdpDecision {
            owners: vec![(
                UdpSocket {
                    pid: 10,
                    created_at: 1,
                    address: "192.0.2.1".parse().unwrap(),
                    scope: [0; 4],
                },
                Some("blocked".into()),
            )],
            complete: true,
        };
        assert!(history.decide(local, at(10), 11, blocked).is_some());
        assert!(
            history
                .decide(local, at(20), 21, UdpDecision::default())
                .is_some()
        );
        assert!(
            history
                .decide(local, at(30), 31, UdpDecision::default())
                .is_some()
        );
        assert!(
            history
                .decide(
                    local,
                    at(32),
                    33,
                    UdpDecision {
                        complete: true,
                        ..UdpDecision::default()
                    }
                )
                .is_some()
        );
        assert!(
            history
                .decide(local, at(34), 35, UdpDecision::default())
                .is_none()
        );
    }

    #[test]
    fn udp_scope_matches_the_zone_in_both_byte_orders() {
        let link_scope = 0x2000_0008u32;
        for bytes in [link_scope.to_be_bytes(), link_scope.to_ne_bytes()] {
            assert!(udp_scope_matches(bytes, 8));
            assert!(!udp_scope_matches(bytes, 3));
        }
    }
}
