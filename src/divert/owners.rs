//! Which rule a UDP datagram belongs to, by the owner of the socket it was sent from.
//!
//! Windows reports UDP sockets in `GetExtendedUdpTable` with their bound address, port and
//! process. A datagram is matched by its local address and port, not by the port alone, since
//! several sockets may share a port on different addresses.
//!
//! Reading the tables costs too much to do for every datagram: one snapshot serves every
//! endpoint for `SNAPSHOT_HOLD`, and decisions are kept per local endpoint, measured with the
//! monotonic clock only:
//! - a datagram that is let through (no rule, a rule that bypasses its stopped tunnel, or owners
//!   that could not be read) is decided again after `PASS_HOLD`, so that a blocked application
//!   reusing the endpoint is noticed quickly;
//! - a blocked endpoint stays blocked for `BLOCK_HOLD`, and for another `BLOCK_HOLD` after its
//!   blocking socket is found gone, unless its rule now bypasses its tunnel. WinDivert keeps a
//!   captured packet for at most its queue time (2 s by default), so datagrams of a blocked
//!   socket that was seen before it closed cannot leak while they wait in the driver. The price
//!   is that another application binding the same endpoint right away is blocked for up to that
//!   time too: the safe side.
//!
//! Known limit: a socket that sends and closes before any of its datagrams is looked up is never
//! seen, so those datagrams find no owner and pass, as before this module.
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

/// How long a "let through" decision is reused.
pub const PASS_HOLD: Duration = Duration::from_millis(100);
/// How long one reading of the system tables answers for every endpoint.
pub const SNAPSHOT_HOLD: Duration = Duration::from_millis(50);
/// How long a "block" decision is reused, and kept after its socket is gone.
/// Matches WinDivert's default queue time.
pub const BLOCK_HOLD: Duration = Duration::from_secs(2);

/// Header and rows of `MIB_UDPTABLE_OWNER_PID` and `MIB_UDP6TABLE_OWNER_PID`.
pub const UDP_TABLE_HEADER: usize = 4;
pub const UDP4_ROW_SIZE: usize = 12;
pub const UDP6_ROW_SIZE: usize = 28;

/// A bound UDP socket; the address can be unspecified for a wildcard socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Socket {
    pid: u32,
    address: IpAddr,
    scope: [u8; 4],
}

impl Socket {
    fn matches(self, local: SocketAddr, ipv6_wildcard: bool) -> bool {
        let source = local.ip().to_canonical();
        match self.address {
            IpAddr::V4(ip) => source.is_ipv4() && (ip.is_unspecified() || self.address == source),
            IpAddr::V6(ip) if ip.is_unspecified() => source.is_ipv6() || ipv6_wildcard,
            IpAddr::V6(ip) => {
                self.address == source
                    && (!ip.is_unicast_link_local()
                        || matches!(local, SocketAddr::V6(addr) if scope_matches(self.scope, addr.scope_id())))
            }
        }
    }
}

/// The interface of a link-local socket, accepted in both byte orders of `SCOPE_ID`.
fn scope_matches(bytes: [u8; 4], interface: u32) -> bool {
    const ZONE_MASK: u32 = 0x0fff_ffff;
    interface == 0
        || bytes == [0; 4]
        || u32::from_be_bytes(bytes) & ZONE_MASK == interface
        || u32::from_ne_bytes(bytes) & ZONE_MASK == interface
}

/// Sockets of a UDP table with their port; rows beyond the buffer or the count are ignored.
fn sockets(table: &[u8], v6: bool) -> impl Iterator<Item = (u16, Socket)> + '_ {
    let (size, port_at, pid_at) = if v6 {
        (UDP6_ROW_SIZE, 20, 24)
    } else {
        (UDP4_ROW_SIZE, 4, 8)
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
            let pid = u32::from_le_bytes(row[pid_at..pid_at + 4].try_into().ok()?);
            let (address, scope) = if v6 {
                let ip = Ipv6Addr::from(*row.first_chunk::<16>()?);
                (IpAddr::V6(ip).to_canonical(), row[16..20].try_into().ok()?)
            } else {
                (Ipv4Addr::from(*row.first_chunk::<4>()?).into(), [0; 4])
            };
            // The network-order port occupies the first two bytes of its 32-bit field.
            let port = u16::from_be_bytes([row[port_at], row[port_at + 1]]);
            (pid != 0).then_some((
                port,
                Socket {
                    pid,
                    address,
                    scope,
                },
            ))
        })
}

fn owners_in(
    table: &[u8],
    v6: bool,
    local: SocketAddr,
    ipv6_wildcard: bool,
) -> impl Iterator<Item = u32> + '_ {
    sockets(table, v6).filter_map(move |(port, socket)| {
        (port == local.port() && socket.matches(local, ipv6_wildcard)).then_some(socket.pid)
    })
}

/// Processes whose sockets may have sent a datagram from `local`, from the IPv4 and IPv6 UDP
/// tables. `None` when the table of the datagram's own family could not be read; without the
/// IPv6 table an IPv4 datagram is still matched against the IPv4 sockets.
pub fn endpoint_owners(
    ipv4: Option<&[u8]>,
    ipv6: Option<&[u8]>,
    local: SocketAddr,
) -> Option<Vec<u32>> {
    let SocketAddr::V4(address) = local else {
        return Some(owners_in(ipv6?, true, local, true).collect());
    };
    let mut owners: Vec<u32> = owners_in(ipv4?, false, local, true).collect();
    if let Some(ipv6) = ipv6 {
        // A mapped socket, or an IPv6 wildcard that may be dual-stack, can send it too; an
        // IPv6-only wildcard is the price of the safe side.
        let mapped = SocketAddr::new(address.ip().to_ipv6_mapped().into(), address.port());
        owners.extend(owners_in(ipv6, true, mapped, true));
    }
    Some(owners)
}

/// One reading of both UDP tables, shared by every endpoint for `SNAPSHOT_HOLD`.
#[derive(Default)]
pub struct Snapshot {
    ipv4: Option<Vec<u8>>,
    ipv6: Option<Vec<u8>>,
    at: Option<Instant>,
}

impl Snapshot {
    /// The owners of `local`, reading the tables with `read(v6)` only when the snapshot is old.
    pub fn owners(
        &mut self,
        now: Instant,
        local: SocketAddr,
        mut read: impl FnMut(bool) -> Option<Vec<u8>>,
    ) -> Option<Vec<u32>> {
        if self
            .at
            .is_none_or(|at| now.saturating_duration_since(at) >= SNAPSHOT_HOLD)
        {
            self.ipv4 = read(false);
            self.ipv6 = read(true);
            self.at = Some(now);
        }
        endpoint_owners(self.ipv4.as_deref(), self.ipv6.as_deref(), local)
    }
}

struct Entry {
    rule: Option<String>,
    /// When the owners were last looked up for this entry.
    checked: Instant,
    /// Until when the entry answers without a lookup.
    until: Instant,
    /// The entry blocks only because its blocking socket was found gone recently.
    grace: bool,
}

/// Recent decisions per local endpoint.
#[derive(Default)]
pub struct UdpOwners {
    entries: HashMap<SocketAddr, Entry>,
    /// No rule can block: no datagram needs a lookup.
    all_bypass: bool,
}

impl UdpOwners {
    /// The rule covering a datagram sent from `local` at `now`, or `None` when no rule does.
    /// `bypass` tells whether a rule currently lets its application around its tunnel; the
    /// verdict itself is left to `handle`. `lookup` reads the owners' rules now, `None` when
    /// the system tables could not be read.
    pub fn decide(
        &mut self,
        local: SocketAddr,
        now: Instant,
        bypass: &dyn Fn(&str) -> bool,
        lookup: impl FnOnce() -> Option<Vec<String>>,
    ) -> Option<String> {
        if self.all_bypass {
            return None;
        }
        let blocks = |rule: &Option<String>| rule.as_deref().is_some_and(|rule| !bypass(rule));
        let previous = self.entries.get(&local);
        // A block whose rule now bypasses its tunnel is held no longer than a pass: the
        // endpoint may have a new owner whose rule must decide.
        if let Some(entry) = previous
            && now < entry.until
            && (blocks(&entry.rule) || now < entry.checked + PASS_HOLD)
        {
            return entry.rule.clone();
        }
        let Some(rules) = lookup() else {
            // Unknown owners: keep the last answer rather than guess, and do not ask again
            // for every datagram.
            let rule = previous.and_then(|entry| entry.rule.clone());
            let until = previous
                .map_or(now, |entry| entry.until)
                .max(now + PASS_HOLD);
            let grace = previous.is_some_and(|entry| entry.grace);
            self.entries.insert(
                local,
                Entry {
                    rule: rule.clone(),
                    checked: now,
                    until,
                    grace,
                },
            );
            return rule;
        };
        // Of several possible senders, a blocking one decides: the safe side.
        let chosen = rules
            .iter()
            .find(|rule| !bypass(rule))
            .or(rules.first())
            .cloned();
        let entry = match previous {
            // The blocking socket is gone: datagrams it sent may still wait in the driver.
            Some(entry) if blocks(&entry.rule) && !entry.grace && !blocks(&chosen) => Entry {
                rule: entry.rule.clone(),
                checked: now,
                until: now + BLOCK_HOLD,
                grace: true,
            },
            _ => Entry {
                until: now
                    + if blocks(&chosen) {
                        BLOCK_HOLD
                    } else {
                        PASS_HOLD
                    },
                rule: chosen,
                checked: now,
                grace: false,
            },
        };
        let answer = entry.rule.clone();
        self.entries.insert(local, entry);
        answer
    }

    /// Rules changed: forget every "let through" decision, since a new rule may now cover the
    /// application, and the decisions of rules that no longer exist unchanged. Blocks of
    /// unchanged rules stay, for datagrams still waiting in the driver queue.
    pub fn rules_changed(&mut self, unchanged: &dyn Fn(&str) -> bool, all_bypass: bool) {
        self.all_bypass = all_bypass;
        self.entries
            .retain(|_, entry| entry.rule.as_deref().is_some_and(unchanged));
    }

    /// A policy change needs no reset: entries keep the rule, and `handle` applies the policy
    /// of the moment. Only the shortcut for "nothing can block" follows it.
    pub fn set_all_bypass(&mut self, all_bypass: bool) {
        self.all_bypass = all_bypass;
    }

    /// Drops entries that would be looked up again anyway.
    pub fn purge(&mut self, now: Instant) {
        self.entries.retain(|_, entry| now < entry.until);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests;
