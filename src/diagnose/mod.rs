//! Reachability check of an SSH server from the user's own network.
//!
//! The run walks the connection path stage by stage: network control (К), DNS (D), TCP to each
//! address (T) and the SSH handshake up to the end of the key exchange without login (S). Each
//! stage records typed observations; [`classify`] turns them into hypotheses with confidence,
//! evidence and advice. Only the first hop goes through the user's network, so the stages concern
//! it alone. The module does not touch the tunnel manager or running tunnels.
mod classify;
mod probes;

pub use classify::classify;

use crate::config::{Tunnel, unbracket};
use anyhow::{Result, bail};
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Connections to the server per run: more would look like brute force to fail2ban, whose ban
/// then looks like an IP block.
pub const CONNECTION_LIMIT: u32 = 8;
/// Connections the TCP stage leaves for the SSH stage.
const SSH_RESERVE: u32 = 2;
/// Domestic control hosts: reachable from Russian networks even in whitelist mode.
pub const CONTROL_DOMESTIC: &[&str] = &["https://ya.ru", "https://vk.com"];
/// Foreign control hosts.
pub const CONTROL_FOREIGN: &[&str] = &["https://github.com", "https://www.wikipedia.org"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Control,
    Dns,
    Tcp,
    Ssh,
}

/// What a probe checks; the classifier tells probes apart by it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    ControlDomestic,
    ControlForeign,
    DnsSystem,
    DnsDoh,
    /// The system answer compared with DoH.
    DnsCompare,
    TcpSsh,
    /// A port of the same IP that is expected to be closed.
    TcpClosed,
    SshHandshake,
}

impl Kind {
    pub fn stage(self) -> Stage {
        match self {
            Self::ControlDomestic | Self::ControlForeign => Stage::Control,
            Self::DnsSystem | Self::DnsDoh | Self::DnsCompare => Stage::Dns,
            Self::TcpSsh | Self::TcpClosed => Stage::Tcp,
            Self::SshHandshake => Stage::Ssh,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Family {
    #[serde(rename = "ipv4")]
    V4,
    #[serde(rename = "ipv6")]
    V6,
}

impl Family {
    pub fn of(address: &IpAddr) -> Self {
        if address.is_ipv4() {
            Self::V4
        } else {
            Self::V6
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    Refused,
    Timeout,
    Unreachable,
    /// The user's own network has no route for the family, e.g. no IPv6: not a block.
    NoLocalRoute,
    DnsFail,
    DnsMismatch,
    BannerMissing,
    ResetAfterBanner,
    KexFailed,
    HostKeyMismatch,
    Skipped(String),
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
    pub fn is_skipped(&self) -> bool {
        matches!(self, Self::Skipped(_))
    }
    fn label(&self) -> String {
        match self {
            Self::Ok => "ok".into(),
            Self::Refused => "refused".into(),
            Self::Timeout => "timeout".into(),
            Self::Unreachable => "unreachable".into(),
            Self::NoLocalRoute => "no_local_route".into(),
            Self::DnsFail => "dns_fail".into(),
            Self::DnsMismatch => "dns_mismatch".into(),
            Self::BannerMissing => "banner_missing".into(),
            Self::ResetAfterBanner => "reset_after_banner".into(),
            Self::KexFailed => "kex_failed".into(),
            Self::HostKeyMismatch => "host_key_mismatch".into(),
            Self::Skipped(reason) => format!("skipped ({reason})"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Probe {
    pub stage: Stage,
    pub kind: Kind,
    /// Control host, DNS provider or port role.
    pub name: String,
    pub family: Option<Family>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub outcome: Outcome,
    pub elapsed_ms: u64,
    pub attempt: u8,
    /// Addresses a DNS probe returned.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<String>,
    /// SSH identification string of the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// SHA-256 fingerprint of the host key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Explanation without host names or addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Probe {
    pub fn new(kind: Kind, name: impl Into<String>) -> Self {
        Self {
            stage: kind.stage(),
            kind,
            name: name.into(),
            family: None,
            address: None,
            port: None,
            outcome: Outcome::Skipped(String::new()),
            elapsed_ms: 0,
            attempt: 1,
            answers: Vec::new(),
            banner: None,
            fingerprint: None,
            detail: None,
        }
    }
    fn at(mut self, address: SocketAddr) -> Self {
        self.family = Some(Family::of(&address.ip()));
        self.address = Some(address.ip().to_string());
        self.port = Some(address.port());
        self
    }
    fn skipped(mut self, reason: &str) -> Self {
        self.outcome = Outcome::Skipped(reason.into());
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Serialize)]
pub struct Verdict {
    pub code: &'static str,
    pub confidence: Confidence,
    /// Indexes into [`Report::probes`].
    pub evidence: Vec<usize>,
    pub hypothesis: &'static str,
    pub advice: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub target: String,
    pub port: u16,
    pub started_at: String,
    pub duration_ms: u64,
    pub redacted: bool,
    /// TCP connections opened to the server during the run.
    pub connections: u32,
    pub probes: Vec<Probe>,
    pub verdicts: Vec<Verdict>,
    pub notes: Vec<String>,
}

/// The first hop to check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    /// Hops after the first one: reachable only through it, so not checked here.
    pub later_hops: usize,
}

impl Target {
    /// A tunnel by ID or name, otherwise `host[:port]` with an optional `[IPv6]`.
    pub fn resolve(value: &str, tunnels: &[Tunnel]) -> Result<Self> {
        if let Some(tunnel) = tunnels
            .iter()
            .find(|t| t.id == value)
            .or_else(|| tunnels.iter().find(|t| t.name == value))
        {
            let jumps = if tunnel.jumps_enabled {
                tunnel.jumps.as_slice()
            } else {
                &[]
            };
            let first = jumps.first().unwrap_or(&tunnel.server);
            return Ok(Self {
                host: unbracket(&first.host).to_string(),
                port: first.port,
                later_hops: jumps.len(),
            });
        }
        let (host, port) = if let Some(rest) = value.strip_prefix('[') {
            let Some((host, tail)) = rest.split_once(']') else {
                bail!("Некорректный адрес: нет закрывающей скобки IPv6.");
            };
            match tail {
                "" => (host, None),
                _ => match tail.strip_prefix(':') {
                    Some(port) => (host, Some(port)),
                    None => bail!("Некорректный адрес: после IPv6 ожидается :порт."),
                },
            }
        } else if value.matches(':').count() == 1 {
            let (host, port) = value.split_once(':').unwrap_or((value, ""));
            (host, Some(port))
        } else {
            (value, None)
        };
        crate::config::host(host, "Адрес")?;
        let port = match port {
            None => 22,
            Some(port) => match port.parse::<u16>() {
                Ok(port) if port > 0 => port,
                _ => bail!("Порт должен быть целым числом от 1 до 65535."),
            },
        };
        Ok(Self {
            host: host.to_string(),
            port,
            later_hops: 0,
        })
    }
}

pub struct Options {
    pub control_domestic: Vec<String>,
    pub control_foreign: Vec<String>,
    pub doh: bool,
    /// KROT's trust store of host keys.
    pub known_hosts: PathBuf,
    pub tcp_timeout: Duration,
    pub ssh_timeout: Duration,
}

impl Options {
    pub fn new(known_hosts: PathBuf) -> Self {
        Self {
            control_domestic: CONTROL_DOMESTIC.iter().map(|s| s.to_string()).collect(),
            control_foreign: CONTROL_FOREIGN.iter().map(|s| s.to_string()).collect(),
            doh: true,
            known_hosts,
            tcp_timeout: Duration::from_secs(5),
            ssh_timeout: Duration::from_secs(10),
        }
    }
}

/// Counts connections to the server; a probe that gets no permit is skipped.
pub(crate) struct Budget {
    used: AtomicU32,
    limit: u32,
}

impl Budget {
    pub(crate) fn new(limit: u32) -> Self {
        Self {
            used: AtomicU32::new(0),
            limit,
        }
    }
    /// Takes one connection if `reserve` connections stay for later stages.
    pub(crate) fn take(&self, reserve: u32) -> bool {
        let mut used = self.used.load(Ordering::SeqCst);
        while used + reserve < self.limit {
            match self
                .used
                .compare_exchange(used, used + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return true,
                Err(current) => used = current,
            }
        }
        false
    }
    pub(crate) fn used(&self) -> u32 {
        self.used.load(Ordering::SeqCst)
    }
}

const CANCELLED: &str = "проверка отменена";
const OVER_LIMIT: &str = "лимит подключений к серверу";

/// Runs all stages. Probes to the server run one after another, so at most one connection to it
/// is open at a time.
pub async fn run(target: Target, options: Options, cancel: CancellationToken) -> Report {
    let started_at = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let started = Instant::now();
    let client = probes::http_client(&options);
    let literal = target
        .host
        .split('%')
        .next()
        .unwrap_or_default()
        .parse::<IpAddr>()
        .ok();
    let (control, dns) = tokio::join!(
        probes::control(&client, &options, &cancel),
        probes::dns(&client, &target, literal, options.doh, &cancel),
    );
    let mut probes = control;
    let mut notes = Vec::new();
    if target.later_hops > 0 {
        notes.push(format!(
            "Проверен только первый узел цепочки; следующие ({}) достижимы лишь через него после входа.",
            target.later_hops
        ));
    }
    let addresses = dns.addresses;
    if dns.from_doh {
        notes.push(
            "Системный резолвер не дал адресов; TCP и SSH проверены по адресам из DoH.".into(),
        );
    }
    probes.extend(dns.probes);
    let budget = Budget::new(CONNECTION_LIMIT);
    probes.extend(server_stages(&target, &addresses, &options, &budget, &cancel).await);
    if cancel.is_cancelled() {
        notes.push("Проверка прервана; гипотезы построены по выполненным этапам.".into());
    }
    let verdicts = classify(&probes);
    Report {
        target: target.host,
        port: target.port,
        started_at,
        duration_ms: started.elapsed().as_millis() as u64,
        redacted: false,
        connections: budget.used(),
        probes,
        verdicts,
        notes,
    }
}

/// Stages T and S against the given addresses, within `budget`.
pub(crate) async fn server_stages(
    target: &Target,
    addresses: &[IpAddr],
    options: &Options,
    budget: &Budget,
    cancel: &CancellationToken,
) -> Vec<Probe> {
    let mut probes = Vec::new();
    let closed_port = if target.port == 1 { 2 } else { 1 };
    let mut reachable = None;
    for &ip in addresses {
        let address = SocketAddr::new(ip, target.port);
        let mut last = Outcome::Ok;
        for attempt in 1..=2 {
            let probe = Probe::new(Kind::TcpSsh, "порт SSH").at(address);
            if cancel.is_cancelled() {
                probes.push(probe.skipped(CANCELLED));
                return probes;
            }
            if !budget.take(SSH_RESERVE) {
                probes.push(probe.skipped(OVER_LIMIT));
                last = Outcome::Skipped(OVER_LIMIT.into());
                break;
            }
            let mut probe = probes::tcp(probe, options.tcp_timeout, cancel).await;
            probe.attempt = attempt;
            last = probe.outcome.clone();
            probes.push(probe);
            // A refusal or a missing local route will not change on a repeat.
            if matches!(last, Outcome::Ok | Outcome::Refused | Outcome::NoLocalRoute) {
                break;
            }
        }
        if last.is_ok() {
            reachable.get_or_insert(address);
        } else if !matches!(last, Outcome::NoLocalRoute | Outcome::Skipped(_)) {
            // A reset from a closed port shows the IP answers even when the SSH port is silent.
            let probe =
                Probe::new(Kind::TcpClosed, "закрытый порт").at(SocketAddr::new(ip, closed_port));
            if !budget.take(SSH_RESERVE) {
                probes.push(probe.skipped(OVER_LIMIT));
            } else {
                probes.push(probes::tcp(probe, options.tcp_timeout, cancel).await);
            }
        }
    }
    let Some(address) = reachable else {
        let probe = Probe::new(Kind::SshHandshake, "обмен ключами");
        let reason = if addresses.is_empty() {
            "нет адресов"
        } else {
            "нет TCP-подключения к порту SSH"
        };
        probes.push(probe.skipped(reason));
        return probes;
    };
    let known = crate::ssh::saved_host_key(&options.known_hosts, &target.host, target.port);
    for attempt in 1..=2 {
        let probe = Probe::new(Kind::SshHandshake, "обмен ключами").at(address);
        if cancel.is_cancelled() {
            probes.push(probe.skipped(CANCELLED));
            break;
        }
        if !budget.take(0) {
            probes.push(probe.skipped(OVER_LIMIT));
            break;
        }
        let mut probe = probes::handshake(probe, &known, options, cancel).await;
        probe.attempt = attempt;
        let done = matches!(probe.outcome, Outcome::Ok | Outcome::HostKeyMismatch);
        probes.push(probe);
        if done {
            break;
        }
    }
    probes
}

/// Hides the server name, its addresses and its key fingerprint, so the report can be attached
/// to an issue. Control hosts and DNS providers stay: they are public and built in.
pub fn redact(report: &mut Report) {
    let mut names: HashMap<String, String> = HashMap::new();
    let (mut v4, mut v6) = (0, 0);
    let mut alias = |address: &str| -> String {
        if let Some(name) = names.get(address) {
            return name.clone();
        }
        let name = match address.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => {
                v4 += 1;
                format!("<IPv4-{v4}>")
            }
            _ => {
                v6 += 1;
                format!("<IPv6-{v6}>")
            }
        };
        names.insert(address.to_string(), name.clone());
        name
    };
    report.target = "<сервер>".into();
    for probe in &mut report.probes {
        if let Some(address) = &probe.address {
            probe.address = Some(alias(address));
        }
        for answer in &mut probe.answers {
            *answer = alias(answer);
        }
        probe.fingerprint = None;
        // RFC 4253: `SSH-proto-software SP comments`; an administrator may put the host name in
        // the comments, so only the protocol and software version stay.
        if let Some(banner) = &mut probe.banner {
            banner.truncate(banner.find(' ').unwrap_or(banner.len()));
        }
    }
    report.redacted = true;
}

fn stage_label(stage: Stage) -> &'static str {
    match stage {
        Stage::Control => "К контроль",
        Stage::Dns => "D DNS",
        Stage::Tcp => "T TCP",
        Stage::Ssh => "S SSH",
    }
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "низкая",
        Confidence::Medium => "средняя",
        Confidence::High => "высокая",
    }
}

/// The human-readable report: a table of stages, then hypotheses with advice.
pub fn render(report: &Report) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let host = crate::config::display_host(&report.target);
    let _ = writeln!(
        out,
        "Проверка {host}:{} — {}, {:.1} с, подключений к серверу: {} из {CONNECTION_LIMIT}{}",
        report.port,
        report.started_at,
        report.duration_ms as f64 / 1000.0,
        report.connections,
        if report.redacted {
            ", узел и адреса скрыты"
        } else {
            ""
        },
    );
    let _ = writeln!(
        out,
        "\n  #  {:<11} {:<18} {:<5} {:<24} {:<2} {:<20} {:>7}",
        "Этап", "Проверка", "Сем.", "Адрес", "П", "Исход", "мс"
    );
    for (index, probe) in report.probes.iter().enumerate() {
        let family = match probe.family {
            Some(Family::V4) => "v4",
            Some(Family::V6) => "v6",
            None => "—",
        };
        let address = match (&probe.address, probe.port) {
            (Some(address), Some(port)) => {
                format!("{}:{port}", crate::config::display_host(address))
            }
            (Some(address), None) => address.clone(),
            _ => "—".into(),
        };
        let _ = writeln!(
            out,
            "{index:>3}  {:<11} {:<18} {:<5} {:<24} {:<2} {:<20} {:>7}",
            stage_label(probe.stage),
            probe.name,
            family,
            address,
            probe.attempt,
            probe.outcome.label(),
            probe.elapsed_ms,
        );
        let mut extra = Vec::new();
        if !probe.answers.is_empty() {
            extra.push(format!("адреса: {}", probe.answers.join(", ")));
        }
        if let Some(banner) = &probe.banner {
            extra.push(format!("баннер: {banner}"));
        }
        if let Some(fingerprint) = &probe.fingerprint {
            extra.push(format!("ключ: {fingerprint}"));
        }
        if let Some(detail) = &probe.detail {
            extra.push(detail.clone());
        }
        for line in extra {
            let _ = writeln!(out, "     {line}");
        }
    }
    let _ = writeln!(out, "\nГипотезы:");
    for verdict in &report.verdicts {
        let prefix = if verdict.confidence == Confidence::Low {
            "Похоже на: "
        } else {
            ""
        };
        let evidence: Vec<String> = verdict.evidence.iter().map(|i| format!("#{i}")).collect();
        let _ = writeln!(
            out,
            "  [{}] {prefix}{}\n    Совет: {}\n    Доводы: {}",
            confidence_label(verdict.confidence),
            verdict.hypothesis,
            verdict.advice,
            if evidence.is_empty() {
                "—".into()
            } else {
                evidence.join(", ")
            },
        );
    }
    for note in &report.notes {
        let _ = writeln!(out, "\n{note}");
    }
    let _ = writeln!(
        out,
        "\nРезультат верен только для текущей сети и момента проверки."
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Endpoint;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[test]
    fn targets_parse_hosts_ports_ipv6_and_tunnels() {
        let parse = |value| Target::resolve(value, &[]).unwrap();
        assert_eq!(parse("example.org").port, 22);
        assert_eq!(parse("example.org:2222").port, 2222);
        assert_eq!(parse("[2001:db8::1]:2200").host, "2001:db8::1");
        assert_eq!(parse("[2001:db8::1]:2200").port, 2200);
        assert_eq!(parse("2001:db8::1").host, "2001:db8::1");
        assert_eq!(parse("2001:db8::1").port, 22);
        for bad in ["example.org:0", "example.org:x", "[::1", "user@host", ""] {
            assert!(Target::resolve(bad, &[]).is_err(), "{bad}");
        }
        let tunnel = Tunnel {
            id: "abc".into(),
            name: "work".into(),
            server: Endpoint {
                host: "final.example".into(),
                port: 2022,
                ..Endpoint::default()
            },
            jumps_enabled: true,
            jumps: vec![Endpoint {
                host: "[2001:db8::2]".into(),
                port: 22,
                ..Endpoint::default()
            }],
            ..Tunnel::default()
        };
        let first = Target::resolve("work", std::slice::from_ref(&tunnel)).unwrap();
        assert_eq!(
            first,
            Target {
                host: "2001:db8::2".into(),
                port: 22,
                later_hops: 1
            }
        );
        let mut direct = tunnel;
        direct.jumps_enabled = false;
        let first = Target::resolve("abc", &[direct]).unwrap();
        assert_eq!(
            (first.host.as_str(), first.port, first.later_hops),
            ("final.example", 2022, 0)
        );
    }

    #[test]
    fn budget_keeps_the_reserve_and_the_limit() {
        let budget = Budget::new(CONNECTION_LIMIT);
        let tcp = (0..10).filter(|_| budget.take(SSH_RESERVE)).count();
        assert_eq!(tcp, 6);
        let ssh = (0..10).filter(|_| budget.take(0)).count();
        assert_eq!(ssh, 2);
        assert_eq!(budget.used(), CONNECTION_LIMIT);
    }

    /// A server that accepts and drops every connection: each TCP probe succeeds, each handshake
    /// fails and is repeated, which is the costliest path for the connection limit.
    #[tokio::test]
    async fn a_run_opens_at_most_the_connection_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicU32::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let target = Target {
            host: "127.0.0.1".into(),
            port,
            later_hops: 0,
        };
        // Repeated addresses stand for a name with many A/AAAA records.
        let addresses = vec!["127.0.0.1".parse().unwrap(); 12];
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::new(directory.path().join("known_hosts.json"));
        options.ssh_timeout = Duration::from_secs(2);
        let budget = Budget::new(CONNECTION_LIMIT);
        let probes = server_stages(
            &target,
            &addresses,
            &options,
            &budget,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(budget.used(), CONNECTION_LIMIT);
        let opened = probes.iter().filter(|p| !p.outcome.is_skipped()).count() as u32;
        assert_eq!(opened, CONNECTION_LIMIT);
        assert!(
            probes
                .iter()
                .any(|p| p.outcome == Outcome::Skipped(OVER_LIMIT.into()))
        );
        let handshakes: Vec<_> = probes
            .iter()
            .filter(|p| p.kind == Kind::SshHandshake)
            .map(|p| p.outcome.clone())
            .collect();
        assert_eq!(handshakes, [Outcome::BannerMissing, Outcome::BannerMissing]);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(accepted.load(Ordering::SeqCst) <= CONNECTION_LIMIT);
    }

    #[tokio::test]
    async fn cancellation_skips_the_remaining_probes() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let target = Target {
            host: "127.0.0.1".into(),
            port: 22,
            later_hops: 0,
        };
        let options = Options::new(PathBuf::from("unused.json"));
        let budget = Budget::new(CONNECTION_LIMIT);
        let probes = server_stages(
            &target,
            &["127.0.0.1".parse().unwrap()],
            &options,
            &budget,
            &cancel,
        )
        .await;
        assert_eq!(budget.used(), 0);
        assert_eq!(probes[0].outcome, Outcome::Skipped(CANCELLED.into()));
    }

    #[test]
    fn redaction_hides_the_server_addresses_and_fingerprint() {
        let mut dns = Probe::new(Kind::DnsSystem, "system");
        dns.answers = vec!["192.0.2.7".into(), "2001:db8::7".into()];
        let mut ssh =
            Probe::new(Kind::SshHandshake, "обмен ключами").at("192.0.2.7:22".parse().unwrap());
        ssh.fingerprint = Some("SHA256:secret".into());
        ssh.banner = Some("SSH-2.0-OpenSSH_9.6 secret.example".into());
        let mut report = Report {
            target: "secret.example".into(),
            port: 22,
            started_at: String::new(),
            duration_ms: 0,
            redacted: false,
            connections: 1,
            probes: vec![Probe::new(Kind::ControlForeign, "github.com"), dns, ssh],
            verdicts: Vec::new(),
            notes: Vec::new(),
        };
        redact(&mut report);
        let text = serde_json::to_string(&report).unwrap() + &render(&report);
        for secret in ["secret", "192.0.2.7", "2001:db8::7"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert_eq!(report.probes[2].address.as_deref(), Some("<IPv4-1>"));
        assert_eq!(report.probes[1].answers, ["<IPv4-1>", "<IPv6-1>"]);
        assert_eq!(
            report.probes[2].banner.as_deref(),
            Some("SSH-2.0-OpenSSH_9.6")
        );
        assert!(text.contains("github.com"));
        assert!(report.redacted);
    }
}
