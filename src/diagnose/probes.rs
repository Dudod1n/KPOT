//! Network probes of the diagnosis: each returns a filled [`Probe`] and never fails.
use super::{CANCELLED, Kind, Options, Outcome, Probe, Target};
use russh::client;
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};
use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// DoH providers with a JSON API: (name, endpoint).
pub const DOH_PROVIDERS: &[(&str, &str)] = &[
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/resolve"),
];
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// An identification line longer than this is not SSH.
const BANNER_LIMIT: usize = 8192;

pub(super) fn http_client(options: &Options) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("krot/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(options.tcp_timeout)
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

async fn cancellable<T>(
    cancel: &CancellationToken,
    operation: impl Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => None,
        value = operation => Some(value),
    }
}

fn millis(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

/// Maps a socket error to an outcome; a missing local route is told apart from a remote failure.
pub(super) fn io_outcome(error: &io::Error) -> Outcome {
    match error.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted => Outcome::Refused,
        io::ErrorKind::TimedOut => Outcome::Timeout,
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::AddrNotAvailable => {
            Outcome::NoLocalRoute
        }
        _ => Outcome::Unreachable,
    }
}

fn http_outcome(error: &reqwest::Error) -> Outcome {
    if error.is_timeout() {
        return Outcome::Timeout;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(error) = current.downcast_ref::<io::Error>() {
            return io_outcome(error);
        }
        source = current.source();
    }
    Outcome::Unreachable
}

fn url_host(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

/// Stage К: an HTTPS request (TCP + TLS) to each control host, repeated once on failure.
pub(super) async fn control(
    client: &reqwest::Client,
    options: &Options,
    cancel: &CancellationToken,
) -> Vec<Probe> {
    let targets: Vec<(Kind, String)> = options
        .control_domestic
        .iter()
        .map(|u| (Kind::ControlDomestic, u.clone()))
        .chain(
            options
                .control_foreign
                .iter()
                .map(|u| (Kind::ControlForeign, u.clone())),
        )
        .map(|(kind, url)| {
            let url = if url.contains("://") {
                url
            } else {
                format!("https://{url}")
            };
            (kind, url)
        })
        .collect();
    let mut tasks = JoinSet::new();
    for (index, (kind, url)) in targets.into_iter().enumerate() {
        let (client, cancel) = (client.clone(), cancel.clone());
        tasks.spawn(async move {
            let mut probes = Vec::new();
            for attempt in 1..=2 {
                let mut probe = Probe::new(kind, url_host(&url));
                probe.attempt = attempt;
                let started = Instant::now();
                let result = cancellable(&cancel, client.head(&url).send()).await;
                probe.elapsed_ms = millis(started);
                probe.outcome = match result {
                    None => Outcome::Skipped(CANCELLED.into()),
                    // Any HTTP answer proves TCP and TLS work.
                    Some(Ok(_)) => Outcome::Ok,
                    Some(Err(error)) => http_outcome(&error),
                };
                let done = probe.outcome.is_ok() || probe.outcome.is_skipped();
                probes.push(probe);
                if done {
                    break;
                }
            }
            (index, probes)
        });
    }
    let mut results: Vec<_> = tasks.join_all().await;
    results.sort_by_key(|(index, _)| *index);
    results.into_iter().flat_map(|(_, probes)| probes).collect()
}

pub(super) struct Dns {
    pub probes: Vec<Probe>,
    /// Addresses for the TCP and SSH stages, alternating families.
    pub addresses: Vec<IpAddr>,
    /// The system resolver gave nothing, so the addresses come from DoH.
    pub from_doh: bool,
}

/// Stage D: the system resolver and DoH providers, then their comparison.
pub(super) async fn dns(
    client: &reqwest::Client,
    target: &Target,
    literal: Option<IpAddr>,
    doh: bool,
    cancel: &CancellationToken,
) -> Dns {
    if literal.is_some() {
        let probe = Probe::new(Kind::DnsSystem, "system").skipped("адрес указан напрямую");
        // A scope ID needs the system resolver.
        let addresses = tokio::net::lookup_host((target.host.as_str(), target.port))
            .await
            .map(|a| a.map(|a| a.ip()).collect())
            .unwrap_or_else(|_| literal.into_iter().collect());
        return Dns {
            probes: vec![probe],
            addresses,
            from_doh: false,
        };
    }
    let doh_probes = async {
        if !doh {
            return Vec::new();
        }
        let mut tasks = JoinSet::new();
        for (index, &(name, endpoint)) in DOH_PROVIDERS.iter().enumerate() {
            let (client, cancel, host) = (client.clone(), cancel.clone(), target.host.clone());
            tasks.spawn(async move {
                (
                    index,
                    doh_probe(&client, name, endpoint, &host, &cancel).await,
                )
            });
        }
        let mut results = tasks.join_all().await;
        results.sort_by_key(|(index, _)| *index);
        results
            .into_iter()
            .flat_map(|(_, probes)| probes)
            .collect::<Vec<_>>()
    };
    let (system, doh_probes) = tokio::join!(system_probe(target, cancel), doh_probes);
    let system_answers = answers(&system);
    let doh_answers: Vec<Vec<IpAddr>> = doh_probes
        .iter()
        .filter(|p| p.outcome.is_ok())
        .map(std::slice::from_ref)
        .map(answers)
        .collect();
    let mut compare = Probe::new(Kind::DnsCompare, "система и DoH");
    match compare_dns(
        system
            .last()
            .is_some_and(|p| p.outcome.is_ok())
            .then_some(system_answers.as_slice()),
        &doh_answers,
    ) {
        None if !doh => compare.outcome = Outcome::Skipped("DoH отключён".into()),
        None => compare.outcome = Outcome::Skipped("нет ответа DoH".into()),
        Some((outcome, detail)) => {
            compare.outcome = outcome;
            compare.detail = Some(detail.into());
        }
    }
    let (addresses, from_doh) = if system_answers.is_empty() {
        let mut union = Vec::new();
        for address in doh_answers.iter().flatten() {
            if !union.contains(address) {
                union.push(*address);
            }
        }
        (union, true)
    } else {
        (system_answers, false)
    };
    let from_doh = from_doh && !addresses.is_empty();
    let mut probes = system;
    probes.extend(doh_probes);
    probes.push(compare);
    Dns {
        probes,
        addresses: interleave(addresses),
        from_doh,
    }
}

/// Addresses of the last successful attempt.
fn answers(probes: &[Probe]) -> Vec<IpAddr> {
    probes
        .iter()
        .rev()
        .find(|p| p.outcome.is_ok())
        .map(|p| p.answers.iter().filter_map(|a| a.parse().ok()).collect())
        .unwrap_or_default()
}

/// The first IPv4, the first IPv6, then the rest: both families get tested within the limit.
fn interleave(addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    let (v4, v6): (Vec<_>, Vec<_>) = addresses.into_iter().partition(IpAddr::is_ipv4);
    let mut out = Vec::new();
    let (mut v4, mut v6) = (v4.into_iter(), v6.into_iter());
    loop {
        match (v4.next(), v6.next()) {
            (None, None) => return out,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
}

async fn system_probe(target: &Target, cancel: &CancellationToken) -> Vec<Probe> {
    let mut probes = Vec::new();
    for attempt in 1..=2 {
        let mut probe = Probe::new(Kind::DnsSystem, "system");
        probe.attempt = attempt;
        let started = Instant::now();
        let lookup = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((target.host.as_str(), target.port)),
        );
        probe.outcome = match cancellable(cancel, lookup).await {
            None => Outcome::Skipped(CANCELLED.into()),
            Some(Err(_)) => Outcome::Timeout,
            Some(Ok(Err(_))) => Outcome::DnsFail,
            Some(Ok(Ok(found))) => {
                let mut seen = HashSet::new();
                probe.answers = found
                    .map(|a| a.ip())
                    .filter(|ip| seen.insert(*ip))
                    .map(|ip| ip.to_string())
                    .collect();
                if probe.answers.is_empty() {
                    Outcome::DnsFail
                } else {
                    Outcome::Ok
                }
            }
        };
        probe.elapsed_ms = millis(started);
        let done = probe.outcome.is_ok() || probe.outcome.is_skipped();
        probes.push(probe);
        if done {
            break;
        }
    }
    probes
}

async fn doh_probe(
    client: &reqwest::Client,
    name: &str,
    endpoint: &str,
    host: &str,
    cancel: &CancellationToken,
) -> Vec<Probe> {
    let mut probes = Vec::new();
    for attempt in 1..=2 {
        let mut probe = Probe::new(Kind::DnsDoh, name);
        probe.attempt = attempt;
        let started = Instant::now();
        let query = async {
            let mut found = Vec::new();
            for record in ["A", "AAAA"] {
                found.extend(doh_query(client, endpoint, host, record).await?);
            }
            Ok::<_, Outcome>(found)
        };
        probe.outcome = match cancellable(cancel, query).await {
            None => Outcome::Skipped(CANCELLED.into()),
            Some(Err(outcome)) => outcome,
            Some(Ok(found)) => {
                probe.answers = found.iter().map(IpAddr::to_string).collect();
                Outcome::Ok
            }
        };
        probe.elapsed_ms = millis(started);
        let done = probe.outcome.is_ok() || probe.outcome.is_skipped();
        probes.push(probe);
        if done {
            break;
        }
    }
    probes
}

async fn doh_query(
    client: &reqwest::Client,
    endpoint: &str,
    host: &str,
    record: &str,
) -> Result<Vec<IpAddr>, Outcome> {
    let url = reqwest::Url::parse_with_params(endpoint, &[("name", host), ("type", record)])
        .map_err(|_| Outcome::DnsFail)?;
    let response = client
        .get(url)
        .header("accept", "application/dns-json")
        .send()
        .await
        .map_err(|e| http_outcome(&e))?;
    if !response.status().is_success() {
        return Err(Outcome::DnsFail);
    }
    let body = response.bytes().await.map_err(|e| http_outcome(&e))?;
    parse_doh(&body).ok_or(Outcome::DnsFail)
}

/// Addresses from a DoH JSON answer; NXDOMAIN is an empty answer, other errors are `None`.
pub(super) fn parse_doh(body: &[u8]) -> Option<Vec<IpAddr>> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    match value.get("Status")?.as_u64()? {
        0 => {}
        3 => return Some(Vec::new()),
        _ => return None,
    }
    let Some(answer) = value.get("Answer").and_then(|a| a.as_array()) else {
        return Some(Vec::new());
    };
    Some(
        answer
            .iter()
            .filter(|r| matches!(r.get("type").and_then(|t| t.as_u64()), Some(1 | 28)))
            .filter_map(|r| r.get("data")?.as_str()?.parse().ok())
            .collect(),
    )
}

/// Addresses that no public server has: resolvers that block return them as a stub.
pub(super) fn stub(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Compares the system answer (`None` when it failed) with successful DoH answers.
pub(super) fn compare_dns(
    system: Option<&[IpAddr]>,
    doh: &[Vec<IpAddr>],
) -> Option<(Outcome, &'static str)> {
    if doh.is_empty() {
        return None;
    }
    let public: HashSet<IpAddr> = doh.iter().flatten().copied().collect();
    let system = system.unwrap_or_default();
    if system.iter().any(|a| stub(a) && !public.contains(a)) {
        return Some((
            Outcome::DnsMismatch,
            "системный резолвер вернул адрес-заглушку",
        ));
    }
    if system.is_empty() && !public.is_empty() {
        return Some((
            Outcome::DnsMismatch,
            "системный резолвер не дал адресов, DoH дал",
        ));
    }
    if !system.is_empty() && !public.is_empty() && system.iter().all(|a| !public.contains(a)) {
        return Some((
            Outcome::DnsMismatch,
            "адреса системы и DoH не пересекаются; у CDN это бывает и без подмены",
        ));
    }
    Some((Outcome::Ok, "ответы согласуются"))
}

/// Cloudflare ranges: its proxy forwards HTTP, not SSH.
const CLOUDFLARE_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(173, 245, 48, 0), 20),
    (Ipv4Addr::new(103, 21, 244, 0), 22),
    (Ipv4Addr::new(103, 22, 200, 0), 22),
    (Ipv4Addr::new(103, 31, 4, 0), 22),
    (Ipv4Addr::new(141, 101, 64, 0), 18),
    (Ipv4Addr::new(108, 162, 192, 0), 18),
    (Ipv4Addr::new(190, 93, 240, 0), 20),
    (Ipv4Addr::new(188, 114, 96, 0), 20),
    (Ipv4Addr::new(197, 234, 240, 0), 22),
    (Ipv4Addr::new(198, 41, 128, 0), 17),
    (Ipv4Addr::new(162, 158, 0, 0), 15),
    (Ipv4Addr::new(104, 16, 0, 0), 13),
    (Ipv4Addr::new(104, 24, 0, 0), 14),
    (Ipv4Addr::new(172, 64, 0, 0), 13),
    (Ipv4Addr::new(131, 0, 72, 0), 22),
];
const CLOUDFLARE_V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x2400, 0xcb00, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2803, 0xf800, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0xb500, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0x8100, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2a06, 0x98c0, 0, 0, 0, 0, 0, 0), 29),
    (Ipv6Addr::new(0x2c0f, 0xf248, 0, 0, 0, 0, 0, 0), 32),
];

/// The CDN that owns the address, if any.
pub(super) fn cdn(address: &IpAddr) -> Option<&'static str> {
    let inside = match address {
        IpAddr::V4(v4) => CLOUDFLARE_V4.iter().any(|(net, bits)| {
            let mask = u32::MAX.checked_shl(32 - u32::from(*bits)).unwrap_or(0);
            u32::from(*v4) & mask == u32::from(*net) & mask
        }),
        IpAddr::V6(v6) => CLOUDFLARE_V6.iter().any(|(net, bits)| {
            let mask = u128::MAX.checked_shl(128 - u32::from(*bits)).unwrap_or(0);
            u128::from(*v6) & mask == u128::from(*net) & mask
        }),
    };
    inside.then_some("Cloudflare")
}

/// Stage T: one TCP connection, closed right away.
pub(super) async fn tcp(mut probe: Probe, timeout: Duration, cancel: &CancellationToken) -> Probe {
    let Some(address) = probe
        .address
        .as_deref()
        .and_then(|a| a.parse::<IpAddr>().ok())
        .zip(probe.port)
        .map(|(ip, port)| SocketAddr::new(ip, port))
    else {
        return probe;
    };
    let started = Instant::now();
    let (outcome, _) = connect(address, timeout, cancel).await;
    probe.elapsed_ms = millis(started);
    probe.outcome = outcome;
    probe
}

async fn connect(
    address: SocketAddr,
    timeout: Duration,
    cancel: &CancellationToken,
) -> (Outcome, Option<TcpStream>) {
    match cancellable(
        cancel,
        tokio::time::timeout(timeout, TcpStream::connect(address)),
    )
    .await
    {
        None => (Outcome::Skipped(CANCELLED.into()), None),
        Some(Err(_)) => (Outcome::Timeout, None),
        Some(Ok(Err(error))) => (io_outcome(&error), None),
        Some(Ok(Ok(stream))) => (Outcome::Ok, Some(stream)),
    }
}

enum Banner {
    Found {
        consumed: Vec<u8>,
        line: String,
        after: usize,
    },
    Missing(&'static str),
}

/// Reads up to the server's `SSH-` line; lines before it are allowed by RFC 4253.
async fn read_banner(stream: &mut TcpStream) -> Banner {
    let mut consumed = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let mut start = 0;
        while let Some(end) = consumed[start..].iter().position(|&b| b == b'\n') {
            let line = &consumed[start..start + end];
            if line.starts_with(b"SSH-") {
                let text = String::from_utf8_lossy(line).trim_end().to_string();
                let after = consumed.len() - (start + end + 1);
                return Banner::Found {
                    consumed,
                    line: text,
                    after,
                };
            }
            start += end + 1;
        }
        if consumed.len() > BANNER_LIMIT {
            return Banner::Missing("ответ сервера не похож на SSH");
        }
        match stream.read(&mut chunk).await {
            Ok(0) => return Banner::Missing("сервер закрыл соединение без баннера"),
            Ok(count) => consumed.extend_from_slice(&chunk[..count]),
            Err(_) => return Banner::Missing("соединение сброшено до баннера"),
        }
    }
}

/// Replays the bytes read with the banner, then counts what the server sends after it.
struct Replay {
    prefix: Vec<u8>,
    offset: usize,
    inner: TcpStream,
    received: Arc<AtomicUsize>,
}

impl AsyncRead for Replay {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let count = buf.remaining().min(self.prefix.len() - self.offset);
            let start = self.offset;
            buf.put_slice(&self.prefix[start..start + count]);
            self.offset += count;
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let count = buf.filled().len() - before;
        self.received.fetch_add(count, Ordering::SeqCst);
        result
    }
}

impl AsyncWrite for Replay {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Captures the host key; login never starts.
struct KeyCatcher(Arc<Mutex<Option<PublicKey>>>);

impl client::Handler for KeyCatcher {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        *self.0.lock().unwrap() = Some(key.public_key().clone());
        Ok(true)
    }
}

/// Stage S: server banner, client banner, KEXINIT and the end of the key exchange, then the key
/// is compared with KROT's trust store. `known` is the saved key or why it could not be read.
pub(super) async fn handshake(
    mut probe: Probe,
    known: &Result<Option<PublicKey>, &'static str>,
    options: &Options,
    cancel: &CancellationToken,
) -> Probe {
    let Some(address) = probe
        .address
        .as_deref()
        .and_then(|a| a.parse::<IpAddr>().ok())
        .zip(probe.port)
        .map(|(ip, port)| SocketAddr::new(ip, port))
    else {
        return probe;
    };
    let started = Instant::now();
    let (outcome, stream) = connect(address, options.tcp_timeout, cancel).await;
    let Some(mut stream) = stream else {
        probe.outcome = outcome;
        probe.detail = Some("TCP-подключение не удалось".into());
        probe.elapsed_ms = millis(started);
        return probe;
    };
    let banner = cancellable(
        cancel,
        tokio::time::timeout(options.ssh_timeout, read_banner(&mut stream)),
    )
    .await;
    let (consumed, after) = match banner {
        None => {
            probe.outcome = Outcome::Skipped(CANCELLED.into());
            probe.elapsed_ms = millis(started);
            return probe;
        }
        Some(Err(_)) => {
            probe.outcome = Outcome::BannerMissing;
            probe.detail = Some(format!(
                "нет баннера за {} с",
                options.ssh_timeout.as_secs()
            ));
            probe.elapsed_ms = millis(started);
            return probe;
        }
        Some(Ok(Banner::Missing(reason))) => {
            probe.outcome = Outcome::BannerMissing;
            probe.detail = Some(reason.into());
            probe.elapsed_ms = millis(started);
            return probe;
        }
        Some(Ok(Banner::Found {
            consumed,
            line,
            after,
        })) => {
            probe.banner = Some(line);
            (consumed, after)
        }
    };
    let received = Arc::new(AtomicUsize::new(after));
    let key = Arc::new(Mutex::new(None));
    let replay = Replay {
        prefix: consumed,
        offset: 0,
        inner: stream,
        received: received.clone(),
    };
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(options.ssh_timeout),
        ..Default::default()
    });
    let exchange = client::connect_stream(config, replay, KeyCatcher(key.clone()));
    let result = cancellable(cancel, tokio::time::timeout(options.ssh_timeout, exchange)).await;
    probe.elapsed_ms = millis(started);
    let failed = |probe: &mut Probe, reason: &str| {
        let after_banner = received.load(Ordering::SeqCst) > 0;
        probe.outcome = if after_banner || key.lock().unwrap().is_some() {
            Outcome::KexFailed
        } else {
            Outcome::ResetAfterBanner
        };
        probe.detail = Some(if after_banner {
            format!("обмен ключами не завершён: {reason}")
        } else {
            format!("после баннера сервер ничего не прислал: {reason}")
        });
    };
    match result {
        None => probe.outcome = Outcome::Skipped(CANCELLED.into()),
        Some(Err(_)) => failed(&mut probe, "истекло время ожидания"),
        Some(Ok(Err(_))) => failed(&mut probe, "соединение закрыто или сброшено"),
        Some(Ok(Ok(handle))) => {
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "", "en")
                .await;
            let Some(server) = key.lock().unwrap().clone() else {
                failed(&mut probe, "сервер не предъявил ключ");
                return probe;
            };
            probe.fingerprint = Some(server.fingerprint(HashAlg::Sha256).to_string());
            let (outcome, detail) = match known {
                Ok(Some(saved)) if saved.key_data() == server.key_data() => {
                    (Outcome::Ok, "ключ узла совпадает с сохранённым в КРОТе")
                }
                Ok(Some(_)) => (
                    Outcome::HostKeyMismatch,
                    "ключ узла отличается от сохранённого в КРОТе",
                ),
                Ok(None) => (
                    Outcome::Ok,
                    "ключ узла ещё не сохранён в КРОТе; сверьте отпечаток при первом подключении",
                ),
                Err(reason) => (Outcome::Ok, *reason),
            };
            probe.outcome = outcome;
            probe.detail = Some(detail.into());
        }
    }
    probe
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn doh_answers_keep_addresses_and_skip_cnames() {
        let body = br#"{"Status":0,"Answer":[{"type":5,"data":"alias.example."},
            {"type":1,"data":"192.0.2.1"},{"type":28,"data":"2001:db8::1"}]}"#;
        assert_eq!(
            parse_doh(body),
            Some(vec![ip("192.0.2.1"), ip("2001:db8::1")])
        );
        assert_eq!(parse_doh(br#"{"Status":3}"#), Some(vec![]));
        assert_eq!(parse_doh(br#"{"Status":2}"#), None);
        assert_eq!(parse_doh(b"<html>"), None);
    }

    #[test]
    fn dns_comparison_finds_stubs_empty_and_disjoint_answers() {
        let public = vec![vec![ip("192.0.2.1")]];
        assert!(compare_dns(Some(&[ip("192.0.2.1")]), &[]).is_none());
        assert_eq!(
            compare_dns(Some(&[ip("192.0.2.1")]), &public).unwrap().0,
            Outcome::Ok
        );
        assert_eq!(
            compare_dns(Some(&[ip("127.0.0.1")]), &public).unwrap().0,
            Outcome::DnsMismatch
        );
        assert_eq!(compare_dns(None, &public).unwrap().0, Outcome::DnsMismatch);
        assert_eq!(
            compare_dns(Some(&[ip("198.51.100.1")]), &public).unwrap().0,
            Outcome::DnsMismatch
        );
        assert_eq!(compare_dns(None, &[vec![]]).unwrap().0, Outcome::Ok);
    }

    #[test]
    fn cdn_and_stub_ranges() {
        assert_eq!(cdn(&ip("104.16.1.1")), Some("Cloudflare"));
        assert_eq!(cdn(&ip("2606:4700::1")), Some("Cloudflare"));
        assert_eq!(cdn(&ip("192.0.2.1")), None);
        assert!(stub(&ip("10.1.2.3")) && stub(&ip("0.0.0.0")) && stub(&ip("fd00::1")));
        assert!(!stub(&ip("192.0.2.1")) && !stub(&ip("2001:db8::1")));
    }

    #[test]
    fn interleave_alternates_families() {
        let out = interleave(vec![ip("192.0.2.1"), ip("192.0.2.2"), ip("2001:db8::1")]);
        assert_eq!(out, [ip("192.0.2.1"), ip("2001:db8::1"), ip("192.0.2.2")]);
    }

    async fn serve_once(reply: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(reply).await.unwrap();
            let mut sink = [0u8; 256];
            let _ = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut sink)).await;
        });
        address
    }

    async fn shake(address: SocketAddr) -> Probe {
        let mut options = Options::new("unused.json".into());
        options.ssh_timeout = Duration::from_secs(2);
        let probe = Probe::new(Kind::SshHandshake, "обмен ключами").at(address);
        handshake(probe, &Ok(None), &options, &CancellationToken::new()).await
    }

    #[tokio::test]
    async fn handshake_tells_where_the_connection_broke() {
        let silent = shake(serve_once(b"").await).await;
        assert_eq!(silent.outcome, Outcome::BannerMissing);
        let http = shake(serve_once(b"HTTP/1.1 400 Bad Request\r\n\r\n").await).await;
        assert_eq!(http.outcome, Outcome::BannerMissing);
        let reset = shake(serve_once(b"SSH-2.0-Test\r\n").await).await;
        assert_eq!(reset.outcome, Outcome::ResetAfterBanner);
        assert_eq!(reset.banner.as_deref(), Some("SSH-2.0-Test"));
        let kex =
            shake(serve_once(b"SSH-2.0-Test\r\n\x00\x00\x00\x0c\x0a\x14garbage!!!").await).await;
        assert_eq!(kex.outcome, Outcome::KexFailed);
    }

    #[test]
    fn socket_errors_separate_local_routes() {
        let outcome = |kind| io_outcome(&io::Error::from(kind));
        assert_eq!(outcome(io::ErrorKind::ConnectionRefused), Outcome::Refused);
        assert_eq!(
            outcome(io::ErrorKind::NetworkUnreachable),
            Outcome::NoLocalRoute
        );
        assert_eq!(
            outcome(io::ErrorKind::HostUnreachable),
            Outcome::Unreachable
        );
        assert_eq!(outcome(io::ErrorKind::TimedOut), Outcome::Timeout);
    }
}
