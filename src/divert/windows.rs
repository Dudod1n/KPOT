//! WinDivert glue: loads the official driver library, runs the packet loop and the relay.
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    ffi::c_void,
    net::SocketAddr,
    os::windows::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    },
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
        MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        LibraryLoader::{GetProcAddress, LoadLibraryW},
        RemoteDesktop::ProcessIdToSessionId,
        SystemInformation::GetSystemDirectoryW,
        Threading::{
            GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    },
    UI::{
        Shell::{SHELLEXECUTEINFOW, ShellExecuteExW},
        WindowsAndMessaging::SW_HIDE,
    },
};

use super::{
    DLL_SHA256, Matcher, Nat, Origin, Processes, SYS_SHA256, TCP, Verdict, handle,
    link::{INBOUND_QUEUE, Inbound, Link},
    owners::{Snapshot, UDP_TABLE_HEADER, UDP4_ROW_SIZE, UDP6_ROW_SIZE, UdpOwners},
    reset, tcp_table_owner,
    udp::{self, Policy},
};
use crate::{
    apps::{DivertReport, DivertRule, DivertStats},
    background::Client,
    config::Store,
    proxy::{Counters, Destination},
};
use krot_udp_proto::metrics::DropReason;

const FILTER: &[u8] = b"outbound and !loopback and !impostor and (tcp or udp)\0";
const FIREWALL_RULE: &str = "KROT-app-relay";
const OUTBOUND: u32 = 1 << 17;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const TCP_TABLE_OWNER_PID_ALL: i32 = 5;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const PARENT_TTL: Duration = Duration::from_secs(2);
const SYNC_TIME: Duration = Duration::from_secs(1);
const MAX_PENDING_LOGS: usize = 500;

const _: () = {
    use std::mem::{offset_of, size_of};
    // The platform-neutral parser in `owners` relies on these layouts.
    assert!(offset_of!(MIB_UDPTABLE_OWNER_PID, table) == UDP_TABLE_HEADER);
    assert!(offset_of!(MIB_UDP6TABLE_OWNER_PID, table) == UDP_TABLE_HEADER);
    assert!(size_of::<MIB_UDPROW_OWNER_PID>() == UDP4_ROW_SIZE);
    assert!(size_of::<MIB_UDP6ROW_OWNER_PID>() == UDP6_ROW_SIZE);
    assert!(offset_of!(MIB_UDPROW_OWNER_PID, dwLocalPort) == 4);
    assert!(offset_of!(MIB_UDPROW_OWNER_PID, dwOwningPid) == 8);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, dwLocalScopeId) == 16);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, dwLocalPort) == 20);
    assert!(offset_of!(MIB_UDP6ROW_OWNER_PID, dwOwningPid) == 24);
};

/// `WINDIVERT_ADDRESS`: timestamp, a bit field, a reserved word and 64 bytes of layer data.
/// For the network layer the data starts with the interface and subinterface indexes, which
/// an injected answer needs; the whole address of the flow's latest packet is kept for it.
#[derive(Clone, Copy)]
#[repr(C)]
struct Address {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    data: [u8; 64],
}

impl Address {
    fn interface_index(&self) -> u32 {
        // The NETWORK layer starts its address data with WINDIVERT_DATA_NETWORK.IfIdx.
        u32::from_ne_bytes(*self.data.first_chunk::<4>().unwrap())
    }
}

type Symbol = unsafe extern "system" fn() -> isize;
type Open = unsafe extern "C" fn(*const u8, i32, i16, u64) -> HANDLE;
type Recv = unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type Send = unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> i32;
type Checksums = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;

#[derive(Clone, Copy)]
struct Api {
    open: Open,
    recv: Recv,
    send: Send,
    checksums: Checksums,
}

/// An open WinDivert handle; the driver allows receiving and sending from any thread.
struct Device(HANDLE);
// SAFETY: the handle is an opaque kernel object used only through thread-safe driver calls.
unsafe impl std::marker::Send for Device {}
// SAFETY: as above; the packet thread receives while the answer task sends.
unsafe impl std::marker::Sync for Device {}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

fn verified(path: &Path, expected: &str, name: &str) -> Result<()> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Не найден {name} рядом с krot.exe."))?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == expected,
        "Файл {name} не совпадает с официальной сборкой WinDivert 2.2.2."
    );
    Ok(())
}

fn load() -> Result<Api> {
    let directory = std::env::current_exe()?
        .parent()
        .context("Не удалось определить каталог КРОТа.")?
        .to_path_buf();
    let library = directory.join("WinDivert.dll");
    verified(&library, DLL_SHA256, "WinDivert.dll")?;
    verified(
        &directory.join("WinDivert64.sys"),
        SYS_SHA256,
        "WinDivert64.sys",
    )?;
    let path = wide(library.as_os_str());
    // SAFETY: the path is NUL-terminated and absolute; the names are NUL-terminated; each
    // symbol is transmuted to the signature declared in windivert.h for this exact version.
    unsafe {
        let module = LoadLibraryW(path.as_ptr());
        ensure!(!module.is_null(), "Не удалось загрузить WinDivert.dll.");
        let symbol = |name: &[u8]| {
            GetProcAddress(module, name.as_ptr())
                .context("WinDivert.dll не содержит нужных функций.")
        };
        Ok(Api {
            open: std::mem::transmute::<Symbol, Open>(symbol(b"WinDivertOpen\0")?),
            recv: std::mem::transmute::<Symbol, Recv>(symbol(b"WinDivertRecv\0")?),
            send: std::mem::transmute::<Symbol, Send>(symbol(b"WinDivertSend\0")?),
            checksums: std::mem::transmute::<Symbol, Checksums>(symbol(
                b"WinDivertHelperCalcChecksums\0",
            )?),
        })
    }
}

fn open(api: &Api) -> Result<Device> {
    // SAFETY: the filter is a NUL-terminated string; layer 0 is the network layer.
    let device = unsafe { (api.open)(FILTER.as_ptr(), 0, 0, 0) };
    if device != INVALID_HANDLE_VALUE {
        return Ok(Device(device));
    }
    // SAFETY: reads the calling thread's last error code.
    match unsafe { GetLastError() } {
        2 => bail!("Не найден WinDivert64.sys рядом с krot.exe."),
        5 => bail!("Нет прав администратора для запуска драйвера WinDivert."),
        577 => bail!("Windows отклонила подпись драйвера WinDivert."),
        654 => bail!(
            "Загружена несовместимая версия WinDivert. Закройте использующие его программы или перезагрузите компьютер."
        ),
        1275 => bail!("Драйвер WinDivert заблокирован системой или антивирусом."),
        code => bail!("Не удалось запустить драйвер WinDivert (код {code})."),
    }
}

fn process_path(pid: u32) -> Option<String> {
    // SAFETY: the handle is checked and closed; the buffer outlives the call that fills it.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let mut buffer = [0u16; 1024];
        let mut length = buffer.len() as u32;
        let found = QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) != 0;
        CloseHandle(process);
        found.then(|| String::from_utf16_lossy(&buffer[..length as usize]))
    }
}

fn session(pid: u32) -> Option<u32> {
    let mut session = 0;
    // SAFETY: writes one u32 through a valid pointer.
    (unsafe { ProcessIdToSessionId(pid, &mut session) } != 0).then_some(session)
}

fn parents() -> HashMap<u32, u32> {
    let mut map = HashMap::new();
    // SAFETY: the snapshot handle is checked and closed; the entry is sized as required.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return map;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            map.insert(entry.th32ProcessID, entry.th32ParentProcessID);
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    map
}

/// Processes of the helper's own logon session; services and other users are never captured.
struct System {
    session: Option<u32>,
    parents: RefCell<Option<(HashMap<u32, u32>, Instant)>>,
}

impl Processes for System {
    fn path(&self, pid: u32) -> Option<String> {
        if session(pid) != self.session {
            return None;
        }
        process_path(pid)
    }
    fn parent(&self, pid: u32) -> Option<u32> {
        let mut cached = self.parents.borrow_mut();
        if cached
            .as_ref()
            .is_none_or(|(_, at)| at.elapsed() > PARENT_TTL)
        {
            *cached = Some((parents(), Instant::now()));
        }
        cached.as_ref()?.0.get(&pid).copied()
    }
}

fn read_port_table(tcp: bool, v6: bool, table: &mut Vec<u8>) -> Option<&[u8]> {
    let family = if v6 { AF_INET6 } else { AF_INET };
    for _ in 0..4 {
        let mut size = table.len() as u32;
        // SAFETY: the buffer is at least `size` bytes; the call reports the size it needs.
        let status = unsafe {
            if tcp {
                GetExtendedTcpTable(
                    table.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            } else {
                GetExtendedUdpTable(
                    table.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    family,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            }
        };
        match status {
            0 => return table.get(..size as usize),
            ERROR_INSUFFICIENT_BUFFER => table.resize(size.saturating_add(4096) as usize, 0),
            _ => return None,
        }
    }
    None
}

fn tcp_port_owner(origin: &Origin, buffer: &mut Vec<u8>) -> Option<u32> {
    let v6 = origin.local.is_ipv6();
    [v6, !v6].into_iter().find_map(|v6| {
        let table = read_port_table(true, v6, buffer)?;
        tcp_table_owner(table, v6, origin.local.port(), origin.remote_port)
    })
}

struct Shared {
    nat: Mutex<Nat>,
    rules: Mutex<Vec<DivertRule>>,
    /// UDP flows of covered sockets with the address their answers are injected with.
    udp: Mutex<udp::Flows<Address>>,
    link: Arc<Link>,
    generation: AtomicU64,
    counters: Mutex<HashMap<String, Arc<Counters>>>,
    logs: Mutex<Vec<(String, String)>>,
    ipv6: Mutex<super::Ipv6Health>,
}

impl Shared {
    fn log(&self, rule: &str, text: String) {
        let mut logs = self.logs.lock().unwrap();
        if logs.len() < MAX_PENDING_LOGS {
            let time = chrono::Local::now().format("%H:%M:%S");
            logs.push((rule.to_owned(), format!("{time} {text}")));
        }
    }
    fn counters(&self, rule: &str) -> Arc<Counters> {
        self.counters
            .lock()
            .unwrap()
            .entry(rule.to_owned())
            .or_default()
            .clone()
    }
}

/// How a rule's UDP is handled while its relay channel works; without it, the fallback.
fn policies(rules: &[DivertRule]) -> HashMap<String, (Policy, Policy)> {
    rules
        .iter()
        .map(|rule| {
            let fallback = if rule.direct && rule.proxy.is_none() {
                Policy::Direct
            } else {
                Policy::Block
            };
            let tunnel = if rule.udp {
                Policy::Tunnel { quic: rule.quic }
            } else {
                fallback
            };
            (rule.id.clone(), (tunnel, fallback))
        })
        .collect()
}

fn packets(api: Api, device: Arc<Device>, relay_port: u16, shared: Arc<Shared>) {
    let own = std::env::current_exe()
        .ok()
        .and_then(|path| path.into_os_string().into_string().ok())
        .unwrap_or_default();
    let mut matcher = Matcher::new(&own);
    let system = System {
        // SAFETY: returns the identifier of the calling process.
        session: session(unsafe { GetCurrentProcessId() }),
        parents: RefCell::new(None),
    };
    let mut generation = u64::MAX;
    let mut policy: HashMap<String, (Policy, Policy)> = HashMap::new();
    let mut quic_logged: HashSet<String> = HashSet::new();
    // Rules whose application goes around its tunnel right now, because the tunnel is down.
    let mut bypassing: HashSet<String> = HashSet::new();
    let mut udp_owners = UdpOwners::default();
    let mut port_table = vec![0u8; 4096];
    let mut udp_table = vec![0u8; 4096];
    let mut udp_snapshot = Snapshot::default();
    let mut buffer = vec![0u8; 40 + 0xffff];
    let mut purged = Instant::now();
    let mut failures = 0u32;
    loop {
        let mut length = 0u32;
        // SAFETY: an all-zero address is a valid value for the driver to overwrite.
        let mut address: Address = unsafe { std::mem::zeroed() };
        // SAFETY: the buffer and both out-pointers are valid for the duration of the call.
        let received = unsafe {
            (api.recv)(
                device.0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut length,
                &mut address,
            )
        };
        if received == 0 {
            failures += 1;
            if failures > 1000 {
                // The driver is gone; the process ends with the helper's main task.
                return;
            }
            continue;
        }
        failures = 0;
        let now = Instant::now();
        let current = shared.generation.load(Ordering::Acquire);
        if current != generation {
            generation = current;
            let rules = shared.rules.lock().unwrap();
            let before = matcher.rules.clone();
            policy = policies(&rules);
            bypassing = policy
                .iter()
                .filter(|(_, (_, fallback))| *fallback == Policy::Direct)
                .map(|(id, _)| id.clone())
                .collect();
            let all_bypass = rules.iter().all(|rule| bypassing.contains(&rule.id));
            if matcher.set_rules(&rules) {
                udp_owners.rules_changed(&|id| matcher.unchanged(&before, id), all_bypass);
            } else {
                udp_owners.set_all_bypass(all_bypass);
            }
            drop(rules);
        }
        let data = &mut buffer[..length as usize];
        let linked = shared.link.up();
        let verdict = {
            let mut nat = shared.nat.lock().unwrap();
            if now.duration_since(purged) > Duration::from_secs(10) {
                purged = now;
                nat.purge(now);
                udp_owners.purge(now);
                for id in shared.udp.lock().unwrap().purge(now) {
                    shared.link.close(id);
                }
            }
            handle(
                data,
                relay_port,
                &mut nat,
                now,
                &mut |protocol, origin| {
                    if matcher.rules.is_empty() {
                        return None;
                    }
                    if protocol == TCP {
                        let pid = tcp_port_owner(origin, &mut port_table)?;
                        return matcher.decide(pid, now, &system);
                    }
                    let mut local = origin.local;
                    if let SocketAddr::V6(addr) = &mut local
                        && addr.ip().is_unicast_link_local()
                    {
                        addr.set_scope_id(address.interface_index());
                    }
                    // The rule as it is; `handle` applies whether it bypasses its tunnel.
                    udp_owners.decide(local, now, &|rule| bypassing.contains(rule), || {
                        let pids = udp_snapshot.owners(now, local, |v6| {
                            read_port_table(false, v6, &mut udp_table).map(<[u8]>::to_vec)
                        })?;
                        Some(
                            pids.into_iter()
                                .filter_map(|pid| matcher.decide(pid, now, &system))
                                .collect(),
                        )
                    })
                },
                &|rule| match policy.get(rule) {
                    Some((tunnel @ Policy::Tunnel { .. }, _)) if linked => *tunnel,
                    Some((Policy::Tunnel { .. }, fallback)) => *fallback,
                    Some((other, _)) => *other,
                    None => Policy::Block,
                },
            )
        };
        match verdict {
            Verdict::Drop => continue,
            Verdict::Capture { rule } => {
                if let Some((local, remote, payload)) = udp::outbound(data) {
                    let flow = shared
                        .udp
                        .lock()
                        .unwrap()
                        .outbound(local, &rule, address, now);
                    if let Some(old) = flow.replaced {
                        shared.link.close(old);
                    }
                    if flow.opened {
                        shared.log(&rule, format!("UDP {remote} через туннель"));
                    }
                    shared
                        .link
                        .send(&rule, flow.id, flow.opened, remote, payload);
                }
                continue;
            }
            Verdict::Quic { rule } => {
                shared.link.dropped(&rule, DropReason::Quic);
                if quic_logged.insert(rule.clone()) {
                    shared.log(
                        &rule,
                        "QUIC (UDP 443) заблокирован: браузер перейдёт на TCP".into(),
                    );
                }
                continue;
            }
            Verdict::Fragment { rule } => {
                shared.link.dropped(&rule, DropReason::Size);
                shared.log(&rule, "Фрагментированная UDP-датаграмма отброшена".into());
                continue;
            }
            Verdict::Refuse { .. } => {
                if let Some(mut answer) = reset(data) {
                    let mut inbound = address;
                    inbound.flags &= !OUTBOUND;
                    let size = answer.len() as u32;
                    // SAFETY: the packet and its address are valid for the duration of the calls.
                    unsafe {
                        (api.checksums)(answer.as_mut_ptr().cast(), size, &mut inbound, 0);
                        (api.send)(
                            device.0,
                            answer.as_ptr().cast(),
                            size,
                            std::ptr::null_mut(),
                            &inbound,
                        )
                    };
                }
                continue;
            }
            Verdict::Pass | Verdict::Reflect => {}
        }
        if matches!(verdict, Verdict::Reflect) {
            address.flags &= !OUTBOUND;
            // SAFETY: the packet and its address are valid; the helper rewrites checksums in place.
            unsafe { (api.checksums)(data.as_mut_ptr().cast(), length, &mut address, 0) };
        }
        // SAFETY: the packet and its address are valid for the duration of the call.
        unsafe {
            (api.send)(
                device.0,
                data.as_ptr().cast(),
                length,
                std::ptr::null_mut(),
                &address,
            )
        };
    }
}

/// Injects answers from the relay as inbound packets to the application's socket.
async fn answers(
    api: Api,
    device: Arc<Device>,
    shared: Arc<Shared>,
    mut inbound: tokio::sync::mpsc::Receiver<Inbound>,
) {
    let ident = AtomicU16::new(rand::random());
    let mut refused: HashSet<String> = HashSet::new();
    while let Some(message) = inbound.recv().await {
        let (id, peer, data) = match message {
            Inbound::Datagram { id, peer, data } => (id, peer, data),
            Inbound::Closed { id } => {
                shared.udp.lock().unwrap().close(id);
                continue;
            }
            Inbound::Lost => {
                shared.udp.lock().unwrap().clear();
                continue;
            }
        };
        let Some((local, rule, mut address)) = shared
            .udp
            .lock()
            .unwrap()
            .inbound(id, Instant::now())
            .map(|(local, flow)| (local, flow.rule.clone(), flow.meta))
        else {
            continue;
        };
        let Some(mut packet) =
            udp::inbound(peer, local, &data, ident.fetch_add(1, Ordering::Relaxed))
        else {
            shared.link.dropped(&rule, DropReason::Size);
            continue;
        };
        address.flags &= !OUTBOUND;
        let length = packet.len() as u32;
        // SAFETY: the packet and its address are valid for the duration of both calls.
        let sent = unsafe {
            (api.checksums)(packet.as_mut_ptr().cast(), length, &mut address, 0);
            (api.send)(
                device.0,
                packet.as_ptr().cast(),
                length,
                std::ptr::null_mut(),
                &address,
            )
        };
        if sent == 0 {
            shared.link.dropped(&rule, DropReason::Size);
            // Once per rule: an answer the stack refused, most likely above the interface MTU.
            if refused.insert(rule.clone()) {
                // SAFETY: reads the calling thread's last error.
                let error = unsafe { GetLastError() };
                shared.log(
                    &rule,
                    format!(
                        "Ответ UDP {} байт не доставлен приложению (код {error})",
                        data.len()
                    ),
                );
            }
        } else {
            shared.link.injected(&rule, data.len());
        }
    }
}

fn netsh(arguments: &str) {
    let mut directory = [0u16; 260];
    // SAFETY: the buffer length matches the size passed to the call.
    let length = unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) };
    if length == 0 || length as usize >= directory.len() {
        return;
    }
    let netsh =
        PathBuf::from(String::from_utf16_lossy(&directory[..length as usize])).join("netsh.exe");
    let _ = std::process::Command::new(netsh)
        .raw_arg(arguments)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// The relay accepts reflected connections that look inbound, so the firewall must let them in.
fn firewall(port: Option<u16>) {
    netsh(&format!(
        "advfirewall firewall delete rule name={FIREWALL_RULE}"
    ));
    if let (Some(port), Ok(program)) = (port, std::env::current_exe())
        && let Some(program) = program.to_str().filter(|path| !path.contains('"'))
    {
        netsh(&format!(
            "advfirewall firewall add rule name={FIREWALL_RULE} dir=in action=allow \
             protocol=TCP localport={port} program=\"{program}\""
        ));
    }
}

async fn accept(listener: tokio::net::TcpListener, shared: Arc<Shared>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        // Only connections the packet loop reflected are known here; anything else is closed.
        let Some(flow) = shared
            .nat
            .lock()
            .unwrap()
            .get(peer.ip(), peer.port())
            .cloned()
        else {
            continue;
        };
        let rule = shared
            .rules
            .lock()
            .unwrap()
            .iter()
            .find(|rule| rule.id == flow.rule)
            .cloned();
        let destination = SocketAddr::new(peer.ip(), flow.remote_port);
        let shared = shared.clone();
        tokio::spawn(async move {
            let counters = shared.counters(&flow.rule);
            match rule {
                Some(DivertRule {
                    proxy: Some(proxy), ..
                }) => {
                    shared.log(&flow.rule, format!("{destination} через туннель"));
                    let target = Destination::Address(destination);
                    let opened = || {
                        if destination.is_ipv6() {
                            shared.ipv6.lock().unwrap().opened(proxy, Instant::now());
                        }
                    };
                    if let Err(error) =
                        crate::proxy::relay_reporting(stream, proxy, &target, &counters, opened)
                            .await
                        && error.kind() == std::io::ErrorKind::ConnectionRefused
                    {
                        shared.log(
                            &flow.rule,
                            format!("{destination}: туннель не открыл соединение"),
                        );
                        // Only the server's own refusal counts: an OS error means the local
                        // SOCKS port itself is gone, as while the tunnel reconnects.
                        if destination.is_ipv6()
                            && error.raw_os_error().is_none()
                            && shared.ipv6.lock().unwrap().failed(
                                proxy,
                                destination.ip(),
                                Instant::now(),
                            )
                        {
                            refuse_ipv6(&shared, proxy, &flow.rule);
                        }
                    }
                }
                Some(DivertRule { direct: true, .. }) => {
                    shared.log(
                        &flow.rule,
                        format!("{destination} напрямую: туннель не работает"),
                    );
                    let _ = crate::proxy::direct(stream, destination, &counters).await;
                }
                _ => shared.log(
                    &flow.rule,
                    format!("{destination} отклонено: туннель не работает"),
                ),
            }
        });
    }
}

/// The server behind `proxy` could not open an IPv6 connection: usually it has no IPv6 route.
/// New IPv6 connections of every rule on that tunnel are refused for a while, so applications
/// fall back to IPv4 instead of seeing a connection that opens and drops.
fn refuse_ipv6(shared: &Shared, proxy: SocketAddr, rule: &str) {
    let rules: Vec<String> = shared
        .rules
        .lock()
        .unwrap()
        .iter()
        .filter(|rule| rule.proxy == Some(proxy))
        .map(|rule| rule.id.clone())
        .collect();
    let refused = shared
        .nat
        .lock()
        .unwrap()
        .refuse_ipv6(rules.iter().map(String::as_str), Instant::now());
    if !refused {
        return;
    }
    shared.log(
        rule,
        format!(
            "Сервер туннеля не открывает IPv6-соединения: {} мин новые IPv6-соединения \
             отклоняются сразу, приложения переходят на IPv4",
            super::IPV6_REFUSAL.as_secs() / 60
        ),
    );
}

fn listener(address: &str) -> Result<tokio::net::TcpListener> {
    let listener = std::net::TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(tokio::net::TcpListener::from_std(listener)?)
}

async fn serve(store: Store) -> Result<()> {
    let client = Client::new(&store);
    let shared = Arc::new(Shared {
        nat: Mutex::new(Nat::default()),
        rules: Mutex::new(Vec::new()),
        udp: Mutex::new(udp::Flows::default()),
        link: Arc::new(Link::default()),
        generation: AtomicU64::new(0),
        counters: Mutex::new(HashMap::new()),
        logs: Mutex::new(Vec::new()),
        ipv6: Mutex::new(super::Ipv6Health::default()),
    });
    let start = || -> Result<u16> {
        let api = load()?;
        let relay = listener("0.0.0.0:0")
            .context("Не удалось открыть порт для перехваченных соединений.")?;
        let port = relay.local_addr()?.port();
        let device = Arc::new(open(&api)?);
        firewall(Some(port));
        let (inbound_send, inbound) = tokio::sync::mpsc::channel(INBOUND_QUEUE);
        let attach = client.clone();
        tokio::spawn(shared.link.clone().run(
            move || {
                let client = attach.clone();
                async move { Ok(tokio::io::split(client.attach_udp().await?)) }
            },
            inbound_send,
        ));
        tokio::spawn(answers(api, device.clone(), shared.clone(), inbound));
        tokio::spawn(accept(relay, shared.clone()));
        // Systems without IPv6 simply have no such traffic to reflect.
        if let Ok(relay) = listener(&format!("[::]:{port}")) {
            tokio::spawn(accept(relay, shared.clone()));
        }
        let shared = shared.clone();
        std::thread::Builder::new()
            .name("divert".into())
            .spawn(move || packets(api, device, port, shared))?;
        Ok(port)
    };
    if let Err(error) = start() {
        let report = DivertReport {
            version: env!("CARGO_PKG_VERSION").into(),
            error: error.to_string(),
            ..Default::default()
        };
        let _ = client.request("divert_sync", json!(report)).await;
        return Err(error);
    }
    let mut failures = 0;
    let mut pending: Vec<(String, String)> = Vec::new();
    // A stopped КРОТ is noticed within seconds, so an update never waits long for the helper.
    while failures < 3 {
        pending.append(&mut shared.logs.lock().unwrap());
        let stats = shared
            .counters
            .lock()
            .unwrap()
            .iter()
            .map(|(rule, counters)| {
                (
                    rule.clone(),
                    DivertStats {
                        connections: counters.connections.load(Ordering::Relaxed),
                        total: counters.total.load(Ordering::Relaxed),
                        sent: counters.sent.load(Ordering::Relaxed),
                        received: counters.received.load(Ordering::Relaxed),
                    },
                )
            })
            .collect();
        let report = DivertReport {
            version: env!("CARGO_PKG_VERSION").into(),
            stats,
            logs: pending.clone(),
            error: String::new(),
            udp: shared.link.stats(),
        };
        let reply = client.request("divert_sync", json!(report)).await.ok();
        // Another version of КРОТ took over: its own helper has to be started instead.
        if reply
            .as_ref()
            .is_some_and(|reply| reply.get("stop").and_then(|stop| stop.as_bool()) == Some(true))
        {
            break;
        }
        let rules = reply
            .and_then(|reply| reply.get("rules").cloned())
            .and_then(|rules| serde_json::from_value::<Vec<DivertRule>>(rules).ok());
        match rules {
            Some(rules) => {
                failures = 0;
                pending.clear();
                let mut current = shared.rules.lock().unwrap();
                if *current != rules {
                    // A refusal holds only while the rule stays on the same running tunnel:
                    // a stopped tunnel lets the application go direct, a new one may have IPv6.
                    shared.nat.lock().unwrap().keep_ipv6_refusals(|id| {
                        let proxy = |rules: &[DivertRule]| {
                            rules
                                .iter()
                                .find(|rule| rule.id == id)
                                .and_then(|rule| rule.proxy)
                        };
                        proxy(&rules).is_some_and(|next| proxy(&current) == Some(next))
                    });
                    *current = rules;
                    shared.generation.fetch_add(1, Ordering::Release);
                }
            }
            None => failures += 1,
        }
        tokio::time::sleep(SYNC_TIME).await;
    }
    firewall(None);
    Ok(())
}

pub(super) fn run(store: Store) -> Result<()> {
    // One helper per configuration: two would fight over the same packets.
    let _lease = Store::new(store.sidecar(".divert"))?.lock()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let result = runtime.block_on(serve(store));
    // The packet thread blocks in the driver; ending the process closes its handle.
    std::process::exit(if result.is_ok() { 0 } else { 1 })
}

pub(super) fn launch(config: &Path) -> Result<()> {
    let executable = std::env::current_exe()?;
    let config = config
        .to_str()
        .filter(|path| !path.contains('"'))
        .context("Путь к конфигурации нельзя передать помощнику.")?;
    let (verb, file, parameters) = (
        wide("runas".as_ref()),
        wide(executable.as_os_str()),
        wide(format!("--config \"{config}\" divert").as_ref()),
    );
    // SAFETY: an all-zero structure is the documented starting point; every string is
    // NUL-terminated and outlives the call.
    let started = unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = parameters.as_ptr();
        info.nShow = SW_HIDE;
        ShellExecuteExW(&mut info) != 0
    };
    ensure!(
        started,
        "Права администратора не предоставлены: перехват не запущен."
    );
    Ok(())
}
