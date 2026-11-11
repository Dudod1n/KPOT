//! Per-application rules: which executable goes through which SOCKS5 tunnel.
//! Stored next to the main configuration so older builds keep reading it.
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    path::PathBuf,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::{Store, Tunnel, atomic_json};

const MAX_APPS_BYTES: usize = 2 * 1024 * 1024;
const MAX_RULES: usize = 256;
const MAX_NAME: usize = 80;
const MAX_PATH: usize = 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AppRule {
    pub id: String,
    pub name: String,
    /// Full path of the executable whose connections are intercepted.
    pub path: String,
    pub tunnel_id: String,
    pub enabled: bool,
    /// `block` keeps the application offline without its tunnel, `direct` lets it bypass.
    pub on_tunnel_down: String,
    pub children: bool,
}

impl Default for AppRule {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().simple().to_string(),
            name: String::new(),
            path: String::new(),
            tunnel_id: String::new(),
            enabled: false,
            on_tunnel_down: "block".into(),
            children: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Apps {
    pub version: u32,
    pub rules: Vec<AppRule>,
}

impl Default for Apps {
    fn default() -> Self {
        Self {
            version: 1,
            rules: Vec::new(),
        }
    }
}

impl Apps {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "Версия файла приложений {} не поддерживается.",
            self.version
        );
        validate_rules(&self.rules)
    }
}

/// What the dispatcher shows for one rule; counters are filled by the interceptor.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppRuntime {
    pub state: String,
    pub connections: u64,
    pub total: u64,
    pub sent: u64,
    pub received: u64,
    pub logs: Vec<String>,
}

/// One enabled rule as the elevated helper needs it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DivertRule {
    pub id: String,
    pub path: String,
    pub children: bool,
    /// Without a tunnel the application connects directly instead of being cut off.
    pub direct: bool,
    /// SOCKS5 port of the tunnel while it is running.
    pub proxy: Option<std::net::SocketAddr>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DivertStats {
    pub connections: u64,
    pub total: u64,
    pub sent: u64,
    pub received: u64,
}

/// What the helper tells the background process about once a second.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DivertReport {
    /// The helper's own version: after an update the old helper must not stay attached.
    pub version: String,
    pub stats: HashMap<String, DivertStats>,
    /// New journal lines as (rule, text).
    pub logs: Vec<(String, String)>,
    /// Set when the helper could not start and is about to exit.
    pub error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interceptor {
    /// This build cannot intercept traffic on this system.
    Unavailable,
    /// The elevated helper is not running: traffic is not touched.
    Detached,
    Attached,
}

/// The loopback address of a tunnel's SOCKS5 port, if its bind address allows one.
pub fn proxy_address(tunnel: &Tunnel) -> Option<std::net::SocketAddr> {
    let bind = tunnel.bind.trim();
    let ip = if bind.eq_ignore_ascii_case("localhost") {
        std::net::Ipv4Addr::LOCALHOST.into()
    } else {
        match bind
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .ok()?
        {
            std::net::IpAddr::V4(ip) if ip.is_unspecified() => std::net::Ipv4Addr::LOCALHOST.into(),
            std::net::IpAddr::V6(ip) if ip.is_unspecified() => std::net::Ipv6Addr::LOCALHOST.into(),
            ip => ip,
        }
    };
    Some(std::net::SocketAddr::new(ip, tunnel.port))
}

/// Rules for the helper: every enabled rule, with a proxy only while its tunnel runs.
pub fn divert_rules(
    rules: &[AppRule],
    tunnels: &[Tunnel],
    tunnel_states: &HashMap<String, String>,
) -> Vec<DivertRule> {
    rules
        .iter()
        .filter(|rule| rule.enabled)
        .map(|rule| DivertRule {
            id: rule.id.clone(),
            path: rule.path.clone(),
            children: rule.children,
            direct: rule.on_tunnel_down == "direct",
            proxy: tunnels
                .iter()
                .find(|tunnel| tunnel.id == rule.tunnel_id && tunnel.kind == "D")
                .filter(|tunnel| {
                    tunnel_states
                        .get(&tunnel.id)
                        .is_some_and(|state| state == "running")
                })
                .and_then(proxy_address),
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

/// The identity of an executable for matching: letter case is ignored, as Windows does,
/// and so is the version that self-updating applications keep in a directory name.
/// Store packages live in `WindowsApps\Name_Version_Arch_Resource_Publisher`, Squirrel
/// applications in `app-Version`; both move to a new directory with every update.
pub fn path_key(path: &str) -> String {
    let path = path.trim().to_lowercase();
    let mut packaged = false;
    let segments: Vec<String> = path
        .split('\\')
        .map(|segment| {
            let parts: Vec<&str> = segment.split('_').collect();
            let key = if std::mem::take(&mut packaged) && parts.len() == 5 {
                format!("{}_*_{}", parts[0], parts[4])
            } else if segment.strip_prefix("app-").is_some_and(|version| {
                version.starts_with(|first: char| first.is_ascii_digit())
                    && version
                        .chars()
                        .all(|symbol| symbol.is_ascii_digit() || symbol == '.')
            }) {
                "app-*".into()
            } else {
                segment.to_owned()
            };
            packaged = segment == "windowsapps";
            key
        })
        .collect();
    segments.join("\\")
}

fn absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with('/')
        || path.starts_with("\\\\")
        || (bytes.len() > 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
}

fn validate_shape(rule: &AppRule) -> Result<()> {
    ensure!(
        !rule.id.is_empty()
            && rule.id.len() <= 64
            && rule
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "Некорректный идентификатор правила."
    );
    let name = rule.name.trim();
    ensure!(!name.is_empty(), "Укажите название правила.");
    ensure!(
        name.chars().count() <= MAX_NAME && !name.chars().any(char::is_control),
        "Название правила: не больше {MAX_NAME} символов, без управляющих символов."
    );
    let path = rule.path.trim();
    ensure!(!path.is_empty(), "Укажите путь к исполняемому файлу.");
    ensure!(
        path.len() <= MAX_PATH && !path.chars().any(char::is_control),
        "Путь к исполняемому файлу слишком длинный или содержит управляющие символы."
    );
    ensure!(absolute(path), "Нужен полный путь к исполняемому файлу.");
    ensure!(
        matches!(rule.on_tunnel_down.as_str(), "block" | "direct"),
        "Поведение без туннеля: block или direct."
    );
    ensure!(
        rule.tunnel_id.len() <= 64 && !rule.tunnel_id.chars().any(char::is_control),
        "Некорректный идентификатор туннеля."
    );
    Ok(())
}

/// Structural checks only: a rule may outlive its tunnel and then waits for a new one.
pub fn validate_rules(rules: &[AppRule]) -> Result<()> {
    ensure!(
        rules.len() <= MAX_RULES,
        "Правил приложений не может быть больше {MAX_RULES}."
    );
    let (mut ids, mut paths) = (HashSet::new(), HashSet::new());
    for rule in rules {
        validate_shape(rule)?;
        ensure!(
            ids.insert(rule.id.as_str()),
            "Идентификаторы правил повторяются."
        );
        ensure!(
            paths.insert(path_key(&rule.path)),
            "Для приложения «{}» уже есть правило.",
            rule.name.trim()
        );
    }
    Ok(())
}

/// Checks a rule the user is saving: its tunnel must exist and be a SOCKS5 one.
pub fn validate_rule(rule: &AppRule, others: &[AppRule], tunnels: &[Tunnel]) -> Result<()> {
    validate_shape(rule)?;
    ensure!(
        !others
            .iter()
            .any(|other| other.id != rule.id && path_key(&other.path) == path_key(&rule.path)),
        "Для этого приложения уже есть правило."
    );
    let tunnel = tunnels
        .iter()
        .find(|tunnel| tunnel.id == rule.tunnel_id)
        .context("Выберите туннель типа D.")?;
    ensure!(
        tunnel.kind == "D",
        "Приложения можно направлять только через туннель типа D (SOCKS5)."
    );
    Ok(())
}

pub fn path(store: &Store) -> PathBuf {
    store.sidecar(".apps.json")
}

pub fn load(store: &Store) -> Result<Apps> {
    let path = path(store);
    let stream = match File::open(&path) {
        Ok(stream) => stream,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Apps::default()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Не удалось открыть правила приложений {}", path.display())
            });
        }
    };
    let mut raw = Vec::new();
    stream
        .take((MAX_APPS_BYTES + 1) as u64)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= MAX_APPS_BYTES,
        "Файл правил приложений {} превышает 2 МиБ.",
        path.display()
    );
    let mut apps: Apps = serde_json::from_slice(&raw)
        .with_context(|| format!("Ошибка в правилах приложений {}", path.display()))?;
    apps.validate()
        .with_context(|| format!("Ошибка в правилах приложений {}", path.display()))?;
    normalize(&mut apps.rules);
    Ok(apps)
}

pub fn save(store: &Store, apps: &Apps) -> Result<()> {
    apps.validate()?;
    let mut normalized = apps.clone();
    normalize(&mut normalized.rules);
    atomic_json(&path(store), &normalized, Some(MAX_APPS_BYTES))
}

pub fn normalize(rules: &mut [AppRule]) {
    for rule in rules {
        rule.name = rule.name.trim().into();
        rule.path = rule.path.trim().into();
    }
}

/// Why this build cannot intercept application traffic; empty where it can.
pub fn unavailable() -> &'static str {
    if cfg!(windows) {
        ""
    } else {
        "Туннелирование приложений пока работает только в Windows. Правила можно подготовить заранее."
    }
}

/// `tunnel_states` holds the SSH state of every tunnel that has one.
pub fn state(
    rule: &AppRule,
    tunnels: &[Tunnel],
    tunnel_states: &HashMap<String, String>,
    interceptor: Interceptor,
) -> &'static str {
    let tunnel = tunnels
        .iter()
        .find(|tunnel| tunnel.id == rule.tunnel_id && tunnel.kind == "D");
    match tunnel {
        _ if interceptor == Interceptor::Unavailable => "unavailable",
        None => "orphan",
        Some(_) if !rule.enabled => "stopped",
        Some(_) if interceptor == Interceptor::Detached => "elevation",
        Some(tunnel)
            if tunnel_states
                .get(&tunnel.id)
                .is_some_and(|state| state == "running") =>
        {
            "running"
        }
        Some(_) if rule.on_tunnel_down == "direct" => "direct",
        Some(_) => "blocked",
    }
}

/// Running processes with a readable executable path, sorted by name.
pub fn processes() -> Vec<Process> {
    let mut list = list_processes();
    list.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then(a.pid.cmp(&b.pid))
    });
    list
}

#[cfg(target_os = "linux")]
fn list_processes() -> Vec<Process> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let path = std::fs::read_link(entry.path().join("exe")).ok()?;
            let name = path.file_name()?.to_str()?.to_owned();
            Some(Process {
                pid,
                name,
                path: path.into_os_string().into_string().ok()?,
            })
        })
        .collect()
}

#[cfg(windows)]
fn list_processes() -> Vec<Process> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
            },
        },
    };
    let mut list = Vec::new();
    // SAFETY: every handle is checked before use and closed exactly once; the entry and
    // the path buffer are sized as the API requires and outlive the calls that fill them.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return list;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry) != 0;
        while more {
            let pid = entry.th32ProcessID;
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if !process.is_null() {
                let mut buffer = [0u16; 1024];
                let mut length = buffer.len() as u32;
                if QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) != 0 {
                    let path = String::from_utf16_lossy(&buffer[..length as usize]);
                    let name = path.rsplit(['\\', '/']).next().unwrap_or(&path).to_owned();
                    list.push(Process { pid, name, path });
                }
                CloseHandle(process);
            }
            more = Process32NextW(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
    }
    list
}

#[cfg(not(any(target_os = "linux", windows)))]
fn list_processes() -> Vec<Process> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel(id: &str, kind: &str) -> Tunnel {
        Tunnel {
            id: id.into(),
            name: id.into(),
            kind: kind.into(),
            ..Default::default()
        }
    }
    fn rule(id: &str, path: &str, tunnel_id: &str) -> AppRule {
        AppRule {
            id: id.into(),
            name: format!("rule {id}"),
            path: path.into(),
            tunnel_id: tunnel_id.into(),
            ..Default::default()
        }
    }

    #[test]
    fn saved_rule_needs_an_existing_socks_tunnel_and_a_unique_executable() {
        let tunnels = [tunnel("local", "L"), tunnel("socks", "D")];
        let saved = [rule("a", r"C:\Tools\curl.exe", "socks")];
        assert!(validate_rule(&rule("b", "/usr/bin/curl", "socks"), &saved, &tunnels).is_ok());
        for (candidate, expected) in [
            (rule("b", r"C:\Tools\app.exe", "local"), "типа D"),
            (rule("b", r"C:\Tools\app.exe", "gone"), "Выберите туннель"),
            (rule("b", r"c:\tools\CURL.exe", "socks"), "уже есть правило"),
            (rule("b", "curl.exe", "socks"), "полный путь"),
            (rule("b", "", "socks"), "Укажите путь"),
        ] {
            let error = validate_rule(&candidate, &saved, &tunnels)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
        }
        // Editing a rule must not collide with itself.
        assert!(validate_rule(&saved[0], &saved, &tunnels).is_ok());
        let mut unnamed = rule("c", "/bin/app", "socks");
        unnamed.name = "  ".into();
        assert!(validate_rule(&unnamed, &saved, &tunnels).is_err());
    }

    #[test]
    fn updated_store_and_squirrel_applications_keep_matching_their_rule() {
        let store = |version: &str| {
            format!(
                r"C:\Program Files\WindowsApps\Claude_{version}_x64__pzs8sxrjxfjjc\app\claude.exe"
            )
        };
        assert_eq!(
            path_key(&store("4.23118.1.0")),
            path_key(&store("4.23200.0.0"))
        );
        assert_eq!(
            path_key(r"C:\Users\u\AppData\Local\Discord\app-1.0.9163\Discord.exe"),
            path_key(r"c:\users\u\appdata\local\discord\APP-1.0.9170\discord.exe")
        );
        // Another package, publisher or file is still another application.
        for other in [
            r"C:\Program Files\WindowsApps\Other_4.23118.1.0_x64__pzs8sxrjxfjjc\app\claude.exe",
            r"C:\Program Files\WindowsApps\Claude_4.23118.1.0_x64__0000000000000\app\claude.exe",
            r"C:\Program Files\WindowsApps\Claude_4.23118.1.0_x64__pzs8sxrjxfjjc\app\other.exe",
        ] {
            assert_ne!(path_key(other), path_key(&store("4.23118.1.0")), "{other}");
        }
        // Ordinary directories are compared as they are, underscores and dashes included.
        for (left, right) in [
            (r"C:\Tools\a_1_b_c_d\x.exe", r"C:\Tools\a_2_b_c_d\x.exe"),
            (r"C:\Tools\app-beta\x.exe", r"C:\Tools\app-gamma\x.exe"),
            (r"C:\Tools\app-1.0\x.exe", r"C:\Tools\app-1.0b\x.exe"),
            ("/opt/app_1/x", "/opt/app_2/x"),
        ] {
            assert_ne!(path_key(left), path_key(right), "{left}");
        }
        let saved = [rule("a", &store("4.23118.1.0"), "socks")];
        let error = validate_rule(
            &rule("b", &store("4.23200.0.0"), "socks"),
            &saved,
            &[tunnel("socks", "D")],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("уже есть правило"), "{error}");
    }

    #[test]
    fn state_follows_the_interceptor_the_tunnel_and_the_chosen_fallback() {
        use Interceptor::{Attached, Detached, Unavailable};
        let tunnels = [tunnel("socks", "D"), tunnel("local", "L")];
        let running = HashMap::from([("socks".to_owned(), "running".to_owned())]);
        let idle = HashMap::new();
        let mut enabled = rule("a", "/bin/app", "socks");
        enabled.enabled = true;
        assert_eq!(state(&enabled, &tunnels, &running, Attached), "running");
        assert_eq!(state(&enabled, &tunnels, &idle, Attached), "blocked");
        assert_eq!(state(&enabled, &tunnels, &running, Detached), "elevation");
        assert_eq!(
            state(&enabled, &tunnels, &running, Unavailable),
            "unavailable"
        );
        enabled.on_tunnel_down = "direct".into();
        assert_eq!(state(&enabled, &tunnels, &idle, Attached), "direct");
        enabled.enabled = false;
        assert_eq!(state(&enabled, &tunnels, &running, Detached), "stopped");
        // A deleted tunnel and a tunnel that stopped being SOCKS5 both orphan the rule.
        for orphan in [rule("b", "/bin/b", "gone"), rule("c", "/bin/c", "local")] {
            assert_eq!(state(&orphan, &tunnels, &running, Attached), "orphan");
        }
    }

    #[test]
    fn helper_gets_enabled_rules_and_a_proxy_only_while_the_tunnel_runs() {
        let mut socks = tunnel("socks", "D");
        socks.bind = "0.0.0.0".into();
        socks.port = 1080;
        let tunnels = [socks, tunnel("local", "L")];
        let running = HashMap::from([("socks".to_owned(), "running".to_owned())]);
        let mut on = rule("on", "/bin/on", "socks");
        on.enabled = true;
        on.on_tunnel_down = "direct".into();
        let mut orphan = rule("orphan", "/bin/orphan", "local");
        orphan.enabled = true;
        let rules = [on, orphan, rule("off", "/bin/off", "socks")];
        let sent = divert_rules(&rules, &tunnels, &running);
        assert_eq!(sent.len(), 2, "disabled rules are not sent");
        assert_eq!(sent[0].proxy, Some("127.0.0.1:1080".parse().unwrap()));
        assert!(sent[0].direct && sent[0].children);
        // An orphaned rule stays so that its application is cut off, not released.
        assert_eq!((sent[1].proxy, sent[1].direct), (None, false));
        assert_eq!(
            divert_rules(&rules, &tunnels, &HashMap::new())[0].proxy,
            None
        );
        for (bind, expected) in [
            ("localhost", Some("127.0.0.1:1080")),
            ("[::]", Some("[::1]:1080")),
            ("192.168.1.5", Some("192.168.1.5:1080")),
            ("proxy.lan", None),
        ] {
            let mut socks = tunnel("socks", "D");
            socks.bind = bind.into();
            socks.port = 1080;
            assert_eq!(
                proxy_address(&socks),
                expected.map(|address| address.parse().unwrap()),
                "{bind}"
            );
        }
    }

    #[test]
    fn rules_live_in_a_sidecar_and_a_broken_file_is_reported_not_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path().join("tunnels.json")).unwrap();
        assert_eq!(load(&store).unwrap(), Apps::default());
        let mut apps = Apps::default();
        apps.rules.push(rule("a", "  /usr/bin/curl ", "socks"));
        save(&store, &apps).unwrap();
        assert!(!store.path.exists(), "the main configuration is untouched");
        assert_eq!(load(&store).unwrap().rules[0].path, "/usr/bin/curl");

        apps.rules.push(rule("b", "/USR/bin/CURL", "socks"));
        assert!(save(&store, &apps).is_err());
        assert_eq!(load(&store).unwrap().rules.len(), 1);

        std::fs::write(path(&store), b"{\"version\":1,\"rules\":[],\"extra\":1}").unwrap();
        assert!(load(&store).is_err());
        std::fs::write(path(&store), b"{\"version\":2,\"rules\":[]}").unwrap();
        assert!(load(&store).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_list_contains_this_test_with_its_executable_path() {
        let current = std::env::current_exe().unwrap();
        let found = processes()
            .into_iter()
            .find(|process| process.pid == std::process::id())
            .expect("the test process is listed");
        assert_eq!(std::path::Path::new(&found.path), current);
        assert_eq!(
            Some(found.name.as_str()),
            current.file_name().unwrap().to_str()
        );
    }
}
