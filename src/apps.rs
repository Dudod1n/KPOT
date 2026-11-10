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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

/// Executables are matched without regard to letter case, as Windows does.
pub fn path_key(path: &str) -> String {
    path.trim().to_lowercase()
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

/// Empty when this build can intercept application traffic, otherwise the reason it cannot.
pub fn unavailable() -> &'static str {
    if cfg!(windows) {
        "Перехват трафика приложений ещё не включён в эту сборку. Правила можно подготовить заранее."
    } else {
        "Туннелирование приложений пока работает только в Windows. Правила можно подготовить заранее."
    }
}

/// `tunnel_states` holds the SSH state of every tunnel that has one.
pub fn state(
    rule: &AppRule,
    tunnels: &[Tunnel],
    tunnel_states: &HashMap<String, String>,
    unavailable: &str,
) -> &'static str {
    let tunnel = tunnels
        .iter()
        .find(|tunnel| tunnel.id == rule.tunnel_id && tunnel.kind == "D");
    match tunnel {
        _ if !unavailable.is_empty() => "unavailable",
        None => "orphan",
        Some(_) if !rule.enabled => "stopped",
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
    fn state_follows_availability_tunnel_and_the_chosen_fallback() {
        let tunnels = [tunnel("socks", "D"), tunnel("local", "L")];
        let running = HashMap::from([("socks".to_owned(), "running".to_owned())]);
        let idle = HashMap::new();
        let mut enabled = rule("a", "/bin/app", "socks");
        enabled.enabled = true;
        assert_eq!(state(&enabled, &tunnels, &running, ""), "running");
        assert_eq!(state(&enabled, &tunnels, &idle, ""), "blocked");
        assert_eq!(state(&enabled, &tunnels, &running, "нет"), "unavailable");
        enabled.on_tunnel_down = "direct".into();
        assert_eq!(state(&enabled, &tunnels, &idle, ""), "direct");
        enabled.enabled = false;
        assert_eq!(state(&enabled, &tunnels, &running, ""), "stopped");
        // A deleted tunnel and a tunnel that stopped being SOCKS5 both orphan the rule.
        assert_eq!(
            state(&rule("b", "/bin/b", "gone"), &tunnels, &running, ""),
            "orphan"
        );
        assert_eq!(
            state(&rule("c", "/bin/c", "local"), &tunnels, &running, ""),
            "orphan"
        );
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
