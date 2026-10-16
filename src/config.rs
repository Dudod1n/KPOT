use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::Ipv6Addr,
    path::{Component, Path, PathBuf},
};
use unicode_casefold::UnicodeCaseFold;
use unicode_general_category::get_general_category;

pub const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: String,
    pub key: String,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            user: String::new(),
            auth: "agent".into(),
            key: "~/.ssh/id_ed25519".into(),
        }
    }
}

impl Endpoint {
    pub fn address(&self) -> String {
        format!("{}@{}:{}", self.user, display_host(&self.host), self.port)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub server: Endpoint,
    pub bind: String,
    pub port: u16,
    pub target: String,
    pub target_port: u16,
    pub reconnect: bool,
    pub jumps_enabled: bool,
    pub jumps: Vec<Endpoint>,
    pub enabled: bool,
}

impl Default for Tunnel {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().simple().to_string(),
            name: String::new(),
            kind: "L".into(),
            server: Endpoint::default(),
            bind: "127.0.0.1".into(),
            port: 8080,
            target: String::new(),
            target_port: 80,
            reconnect: true,
            jumps_enabled: false,
            jumps: Vec::new(),
            enabled: false,
        }
    }
}

impl Tunnel {
    pub fn route(&self) -> String {
        let listen = format!("{}:{}", display_host(&self.bind), self.port);
        if self.kind == "D" {
            format!("SOCKS5 · {listen}")
        } else {
            format!(
                "{} · {listen} → {}:{}",
                self.kind,
                display_host(&self.target),
                self.target_port
            )
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub theme: String,
    pub motion: bool,
    pub splash: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
            motion: true,
            splash: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub settings: Settings,
    pub tunnels: Vec<Tunnel>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            settings: Settings::default(),
            tunnels: Vec::new(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "Поддерживается только версия конфигурации 1."
        );
        ensure!(
            matches!(self.settings.theme.as_str(), "dark" | "light" | "system"),
            "Неизвестная тема."
        );
        let mut ids = HashSet::new();
        for tunnel in &self.tunnels {
            validate_tunnel(tunnel, &self.tunnels)?;
            ensure!(
                ids.insert(&tunnel.id),
                "В конфигурации повторяется ID туннеля."
            );
        }
        Ok(())
    }

    fn normalize(&mut self) {
        for tunnel in &mut self.tunnels {
            tunnel.server.host = unbracket(&tunnel.server.host).to_owned();
            tunnel.bind = unbracket(&tunnel.bind).to_owned();
            if tunnel.kind != "D" {
                tunnel.target = unbracket(&tunnel.target).to_owned();
            }
            for hop in &mut tunnel.jumps {
                hop.host = unbracket(&hop.host).to_owned();
            }
        }
    }
}

fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(host)
}

fn display_host(host: &str) -> String {
    let host = unbracket(host);
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.into()
    }
}

fn text(value: &str, label: &str, required: bool) -> Result<()> {
    ensure!(
        !required || !value.trim().is_empty(),
        "{label}: укажите значение."
    );
    ensure!(
        !value
            .chars()
            .any(|c| get_general_category(c).abbreviation().starts_with('C')),
        "{label}: управляющие символы недопустимы."
    );
    ensure!(
        value.chars().count() <= 4096,
        "{label}: слишком длинное значение."
    );
    Ok(())
}

fn host(value: &str, label: &str) -> Result<()> {
    text(value, label, true)?;
    ensure!(
        !value
            .chars()
            .any(|c| c.is_whitespace() || "/\\@?#".contains(c)),
        "{label}: укажите имя узла или IP-адрес без пробелов."
    );
    let value = unbracket(value);
    ensure!(!value.is_empty(), "{label}: укажите непустой адрес.");
    if value.contains(':') {
        // Preserve IPv6 scope IDs for DNS and socket resolution.
        let address = value.split_once('%').map_or(value, |(address, _)| address);
        ensure!(
            address.parse::<Ipv6Addr>().is_ok()
                && (!value.contains('%') || value.split('%').count() == 2 && !value.ends_with('%')),
            "{label}: некорректный IPv6-адрес."
        );
    } else {
        ensure!(!value.contains(['[', ']']), "{label}: некорректный адрес.");
    }
    Ok(())
}

fn endpoint(value: &Endpoint, label: &str, required: bool) -> Result<()> {
    text(&value.host, &format!("{label}, адрес"), required)?;
    if !value.host.is_empty() {
        host(&value.host, &format!("{label}, адрес"))?;
    }
    text(&value.user, &format!("{label}, пользователь"), required)?;
    text(
        &value.key,
        &format!("{label}, файл ключа"),
        required && value.auth == "key",
    )?;
    ensure!(
        value.port > 0,
        "{label}: порт должен быть целым числом от 1 до 65535."
    );
    ensure!(
        matches!(value.auth.as_str(), "agent" | "key" | "password"),
        "{label}: неизвестный способ входа."
    );
    Ok(())
}

fn host_identity(value: &Endpoint) -> (String, u16) {
    (
        unbracket(&value.host)
            .trim_end_matches('.')
            .case_fold()
            .collect(),
        value.port,
    )
}

pub fn validate_tunnel(tunnel: &Tunnel, others: &[Tunnel]) -> Result<()> {
    text(&tunnel.id, "ID туннеля", true)?;
    text(&tunnel.name, "Имя туннеля", true)?;
    ensure!(
        tunnel.name.chars().count() <= 32,
        "Имя туннеля должно быть не длиннее 32 символов."
    );
    let name: String = tunnel.name.trim().case_fold().collect();
    for other in others {
        text(&other.name, "Имя туннеля", true)?;
        ensure!(
            other.id == tunnel.id || other.name.trim().case_fold().collect::<String>() != name,
            "Туннель с таким именем уже существует."
        );
    }
    ensure!(
        matches!(tunnel.kind.as_str(), "L" | "R" | "D"),
        "Тип туннеля должен быть L, R или D."
    );
    endpoint(&tunnel.server, "SSH-сервер", true)?;
    host(&tunnel.bind, "Адрес прослушивания")?;
    ensure!(
        tunnel.port > 0,
        "Порт прослушивания должен быть от 1 до 65535."
    );
    if tunnel.kind == "D" {
        text(&tunnel.target, "Адрес назначения", false)?;
    } else {
        host(&tunnel.target, "Адрес назначения")?;
    }
    ensure!(
        tunnel.target_port > 0,
        "Порт назначения должен быть от 1 до 65535."
    );
    ensure!(
        !tunnel.jumps_enabled || !tunnel.jumps.is_empty(),
        "Добавьте jump-хост или отключите цепочку."
    );
    let mut seen = HashSet::from([host_identity(&tunnel.server)]);
    for (index, hop) in tunnel.jumps.iter().enumerate() {
        endpoint(
            hop,
            &format!("Jump host {}", index + 1),
            tunnel.jumps_enabled,
        )?;
        if tunnel.jumps_enabled {
            ensure!(
                seen.insert(host_identity(hop)),
                "Jump host {} повторяет другой узел цепочки.",
                index + 1
            );
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct Store {
    pub path: PathBuf,
}

impl Store {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let path = if path == Path::new("~") {
            home_dir()
        } else if let Ok(suffix) = path.strip_prefix("~/") {
            home_dir().join(suffix)
        } else {
            path.to_path_buf()
        };
        let absolute = if path.is_absolute() {
            path
        } else {
            std::path::absolute(path)?
        };
        Ok(Self {
            path: resolve_path(&absolute, 0)?,
        })
    }

    pub fn load(&self) -> Result<Config> {
        let stream = match File::open(&self.path) {
            Ok(stream) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Config::default());
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Не удалось открыть конфигурацию {}", self.path.display())
                });
            }
        };
        let mut raw = Vec::new();
        stream
            .take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut raw)?;
        ensure!(
            raw.len() <= MAX_CONFIG_BYTES,
            "Файл конфигурации {} превышает 2 МиБ.",
            self.path.display()
        );
        let mut config: Config = serde_json::from_slice(&raw)
            .with_context(|| format!("Ошибка конфигурации {}", self.path.display()))?;
        config
            .validate()
            .with_context(|| format!("Ошибка конфигурации {}", self.path.display()))?;
        config.normalize();
        Ok(config)
    }

    pub fn save(&self, config: &Config) -> Result<()> {
        config.validate()?;
        let mut normalized = config.clone();
        normalized.normalize();
        atomic_json(&self.path, &normalized, Some(MAX_CONFIG_BYTES))
    }

    pub fn known_hosts_path(&self) -> PathBuf {
        self.sidecar(".known_hosts.json")
    }

    pub fn sidecar(&self, suffix: &str) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(suffix);
        PathBuf::from(name)
    }

    pub fn lock(&self) -> Result<File> {
        create_parent(&self.path)?;
        let path = self.sidecar(".lock");
        let mut stream = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        restrict_access(&path)?;
        fs2::FileExt::try_lock_exclusive(&stream)
            .context("Эта конфигурация уже открыта в другом экземпляре КРОТ.")?;
        if stream.metadata()?.len() == 0 {
            stream.write_all(b"\0")?;
            stream.flush()?;
        }
        stream.seek(SeekFrom::Start(0))?;
        Ok(stream)
    }
}

fn resolve_path(path: &Path, depth: usize) -> Result<PathBuf> {
    ensure!(
        depth < 40,
        "Слишком много символических ссылок в пути конфигурации."
    );
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Prefix(_) | Component::RootDir => resolved.push(component.as_os_str()),
            Component::Normal(part) => {
                resolved.push(part);
                match fs::symlink_metadata(&resolved) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        let target = fs::read_link(&resolved)?;
                        resolved.pop();
                        resolved = resolve_path(&resolved.join(target), depth + 1)?;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).context("Не удалось разрешить путь конфигурации");
                    }
                }
            }
        }
    }
    Ok(resolved)
}

fn home_dir() -> PathBuf {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME");
    home.map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn default_config_path() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join("AppData/Roaming"));
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home_dir().join(".config"));
    base.join("krot/config.json")
}

fn create_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)?;
    Ok(())
}

pub fn atomic_json(path: &Path, value: &impl Serialize, max_bytes: Option<usize>) -> Result<()> {
    let mut encoded = serde_json::to_vec_pretty(value)?;
    encoded.push(b'\n');
    if let Some(limit) = max_bytes {
        ensure!(
            encoded.len() <= limit,
            "Файл конфигурации превышает 2 МиБ; прежний файл сохранён."
        );
    }
    create_parent(path)?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    #[cfg(windows)]
    let staging = tempfile::Builder::new()
        .prefix(".krot-private-")
        .tempdir_in(parent)?;
    #[cfg(windows)]
    let parent = {
        // A protected parent prevents opening an inherited broad-ACL file before it is secured.
        restrict_access(staging.path())?;
        staging.path()
    };
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    restrict_access(temporary.path())?;
    temporary.write_all(&encoded)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("Не удалось атомарно сохранить файл")?;
    Ok(())
}

#[cfg(unix)]
pub fn restrict_access(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if path.is_dir() { 0o700 } else { 0o600 }),
    )?;
    Ok(())
}

#[cfg(windows)]
pub fn restrict_access(path: &Path) -> Result<()> {
    use std::{
        ffi::c_void,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{HANDLE, LocalFree},
        Security::{Authorization::*, *},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct LocalMemory(*mut c_void);
    impl Drop for LocalMemory {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let check = |success| {
        if success != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    unsafe {
        let mut handle: HANDLE = ptr::null_mut();
        check(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut handle,
        ))?;
        let token = OwnedHandle::from_raw_handle(handle);
        let mut length = 0;
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut length,
        );
        ensure!(length > 0, "Не удалось получить SID текущего пользователя.");
        let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        check(GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        ))?;
        let sid = (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        let mut sid_text = ptr::null_mut();
        check(ConvertSidToStringSidW(sid, &mut sid_text))?;
        let sid_memory = LocalMemory(sid_text.cast());
        let mut sid_length = 0;
        while *sid_text.add(sid_length) != 0 {
            sid_length += 1;
        }
        let sid_string = String::from_utf16(std::slice::from_raw_parts(sid_text, sid_length))?;
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{sid_string})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = ptr::null_mut();
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        ))?;
        let descriptor_memory = LocalMemory(descriptor);
        let (mut present, mut defaulted, mut dacl) = (0, 0, ptr::null_mut());
        check(GetSecurityDescriptorDacl(
            descriptor,
            &mut present,
            &mut dacl,
            &mut defaulted,
        ))?;
        ensure!(
            present != 0 && !dacl.is_null(),
            "Не удалось создать закрытый DACL."
        );
        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let result = SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        );
        drop(descriptor_memory);
        drop(sid_memory);
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result as i32))
                .context("Не удалось защитить файл DACL");
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn restrict_access(_path: &Path) -> Result<()> {
    anyhow::bail!("Поддерживаются только Windows и Linux.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tunnel(name: &str) -> Tunnel {
        Tunnel {
            name: name.into(),
            server: Endpoint {
                host: "example.org".into(),
                user: "alice".into(),
                ..Endpoint::default()
            },
            target: "localhost".into(),
            ..Tunnel::default()
        }
    }

    #[test]
    fn reads_v1_configuration_and_optional_defaults() {
        let config: Config = serde_json::from_value(json!({
            "version": 1,
            "tunnels": [{"name":"web", "server":{"host":"example.org", "user":"alice"}, "target":"localhost"}]
        })).unwrap();
        config.validate().unwrap();
        assert_eq!(config.settings, Settings::default());
        assert_eq!(config.tunnels[0].server.port, 22);
        assert_eq!(config.tunnels[0].server.key, "~/.ssh/id_ed25519");
        assert_eq!(config.tunnels[0].id.len(), 32);
        assert!(config.tunnels[0].reconnect);
        assert!(!config.tunnels[0].enabled);
    }

    #[test]
    fn rejects_secrets_wrong_port_types_and_missing_envelope() {
        let valid = json!({"version":1,"tunnels":[tunnel("web")]});
        for wrong in [json!(true), json!("22"), json!(65536), json!(-1)] {
            let mut data = valid.clone();
            data["tunnels"][0]["server"]["port"] = wrong;
            assert!(serde_json::from_value::<Config>(data).is_err());
        }
        let mut secret = valid.clone();
        secret["tunnels"][0]["server"]["password"] = json!("never-save-this");
        assert!(serde_json::from_value::<Config>(secret).is_err());
        assert!(serde_json::from_value::<Config>(json!({})).is_err());
        let mut zero = tunnel("web");
        zero.port = 0;
        assert!(validate_tunnel(&zero, &[]).is_err());
    }

    #[test]
    fn validates_unicode_names_disabled_jumps_and_route_cycles() {
        let first = tunnel("Straße");
        let mut second = tunnel(" STRASSE ");
        assert!(validate_tunnel(&second, &[first]).is_err());
        second.name = "веб".into();
        second.jumps.push(Endpoint::default());
        validate_tunnel(&second, &[]).unwrap();
        second.jumps_enabled = true;
        assert!(validate_tunnel(&second, &[]).is_err());
        second.jumps[0] = Endpoint {
            host: "EXAMPLE.ORG.".into(),
            user: "bob".into(),
            ..Endpoint::default()
        };
        assert!(validate_tunnel(&second, &[]).is_err());
        for character in ['\n', '\u{200b}', '\u{e000}', '\u{0378}'] {
            second.name = format!("web{character}");
            assert!(validate_tunnel(&second, &[]).is_err());
        }
    }

    #[test]
    fn stores_ipv6_without_brackets_and_renders_it_once() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path().join("config.json")).unwrap();
        let mut entry = tunnel("ipv6");
        entry.server.host = "[::1]".into();
        entry.bind = "[::1]".into();
        entry.target = "[2001:db8::2]".into();
        assert_eq!(entry.server.address(), "alice@[::1]:22");
        assert_eq!(entry.route(), "L · [::1]:8080 → [2001:db8::2]:80");
        store
            .save(&Config {
                tunnels: vec![entry],
                ..Config::default()
            })
            .unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.tunnels[0].server.host, "::1");
        assert_eq!(loaded.tunnels[0].target, "2001:db8::2");
    }

    #[test]
    fn missing_is_empty_but_corrupt_and_oversize_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path().join("config.json")).unwrap();
        assert_eq!(store.load().unwrap(), Config::default());
        std::fs::write(&store.path, b"{broken").unwrap();
        assert!(store.load().is_err());
        assert_eq!(std::fs::read(&store.path).unwrap(), b"{broken");
        let previous = json!({"old": true});
        atomic_json(&store.path, &previous, None).unwrap();
        let bytes = std::fs::read(&store.path).unwrap();
        assert!(atomic_json(&store.path, &"x".repeat(256), Some(10)).is_err());
        assert_eq!(std::fs::read(&store.path).unwrap(), bytes);
        std::fs::write(&store.path, vec![b' '; MAX_CONFIG_BYTES + 1]).unwrap();
        assert!(store.load().is_err());
    }

    #[test]
    fn lock_is_exclusive_released_by_drop_and_uses_shared_suffix() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path().join("config.json")).unwrap();
        let lock = store.lock().unwrap();
        assert!(store.sidecar(".lock").exists());
        assert!(store.lock().is_err());
        drop(lock);
        store.lock().unwrap();
        assert_eq!(
            store.known_hosts_path(),
            directory.path().join("config.json.known_hosts.json")
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolves_symlinks_before_parent_components_and_restricts_files() {
        use std::os::unix::{fs::PermissionsExt, fs::symlink};
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join("real/nested")).unwrap();
        symlink(
            directory.path().join("real/nested"),
            directory.path().join("alias"),
        )
        .unwrap();
        let store = Store::new(directory.path().join("alias/../config.json")).unwrap();
        assert_eq!(store.path, directory.path().join("real/config.json"));
        store.save(&Config::default()).unwrap();
        assert_eq!(
            std::fs::metadata(&store.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
