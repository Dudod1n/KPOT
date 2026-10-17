use crate::config::Store;
#[cfg(any(target_os = "linux", test))]
use crate::config::restrict_access;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", test))]
use std::{collections::HashMap, fs, io::Write};

fn registration(path: &Path) -> Result<(PathBuf, String)> {
    let path = Store::new(path)?.path;
    let text = path
        .to_str()
        .context("Путь конфигурации не является корректным Unicode.")?;
    #[cfg(windows)]
    let text = text.replace('/', "\\").to_lowercase();
    let digest = hex::encode(Sha256::digest(text.as_bytes()));
    let name = format!("krot-{}", &digest[..16]);
    Ok((path, name))
}

fn launch_command(config: &Path) -> Result<Vec<String>> {
    let executable = std::env::current_exe()?;
    Ok(vec![
        executable
            .to_str()
            .context("Путь программы не является корректным Unicode.")?
            .into(),
        "--config".into(),
        config
            .to_str()
            .context("Путь конфигурации не является корректным Unicode.")?
            .into(),
        "serve".into(),
    ])
}

#[cfg(any(target_os = "linux", test))]
fn desktop_command(command: &[String]) -> Result<String> {
    ensure!(!command.is_empty(), "Не указана программа автозапуска.");
    ensure!(
        !command[0].contains('='),
        "Автозапуск Linux: путь программы не должен содержать знак «=»."
    );
    let mut arguments = Vec::new();
    for argument in command {
        let mut escaped = String::new();
        for character in argument.chars() {
            if "\\\"`$".contains(character) {
                escaped.push('\\');
            }
            escaped.push(character);
            if character == '%' {
                escaped.push('%');
            }
        }
        arguments.push(format!("\"{escaped}\""));
    }
    Ok(arguments
        .join(" ")
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t"))
}

#[cfg(target_os = "linux")]
fn desktop_path(name: &str) -> PathBuf {
    let fallback = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config");
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or(fallback)
        .join("autostart")
        .join(format!("{name}.desktop"))
}

#[cfg(any(target_os = "linux", test))]
fn desktop_entry(path: &Path) -> Result<Option<HashMap<String, String>>> {
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("Не удалось прочитать запись автозапуска"),
    };
    let Ok(text) = String::from_utf8(raw) else {
        return Ok(Some(HashMap::new()));
    };
    let mut entry = HashMap::new();
    let mut sections = std::collections::HashSet::new();
    let mut current_section = "";
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with(['#', ';']))
    {
        if line.starts_with('[') && line.ends_with(']') {
            current_section = &line[1..line.len() - 1];
            if !sections.insert(current_section) {
                return Ok(Some(HashMap::new()));
            }
        } else {
            let Some((key, value)) = line.split_once('=') else {
                return Ok(Some(HashMap::new()));
            };
            if current_section == "Desktop Entry"
                && entry
                    .insert(key.trim().into(), value.trim().into())
                    .is_some()
            {
                return Ok(Some(HashMap::new()));
            }
        }
    }
    Ok(Some(entry))
}

#[cfg(any(target_os = "linux", test))]
fn desktop_enabled(entry: &HashMap<String, String>, name: &str) -> bool {
    entry
        .get("X-Krot-Autostart")
        .is_some_and(|value| value == name)
        && entry
            .get("Type")
            .is_some_and(|value| value == "Application")
        && entry.get("Exec").is_some_and(|value| !value.is_empty())
        && entry.get("Hidden").is_none_or(|value| value != "true")
        && entry
            .get("X-GNOME-Autostart-enabled")
            .is_none_or(|value| value != "false")
}

#[cfg(any(target_os = "linux", test))]
fn set_desktop(path: &Path, name: &str, command: &[String], enabled: bool) -> Result<()> {
    let existing = desktop_entry(path)?;
    ensure!(
        existing.as_ref().is_none_or(|entry| entry
            .get("X-Krot-Autostart")
            .is_some_and(|value| value == name)),
        "Запись автозапуска принадлежит другой программе; она не изменена."
    );
    if !enabled {
        if existing.is_some() {
            fs::remove_file(path)?;
        }
        return Ok(());
    }
    let command = desktop_command(command)?;
    let content = format!(
        "[Desktop Entry]\nType=Application\nName=КРОТ\nExec={command}\nTerminal=false\nX-Krot-Autostart={name}\n"
    );
    if existing.is_some() && fs::read(path)? == content.as_bytes() {
        return Ok(());
    }
    let parent = path.parent().context("Не указан каталог автозапуска.")?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    restrict_access(temporary.path())?;
    temporary.write_all(content.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(any(windows, test))]
fn windows_command(command: &[String]) -> String {
    command
        .iter()
        .map(|argument| {
            let quoted = argument.is_empty() || argument.contains([' ', '\t']);
            let mut result = if quoted {
                "\"".to_owned()
            } else {
                String::new()
            };
            let mut slashes = 0;
            for character in argument.chars() {
                if character == '\\' {
                    slashes += 1;
                    continue;
                }
                if character == '"' {
                    result.push_str(&"\\".repeat(slashes * 2 + 1));
                    result.push('"');
                } else {
                    result.push_str(&"\\".repeat(slashes));
                    result.push(character);
                }
                slashes = 0;
            }
            result.push_str(&"\\".repeat(if quoted { slashes * 2 } else { slashes }));
            if quoted {
                result.push('"');
            }
            result
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(windows, test))]
fn windows_owned(value: &(String, u32), config: &Path) -> bool {
    if value.1 != 1 {
        return false;
    } // REG_SZ
    let Some(config) = config.to_str() else {
        return false;
    };
    for (basename, prefix) in [
        ("krot.exe", vec![]),
        ("krot-cli.exe", vec![]),
        ("krot-windows-x64.exe", vec![]),
        ("krot-cli-windows-x64.exe", vec![]),
        ("krot-background.exe", vec![]),
        ("pythonw.exe", vec!["-m".into(), "krot".into()]),
    ] {
        let mut suffix_command = prefix;
        suffix_command.extend(["--config".into(), config.into(), "serve".into()]);
        let suffix = format!(" {}", windows_command(&suffix_command));
        let Some(launcher) = value.0.strip_suffix(&suffix) else {
            continue;
        };
        let executable = launcher
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(launcher);
        let path = executable.replace('/', "\\");
        let absolute = path.starts_with("\\\\")
            || (path.as_bytes().get(1) == Some(&b':') && path.as_bytes().get(2) == Some(&b'\\'));
        if absolute
            && path
                .rsplit('\\')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(basename))
            && windows_command(&[executable.into()]) == launcher
        {
            return true;
        }
    }
    false
}

#[cfg(windows)]
mod registry {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
        System::Registry::*,
    };
    const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }
    fn check(code: u32) -> Result<()> {
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(code as i32))
                .context("Не удалось изменить автозапуск Windows")
        }
    }

    pub fn value(name: &str) -> Result<Option<(String, u32)>> {
        value_at(RUN_KEY, name)
    }

    fn value_at(path: &str, name: &str) -> Result<Option<(String, u32)>> {
        unsafe {
            let mut handle = std::ptr::null_mut();
            let code = RegOpenKeyExW(
                HKEY_CURRENT_USER,
                wide(path).as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut handle,
            );
            if code == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            check(code)?;
            let key = Key(handle);
            let (mut kind, mut length) = (0, 0);
            let name = wide(name);
            let code = RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut length,
            );
            if code == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            check(code)?;
            ensure!(
                length <= 64 * 1024,
                "Слишком длинная запись автозапуска Windows."
            );
            if kind != REG_SZ {
                return Ok(Some((String::new(), kind)));
            }
            let mut buffer = vec![0u16; (length as usize).div_ceil(2)];
            check(RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                buffer.as_mut_ptr().cast(),
                &mut length,
            ))?;
            if kind != REG_SZ || length % 2 != 0 {
                return Ok(Some((String::new(), 0)));
            }
            buffer.truncate(length as usize / 2);
            if buffer.last() == Some(&0) {
                buffer.pop();
            }
            let text = String::from_utf16(&buffer).unwrap_or_default();
            Ok(Some((text, kind)))
        }
    }

    pub fn set(name: &str, command: Option<&str>) -> Result<()> {
        set_at(RUN_KEY, name, command)
    }

    fn set_at(path: &str, name: &str, command: Option<&str>) -> Result<()> {
        let expected = command.map(|command| (command.to_owned(), REG_SZ));
        if value_at(path, name)? == expected {
            return Ok(());
        }
        unsafe {
            let mut handle = std::ptr::null_mut();
            check(RegCreateKeyExW(
                HKEY_CURRENT_USER,
                wide(path).as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut handle,
                std::ptr::null_mut(),
            ))?;
            let key = Key(handle);
            let name = wide(name);
            if let Some(command) = command {
                let command = wide(command);
                check(RegSetValueExW(
                    key.0,
                    name.as_ptr(),
                    0,
                    REG_SZ,
                    command.as_ptr().cast(),
                    (command.len() * 2) as u32,
                ))?;
            } else {
                let code = RegDeleteValueW(key.0, name.as_ptr());
                if code != ERROR_FILE_NOT_FOUND {
                    check(code)?;
                }
            }
        }
        ensure!(
            value_at(path, name)? == expected,
            "Windows не подтвердила изменение автозапуска. Проверьте разрешения и журнал защиты."
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::{
            Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::{CreateEventW, WaitForSingleObject},
        };

        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                unsafe {
                    RegDeleteTreeW(HKEY_CURRENT_USER, wide(&self.0).as_ptr());
                }
            }
        }

        #[test]
        fn registry_roundtrip_preserves_unicode_and_does_not_rewrite_unchanged_values() {
            let path = format!("Software\\KPOT-tests\\{}", uuid::Uuid::new_v4());
            let _cleanup = Cleanup(path.clone());
            let name = "test-startup";
            assert!(value_at(&path, name).unwrap().is_none());
            set_at(&path, name, None).unwrap();
            let config = Path::new("C:\\Users\\Alice Smith\\КРОТ\\config.json");
            let old = windows_command(&[
                "C:\\old\\krot.exe".into(),
                "--config".into(),
                config.to_str().unwrap().into(),
                "serve".into(),
            ]);
            let current = windows_command(&[
                "C:\\Program Files\\КРОТ\\krot.exe".into(),
                "--config".into(),
                config.to_str().unwrap().into(),
                "serve".into(),
            ]);
            assert!(windows_owned(&(old.clone(), REG_SZ), config));
            set_at(&path, name, Some(&old)).unwrap();
            set_at(&path, "other", Some("keep")).unwrap();
            let mut handle = std::ptr::null_mut();
            check(unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    wide(&path).as_ptr(),
                    0,
                    KEY_NOTIFY,
                    &mut handle,
                )
            })
            .unwrap();
            let key = Key(handle);
            let raw = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
            assert!(!raw.is_null());
            let event = unsafe { OwnedHandle::from_raw_handle(raw) };
            check(unsafe {
                RegNotifyChangeKeyValue(
                    key.0,
                    0,
                    REG_NOTIFY_CHANGE_LAST_SET,
                    event.as_raw_handle(),
                    1,
                )
            })
            .unwrap();
            set_at(&path, name, Some(&old)).unwrap();
            assert_eq!(
                unsafe { WaitForSingleObject(event.as_raw_handle(), 50) },
                WAIT_TIMEOUT
            );
            set_at(&path, name, Some(&current)).unwrap();
            assert_eq!(
                unsafe { WaitForSingleObject(event.as_raw_handle(), 1000) },
                WAIT_OBJECT_0
            );
            assert_eq!(value_at(&path, name).unwrap(), Some((current, REG_SZ)));
            assert_eq!(
                value_at(&path, "other").unwrap(),
                Some(("keep".into(), REG_SZ))
            );
            set_at(&path, name, None).unwrap();
            assert!(value_at(&path, name).unwrap().is_none());
        }
    }
}

pub fn is_enabled(path: &Path) -> Result<bool> {
    let (path, name) = registration(path)?;
    #[cfg(windows)]
    {
        Ok(registry::value(&name)?.is_some_and(|value| windows_owned(&value, &path)))
    }
    #[cfg(target_os = "linux")]
    {
        let _ = path;
        Ok(
            desktop_entry(&desktop_path(&name))?
                .is_some_and(|entry| desktop_enabled(&entry, &name)),
        )
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (path, name);
        Ok(false)
    }
}

pub fn set_enabled(path: &Path, enabled: bool) -> Result<()> {
    let (path, name) = registration(path)?;
    #[cfg(windows)]
    {
        let existing = registry::value(&name)?;
        ensure!(
            existing
                .as_ref()
                .is_none_or(|value| windows_owned(value, &path)),
            "Запись автозапуска принадлежит другой программе; она не изменена."
        );
        if enabled {
            let command = windows_command(&launch_command(&path)?);
            ensure!(
                command.encode_utf16().count() <= 260,
                "Автозапуск Windows: команда длиннее 260 символов. Переместите программу или конфигурацию в более короткий путь."
            );
            registry::set(&name, Some(&command))?;
        } else if existing.is_some() {
            registry::set(&name, None)?;
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        set_desktop(
            &desktop_path(&name),
            &name,
            &launch_command(&path)?,
            enabled,
        )
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (path, name, enabled);
        anyhow::bail!("Автозапуск поддерживается только в Windows и Linux.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_escaping_preserves_spaces_percent_quotes_and_controls() {
        let command = vec![
            "/opt/КРОТ/krot".into(),
            "--config".into(),
            "/home/alice/a % \" `$\\\n\t.json".into(),
            "serve".into(),
        ];
        let generated = desktop_command(&command).unwrap();
        assert!(generated.starts_with("\"/opt/КРОТ/krot\" \"--config\" "));
        assert!(generated.contains("%%"));
        assert!(generated.contains("\\\\\""));
        assert!(generated.contains("\\n\\t"));
        assert!(!generated.contains('\n'));
        assert!(desktop_command(&["/opt/a=b/krot".into()]).is_err());
    }

    #[test]
    fn desktop_registration_is_atomic_owned_and_never_touches_actual_autostart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("autostart/krot-test.desktop");
        let command = vec![
            "/opt/krot".into(),
            "--config".into(),
            "/home/alice/config.json".into(),
            "serve".into(),
        ];
        set_desktop(&path, "krot-test", &command, true).unwrap();
        let mut entry = desktop_entry(&path).unwrap().unwrap();
        assert!(desktop_enabled(&entry, "krot-test"));
        entry.insert("Hidden".into(), "true".into());
        assert!(!desktop_enabled(&entry, "krot-test"));
        set_desktop(&path, "krot-test", &command, false).unwrap();
        assert!(!path.exists());
        fs::write(
            &path,
            "[Desktop Entry]\nType=Application\nExec=another-app\n",
        )
        .unwrap();
        let original = fs::read(&path).unwrap();
        assert!(set_desktop(&path, "krot-test", &command, true).is_err());
        assert!(set_desktop(&path, "krot-test", &command, false).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn windows_quoting_and_relocated_python_or_rust_ownership() {
        let config = Path::new("C:\\Users\\Alice Smith\\config.json");
        for launcher in [
            "C:\\Program Files\\КРОТ\\krot.exe",
            "C:\\Program Files\\КРОТ\\krot-cli.exe",
            "C:\\Program Files\\КРОТ\\krot-windows-x64.exe",
            "C:\\Program Files\\КРОТ\\krot-cli-windows-x64.exe",
            "C:\\old\\krot-background.exe",
            "C:\\Python\\pythonw.exe",
        ] {
            let mut command = vec![launcher.to_string()];
            if launcher.ends_with("pythonw.exe") {
                command.extend(["-m".into(), "krot".into()]);
            }
            command.extend([
                "--config".into(),
                config.to_str().unwrap().into(),
                "serve".into(),
            ]);
            assert!(windows_owned(&(windows_command(&command), 1), config));
        }
        assert!(!windows_owned(
            &(
                windows_command(&[
                    "C:\\other.exe".into(),
                    "--config".into(),
                    config.to_str().unwrap().into(),
                    "serve".into()
                ]),
                1
            ),
            config
        ));
        assert_eq!(
            windows_command(&["a b\\".into(), "x\"y".into(), "".into()]),
            "\"a b\\\\\" x\\\"y \"\""
        );
    }

    #[test]
    #[cfg(unix)]
    fn unchanged_desktop_registration_keeps_the_original_file() {
        use std::os::unix::fs::MetadataExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("autostart/krot-test.desktop");
        let command = vec![
            "/opt/krot".into(),
            "--config".into(),
            "/tmp/config.json".into(),
            "serve".into(),
        ];
        set_desktop(&path, "krot-test", &command, true).unwrap();
        let original = fs::metadata(&path).unwrap().ino();
        set_desktop(&path, "krot-test", &command, true).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().ino(), original);
        let moved = vec![
            "/opt/new/krot".into(),
            "--config".into(),
            "/tmp/config.json".into(),
            "serve".into(),
        ];
        set_desktop(&path, "krot-test", &moved, true).unwrap();
        assert_ne!(fs::metadata(&path).unwrap().ino(), original);
        assert!(desktop_entry(&path).unwrap().unwrap()["Exec"].contains("/opt/new/krot"));
    }
    #[test]
    fn canonical_configuration_has_one_registration_name() {
        let directory = tempfile::tempdir().unwrap();
        let canonical = directory.path().join("config.json");
        let (path, name) = registration(&directory.path().join("missing/../config.json")).unwrap();
        assert_eq!(path, canonical);
        let text = canonical.to_str().unwrap();
        #[cfg(windows)]
        let text = text.replace('/', "\\").to_lowercase();
        assert_eq!(
            name,
            format!(
                "krot-{}",
                &hex::encode(Sha256::digest(text.as_bytes()))[..16]
            )
        );
    }
}
