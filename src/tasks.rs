//! Windows Task Scheduler entries of one configuration.
//!
//! `Logon` starts the background КРОТ right after sign-in: unlike the Run key it is not held
//! back by Explorer's startup delay. `Divert` starts the interception helper with administrator
//! rights on demand: Windows asks for consent once, when the task is registered.
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Logon,
    Divert,
}

#[cfg(any(windows, test))]
impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Logon => "logon",
            Kind::Divert => "divert",
        }
    }
    #[cfg_attr(not(windows), allow(dead_code))]
    fn command(self) -> &'static str {
        match self {
            Kind::Logon => "serve",
            Kind::Divert => "divert",
        }
    }
}

/// The windowed program that sits next to a console one: tasks always start the windowed
/// program, so `krot-cli` and the window find the same task and no console opens at logon.
#[cfg(any(windows, test))]
fn windowed_name(name: &str) -> Option<&'static str> {
    [
        ("krot-cli.exe", "krot.exe"),
        ("krot-cli-windows-x64.exe", "krot-windows-x64.exe"),
    ]
    .into_iter()
    .find(|(console, _)| name.eq_ignore_ascii_case(console))
    .map(|(_, windowed)| windowed)
}

/// Program that tasks and the elevated helper start: the windowed КРОТ of this copy.
pub fn program() -> std::io::Result<PathBuf> {
    let current = std::env::current_exe()?;
    #[cfg(windows)]
    if let Some(windowed) = current
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(windowed_name)
    {
        let sibling = current.with_file_name(windowed);
        if sibling.is_file() {
            return Ok(sibling);
        }
    }
    Ok(current)
}

fn choice(config: &Path) -> anyhow::Result<PathBuf> {
    Ok(crate::config::Store::new(config)?.sidecar(".elevation-on"))
}

/// The user has turned remembering on with `krot-cli elevation enable`. It is off unless
/// asked for: the task runs КРОТ from its directory with administrator rights and no question.
pub fn remembering(config: &Path) -> bool {
    choice(config).is_ok_and(|path| path.exists())
}

/// The choice survives later consents until it is changed again.
pub fn set_remembering(config: &Path, enabled: bool) -> anyhow::Result<()> {
    let path = choice(config)?;
    if enabled {
        std::fs::write(&path, b"")?;
    } else {
        match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error)?,
            _ => {}
        }
    }
    Ok(())
}

/// Every task of this configuration and kind, whichever copy of КРОТ registered it.
#[cfg(any(windows, test))]
fn prefix(registration: &str, kind: Kind) -> String {
    format!("\\{registration}-{}-", kind.label())
}

/// The program part changes when КРОТ moves, so a stale task is never taken for the current one.
#[cfg(any(windows, test))]
fn task_name(registration: &str, kind: Kind, executable: &str) -> String {
    use sha2::{Digest, Sha256};
    let program = executable.replace('/', "\\").to_lowercase();
    let digest = hex::encode(Sha256::digest(program.as_bytes()));
    format!("{}{}", prefix(registration, kind), &digest[..8])
}

/// A task of any configuration and kind that starts `executable`: the uninstaller removes
/// those of the installed program and leaves the tasks of other copies.
#[cfg(any(windows, test))]
fn program_task(name: &str, executable: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("\\krot-") else {
        return false;
    };
    let Some(digest) = rest.get(..16).filter(|digest| {
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) else {
        return false;
    };
    [Kind::Logon, Kind::Divert].into_iter().any(|kind| {
        task_name(&format!("krot-{digest}"), kind, executable).eq_ignore_ascii_case(name)
    })
}

#[cfg(any(windows, test))]
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Task Scheduler 1.2 definition: no battery or time limits, normal priority, one instance.
#[cfg(any(windows, test))]
fn task_xml(kind: Kind, user: &str, command: &str, arguments: &str) -> String {
    let user = escape(user);
    let (triggers, level, description) = match kind {
        Kind::Logon => (
            format!(
                "<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>"
            ),
            "LeastPrivilege",
            "КРОТ: фоновые туннели после входа в систему",
        ),
        Kind::Divert => (
            String::new(),
            "HighestAvailable",
            "КРОТ: перехват трафика приложений с правами администратора",
        ),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\
<RegistrationInfo><Description>{description}</Description></RegistrationInfo>\
{triggers}\
<Principals><Principal id=\"Author\"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>{level}</RunLevel></Principal></Principals>\
<Settings>\
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\
<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\
<AllowHardTerminate>true</AllowHardTerminate>\
<StartWhenAvailable>false</StartWhenAvailable>\
<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\
<IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\
<AllowStartOnDemand>true</AllowStartOnDemand>\
<Enabled>true</Enabled>\
<Hidden>false</Hidden>\
<RunOnlyIfIdle>false</RunOnlyIfIdle>\
<WakeToRun>false</WakeToRun>\
<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\
<Priority>5</Priority>\
</Settings>\
<Actions Context=\"Author\"><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions>\
</Task>\r\n",
        escape(command),
        escape(arguments),
    )
}

/// `schtasks /query /xml` output of a task that Windows will not start.
#[cfg(any(windows, test))]
fn disabled(output: &[u8]) -> bool {
    let text = if output.len() >= 2 && output.len().is_multiple_of(2) && output.contains(&0) {
        let units: Vec<u16> = output
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(output).into_owned()
    };
    text.split_whitespace()
        .collect::<String>()
        .contains("<Enabled>false</Enabled>")
}

/// Task names from `schtasks /query /fo csv /nh`: the first quoted field of every row.
#[cfg(any(windows, test))]
fn listed_names(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix('"')?.split('"').next())
        .map(str::to_owned)
        .collect()
}

#[cfg(windows)]
pub use system::{
    elevated, register, registered, remove_program_tasks, run, runas, unregister,
    unregister_others, user_sid,
};

/// Administrator rights exist only on Windows.
#[cfg(not(windows))]
pub fn elevated() -> bool {
    false
}

#[cfg(not(windows))]
pub fn registered(_config: &Path, _kind: Kind, _any_copy: bool) -> anyhow::Result<bool> {
    Ok(false)
}

#[cfg(windows)]
mod system {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use std::{io::Write, os::windows::process::CommandExt, process::Command};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_ELEVATION,
            TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
        },
        System::Threading::{
            GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
        },
        UI::{
            Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
            WindowsAndMessaging::SW_HIDE,
        },
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn token() -> Result<Token> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: the pseudo handle of the current process needs no closing.
        ensure!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } != 0,
            std::io::Error::last_os_error()
        );
        Ok(Token(handle))
    }

    /// The process runs with an elevated administrator token.
    pub fn elevated() -> bool {
        let Ok(token) = token() else {
            return false;
        };
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut length = 0;
        // SAFETY: the buffer is a TOKEN_ELEVATION of the declared size.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                (&raw mut elevation).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut length,
            )
        };
        ok != 0 && elevation.TokenIsElevated != 0
    }

    /// SID of the account the process runs as, e.g. `S-1-5-21-…`.
    pub fn user_sid() -> Result<String> {
        let token = token()?;
        let mut length = 0;
        // SAFETY: the first call only reports the required size.
        unsafe {
            GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut length);
        }
        ensure!(
            length as usize >= size_of::<TOKEN_USER>(),
            "Не удалось определить пользователя Windows."
        );
        let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
        // SAFETY: the buffer is aligned for TOKEN_USER and has the reported size.
        ensure!(
            unsafe {
                GetTokenInformation(
                    token.0,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            } != 0,
            std::io::Error::last_os_error()
        );
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text = std::ptr::null_mut();
        // SAFETY: the SID points into `buffer`; the string is released with LocalFree.
        ensure!(
            unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } != 0,
            std::io::Error::last_os_error()
        );
        let sid = unsafe {
            let length = (0..).take_while(|&i| *text.add(i) != 0).count();
            let sid = String::from_utf16(std::slice::from_raw_parts(text, length));
            LocalFree(text as HLOCAL);
            sid
        }?;
        Ok(sid)
    }

    /// The Windows directory from the system, not from the environment, which the user sets.
    fn windows_directory() -> std::path::PathBuf {
        use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
        let mut directory = [0u16; 260];
        // SAFETY: the buffer length matches the size passed to the call.
        let length =
            unsafe { GetSystemWindowsDirectoryW(directory.as_mut_ptr(), directory.len() as u32) };
        if length == 0 || length as usize >= directory.len() {
            return "C:\\Windows".into();
        }
        String::from_utf16_lossy(&directory[..length as usize]).into()
    }

    fn schtasks_path() -> std::path::PathBuf {
        windows_directory().join("System32").join("schtasks.exe")
    }

    fn schtasks(arguments: &[&str]) -> Result<std::process::Output> {
        Command::new(schtasks_path())
            .args(arguments)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(std::process::Stdio::null())
            .output()
            .context("Не удалось запустить планировщик заданий Windows")
    }

    /// Starts `file` with administrator rights after the user's consent. With `wait` it also
    /// waits for the program and requires a zero exit code.
    pub fn runas(file: &std::ffi::OsStr, parameters: &str, wait: bool) -> Result<()> {
        let wide = |text: &std::ffi::OsStr| -> Vec<u16> {
            use std::os::windows::ffi::OsStrExt;
            text.encode_wide().chain(Some(0)).collect()
        };
        let (verb, file, parameters) = (
            wide("runas".as_ref()),
            wide(file),
            wide(parameters.as_ref()),
        );
        // SAFETY: an all-zero structure is the documented starting point; the strings
        // outlive the call and a returned process handle is closed below.
        unsafe {
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
            if wait {
                info.fMask = SEE_MASK_NOCLOSEPROCESS;
            }
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = parameters.as_ptr();
            info.nShow = SW_HIDE;
            ensure!(
                ShellExecuteExW(&mut info) != 0,
                "Права администратора не предоставлены."
            );
            if !wait {
                return Ok(());
            }
            ensure!(!info.hProcess.is_null(), "Программа не запустилась.");
            WaitForSingleObject(info.hProcess, INFINITE);
            let mut code = 1;
            let read = GetExitCodeProcess(info.hProcess, &mut code);
            CloseHandle(info.hProcess);
            ensure!(read != 0 && code == 0, "Программа завершилась с ошибкой.");
        }
        Ok(())
    }

    fn names(config: &Path, kind: Kind) -> Result<(String, String)> {
        let (_, registration) = crate::autostart::registration(config)?;
        let executable = program()?;
        let executable = executable
            .to_str()
            .context("Путь программы не является корректным Unicode.")?;
        Ok((
            prefix(&registration, kind),
            task_name(&registration, kind, executable),
        ))
    }

    fn listed(prefix: &str) -> Result<Vec<String>> {
        let output = schtasks(&["/query", "/fo", "csv", "/nh"])?;
        ensure!(
            output.status.success(),
            "Не удалось прочитать задания Windows."
        );
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(listed_names(&text)
            .into_iter()
            .filter(|name| {
                name.get(..prefix.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
            })
            .collect())
    }

    /// The task of this copy exists and is enabled, or with `any_copy` a task of any copy exists.
    pub fn registered(config: &Path, kind: Kind, any_copy: bool) -> Result<bool> {
        let (prefix, name) = names(config, kind)?;
        if any_copy {
            return Ok(!listed(&prefix)?.is_empty());
        }
        let output = schtasks(&["/query", "/tn", &name, "/xml"])?;
        Ok(output.status.success() && !disabled(&output.stdout))
    }

    /// Registers the task for the current user and copy, replacing the tasks of other copies.
    /// `Divert` needs administrator rights: call it from an elevated process.
    pub fn register(config: &Path, kind: Kind) -> Result<()> {
        let (prefix, name) = names(config, kind)?;
        let config = crate::config::Store::new(config)?.path;
        let executable = program()?;
        let command = executable
            .to_str()
            .context("Путь программы не является корректным Unicode.")?;
        let arguments = crate::autostart::windows_command(&[
            "--config".into(),
            config
                .to_str()
                .context("Путь конфигурации не является корректным Unicode.")?
                .into(),
            kind.command().into(),
        ]);
        let xml = task_xml(kind, &user_sid()?, command, &arguments);
        // `schtasks` reads the definition by its path later. An elevated process keeps it in the
        // system temporary directory, where users create files but cannot change or rename
        // those of others: the user's own one would let any program of theirs swap it.
        let mut builder = tempfile::Builder::new();
        builder.prefix("krot-task-").suffix(".xml");
        let mut file = if elevated() {
            builder.tempfile_in(windows_directory().join("Temp"))?
        } else {
            builder.tempfile()?
        };
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        // `schtasks` cannot open a file that is still open for writing: close it and keep
        // only the path, which removes the file when dropped.
        let file = file.into_temp_path();
        let path = file
            .to_str()
            .context("Путь временного файла не является корректным Unicode.")?
            .to_owned();
        let output = schtasks(&["/create", "/tn", &name, "/xml", &path, "/f"])?;
        if !output.status.success() {
            bail!(
                "Планировщик заданий Windows не создал задание: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        // The task exists by now: failing to clear the tasks of other copies is no failure.
        let _ = remove(&prefix, Some(&name), false);
        Ok(())
    }

    /// Removes the tasks of every copy. A task that an elevated process registered may refuse
    /// the user's deletion: with `consent` Windows then asks for administrator rights. The
    /// helper's task is always registered so, a logon task when an older КРОТ ran elevated.
    pub fn unregister(config: &Path, kind: Kind, consent: bool) -> Result<()> {
        let (prefix, _) = names(config, kind)?;
        remove(&prefix, None, consent)
    }

    /// Removes the tasks of the other copies, which `register` leaves where they refuse.
    pub fn unregister_others(config: &Path, kind: Kind, consent: bool) -> Result<()> {
        let (prefix, name) = names(config, kind)?;
        remove(&prefix, Some(&name), consent)
    }

    fn remove(prefix: &str, keep: Option<&str>, consent: bool) -> Result<()> {
        for name in listed(prefix)? {
            if keep.is_some_and(|keep| keep.eq_ignore_ascii_case(&name))
                || schtasks(&["/delete", "/tn", &name, "/f"])?.status.success()
            {
                continue;
            }
            ensure!(
                consent,
                "Не удалось удалить задание планировщика Windows {name}."
            );
            runas(
                schtasks_path().as_os_str(),
                &format!("/delete /tn \"{name}\" /f"),
                true,
            )
            .context("Планировщик заданий Windows не удалил задание.")?;
        }
        Ok(())
    }

    /// Removes the tasks of every configuration that start `executable`; for the uninstaller,
    /// which runs with the rights to delete them all.
    pub fn remove_program_tasks(executable: &str) -> Result<()> {
        let mut failed = Vec::new();
        for name in listed("\\krot-")? {
            if program_task(&name, executable)
                && !schtasks(&["/delete", "/tn", &name, "/f"])?.status.success()
            {
                failed.push(name);
            }
        }
        ensure!(
            failed.is_empty(),
            "Не удалось удалить задания планировщика Windows: {}.",
            failed.join(", ")
        );
        Ok(())
    }

    /// Starts the task of this copy; Windows applies its rights without asking.
    pub fn run(config: &Path, kind: Kind) -> Result<()> {
        let (_, name) = names(config, kind)?;
        let output = schtasks(&["/run", "/tn", &name])?;
        ensure!(
            output.status.success(),
            "Задание Windows не запустилось: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_names_separate_configurations_kinds_and_copies() {
        let logon = task_name("krot-0123456789abcdef", Kind::Logon, "C:\\КРОТ\\krot.exe");
        assert!(logon.starts_with("\\krot-0123456789abcdef-logon-"));
        assert_eq!(
            logon.len(),
            prefix("krot-0123456789abcdef", Kind::Logon).len() + 8
        );
        assert!(logon.is_ascii());
        assert_eq!(
            logon,
            task_name("krot-0123456789abcdef", Kind::Logon, "c:/кРОТ/KROT.exe")
        );
        assert_ne!(
            logon,
            task_name("krot-0123456789abcdef", Kind::Logon, "D:\\КРОТ\\krot.exe")
        );
        assert_ne!(
            logon,
            task_name("krot-0123456789abcdef", Kind::Divert, "C:\\КРОТ\\krot.exe")
        );
    }

    #[test]
    fn task_xml_escapes_paths_and_keeps_the_helper_on_demand() {
        let xml = task_xml(
            Kind::Divert,
            "S-1-5-21-1",
            "C:\\R&D <x>\\krot.exe",
            "--config \"C:\\Users\\Алиса\\a'b.json\" divert",
        );
        assert!(xml.contains("<Command>C:\\R&amp;D &lt;x&gt;\\krot.exe</Command>"));
        assert!(xml.contains("&quot;C:\\Users\\Алиса\\a&apos;b.json&quot; divert"));
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(!xml.contains("<Triggers>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
        let logon = task_xml(Kind::Logon, "S-1-5-21-1", "C:\\krot.exe", "serve");
        assert!(logon.contains("<LogonTrigger><Enabled>true</Enabled><UserId>S-1-5-21-1</UserId>"));
        assert!(logon.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(!logon.contains("Delay"));
    }

    #[test]
    fn console_programs_map_to_the_windowed_one() {
        assert_eq!(windowed_name("KROT-CLI.exe"), Some("krot.exe"));
        assert_eq!(
            windowed_name("krot-cli-windows-x64.exe"),
            Some("krot-windows-x64.exe")
        );
        assert_eq!(windowed_name("krot.exe"), None);
    }

    #[test]
    fn disabled_tasks_are_recognised_in_utf8_and_utf16() {
        let enabled = "<Settings>\r\n  <Enabled>true</Enabled>\r\n</Settings>";
        let off = "<Settings>\r\n  <Enabled>false</Enabled>\r\n</Settings>";
        assert!(!disabled(enabled.as_bytes()));
        assert!(disabled(off.as_bytes()));
        let utf16: Vec<u8> = off.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(disabled(&utf16));
    }

    #[test]
    fn remembering_is_off_until_asked_for_and_persists_per_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.json");
        assert!(!remembering(&config));
        set_remembering(&config, true).unwrap();
        set_remembering(&config, true).unwrap();
        assert!(remembering(&config));
        assert!(!remembering(&directory.path().join("other.json")));
        set_remembering(&config, false).unwrap();
        set_remembering(&config, false).unwrap();
        assert!(!remembering(&config));
    }

    #[test]
    fn the_uninstaller_finds_the_tasks_of_its_program_only() {
        let program = "C:\\Program Files\\KROT\\krot.exe";
        for kind in [Kind::Logon, Kind::Divert] {
            let name = task_name("krot-0123456789abcdef", kind, program);
            assert!(program_task(&name, program));
            assert!(program_task(&name.to_uppercase(), &program.to_lowercase()));
            assert!(!program_task(
                &task_name("krot-0123456789abcdef", kind, "D:\\krot\\krot.exe"),
                program
            ));
        }
        assert!(!program_task("\\krot-xyz-logon-12345678", program));
        assert!(!program_task("\\Microsoft\\krot", program));
    }

    #[test]
    fn listed_names_take_the_first_csv_field() {
        let output = "\"\\krot-a-logon-1\",\"N/A\",\"Ready\"\r\n\r\n\"\\Microsoft\\x\",\"N/A\",\"Готово\"\r\nINFO: none\r\n";
        assert_eq!(listed_names(output), ["\\krot-a-logon-1", "\\Microsoft\\x"]);
    }
}
