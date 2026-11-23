//! Interception service of the installed КРОТ on Windows.
//!
//! The installer puts КРОТ into a directory that only administrators can change and registers
//! the service `KrotDivert`, which runs from there as LocalSystem. The background КРОТ of a
//! user asks it over a named pipe for an interception helper. The service finds out who asks
//! from the pipe itself, starts the helper from its own directory and limits it to the
//! processes of that user in that session. The service and its helper never open the user's
//! files: the address of the background process comes in the request.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Name of the service in the Service Control Manager; the installer registers it.
pub const NAME: &str = "KrotDivert";
/// Requests and replies are single JSON lines.
#[cfg_attr(not(windows), allow(dead_code))]
const MAX_MESSAGE: usize = 4096;
/// Helpers the service runs at once: one per configuration of every user in every session.
#[cfg_attr(not(windows), allow(dead_code))]
const MAX_HELPERS: usize = 64;
/// Helpers of one user: one user cannot take the places of the others.
#[cfg_attr(not(windows), allow(dead_code))]
const MAX_USER_HELPERS: usize = 4;

/// What the background КРОТ asks the service for: a helper attached to it.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub version: String,
    /// Names the configuration: a user runs one helper per configuration in a session.
    pub key: String,
    pub port: u16,
    pub token: String,
}

impl Request {
    #[cfg_attr(not(windows), allow(dead_code))]
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == env!("CARGO_PKG_VERSION"),
            "Служба перехвата другой версии, чем КРОТ. Переустановите КРОТ."
        );
        ensure!(
            !self.key.is_empty()
                && self.key.len() <= 64
                && self
                    .key
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && self.port != 0
                && self.token.len() == 64
                && self
                    .token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "Некорректный запрос к службе перехвата."
        );
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(windows), allow(dead_code))]
struct Reply {
    ok: bool,
    #[serde(default)]
    error: String,
}

/// What the service tells the helper it starts, on the helper's standard input: the secret
/// never appears among the arguments of a process.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct Assignment {
    pub port: u16,
    pub token: String,
    /// The helper captures only processes of this session…
    pub session: u32,
    /// …that run as this user (a SID such as `S-1-5-21-…`).
    pub user: String,
}

/// A path as Windows compares it: without the `\\?\` prefix, a trailing separator and case.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn path_key(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\");
    let text = text.strip_prefix("\\\\?\\").unwrap_or(&text);
    text.trim_end_matches('\\').to_lowercase()
}

/// A program of the installed copy that may ask the service for a helper.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn installed_program(program: &Path, directory: &Path) -> bool {
    // Split as Windows paths whatever the platform, so that the tests run everywhere.
    let program = path_key(program);
    program.rsplit_once('\\').is_some_and(|(parent, name)| {
        parent == path_key(directory) && (name == "krot.exe" || name == "krot-cli.exe")
    })
}

/// A `Run` value that the installed `program` registered for autostart: its name is the
/// registration of a configuration and its command starts this very program.
#[cfg(any(windows, test))]
fn installed_run_value(name: &str, command: &str, program: &str) -> bool {
    let registration = name
        .strip_prefix("krot-")
        .is_some_and(|digest| digest.len() == 16 && digest.bytes().all(|b| b.is_ascii_hexdigit()));
    let launcher = format!(
        "{} ",
        crate::autostart::windows_command(&[program.to_owned()])
    );
    registration
        && command
            .get(..launcher.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(&launcher))
}

#[cfg(windows)]
pub(crate) use system::process_user;
#[cfg(windows)]
pub use system::{cleanup, install_dir, installed, prepare_install, request, run, system_program};

/// Only Windows has the service.
#[cfg(not(windows))]
pub fn installed() -> bool {
    false
}

#[cfg(not(windows))]
pub fn install_dir() -> Option<std::path::PathBuf> {
    None
}

#[cfg(windows)]
mod system {
    use super::*;
    use anyhow::{Context, bail};
    use std::{
        collections::HashMap,
        ffi::c_void,
        io::{BufRead, Read, Write},
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle, process::CommandExt},
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::{
            Arc, Condvar, Mutex, OnceLock,
            atomic::{AtomicPtr, AtomicU16, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_CALL_NOT_IMPLEMENTED, ERROR_IO_PENDING, ERROR_NO_MORE_ITEMS,
            ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_SERVICE_SPECIFIC_ERROR, GetLastError,
            HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree, NO_ERROR, WAIT_OBJECT_0,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, PSECURITY_DESCRIPTOR, RevertToSelf, SECURITY_ATTRIBUTES,
            TOKEN_QUERY, TOKEN_USER, TokenSessionId, TokenUser,
        },
        Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES,
            FILE_READ_DATA, FILE_READ_EA, FILE_WRITE_DATA, PIPE_ACCESS_DUPLEX, ReadFile,
            SECURITY_IDENTIFICATION, SYNCHRONIZE, WriteFile,
        },
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            },
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
                GetNamedPipeServerProcessId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
                WaitNamedPipeW,
            },
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE,
                KEY_SET_VALUE, REG_OPTION_OPEN_LINK, REG_SZ, RRF_RT_REG_SZ, RegCloseKey,
                RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW,
            },
            RemoteDesktop::ProcessIdToSessionId,
            Services::{
                CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
                RegisterServiceCtrlHandlerExW, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
                SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
                SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS,
                SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
                SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
                SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
            },
            SystemInformation::GetSystemDirectoryW,
            Threading::{
                CreateEventW, GetCurrentProcessId, GetCurrentThread, INFINITE, OpenProcess,
                OpenProcessToken, OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
                WaitForSingleObject,
            },
        },
    };
    use zeroize::{Zeroize, Zeroizing};

    const PIPE: &str = r"\\.\pipe\krot-divert";
    /// Network logons are refused; SYSTEM and administrators own the pipe; any signed-in user
    /// may read and write it, but not create another instance of it (`FILE_APPEND_DATA`).
    /// Who the client is, and which processes its helper may touch, is checked per request.
    const PIPE_SDDL: &str = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;AU)";
    const CLIENT_ACCESS: u32 =
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    /// A client has this long to send its request and to take the reply.
    const CLIENT_TIME: Duration = Duration::from_secs(5);
    /// Requests served at once; more connections are closed unanswered.
    const MAX_CLIENTS: usize = 8;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn last_error() -> std::io::Error {
        std::io::Error::last_os_error()
    }

    /// A kernel handle closed when dropped.
    struct Owned(HANDLE);
    // SAFETY: kernel handles may be used and closed from any thread.
    unsafe impl Send for Owned {}
    // SAFETY: as above; the job handle is only passed to thread-safe calls.
    unsafe impl Sync for Owned {}
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: the handle is owned and closed once.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the key is owned and closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    /// The installation directory that the installer recorded in `HKLM\SOFTWARE\KROT`, where
    /// only administrators write.
    pub fn install_dir() -> Option<PathBuf> {
        let (key, name) = (wide("SOFTWARE\\KROT"), wide("InstallDir"));
        let mut size = 0u32;
        // SAFETY: the first call only reports the size; the second fills a buffer of that size.
        unsafe {
            if RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            ) != 0
                || size < 4
            {
                return None;
            }
            let mut buffer = vec![0u16; size as usize / 2 + 1];
            let mut size = (buffer.len() * 2) as u32;
            if RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            ) != 0
            {
                return None;
            }
            let length = buffer.iter().position(|&unit| unit == 0)?;
            let text = String::from_utf16(&buffer[..length]).ok()?;
            let path = PathBuf::from(text.trim_end_matches('\\'));
            path.is_absolute().then_some(path)
        }
    }

    /// This copy is the installed one: it runs from the directory the installer recorded. It
    /// uses the service for interception and the installer for updates.
    pub fn installed() -> bool {
        static INSTALLED: OnceLock<bool> = OnceLock::new();
        *INSTALLED.get_or_init(|| {
            let (Some(directory), Ok(program)) = (install_dir(), std::env::current_exe()) else {
                return false;
            };
            installed_program(&program, &directory)
        })
    }

    /// A program of the system directory, found through the system, not the environment.
    pub fn system_program(name: &str) -> PathBuf {
        let mut directory = [0u16; 260];
        // SAFETY: the buffer length matches the size passed to the call.
        let length = unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) };
        let directory = if length == 0 || length as usize >= directory.len() {
            "C:\\Windows\\System32".to_owned()
        } else {
            String::from_utf16_lossy(&directory[..length as usize])
        };
        PathBuf::from(directory).join(name)
    }

    /// The process of the running service, from the Service Control Manager.
    fn service_process() -> Option<u32> {
        let name = wide(NAME);
        // SAFETY: every handle is checked and closed; the status is a plain structure of the
        // size passed to the call.
        unsafe {
            let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if manager.is_null() {
                return None;
            }
            let service = OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS);
            let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
            let mut needed = 0;
            let read = !service.is_null()
                && QueryServiceStatusEx(
                    service,
                    SC_STATUS_PROCESS_INFO,
                    (&raw mut status).cast(),
                    size_of::<SERVICE_STATUS_PROCESS>() as u32,
                    &mut needed,
                ) != 0;
            if !service.is_null() {
                CloseServiceHandle(service);
            }
            CloseServiceHandle(manager);
            (read && status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0)
                .then_some(status.dwProcessId)
        }
    }

    /// Opens the service's pipe and makes sure that the service itself holds its other end:
    /// a program that took the name first would otherwise receive the request and its token.
    fn connect() -> Result<std::fs::File> {
        let deadline = Instant::now() + CLIENT_TIME;
        loop {
            let opened = std::fs::OpenOptions::new()
                .access_mode(CLIENT_ACCESS)
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(PIPE);
            match opened {
                Ok(pipe) => {
                    let mut server = 0;
                    // SAFETY: the handle is an open pipe; the call writes one u32.
                    let known =
                        unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server) }
                            != 0;
                    ensure!(
                        known && Some(server) == service_process(),
                        "Канал перехвата открыт не службой КРОТа; запрос не отправлен."
                    );
                    return Ok(pipe);
                }
                Err(error)
                    if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                        && Instant::now() < deadline =>
                {
                    // SAFETY: the name is NUL-terminated.
                    unsafe { WaitNamedPipeW(wide(PIPE).as_ptr(), 500) };
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => bail!(
                    "Служба перехвата КРОТа не запущена. Запустите службу «КРОТ: перехват приложений» или переустановите КРОТ."
                ),
                Err(error) => {
                    return Err(error).context("Не удалось подключиться к службе перехвата КРОТа.");
                }
            }
        }
    }

    /// Asks the service for a helper attached to the background КРОТ of `config`.
    pub fn request(config: &Path) -> Result<()> {
        let store = crate::config::Store::new(config)?;
        let (port, token) =
            crate::background::endpoint(&store)?.context("Фоновый КРОТ не запущен.")?;
        let (_, key) = crate::autostart::registration(&store.path)?;
        let mut request = Request {
            version: env!("CARGO_PKG_VERSION").into(),
            key,
            port,
            token: token.as_str().to_owned(),
        };
        let encoded = serde_json::to_vec(&request);
        request.token.zeroize();
        let mut line = Zeroizing::new(encoded?);
        line.push(b'\n');
        let mut pipe = connect()?;
        pipe.write_all(&line)
            .context("Служба перехвата КРОТа не приняла запрос.")?;
        let mut answer = Vec::new();
        std::io::BufReader::new(&pipe)
            .take(MAX_MESSAGE as u64 + 1)
            .read_until(b'\n', &mut answer)
            .context("Служба перехвата КРОТа не ответила.")?;
        ensure!(
            answer.len() <= MAX_MESSAGE && answer.last() == Some(&b'\n'),
            "Служба перехвата КРОТа не ответила."
        );
        let reply: Reply =
            serde_json::from_slice(&answer).context("Некорректный ответ службы перехвата.")?;
        ensure!(
            reply.ok,
            "{}",
            reply.error.chars().take(400).collect::<String>()
        );
        Ok(())
    }

    /// One instance of the service's pipe, used with overlapped I/O so that a silent client
    /// cannot hold a thread of the service forever.
    struct Pipe {
        handle: Owned,
        event: Owned,
    }

    impl Pipe {
        fn create(first: bool) -> Result<Self> {
            let sddl = wide(PIPE_SDDL);
            let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: the string is NUL-terminated; the descriptor is freed with LocalFree.
            ensure!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        SDDL_REVISION_1,
                        &mut descriptor,
                        std::ptr::null_mut(),
                    )
                } != 0,
                last_error()
            );
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let name = wide(PIPE);
            let mode = PIPE_ACCESS_DUPLEX
                | FILE_FLAG_OVERLAPPED
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                };
            // SAFETY: the name and the attributes outlive the call.
            let handle = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    mode,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    MAX_MESSAGE as u32,
                    MAX_MESSAGE as u32,
                    0,
                    &attributes,
                )
            };
            let error = last_error();
            // SAFETY: the descriptor came from the conversion above.
            unsafe { LocalFree(descriptor as HLOCAL) };
            ensure!(handle != INVALID_HANDLE_VALUE, error);
            let handle = Owned(handle);
            // SAFETY: a manual-reset event without a name or inheritance.
            let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            ensure!(!event.is_null(), last_error());
            Ok(Self {
                handle,
                event: Owned(event),
            })
        }

        fn overlapped(&self) -> OVERLAPPED {
            // SAFETY: an all-zero OVERLAPPED is valid; the event signals the completion.
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            overlapped.hEvent = self.event.0;
            overlapped
        }

        /// Finishes an overlapped operation that `started` began, waiting up to `timeout`.
        fn finish(&self, overlapped: &OVERLAPPED, started: bool, timeout: u32) -> Result<u32> {
            let mut count = 0;
            if !started {
                // SAFETY: reads the calling thread's last error.
                let error = unsafe { GetLastError() };
                ensure!(
                    error == ERROR_IO_PENDING,
                    std::io::Error::from_raw_os_error(error as i32)
                );
                // SAFETY: the event belongs to this pipe; on a timeout the operation is
                // cancelled and awaited, so neither the buffer nor `overlapped` is used later.
                unsafe {
                    if WaitForSingleObject(self.event.0, timeout) != WAIT_OBJECT_0 {
                        CancelIoEx(self.handle.0, overlapped);
                        GetOverlappedResult(self.handle.0, overlapped, &mut count, 1);
                        bail!("Клиент службы перехвата не ответил вовремя.");
                    }
                }
            }
            // SAFETY: the operation has completed.
            ensure!(
                unsafe { GetOverlappedResult(self.handle.0, overlapped, &mut count, 0) } != 0,
                last_error()
            );
            Ok(count)
        }

        /// Waits for a client.
        fn accept(&self) -> Result<()> {
            let overlapped = self.overlapped();
            // SAFETY: `overlapped` lives until the operation completes in `finish`.
            if unsafe { ConnectNamedPipe(self.handle.0, (&raw const overlapped).cast_mut()) } != 0 {
                return Ok(());
            }
            // SAFETY: reads the calling thread's last error.
            if unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                return Ok(());
            }
            self.finish(&overlapped, false, INFINITE).map(|_| ())
        }

        fn read(&self, buffer: &mut [u8], timeout: Duration) -> Result<usize> {
            let overlapped = self.overlapped();
            // SAFETY: the buffer and `overlapped` live until the operation completes.
            let started = unsafe {
                ReadFile(
                    self.handle.0,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    std::ptr::null_mut(),
                    (&raw const overlapped).cast_mut(),
                )
            } != 0;
            Ok(self.finish(&overlapped, started, timeout.as_millis() as u32)? as usize)
        }

        fn read_line(&self, deadline: Instant) -> Result<Zeroizing<Vec<u8>>> {
            let mut line = Zeroizing::new(Vec::new());
            let mut buffer = Zeroizing::new([0u8; 512]);
            while !line.contains(&b'\n') {
                ensure!(
                    line.len() <= MAX_MESSAGE,
                    "Запрос к службе перехвата слишком велик."
                );
                let left = deadline.saturating_duration_since(Instant::now());
                ensure!(
                    !left.is_zero(),
                    "Клиент службы перехвата не ответил вовремя."
                );
                let count = self.read(&mut buffer[..], left)?;
                ensure!(count > 0, "Клиент службы перехвата закрыл канал.");
                line.extend_from_slice(&buffer[..count]);
            }
            ensure!(
                line.len() <= MAX_MESSAGE && line.last() == Some(&b'\n'),
                "Некорректный запрос к службе перехвата."
            );
            Ok(line)
        }

        fn write_all(&self, mut data: &[u8], deadline: Instant) -> Result<()> {
            while !data.is_empty() {
                let overlapped = self.overlapped();
                // SAFETY: the data and `overlapped` live until the operation completes.
                let started = unsafe {
                    WriteFile(
                        self.handle.0,
                        data.as_ptr(),
                        data.len() as u32,
                        std::ptr::null_mut(),
                        (&raw const overlapped).cast_mut(),
                    )
                } != 0;
                let left = deadline.saturating_duration_since(Instant::now());
                let count = self.finish(&overlapped, started, left.as_millis() as u32)?;
                ensure!(count > 0, "Клиент службы перехвата закрыл канал.");
                data = &data[count as usize..];
            }
            Ok(())
        }

        /// Waits until the client has read the reply and closed its end.
        fn drain(&self, deadline: Instant) {
            let mut buffer = [0u8; 64];
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match self.read(&mut buffer, left) {
                    Ok(count) if count > 0 && !left.is_zero() => continue,
                    _ => return,
                }
            }
        }

        /// Who holds the other end: the user and session of its token, checked against the
        /// process that opened the pipe, and that process's program.
        fn client(&self) -> Result<Client> {
            let mut process = 0;
            // SAFETY: the handle is a connected pipe; the call writes one u32.
            ensure!(
                unsafe { GetNamedPipeClientProcessId(self.handle.0, &mut process) } != 0,
                "Не удалось определить клиента службы перехвата."
            );
            let mut token = std::ptr::null_mut();
            // SAFETY: the impersonation ends right after the token is opened; a thread that
            // cannot revert would act as the client, so the process ends instead.
            let opened = unsafe {
                ensure!(
                    ImpersonateNamedPipeClient(self.handle.0) != 0,
                    "Не удалось проверить клиента службы перехвата."
                );
                let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
                if RevertToSelf() == 0 {
                    std::process::abort();
                }
                opened
            };
            ensure!(
                opened != 0,
                "Не удалось проверить клиента службы перехвата."
            );
            let token = Owned(token);
            let user =
                token_user(token.0).context("Не удалось определить пользователя клиента.")?;
            let mut session = 0u32;
            let mut length = 0;
            // SAFETY: the buffer is one u32, as TokenSessionId returns.
            ensure!(
                unsafe {
                    GetTokenInformation(
                        token.0,
                        TokenSessionId,
                        (&raw mut session).cast(),
                        size_of::<u32>() as u32,
                        &mut length,
                    )
                } != 0,
                "Не удалось определить сеанс клиента."
            );
            ensure!(
                process_session(process) == Some(session),
                "Клиент службы перехвата относится к другому сеансу."
            );
            let program =
                process_image(process).context("Не удалось определить программу клиента.")?;
            Ok(Client {
                user,
                session,
                program: PathBuf::from(program),
            })
        }
    }

    struct Client {
        user: String,
        session: u32,
        program: PathBuf,
    }

    /// The user of a token as a string SID.
    fn token_user(token: HANDLE) -> Option<String> {
        let mut length = 0;
        // SAFETY: the first call only reports the size; the buffer is aligned for TOKEN_USER;
        // the string is released with LocalFree.
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
            if (length as usize) < size_of::<TOKEN_USER>() {
                return None;
            }
            let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
            if GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            ) == 0
            {
                return None;
            }
            let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            let mut text = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
                return None;
            }
            let length = (0..).take_while(|&i| *text.add(i) != 0).count();
            let sid = String::from_utf16(std::slice::from_raw_parts(text, length)).ok();
            LocalFree(text as HLOCAL);
            sid
        }
    }

    /// The user a process runs as, for the helper's scope.
    pub(crate) fn process_user(pid: u32) -> Option<String> {
        // SAFETY: both handles are checked and closed.
        unsafe {
            let process = Owned(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid));
            if process.0.is_null() {
                return None;
            }
            let mut token = std::ptr::null_mut();
            if OpenProcessToken(process.0, TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let token = Owned(token);
            token_user(token.0)
        }
    }

    fn process_session(pid: u32) -> Option<u32> {
        let mut session = 0;
        // SAFETY: writes one u32 through a valid pointer.
        (unsafe { ProcessIdToSessionId(pid, &mut session) } != 0).then_some(session)
    }

    fn process_image(pid: u32) -> Option<String> {
        // SAFETY: the handle is checked and closed; the buffer outlives the call.
        unsafe {
            let process = Owned(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid));
            if process.0.is_null() {
                return None;
            }
            let mut buffer = [0u16; 1024];
            let mut length = buffer.len() as u32;
            (QueryFullProcessImageNameW(process.0, 0, buffer.as_mut_ptr(), &mut length) != 0)
                .then(|| String::from_utf16_lossy(&buffer[..length as usize]))
        }
    }

    struct Helper {
        port: u16,
        token: Zeroizing<String>,
        child: Child,
        /// The helper's relay port, which it reports once its firewall rule exists.
        relay: Arc<AtomicU16>,
    }

    impl Helper {
        /// Ends the helper and removes its firewall rule, which a killed helper leaves.
        fn end(mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.forget();
        }

        fn forget(&self) {
            let port = self.relay.load(Ordering::Acquire);
            if port != 0 {
                crate::divert::close_service_firewall(port);
            }
        }
    }

    /// The running service: its helpers and the job that ends them with the service.
    struct Host {
        program: PathBuf,
        directory: PathBuf,
        job: Owned,
        helpers: Mutex<HashMap<(u32, String, String), Helper>>,
        clients: AtomicUsize,
    }

    impl Host {
        fn start() -> Result<Arc<Self>> {
            let program = std::env::current_exe()?;
            let directory = program
                .parent()
                .context("Не найден каталог службы.")?
                .to_path_buf();
            // SAFETY: an unnamed job; the limits are a plain structure of the size passed.
            let job = unsafe {
                let job = Owned(CreateJobObjectW(std::ptr::null(), std::ptr::null()));
                ensure!(!job.0.is_null(), last_error());
                let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                ensure!(
                    SetInformationJobObject(
                        job.0,
                        JobObjectExtendedLimitInformation,
                        (&raw const limits).cast::<c_void>(),
                        size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    ) != 0,
                    last_error()
                );
                job
            };
            // Helpers of a service that ended abruptly may have left their rules.
            crate::divert::clear_service_firewall();
            let host = Arc::new(Self {
                program,
                directory,
                job,
                helpers: Mutex::new(HashMap::new()),
                clients: AtomicUsize::new(0),
            });
            let listener = host.clone();
            std::thread::Builder::new()
                .name("pipe".into())
                .spawn(move || listener.listen())?;
            Ok(host)
        }

        fn stop(&self) {
            for (_, helper) in self.helpers.lock().unwrap().drain() {
                helper.end();
            }
            crate::divert::clear_service_firewall();
        }

        fn listen(self: Arc<Self>) {
            // The first instance fails while another program holds the name. The service runs
            // on and tries again: failing would roll back an installation, and clients check
            // that the service itself answers anyway.
            let mut pipe = loop {
                match Pipe::create(true) {
                    Ok(pipe) => break pipe,
                    Err(_) => std::thread::sleep(Duration::from_secs(1)),
                }
            };
            loop {
                let connected = pipe.accept();
                // The next instance exists before this one is handed over.
                let next = loop {
                    match Pipe::create(false) {
                        Ok(next) => break next,
                        Err(_) => std::thread::sleep(Duration::from_secs(1)),
                    }
                };
                let current = std::mem::replace(&mut pipe, next);
                if connected.is_err() {
                    continue;
                }
                if self.clients.fetch_add(1, Ordering::AcqRel) >= MAX_CLIENTS {
                    self.clients.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }
                let host = self.clone();
                let spawned = std::thread::Builder::new().spawn(move || {
                    host.serve(&current);
                    host.clients.fetch_sub(1, Ordering::AcqRel);
                });
                if spawned.is_err() {
                    self.clients.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }

        fn serve(&self, pipe: &Pipe) {
            let deadline = Instant::now() + CLIENT_TIME;
            let reply = match self.answer(pipe, deadline) {
                Ok(()) => Reply {
                    ok: true,
                    error: String::new(),
                },
                // Only messages written here leave the service, never system details.
                Err(error) => Reply {
                    ok: false,
                    error: error.to_string().chars().take(400).collect(),
                },
            };
            let Ok(mut line) = serde_json::to_vec(&reply) else {
                return;
            };
            line.push(b'\n');
            if pipe.write_all(&line, deadline).is_ok() {
                pipe.drain(deadline);
            }
        }

        fn answer(&self, pipe: &Pipe, deadline: Instant) -> Result<()> {
            // Impersonation needs the client's data read first.
            let line = pipe.read_line(deadline)?;
            let client = pipe.client()?;
            ensure!(
                installed_program(&client.program, &self.directory),
                "Служба перехвата обслуживает только установленный КРОТ."
            );
            let request: Request =
                serde_json::from_slice(&line).context("Некорректный запрос к службе перехвата.")?;
            request.validate()?;
            self.assign(client, request)
        }

        /// Starts the helper for the client's configuration unless it already runs for the
        /// same background process; a helper of an earlier background process is replaced.
        fn assign(&self, client: Client, mut request: Request) -> Result<()> {
            let mut helpers = self.helpers.lock().unwrap();
            // A helper that ended by itself removed its rule, unless it crashed.
            helpers.retain(|_, helper| {
                let running = matches!(helper.child.try_wait(), Ok(None));
                if !running {
                    helper.forget();
                }
                running
            });
            let key = (client.session, client.user.clone(), request.key.clone());
            if let Some(helper) = helpers.get(&key)
                && helper.port == request.port
                && *helper.token == request.token
            {
                return Ok(());
            }
            if let Some(helper) = helpers.remove(&key) {
                helper.end();
            }
            ensure!(
                helpers.len() < MAX_HELPERS
                    && helpers
                        .keys()
                        .filter(|(_, user, _)| *user == client.user)
                        .count()
                        < MAX_USER_HELPERS,
                "Служба перехвата уже обслуживает слишком много конфигураций."
            );
            let token = Zeroizing::new(std::mem::take(&mut request.token));
            let mut assignment = Assignment {
                port: request.port,
                token: token.as_str().to_owned(),
                session: client.session,
                user: client.user,
            };
            let encoded = serde_json::to_vec(&assignment);
            assignment.token.zeroize();
            let mut data = Zeroizing::new(encoded?);
            data.push(b'\n');
            let mut child = Command::new(&self.program)
                .arg("divert-service")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .context("Служба не запустила помощник перехвата.")?;
            // SAFETY: both handles are valid; the job ends the helper with the service.
            let joined =
                unsafe { AssignProcessToJobObject(self.job.0, child.as_raw_handle()) } != 0;
            let written = joined
                && child
                    .stdin
                    .take()
                    .is_some_and(|mut input| input.write_all(&data).is_ok());
            if !written {
                let _ = child.kill();
                let _ = child.wait();
                bail!("Служба не запустила помощник перехвата.");
            }
            let relay = Arc::new(AtomicU16::new(0));
            if let Some(output) = child.stdout.take() {
                let relay = relay.clone();
                // Only a port number is read; the helper writes nothing else there.
                let _ = std::thread::Builder::new().spawn(move || {
                    let mut line = String::new();
                    let _ = std::io::BufReader::new(output.take(16)).read_line(&mut line);
                    if let Ok(port) = line.trim().parse::<u16>() {
                        relay.store(port, Ordering::Release);
                    }
                });
            }
            helpers.insert(
                key,
                Helper {
                    port: request.port,
                    token,
                    child,
                    relay,
                },
            );
            Ok(())
        }
    }

    static STATUS: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    static STOP: Mutex<bool> = Mutex::new(false);
    static STOPPED: Condvar = Condvar::new();

    fn report(state: u32, exit: u32) {
        let handle = STATUS.load(Ordering::Acquire);
        if handle.is_null() {
            return;
        }
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: exit,
            dwServiceSpecificExitCode: u32::from(exit != 0),
            dwCheckPoint: 0,
            dwWaitHint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
                10_000
            } else {
                0
            },
        };
        // SAFETY: the handle came from RegisterServiceCtrlHandlerExW.
        unsafe { SetServiceStatus(handle, &status) };
    }

    unsafe extern "system" fn control(
        code: u32,
        _event: u32,
        _data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        match code {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                report(SERVICE_STOP_PENDING, 0);
                *STOP.lock().unwrap() = true;
                STOPPED.notify_all();
                NO_ERROR
            }
            SERVICE_CONTROL_INTERROGATE => NO_ERROR,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    unsafe extern "system" fn service_main(_count: u32, _arguments: *mut windows_sys::core::PWSTR) {
        let name = wide(NAME);
        // SAFETY: the name is NUL-terminated; the handler is a static function.
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), std::ptr::null())
        };
        if handle.is_null() {
            return;
        }
        STATUS.store(handle, Ordering::Release);
        report(SERVICE_START_PENDING, 0);
        let Ok(host) = Host::start() else {
            report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
            return;
        };
        report(SERVICE_RUNNING, 0);
        let mut stop = STOP.lock().unwrap();
        while !*stop {
            stop = STOPPED.wait(stop).unwrap();
        }
        drop(stop);
        host.stop();
        report(SERVICE_STOPPED, 0);
    }

    /// Runs as the service `KrotDivert`; the Service Control Manager starts it.
    pub fn run() -> Result<()> {
        let mut name = wide(NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_mut_ptr(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];
        // SAFETY: the table ends with an empty entry and outlives the dispatcher.
        ensure!(
            unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0,
            "Эту команду запускает только диспетчер служб Windows."
        );
        Ok(())
    }

    /// Ends every КРОТ process of the installation but this one: the uninstaller removes
    /// their files next.
    fn stop_processes(directory: &Path) {
        // SAFETY: returns the identifier of the calling process.
        let own = unsafe { GetCurrentProcessId() };
        let mut pids = Vec::new();
        // SAFETY: the snapshot handle is checked and closed; the entry is sized as required.
        unsafe {
            let snapshot = Owned(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            if snapshot.0 == INVALID_HANDLE_VALUE {
                return;
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let mut more = Process32FirstW(snapshot.0, &mut entry) != 0;
            while more {
                pids.push(entry.th32ProcessID);
                more = Process32NextW(snapshot.0, &mut entry) != 0;
            }
        }
        for pid in pids.into_iter().filter(|&pid| pid != own && pid != 0) {
            let Some(image) = process_image(pid) else {
                continue;
            };
            if !installed_program(Path::new(&image), directory) {
                continue;
            }
            // SAFETY: the handle is checked and closed. The wait lets Windows Installer replace
            // the files right after: a file still mapped by a process is only replaced at reboot.
            unsafe {
                let process = Owned(OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, 0, pid));
                if !process.0.is_null() && TerminateProcess(process.0, 1) != 0 {
                    WaitForSingleObject(process.0, 10_000);
                }
            }
        }
    }

    /// Removes the `Run` values of every signed-in user that start the installed program.
    /// The keys are opened as links, so a link planted in a user's hive leads nowhere else.
    fn remove_run_values(program: &str) {
        let mut users = Vec::new();
        for index in 0.. {
            let mut name = [0u16; 256];
            let mut length = name.len() as u32;
            // SAFETY: the buffer and its length match.
            let status = unsafe {
                RegEnumKeyExW(
                    HKEY_USERS,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status == 0 {
                users.push(String::from_utf16_lossy(&name[..length as usize]));
            }
        }
        for user in users {
            let path = wide(&format!(
                "{user}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            ));
            let mut key: HKEY = std::ptr::null_mut();
            // SAFETY: the path is NUL-terminated; the key is closed by `Key`.
            if unsafe {
                RegOpenKeyExW(
                    HKEY_USERS,
                    path.as_ptr(),
                    REG_OPTION_OPEN_LINK,
                    KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS,
                    &mut key,
                )
            } != 0
            {
                continue;
            }
            let key = Key(key);
            let mut doomed = Vec::new();
            for index in 0.. {
                let mut name = vec![0u16; 16384];
                let mut name_length = name.len() as u32;
                let mut data = vec![0u16; 4096];
                let mut data_length = (data.len() * 2) as u32;
                let mut kind = 0u32;
                // SAFETY: both buffers match the lengths passed.
                let status = unsafe {
                    RegEnumValueW(
                        key.0,
                        index,
                        name.as_mut_ptr(),
                        &mut name_length,
                        std::ptr::null(),
                        &mut kind,
                        data.as_mut_ptr().cast(),
                        &mut data_length,
                    )
                };
                if status == ERROR_NO_MORE_ITEMS {
                    break;
                }
                if status != 0 || kind != REG_SZ {
                    continue;
                }
                let name = String::from_utf16_lossy(&name[..name_length as usize]);
                let units = &data[..(data_length as usize / 2).min(data.len())];
                let end = units
                    .iter()
                    .position(|&unit| unit == 0)
                    .unwrap_or(units.len());
                let command = String::from_utf16_lossy(&units[..end]);
                if installed_run_value(&name, &command, program) {
                    doomed.push(name);
                }
            }
            for name in doomed {
                let name = wide(&name);
                // SAFETY: the key is open for setting values; the name is NUL-terminated.
                unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
            }
        }
    }

    /// Run by the installer as LocalSystem before it replaces the files in `directory`: a
    /// running КРОТ there, for example a portable copy unpacked into the same folder, would
    /// keep its older files until a reboot, and the service would start the older program.
    /// Copies in other folders go on running.
    pub fn prepare_install(directory: &Path) -> Result<()> {
        ensure!(
            directory.is_absolute(),
            "Каталог установки должен быть абсолютным путём."
        );
        stop_processes(directory);
        Ok(())
    }

    /// Run by the uninstaller as LocalSystem before it removes the files: ends the running
    /// КРОТ of this installation and removes what it registered outside its directory.
    /// Each step goes on when another fails; nothing is opened in a user's profile.
    pub fn cleanup() -> Result<()> {
        ensure!(installed(), "Команду выполняет только установщик КРОТа.");
        let program = std::env::current_exe()?;
        let directory = program.parent().context("Не найден каталог КРОТа.")?;
        let krot = directory.join("krot.exe");
        let krot = krot
            .to_str()
            .context("Путь программы не является корректным Unicode.")?;
        stop_processes(directory);
        let tasks = crate::tasks::remove_program_tasks(krot);
        remove_run_values(krot);
        crate::divert::clear_service_firewall();
        tasks
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_pipe_descriptor_is_valid() {
            let sddl = wide(PIPE_SDDL);
            let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: as in `Pipe::create`.
            unsafe {
                assert_ne!(
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        SDDL_REVISION_1,
                        &mut descriptor,
                        std::ptr::null_mut(),
                    ),
                    0
                );
                LocalFree(descriptor as HLOCAL);
            }
            // Users get no FILE_APPEND_DATA (0x4), which creates pipe instances.
            assert_eq!(0x12008b & 0x4, 0);
            assert_eq!(CLIENT_ACCESS & !0x12008b, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            version: env!("CARGO_PKG_VERSION").into(),
            key: "krot-0123456789abcdef".into(),
            port: 40000,
            token: "ab".repeat(32),
        }
    }

    #[test]
    fn requests_are_strict_about_version_key_port_and_token() {
        request().validate().unwrap();
        let mut other = request();
        other.version = "0.0.1".into();
        assert!(other.validate().is_err());
        for key in ["", "KROT-0123", "krot/../x", &"k".repeat(65)] {
            let mut other = request();
            other.key = key.into();
            assert!(other.validate().is_err(), "{key}");
        }
        let mut other = request();
        other.port = 0;
        assert!(other.validate().is_err());
        for token in ["ab".repeat(31), "AB".repeat(32), "zz".repeat(32)] {
            let mut other = request();
            other.token = token;
            assert!(other.validate().is_err());
        }
        let extra = serde_json::json!({
            "version": "1", "key": "k", "port": 1, "token": "t", "session": 0
        });
        assert!(serde_json::from_value::<Request>(extra).is_err());
    }

    #[test]
    fn only_programs_of_the_installation_are_served() {
        let directory = Path::new("C:\\Program Files\\KROT");
        assert!(installed_program(
            Path::new("c:\\program files\\krot\\KROT.EXE"),
            directory
        ));
        assert!(installed_program(
            Path::new("\\\\?\\C:\\Program Files\\KROT\\krot-cli.exe"),
            Path::new("C:\\Program Files\\KROT\\")
        ));
        assert!(!installed_program(
            Path::new("C:\\Users\\a\\KROT\\krot.exe"),
            directory
        ));
        assert!(!installed_program(
            Path::new("C:\\Program Files\\KROT\\other.exe"),
            directory
        ));
        assert!(!installed_program(
            Path::new("C:\\Program Files\\KROT\\sub\\krot.exe"),
            directory
        ));
    }

    #[test]
    fn only_autostart_values_of_the_installed_program_are_removed() {
        let program = "C:\\Program Files\\KROT\\krot.exe";
        let command = "\"C:\\Program Files\\KROT\\krot.exe\" --config C:\\Users\\a\\c.json serve";
        assert!(installed_run_value(
            "krot-0123456789abcdef",
            command,
            program
        ));
        assert!(installed_run_value(
            "krot-0123456789abcdef",
            &command.to_lowercase(),
            program
        ));
        assert!(!installed_run_value("krot-0123", command, program));
        assert!(!installed_run_value("OneDrive", command, program));
        assert!(!installed_run_value(
            "krot-0123456789abcdef",
            "\"C:\\Users\\a\\KROT\\krot.exe\" --config c.json serve",
            program
        ));
        assert!(!installed_run_value(
            "krot-0123456789abcdef",
            "\"C:\\Program Files\\KROT\\krot.exe.bak\" serve",
            program
        ));
    }
}
