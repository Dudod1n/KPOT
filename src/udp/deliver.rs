//! Uploading `krot-relay` to the SSH server and starting it through exec channels.
//!
//! Every command runs as `/bin/sh -c '<fixed script>' krot <arguments>`: the login shell may be
//! fish or csh, and positional arguments keep the script free of quoting. Arguments are only
//! hashes; no secret ever appears in a command line.
//!
//! 1. `PROBE` prints a marker with `uname -s` and `uname -m`. No marker means the server runs
//!    something else for every command (`ForceCommand`) or has no shell.
//! 2. `ENSURE` checks `~/.cache/krot/krot-relay-<hash>`; when it is missing or differs it
//!    asks for the bytes, stores them in a temporary file, checks the hash and renames.
//! 3. `RUN` checks the hash again and `exec`s the relay.
use std::fmt;

/// Exit codes of the scripts, besides the shell's own 126 and 127.
pub mod code {
    /// `RUN`: the file is missing or its hash differs.
    pub const CHANGED: u32 = 90;
    pub const NO_HASH_TOOL: u32 = 93;
    pub const NO_HOME: u32 = 94;
    /// The cache directory is a symbolic link or belongs to someone else.
    pub const UNSAFE_DIRECTORY: u32 = 95;
    pub const NOT_WRITABLE: u32 = 96;
    /// The uploaded bytes do not have the expected hash.
    pub const CORRUPTED: u32 = 97;
    /// The shell could not execute the file: `noexec` or a foreign format.
    pub const NOT_EXECUTABLE: u32 = 126;
    pub const NOT_FOUND: u32 = 127;
}

pub const MARKER: &str = "KROT1";
pub const NEED: &str = "KROT-NEED";
pub const HAVE: &str = "KROT-HAVE";
pub const STORED: &str = "KROT-STORED";

pub const PROBE: &str = r#"printf "KROT1 %s %s\n" "$(uname -s)" "$(uname -m)""#;

/// Selects a SHA-256 tool and prepares the cache directory; `$1` is the short hash.
const PREPARE: &str = r#"if command -v sha256sum >/dev/null 2>&1; then H="sha256sum"
elif command -v shasum >/dev/null 2>&1; then H="shasum -a 256"
elif command -v openssl >/dev/null 2>&1; then H="openssl dgst -sha256 -r"
else exit 93; fi
h() { $H < "$1" | cut -c1-64; }
[ -n "$HOME" ] || exit 94
d="$HOME/.cache/krot"
[ -L "$d" ] && exit 95
umask 077
mkdir -p "$d" 2>/dev/null || exit 96
[ -O "$d" ] || exit 95
chmod 700 "$d" 2>/dev/null || exit 96
f="$d/krot-relay-$1"
"#;

const ENSURE_TAIL: &str = r#"if [ -f "$f" ] && [ "$(h "$f")" = "$2" ]; then echo KROT-HAVE; exit 0; fi
t="$d/.upload.$$"
rm -f "$t"
echo KROT-NEED
cat > "$t" 2>/dev/null || { rm -f "$t"; exit 96; }
[ "$(h "$t")" = "$2" ] || { rm -f "$t"; exit 97; }
chmod 700 "$t" && mv -f "$t" "$f" || { rm -f "$t"; exit 96; }
for o in "$d"/krot-relay-*; do [ "$o" = "$f" ] || rm -f "$o"; done
echo KROT-STORED
"#;

const RUN_TAIL: &str = r#"[ -f "$f" ] && [ "$(h "$f")" = "$2" ] || exit 90
exec "$f"
"#;

pub fn ensure_script() -> String {
    format!("{PREPARE}{ENSURE_TAIL}")
}

pub fn run_script() -> String {
    format!("{PREPARE}{RUN_TAIL}")
}

/// A hash short enough for a file name and long enough to tell versions apart.
pub fn short(sha256: &str) -> &str {
    &sha256[..16]
}

/// The exec command for `script` with plain-token arguments.
pub fn command(script: &str, arguments: &[&str]) -> String {
    assert!(!script.contains('\''), "scripts are single-quoted");
    assert!(
        arguments
            .iter()
            .all(|argument| !argument.is_empty()
                && argument.bytes().all(|b| b.is_ascii_alphanumeric())),
        "arguments are plain tokens"
    );
    let mut command = format!("/bin/sh -c '{script}' krot");
    for argument in arguments {
        command.push(' ');
        command.push_str(argument);
    }
    command
}

/// Why the relay cannot run on this server, worded for the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    /// The server refused to run commands or to open the channel.
    NoExec,
    /// The server answered the probe with something else.
    NoShell,
    UnsupportedSystem,
    UnsupportedMachine,
    /// This build carries no relay for the server's architecture.
    NotBuilt,
    NoHashTool,
    NoHome,
    UnsafeDirectory,
    NotWritable,
    Corrupted,
    NotExecutable,
    /// The relay speaks another protocol version.
    Version,
    /// The relay stopped or did not answer.
    Failed,
}

impl Problem {
    pub fn from_exit(code: u32) -> Self {
        match code {
            code::NO_HASH_TOOL => Self::NoHashTool,
            code::NO_HOME => Self::NoHome,
            code::UNSAFE_DIRECTORY => Self::UnsafeDirectory,
            code::NOT_WRITABLE => Self::NotWritable,
            code::CORRUPTED => Self::Corrupted,
            code::NOT_EXECUTABLE => Self::NotExecutable,
            code::NOT_FOUND => Self::NoShell,
            _ => Self::Failed,
        }
    }

    /// Whether trying again later may help without a change on the server.
    pub fn retryable(self) -> bool {
        matches!(self, Self::Failed | Self::Corrupted)
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::NoExec => "SSH-сервер не разрешает выполнять команды.",
            Self::NoShell => {
                "На SSH-сервере нет командной оболочки или вход ограничен одной командой (ForceCommand)."
            }
            Self::UnsupportedSystem => "Помощник UDP работает только на SSH-серверах с Linux.",
            Self::UnsupportedMachine => {
                "Архитектура SSH-сервера не поддерживается: нужен x86_64 или aarch64."
            }
            Self::NotBuilt => "Эта сборка КРОТа не содержит серверного помощника UDP.",
            Self::NoHashTool => {
                "На SSH-сервере нет sha256sum, shasum или openssl для проверки помощника."
            }
            Self::NoHome => "На SSH-сервере не задан домашний каталог.",
            Self::UnsafeDirectory => {
                "Каталог ~/.cache/krot на SSH-сервере — ссылка или принадлежит другому пользователю."
            }
            Self::NotWritable => "Каталог ~/.cache/krot на SSH-сервере недоступен для записи.",
            Self::Corrupted => "Помощник повредился при загрузке на SSH-сервер.",
            Self::NotExecutable => {
                "Помощник на SSH-сервере не запускается: домашний каталог, вероятно, смонтирован с noexec."
            }
            Self::Version => "Помощник на SSH-сервере другой версии.",
            Self::Failed => "Помощник UDP на SSH-сервере остановился.",
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// The system and machine from the probe output.
pub fn parse_probe(output: &str) -> Result<(&str, &str), Problem> {
    let line = output
        .lines()
        .find_map(|line| {
            line.strip_prefix(MARKER)
                .and_then(|rest| rest.strip_prefix(' '))
        })
        .ok_or(Problem::NoShell)?;
    let mut parts = line.split(' ');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(system), Some(machine), None) if !system.is_empty() && !machine.is_empty() => {
            Ok((system, machine))
        }
        _ => Err(Problem::NoShell),
    }
}

/// The relay for a probed server, or why there is none.
pub fn select(output: &str) -> Result<&'static crate::relay::Relay, Problem> {
    let (system, machine) = parse_probe(output)?;
    if system != "Linux" {
        return Err(Problem::UnsupportedSystem);
    }
    if !matches!(machine, "x86_64" | "amd64" | "aarch64" | "arm64") {
        return Err(Problem::UnsupportedMachine);
    }
    crate::relay::for_machine(machine).ok_or(Problem::NotBuilt)
}

#[cfg(all(test, unix))]
mod tests;

/// The relay running on the server behind an exec channel, with the transport over it.
pub struct Launched {
    pub transport: super::transport::Transport,
    pub events: tokio::sync::mpsc::Receiver<super::transport::Event>,
    /// The relay had to be uploaded first.
    pub uploaded: bool,
}

const EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const MAX_OUTPUT: usize = 4096;

/// Runs `command`, answers `KROT-NEED` with `upload`, and returns the exit code and stdout.
async fn exec<H: russh::client::Handler>(
    handle: &russh::client::Handle<H>,
    command: &str,
    upload: &[u8],
) -> Result<(Option<u32>, String), Problem> {
    use russh::ChannelMsg;
    let run = async {
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|_| Problem::NoExec)?;
        channel
            .exec(true, command)
            .await
            .map_err(|_| Problem::NoExec)?;
        let mut stdout = Vec::new();
        let mut code = None;
        let mut sent = false;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Failure => return Err(Problem::NoExec),
                ChannelMsg::Data { data } => {
                    if stdout.len() < MAX_OUTPUT {
                        stdout
                            .extend_from_slice(&data[..data.len().min(MAX_OUTPUT - stdout.len())]);
                    }
                    if !sent
                        && String::from_utf8_lossy(&stdout)
                            .lines()
                            .any(|line| line == NEED)
                    {
                        sent = true;
                        channel.data(upload).await.map_err(|_| Problem::Failed)?;
                        channel.eof().await.map_err(|_| Problem::Failed)?;
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok((code, String::from_utf8_lossy(&stdout).into_owned()))
    };
    tokio::time::timeout(EXEC_TIMEOUT, run)
        .await
        .map_err(|_| Problem::Failed)?
}

/// Makes sure the server holds the relay, starts it and greets it.
pub async fn launch<H: russh::client::Handler>(
    handle: &russh::client::Handle<H>,
    settings: krot_udp_proto::Settings,
) -> Result<Launched, Problem> {
    let (code, output) = exec(handle, &command(PROBE, &[]), b"").await?;
    if code.is_some_and(|code| code != 0) && parse_probe(&output).is_err() {
        return Err(Problem::from_exit(code.unwrap_or(0)).or_no_shell());
    }
    let relay = select(&output)?;
    let arguments = [short(relay.sha256), relay.sha256];
    let mut uploaded = false;
    // A file changed between the check and the start is uploaded again once.
    for _ in 0..2 {
        let (code, output) =
            exec(handle, &command(&ensure_script(), &arguments), relay.bytes).await?;
        match code {
            Some(0) if output.lines().any(|line| line == HAVE) => {}
            Some(0) if output.lines().any(|line| line == STORED) => uploaded = true,
            Some(code) => return Err(Problem::from_exit(code)),
            None => return Err(Problem::Failed),
        }
        match start(handle, &arguments, settings).await {
            Err(Some(code::CHANGED)) => continue,
            Err(Some(code)) => return Err(Problem::from_exit(code)),
            Err(None) => return Err(Problem::Failed),
            Ok(Err(problem)) => return Err(problem),
            Ok(Ok((transport, events))) => {
                return Ok(Launched {
                    transport,
                    events,
                    uploaded,
                });
            }
        }
    }
    Err(Problem::Failed)
}

type Started = Result<
    (
        super::transport::Transport,
        tokio::sync::mpsc::Receiver<super::transport::Event>,
    ),
    Problem,
>;

/// Starts the relay. `Err` carries the exit code when the relay never answered.
async fn start<H: russh::client::Handler>(
    handle: &russh::client::Handle<H>,
    arguments: &[&str],
    settings: krot_udp_proto::Settings,
) -> Result<Started, Option<u32>> {
    use super::transport::{Failure, Transport};
    use russh::ChannelMsg;
    use tokio::io::AsyncWriteExt;
    let channel = handle.channel_open_session().await.map_err(|_| None)?;
    channel
        .exec(true, command(&run_script(), arguments))
        .await
        .map_err(|_| None)?;
    let (mut reading, writing) = channel.split();
    // The relay's stdout feeds the transport; the exit status tells why it stopped.
    let (mut sink, source) = tokio::io::duplex(256 * 1024);
    let (exit_send, exit) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut exit_send = Some(exit_send);
        while let Some(message) = reading.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    if sink.write_all(&data).await.is_err() {
                        break;
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    if let Some(send) = exit_send.take() {
                        let _ = send.send(exit_status);
                    }
                }
                ChannelMsg::Failure | ChannelMsg::Eof | ChannelMsg::Close => {
                    if matches!(message, ChannelMsg::Close | ChannelMsg::Failure) {
                        break;
                    }
                }
                _ => {}
            }
        }
        let _ = sink.shutdown().await;
    });
    match Transport::start(source, writing.make_writer(), settings).await {
        Ok(started) => Ok(Ok(started)),
        Err(Failure::Version(_)) => Ok(Err(Problem::Version)),
        Err(_) => {
            let code = tokio::time::timeout(std::time::Duration::from_secs(2), exit)
                .await
                .ok()
                .and_then(Result::ok);
            Err(code)
        }
    }
}

impl Problem {
    /// A probe that failed without the marker means there is no usable shell.
    fn or_no_shell(self) -> Self {
        if self == Self::Failed {
            Self::NoShell
        } else {
            self
        }
    }
}
