//! Diagnostic journal of the background process and the interception helper: a file beside the
//! configuration that outlives the process, so a crash, a restart or a kill by an antivirus
//! leaves the time and the reason of the events before it.
//!
//! Records are locally authored texts. Secrets (passwords, passphrases, keys, the local
//! protocol token) are never passed here; errors that may echo request data go through
//! [`hide_values`] first.

use std::{
    cell::Cell,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use crate::config::{Store, restrict_access};

/// One file stays below this size; on overflow it becomes `<file>.1`, replacing the older part.
pub const MAX_BYTES: u64 = 1024 * 1024;
const MAX_LINE_CHARS: usize = 2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Info => "INFO ",
            Level::Warn => "WARN ",
            Level::Error => "ERROR",
        }
    }
}

pub fn background_path(store: &Store) -> PathBuf {
    store.sidecar(".log")
}

pub fn divert_path(store: &Store) -> PathBuf {
    store.sidecar(".divert.log")
}

pub fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".1");
    PathBuf::from(name)
}

struct Journal {
    path: PathBuf,
    file: Option<File>,
    size: u64,
}

impl Journal {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            file: None,
            size: 0,
        }
    }

    fn write<Zone: chrono::TimeZone>(
        &mut self,
        time: &chrono::DateTime<Zone>,
        level: Level,
        text: &str,
    ) where
        Zone::Offset: std::fmt::Display,
    {
        let line = format!(
            "{} {} {}\n",
            time.format("%Y-%m-%d %H:%M:%S%.3f %:z"),
            level.tag(),
            clean(text)
        );
        let length = line.len() as u64;
        if self.file.is_none() || self.size + length > MAX_BYTES {
            self.open(length);
        }
        if let Some(file) = &mut self.file {
            if file.write_all(line.as_bytes()).is_ok() {
                self.size += length;
            } else {
                self.file = None;
            }
        }
    }

    fn open(&mut self, incoming: u64) {
        self.file = None;
        let size = fs::metadata(&self.path).map_or(0, |metadata| metadata.len());
        // A part held open by another program cannot be replaced: the file starts anew instead
        // of growing past the bound.
        let overflow = size > 0
            && size + incoming > MAX_BYTES
            && fs::rename(&self.path, rotated_path(&self.path)).is_err();
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let Ok(file) = options.open(&self.path) else {
            return;
        };
        // Like the configuration: only its owner reads the journal; otherwise nothing is written.
        if restrict_access(&self.path).is_err() || (overflow && file.set_len(0).is_err()) {
            return;
        }
        self.size = file.metadata().map_or(0, |metadata| metadata.len());
        self.file = Some(file);
    }
}

static JOURNAL: OnceLock<Mutex<Journal>> = OnceLock::new();

/// Sends this process's records, panics included, to `path`. Later calls change nothing.
pub fn init(path: PathBuf) {
    if JOURNAL.set(Mutex::new(Journal::new(path))).is_err() {
        return;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // A panic inside `write` holds the lock: skip the record instead of a deadlock.
        if !WRITING.get() {
            write(Level::Error, &hide_values(&format!("Паника: {info}")));
        }
        previous(info);
    }));
}

thread_local! {
    static WRITING: Cell<bool> = const { Cell::new(false) };
}

struct Writing;

impl Drop for Writing {
    fn drop(&mut self) {
        WRITING.set(false);
    }
}

/// Appends a record if [`init`] was called; a failing disk never fails the caller.
pub fn write(level: Level, text: &str) {
    if let Some(journal) = JOURNAL.get() {
        WRITING.set(true);
        let _writing = Writing;
        let mut journal = journal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        journal.write(&chrono::Local::now(), level, text);
    }
}

/// Records the start once the process owns its configuration, so a refused second copy
/// does not look like a restart.
pub fn started(process: &str) {
    write(
        Level::Info,
        &format!(
            "{process} запущен: версия {}, PID {}.",
            env!("CARGO_PKG_VERSION"),
            std::process::id()
        ),
    );
}

/// Records the end of a process started with [`init`].
pub fn finished(process: &str, result: &anyhow::Result<()>) {
    let pid = std::process::id();
    match result {
        Ok(()) => write(Level::Info, &format!("{process} остановлен, PID {pid}.")),
        Err(error) => write(
            Level::Error,
            &format!(
                "{process} (PID {pid}) завершился с ошибкой: {}",
                hide_values(&format!("{error:#}"))
            ),
        ),
    }
}

/// Hides quoted values: serde and other parsers echo the rejected input, which may be a
/// password sent in a request, as `"value"` or `` `value` ``.
pub fn hide_values(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut open: Option<char> = None;
    let mut escaped = false;
    for character in text.chars() {
        match open {
            // `{:?}` escapes a quote inside the value: it does not end the value.
            Some(_) if escaped => escaped = false,
            Some(_) if character == '\\' => escaped = true,
            Some(quote) if character == quote => {
                result.push('…');
                result.push(quote);
                open = None;
            }
            Some(_) => {}
            None => {
                result.push(character);
                if character == '"' || character == '`' {
                    open = Some(character);
                }
            }
        }
    }
    if open.is_some() {
        result.push('…');
    }
    result
}

/// One record is one line: control characters, such as a server's newlines, become spaces.
fn clean(text: &str) -> String {
    text.chars()
        .take(MAX_LINE_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn time() -> chrono::DateTime<chrono::FixedOffset> {
        chrono::FixedOffset::east_opt(3 * 3600)
            .unwrap()
            .with_ymd_and_hms(2026, 11, 21, 10, 0, 0)
            .unwrap()
    }

    #[test]
    fn records_survive_a_new_process_and_carry_date_level_and_one_line() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json.log");
        Journal::new(path.clone()).write(&time(), Level::Warn, "первый\nзапуск\x1b[31m");
        // A new process appends instead of replacing the previous events.
        Journal::new(path.clone()).write(&time(), Level::Info, "второй");
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            "2026-11-21 10:00:00.000 +03:00 WARN  первый запуск [31m\n\
             2026-11-21 10:00:00.000 +03:00 INFO  второй\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn rotation_keeps_one_older_part_and_bounds_the_total() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json.log");
        let mut journal = Journal::new(path.clone());
        let text = "x".repeat(MAX_LINE_CHARS);
        for _ in 0..(3 * MAX_BYTES as usize / MAX_LINE_CHARS) {
            journal.write(&time(), Level::Info, &text);
        }
        journal.write(&time(), Level::Info, "последняя");
        let current = fs::metadata(&path).unwrap().len();
        let older = fs::metadata(rotated_path(&path)).unwrap().len();
        assert!(current <= MAX_BYTES && older <= MAX_BYTES);
        assert!(older > MAX_BYTES - 4096, "the older part is full");
        assert!(fs::read_to_string(&path).unwrap().ends_with("последняя\n"));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn a_part_that_cannot_be_replaced_does_not_unbound_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json.log");
        // Renaming onto a non-empty directory fails, like a part held open on Windows.
        fs::create_dir(rotated_path(&path)).unwrap();
        fs::write(rotated_path(&path).join("held"), "").unwrap();
        let mut journal = Journal::new(path.clone());
        let text = "x".repeat(MAX_LINE_CHARS);
        for _ in 0..(2 * MAX_BYTES as usize / MAX_LINE_CHARS) {
            journal.write(&time(), Level::Info, &text);
        }
        journal.write(&time(), Level::Info, "последняя");
        assert!(fs::metadata(&path).unwrap().len() <= MAX_BYTES);
        assert!(fs::read_to_string(&path).unwrap().ends_with("последняя\n"));
    }

    #[test]
    fn echoed_request_values_are_hidden() {
        let error = serde_json::from_value::<bool>(serde_json::json!("hunter2")).unwrap_err();
        let shown = hide_values(&format!("Некорректный ответ: {error}"));
        assert!(!shown.contains("hunter2"), "{shown}");
        assert_eq!(
            hide_values("unknown field `secret`, value \"pass"),
            "unknown field `…`, value \"…"
        );
        let error = serde_json::from_value::<bool>(serde_json::json!("a\"secret\\")).unwrap_err();
        let shown = hide_values(&error.to_string());
        assert!(!shown.contains("secret"), "{shown}");
        assert_eq!(shown, "invalid type: string \"…\", expected a boolean");
        assert_eq!(
            hide_values("«Туннель» без кавычек"),
            "«Туннель» без кавычек"
        );
    }
}
