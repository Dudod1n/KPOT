#![cfg(windows)]
//! Tasks of the Windows Task Scheduler through the real `schtasks.exe`.
//!
//! The test changes the system scheduler and the user's `Run` key, so it runs only with
//! `CI=true`: the hosted runner is a disposable administrator account. Elsewhere it is skipped
//! and leaves the user's tasks alone.
use krot::{
    autostart,
    config::{Config, Store},
    tasks::{self, Kind},
};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn schtasks(arguments: &[&str]) -> Output {
    Command::new("schtasks.exe")
        .args(arguments)
        .output()
        .expect("schtasks.exe starts")
}

/// `schtasks` prints XML in UTF-16 or in the console code page.
fn text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes.len().is_multiple_of(2) && bytes.contains(&0) {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// Names of every task that starts with `prefix`, if the scheduler lists them.
fn query(prefix: &str) -> Option<Vec<String>> {
    let output = Command::new("schtasks.exe")
        .args(["/query", "/fo", "csv", "/nh"])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let names = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix('"')?.split('"').next())
        .filter(|name| {
            name.get(..prefix.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
        })
        .map(str::to_owned)
        .collect();
    Some(names)
}

fn listed(prefix: &str) -> Vec<String> {
    query(prefix).expect("schtasks /query lists the tasks")
}

fn name(config: &Path) -> String {
    autostart::registration(config).unwrap().1
}

fn prefix(config: &Path, kind: &str) -> String {
    format!("\\{}-{kind}-", name(config))
}

fn cli(config: &Path, arguments: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_krot-cli"))
        .arg("--config")
        .arg(config)
        .args(arguments)
        .output()
        .unwrap();
    let mut printed = String::from_utf8_lossy(&output.stdout).into_owned();
    printed.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), printed)
}

const RUN_KEY: &str = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";

fn run_key(config: &Path) -> bool {
    Command::new("reg.exe")
        .args(["query", RUN_KEY, "/v", &name(config)])
        .output()
        .unwrap()
        .status
        .success()
}

/// Removes every task and `Run` entry of the test configurations, also after a failure.
/// It never panics: a panic while the test unwinds would abort before the rest is removed.
struct Cleanup(Vec<String>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for name in &self.0 {
            for task in query(&format!("\\{name}-")).unwrap_or_default() {
                let _ = Command::new("schtasks.exe")
                    .args(["/delete", "/tn", &task, "/f"])
                    .output();
            }
            let _ = Command::new("reg.exe")
                .args(["delete", RUN_KEY, "/v", name, "/f"])
                .output();
        }
    }
}

fn store(path: PathBuf) -> PathBuf {
    let store = Store::new(path).unwrap();
    store.save(&Config::default()).unwrap();
    store.path
}

#[test]
fn tasks_are_registered_found_and_removed_through_the_real_scheduler() {
    if std::env::var("CI").as_deref() != Ok("true") {
        eprintln!("Skipped: the test changes the Task Scheduler and runs only with CI=true.");
        return;
    }
    assert!(tasks::elevated(), "The CI runner runs as an administrator");
    let temp = tempfile::tempdir().unwrap();
    let first = store(temp.path().join("first").join("config.json"));
    let second = store(temp.path().join("second").join("config.json"));
    let cleanup = Cleanup(vec![name(&first), name(&second)]);
    let divert = prefix(&first, "divert");
    assert!(listed(&divert).is_empty());

    // Remembering is off until the user turns it on.
    assert!(!tasks::remembering(&first));
    let (ok, printed) = cli(&first, &["elevation", "status"]);
    assert!(ok, "{printed}");
    assert!(printed.contains("выключен"), "{printed}");

    // `register` creates the task of this copy with its command and user.
    tasks::register(&first, Kind::Divert).unwrap();
    assert!(tasks::registered(&first, Kind::Divert, false).unwrap());
    assert!(tasks::registered(&first, Kind::Divert, true).unwrap());
    let names = listed(&divert);
    assert_eq!(names.len(), 1, "{names:?}");
    let output = schtasks(&["/query", "/tn", &names[0], "/xml"]);
    assert!(output.status.success());
    let xml = text(&output.stdout).to_lowercase();
    let program = tasks::program().unwrap();
    let program = program.to_str().unwrap().to_lowercase();
    assert!(
        xml.contains(&format!("<command>{program}</command>")),
        "{xml}"
    );
    assert!(
        xml.contains(&first.to_str().unwrap().to_lowercase()),
        "{xml}"
    );
    assert!(xml.contains("divert</arguments>"), "{xml}");
    assert!(
        xml.contains("<runlevel>highestavailable</runlevel>"),
        "{xml}"
    );
    let sid = tasks::user_sid().unwrap().to_lowercase();
    let user = std::env::var("USERNAME").unwrap().to_lowercase();
    assert!(
        xml.contains(&format!("<userid>{sid}</userid>")) || xml.contains(&user),
        "{xml}"
    );

    // A second registration replaces the task instead of adding one.
    tasks::register(&first, Kind::Divert).unwrap();
    assert_eq!(listed(&divert), names);

    // Another configuration has a task of its own, and removing it leaves the first.
    tasks::register(&second, Kind::Divert).unwrap();
    assert_eq!(listed(&prefix(&second, "divert")).len(), 1);
    assert_eq!(listed(&divert), names);
    tasks::unregister(&second, Kind::Divert, false).unwrap();
    assert!(!tasks::registered(&second, Kind::Divert, true).unwrap());
    assert_eq!(listed(&divert), names);

    // Another copy of КРОТ (the windowed program next to krot-cli) replaces the task of
    // this one, which no longer takes it for its own.
    let (ok, printed) = cli(&first, &["elevation", "enable"]);
    assert!(ok, "{printed}");
    assert!(printed.contains("включён"), "{printed}");
    assert!(tasks::remembering(&first));
    let copies = listed(&divert);
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert_ne!(copies, names);
    assert!(!tasks::registered(&first, Kind::Divert, false).unwrap());
    assert!(tasks::registered(&first, Kind::Divert, true).unwrap());
    let (ok, printed) = cli(&first, &["elevation", "status"]);
    assert!(ok && printed.contains("включён"), "{printed}");

    // Turning remembering off removes the task and the choice.
    let (ok, printed) = cli(&first, &["elevation", "disable"]);
    assert!(ok, "{printed}");
    assert!(printed.contains("выключен"), "{printed}");
    assert!(!printed.contains("осталось"), "{printed}");
    assert!(!tasks::remembering(&first));
    assert!(!tasks::registered(&first, Kind::Divert, true).unwrap());
    assert!(listed(&divert).is_empty());

    // An elevated КРОТ turns autostart on through the Run key only, and replaces a logon task
    // that an older elevated КРОТ registered: one way of starting at logon.
    let logon = prefix(&second, "logon");
    tasks::register(&second, Kind::Logon).unwrap();
    assert_eq!(listed(&logon).len(), 1);
    let (ok, printed) = cli(&second, &["autostart", "enable"]);
    assert!(ok, "{printed}");
    assert!(printed.contains("включён"), "{printed}");
    assert!(listed(&logon).is_empty());
    assert!(run_key(&second));
    // The elevated background leaves the move to a logon task to the user's own КРОТ.
    autostart::migrate(&second);
    assert!(listed(&logon).is_empty());
    assert!(run_key(&second));
    let (ok, printed) = cli(&second, &["autostart", "disable"]);
    assert!(ok, "{printed}");
    assert!(printed.contains("выключен"), "{printed}");
    assert!(!run_key(&second));
    assert!(listed(&logon).is_empty());

    drop(cleanup);
    for config in [&first, &second] {
        let left = listed(&format!("\\{}-", name(config)));
        assert!(left.is_empty(), "{left:?}");
        assert!(!run_key(config));
    }
}
