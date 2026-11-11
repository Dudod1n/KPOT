//! The scripts run by the local `/bin/sh` with a temporary home, as a server would run them.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

struct Output {
    code: u32,
    stdout: String,
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Runs `script` like the SSH server would and answers `KROT-NEED` with `upload`.
fn run(
    home: &Path,
    path: Option<&Path>,
    script: &str,
    arguments: &[&str],
    upload: &[u8],
) -> Output {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(script)
        .arg("krot")
        .args(arguments)
        .env_clear()
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command.env(
        "PATH",
        path.map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/usr/local/bin:/usr/bin:/bin")),
    );
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut output = String::new();
    let mut line = String::new();
    while stdout.read_line(&mut line).unwrap() > 0 {
        if line.trim_end() == NEED
            && let Some(mut input) = stdin.take()
        {
            input.write_all(upload).unwrap();
        }
        output.push_str(&line);
        line.clear();
    }
    drop(stdin);
    let status = child.wait().unwrap();
    Output {
        code: status.code().unwrap() as u32,
        stdout: output,
    }
}

fn ensure(home: &Path, bytes: &[u8], upload: &[u8]) -> Output {
    let full = hash(bytes);
    run(home, None, &ensure_script(), &[short(&full), &full], upload)
}

fn start(home: &Path, bytes: &[u8]) -> Output {
    let full = hash(bytes);
    run(home, None, &run_script(), &[short(&full), &full], b"")
}

fn relay(text: &str) -> Vec<u8> {
    format!("#!/bin/sh\necho {text}\n").into_bytes()
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn the_probe_reports_this_system() {
    let home = tempfile::tempdir().unwrap();
    let output = run(home.path(), None, PROBE, &[], b"");
    assert_eq!(output.code, 0);
    let (system, machine) = parse_probe(&output.stdout).unwrap();
    assert_eq!(system, "Linux");
    assert_eq!(machine, std::env::consts::ARCH);
}

#[test]
fn probe_output_is_parsed_strictly() {
    assert_eq!(parse_probe("KROT1 Linux x86_64\n"), Ok(("Linux", "x86_64")));
    assert_eq!(
        parse_probe("Welcome!\nKROT1 Linux aarch64\n"),
        Ok(("Linux", "aarch64"))
    );
    for output in [
        "",
        "This account is restricted\n",
        "KROT1 Linux\n",
        "KROT1  x\n",
        "KROT1 a b c\n",
    ] {
        assert_eq!(parse_probe(output), Err(Problem::NoShell), "{output:?}");
    }
    assert_eq!(
        select("KROT1 FreeBSD amd64\n").err(),
        Some(Problem::UnsupportedSystem)
    );
    assert_eq!(
        select("KROT1 Linux armv7l\n").err(),
        Some(Problem::UnsupportedMachine)
    );
}

#[test]
fn the_relay_is_uploaded_once_checked_and_started() {
    let home = tempfile::tempdir().unwrap();
    let bytes = relay("RELAY-RUNNING");
    let first = ensure(home.path(), &bytes, &bytes);
    assert_eq!(first.code, 0, "{}", first.stdout);
    assert_eq!(first.stdout, format!("{NEED}\n{STORED}\n"));
    let directory = home.path().join(".cache/krot");
    let file = directory.join(format!("krot-relay-{}", short(&hash(&bytes))));
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    assert_eq!((mode(&directory), mode(&file)), (0o700, 0o700));

    let second = ensure(home.path(), &bytes, b"");
    assert_eq!((second.code, second.stdout.as_str()), (0, "KROT-HAVE\n"));

    let started = start(home.path(), &bytes);
    assert_eq!(
        (started.code, started.stdout.as_str()),
        (0, "RELAY-RUNNING\n")
    );
    // Nothing but the relay is left in the directory.
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
}

#[test]
fn corrupted_uploads_and_changed_files_are_refused() {
    let home = tempfile::tempdir().unwrap();
    let bytes = relay("GOOD");
    let corrupted = ensure(home.path(), &bytes, &relay("EVIL"));
    assert_eq!(corrupted.code, code::CORRUPTED);
    let directory = home.path().join(".cache/krot");
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);

    assert_eq!(ensure(home.path(), &bytes, &bytes).code, 0);
    let file = directory.join(format!("krot-relay-{}", short(&hash(&bytes))));
    std::fs::write(&file, relay("EVIL")).unwrap();
    assert_eq!(start(home.path(), &bytes).code, code::CHANGED);
    // The next ensure replaces the changed file.
    assert_eq!(
        ensure(home.path(), &bytes, &bytes).stdout,
        format!("{NEED}\n{STORED}\n")
    );
    assert_eq!(start(home.path(), &bytes).stdout, "GOOD\n");
}

#[test]
fn a_new_version_replaces_the_old_ones() {
    let home = tempfile::tempdir().unwrap();
    let old = relay("OLD");
    let new = relay("NEW");
    assert_eq!(ensure(home.path(), &old, &old).code, 0);
    assert_eq!(ensure(home.path(), &new, &new).code, 0);
    let names: Vec<String> = std::fs::read_dir(home.path().join(".cache/krot"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, [format!("krot-relay-{}", short(&hash(&new)))]);
}

#[test]
fn unsafe_or_unusable_servers_are_named() {
    let bytes = relay("X");

    let linked = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::create_dir(linked.path().join(".cache")).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), linked.path().join(".cache/krot")).unwrap();
    assert_eq!(
        ensure(linked.path(), &bytes, &bytes).code,
        code::UNSAFE_DIRECTORY
    );

    let blocked = tempfile::tempdir().unwrap();
    std::fs::write(blocked.path().join(".cache"), b"not a directory").unwrap();
    assert_eq!(
        ensure(blocked.path(), &bytes, &bytes).code,
        code::NOT_WRITABLE
    );

    // The file loses its execute bit, as on a noexec mount the kernel refuses it.
    let home = tempfile::tempdir().unwrap();
    assert_eq!(ensure(home.path(), &bytes, &bytes).code, 0);
    let file = home
        .path()
        .join(".cache/krot")
        .join(format!("krot-relay-{}", short(&hash(&bytes))));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(start(home.path(), &bytes).code, code::NOT_EXECUTABLE);

    // A server without any SHA-256 tool.
    let tools = tempfile::tempdir().unwrap();
    for tool in ["uname", "cut", "mkdir", "chmod", "cat", "mv", "rm"] {
        let path = ["/usr/bin", "/bin"]
            .iter()
            .map(|directory| Path::new(directory).join(tool))
            .find(|path| path.exists())
            .unwrap();
        std::os::unix::fs::symlink(path, tools.path().join(tool)).unwrap();
    }
    let full = hash(&bytes);
    let output = run(
        home.path(),
        Some(tools.path()),
        &ensure_script(),
        &[short(&full), &full],
        &bytes,
    );
    assert_eq!(output.code, code::NO_HASH_TOOL);
}

#[test]
fn exit_codes_map_to_messages_and_commands_quote_only_the_script() {
    assert_eq!(
        Problem::from_exit(code::NOT_EXECUTABLE),
        Problem::NotExecutable
    );
    assert_eq!(Problem::from_exit(code::NOT_FOUND), Problem::NoShell);
    assert_eq!(Problem::from_exit(1), Problem::Failed);
    assert!(Problem::NotExecutable.message().contains("noexec"));
    let command = command(PROBE, &[]);
    assert_eq!(command, format!("/bin/sh -c '{PROBE}' krot"));
    assert!(super::command(&run_script(), &["0123abcd", "ff00"]).ends_with("' krot 0123abcd ff00"));
}

#[test]
#[should_panic(expected = "plain tokens")]
fn arguments_cannot_carry_shell_syntax() {
    command(PROBE, &["$(id)"]);
}
