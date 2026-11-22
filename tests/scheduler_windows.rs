#![cfg(windows)]
//! Tasks of the Windows Task Scheduler through the real `schtasks.exe`.
//!
//! The tests change the system scheduler, the user's `Run` key and, for the part that runs as a
//! standard user, the local accounts and the UAC policy, so they run only with `CI=true`: the
//! hosted runner is a disposable administrator account. Elsewhere they are skipped and leave
//! the user's tasks alone.
use krot::{
    autostart,
    config::{Config, Store},
    tasks::{self, Kind},
};
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
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

/// Standard output followed by standard error.
fn combined(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

fn krot(
    program: &Path,
    config: &Path,
    arguments: &[&str],
    environment: &[(&str, &Path)],
) -> (bool, String) {
    let output = Command::new(program)
        .arg("--config")
        .arg(config)
        .args(arguments)
        .envs(environment.iter().copied())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (output.status.success(), combined(&output))
}

fn cli(config: &Path, arguments: &[&str]) -> (bool, String) {
    krot(
        env!("CARGO_BIN_EXE_krot-cli").as_ref(),
        config,
        arguments,
        &[],
    )
}

fn ci() -> bool {
    let ci = std::env::var("CI").as_deref() == Ok("true");
    if !ci {
        eprintln!("Skipped: the test changes the Task Scheduler and runs only with CI=true.");
    }
    ci
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
    if !ci() {
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

/// Runs `krot-cli` where it cannot start any other process, `schtasks.exe` included: a job
/// that allows one active process stands for a Task Scheduler that is not available.
fn without_scheduler(config: &Path, arguments: &[&str]) -> (bool, String) {
    use std::os::windows::{io::AsRawHandle, process::CommandExt};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectExtendedLimitInformation, SetInformationJobObject,
            },
            Threading::{
                CREATE_NO_WINDOW, CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
            },
        },
    };
    // SAFETY: an unnamed job; the limits are a plain structure of the size passed.
    let job = unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        assert!(!job.is_null(), "{}", std::io::Error::last_os_error());
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        assert!(
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) != 0,
            "{}",
            std::io::Error::last_os_error()
        );
        job
    };
    // The process joins the job before its first instruction, so it never starts a child.
    let child = Command::new(env!("CARGO_BIN_EXE_krot-cli"))
        .arg("--config")
        .arg(config)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
        .spawn()
        .unwrap();
    // SAFETY: the handles are valid and closed here; the entry has the declared size.
    unsafe {
        assert!(
            AssignProcessToJobObject(job, child.as_raw_handle()) != 0,
            "{}",
            std::io::Error::last_os_error()
        );
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        assert!(snapshot != INVALID_HANDLE_VALUE);
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut more = Thread32First(snapshot, &mut entry) != 0;
        let mut resumed = 0;
        while more {
            if entry.th32OwnerProcessID == child.id() {
                let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                assert!(!thread.is_null(), "{}", std::io::Error::last_os_error());
                assert_ne!(ResumeThread(thread), u32::MAX);
                CloseHandle(thread);
                resumed += 1;
            }
            more = Thread32Next(snapshot, &mut entry) != 0;
        }
        CloseHandle(snapshot);
        assert_eq!(resumed, 1, "The suspended process has one thread");
    }
    let output = child.wait_with_output().unwrap();
    // SAFETY: the job handle is owned here.
    unsafe {
        CloseHandle(job);
    }
    (output.status.success(), combined(&output))
}

#[test]
fn the_elevated_task_definition_and_the_autostart_status_need_no_user_environment() {
    if !ci() {
        return;
    }
    assert!(tasks::elevated(), "The CI runner runs as an administrator");
    let temp = tempfile::tempdir().unwrap();
    let config = store(temp.path().join("environment").join("config.json"));
    let cleanup = Cleanup(vec![name(&config)]);
    let divert = prefix(&config, "divert");

    // An elevated process writes the task definition into the system temporary directory, not
    // into the user's one, which programs without administrator rights could change.
    let missing = temp.path().join("missing");
    let (ok, printed) = krot(
        env!("CARGO_BIN_EXE_krot-cli").as_ref(),
        &config,
        &["elevation", "enable"],
        &[("TMP", &missing), ("TEMP", &missing)],
    );
    assert!(ok, "{printed}");
    assert!(printed.contains("включён"), "{printed}");
    assert_eq!(listed(&divert).len(), 1);
    let (ok, printed) = cli(&config, &["elevation", "disable"]);
    assert!(ok && printed.contains("выключен"), "{printed}");
    assert!(listed(&divert).is_empty());

    // Without the Task Scheduler autostart works through the Run key alone, and its status
    // tells whether the Run key is there instead of failing.
    let (ok, printed) = without_scheduler(&config, &["autostart", "status"]);
    assert!(ok, "{printed}");
    assert!(printed.contains("выключен"), "{printed}");
    let (ok, printed) = without_scheduler(&config, &["autostart", "enable"]);
    assert!(ok, "{printed}");
    assert!(printed.contains("включён"), "{printed}");
    assert!(run_key(&config));
    let (ok, printed) = without_scheduler(&config, &["autostart", "disable"]);
    assert!(ok, "{printed}");
    assert!(printed.contains("выключен"), "{printed}");
    assert!(!run_key(&config));

    drop(cleanup);
    assert!(listed(&format!("\\{}-", name(&config))).is_empty());
    assert!(!run_key(&config));
}

/// PowerShell scripts for the standard user's account; values come in environment variables.
const SCRIPTS: [(&str, &str); 4] = [
    (
        "create.ps1",
        r#"$ErrorActionPreference = 'Stop'
$policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$values = Get-ItemProperty -Path $policy
[Console]::Error.WriteLine("EnableLUA=$($values.EnableLUA) ConsentPromptBehaviorUser=$($values.ConsentPromptBehaviorUser)")
$consent = if ($null -eq $values.ConsentPromptBehaviorUser) { 'absent' } else { [string]$values.ConsentPromptBehaviorUser }
Write-Output "consent=$consent"
# Elevation requests of standard users are denied at once: nobody would answer a prompt.
Set-ItemProperty -Path $policy -Name ConsentPromptBehaviorUser -Value 0 -Type DWord
$password = ConvertTo-SecureString $env:KROT_TEST_PASSWORD -AsPlainText -Force
$user = New-LocalUser -Name $env:KROT_TEST_USER -Password $password -PasswordNeverExpires -AccountNeverExpires -Description 'KROT scheduler test'
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
Write-Output "sid=$($user.SID.Value)"
"#,
    ),
    (
        "run.ps1",
        r#"$ErrorActionPreference = 'Stop'
try {
    $password = ConvertTo-SecureString $env:KROT_TEST_PASSWORD -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ("$env:COMPUTERNAME\$env:KROT_TEST_USER", $password)
    $process = Start-Process -FilePath $env:KROT_TEST_PROGRAM -ArgumentList $env:KROT_TEST_ARGUMENTS -Credential $credential -LoadUserProfile -WorkingDirectory $env:KROT_TEST_DIRECTORY -RedirectStandardOutput $env:KROT_TEST_STDOUT -RedirectStandardError $env:KROT_TEST_STDERR -PassThru
} catch {
    [Console]::Error.WriteLine($_)
    exit 200
}
$null = $process.Handle
if (-not $process.WaitForExit(120000)) {
    $process.Kill()
    exit 201
}
exit $process.ExitCode
"#,
    ),
    (
        "remove.ps1",
        r#"$name = $env:KROT_TEST_USER
& taskkill.exe /f /fi "USERNAME eq $name" 2>&1 | Out-Null
$user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
if ($user) {
    $sid = $user.SID.Value
    for ($i = 0; $i -lt 30; $i++) {
        $profiles = @(Get-CimInstance Win32_UserProfile -Filter "SID='$sid'")
        if ($profiles.Count -eq 0) { break }
        try { $profiles | Remove-CimInstance -ErrorAction Stop; break } catch { Start-Sleep -Seconds 1 }
    }
    Remove-LocalUser -Name $name
}
$policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if ($env:KROT_TEST_CONSENT -eq 'absent') {
    Remove-ItemProperty -Path $policy -Name ConsentPromptBehaviorUser -ErrorAction SilentlyContinue
} elseif ($env:KROT_TEST_CONSENT) {
    Set-ItemProperty -Path $policy -Name ConsentPromptBehaviorUser -Value ([int]$env:KROT_TEST_CONSENT) -Type DWord
}
"#,
    ),
    (
        "left.ps1",
        r#"$user = [bool](Get-LocalUser -Name $env:KROT_TEST_USER -ErrorAction SilentlyContinue)
$profiles = @(Get-CimInstance Win32_UserProfile -Filter "SID='$env:KROT_TEST_SID'").Count
$hive = Test-Path "Registry::HKEY_USERS\$env:KROT_TEST_SID"
Write-Output "user=$user profiles=$profiles hive=$hive"
"#,
    ),
];

fn scripts() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    for (name, script) in SCRIPTS {
        std::fs::write(directory.path().join(name), script).unwrap();
    }
    directory
}

fn powershell(scripts: &Path, script: &str, user: &str, environment: &[(&str, &OsStr)]) -> Output {
    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(scripts.join(script))
        // The modules of PowerShell 7, which runs the CI steps, do not load in Windows
        // PowerShell: without the variable it finds its own.
        .env_remove("PSModulePath")
        .env("KROT_TEST_USER", user)
        .envs(environment.iter().copied())
        .stdin(Stdio::null())
        .output()
        .expect("powershell.exe starts")
}

/// A local account without administrator rights, with a password made for this run only.
/// Dropping it ends its processes, removes its profile with its `Run` key and the account,
/// and restores the UAC policy. It never panics, like [`Cleanup`].
struct StandardUser {
    name: String,
    password: String,
    sid: String,
    consent: Option<String>,
    scripts: tempfile::TempDir,
}

impl StandardUser {
    fn create() -> Self {
        let mut user = StandardUser {
            name: format!("krot{}", hex::encode(rand::random::<[u8; 4]>())),
            // Upper and lower case letters, digits and a symbol satisfy the password policy.
            password: format!("Kr0t!{}", hex::encode(rand::random::<[u8; 16]>())),
            sid: String::new(),
            consent: None,
            scripts: scripts(),
        };
        let output = powershell(
            user.scripts.path(),
            "create.ps1",
            &user.name,
            &[("KROT_TEST_PASSWORD", user.password.as_ref())],
        );
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if let Some(consent) = line.strip_prefix("consent=") {
                user.consent = Some(consent.trim().to_owned());
            } else if let Some(sid) = line.strip_prefix("sid=") {
                user.sid = sid.trim().to_owned();
            }
        }
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success() && user.sid.starts_with("S-1-5-21-"),
            "{}",
            combined(&output)
        );
        user
    }

    /// Runs `program` as this user, without administrator rights: its success and output.
    fn run(&self, directory: &Path, program: &Path, arguments: &[&OsStr]) -> (bool, String) {
        static RUNS: AtomicUsize = AtomicUsize::new(0);
        let run = RUNS.fetch_add(1, Ordering::Relaxed);
        let stdout = self.scripts.path().join(format!("{run}.out"));
        let stderr = self.scripts.path().join(format!("{run}.err"));
        let arguments = arguments
            .iter()
            .map(|argument| format!("\"{}\"", argument.to_str().unwrap()))
            .collect::<Vec<_>>()
            .join(" ");
        let output = powershell(
            self.scripts.path(),
            "run.ps1",
            &self.name,
            &[
                ("KROT_TEST_PASSWORD", self.password.as_ref()),
                ("KROT_TEST_PROGRAM", program.as_os_str()),
                ("KROT_TEST_ARGUMENTS", arguments.as_ref()),
                ("KROT_TEST_DIRECTORY", directory.as_os_str()),
                ("KROT_TEST_STDOUT", stdout.as_os_str()),
                ("KROT_TEST_STDERR", stderr.as_os_str()),
            ],
        );
        let code = output.status.code();
        assert!(
            !matches!(code, Some(200 | 201) | None),
            "{} did not run as the standard user (code {code:?}): {}",
            program.display(),
            combined(&output)
        );
        let mut text = String::new();
        for path in [stdout, stderr] {
            text.push_str(&String::from_utf8_lossy(
                &std::fs::read(path).unwrap_or_default(),
            ));
        }
        (code == Some(0), text)
    }

    fn krot(&self, program: &Path, config: &Path, arguments: &[&str]) -> (bool, String) {
        let mut all: Vec<&OsStr> = vec!["--config".as_ref(), config.as_os_str()];
        all.extend(arguments.iter().map(OsStr::new));
        self.run(config.parent().unwrap(), program, &all)
    }

    /// The `Run` entry of `config` exists in this user's own registry.
    fn run_key(&self, config: &Path) -> bool {
        let reg = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("reg.exe");
        let name = name(config);
        let arguments: [&OsStr; 4] = [
            "query".as_ref(),
            RUN_KEY.as_ref(),
            "/v".as_ref(),
            name.as_ref(),
        ];
        self.run(config.parent().unwrap(), &reg, &arguments).0
    }
}

impl Drop for StandardUser {
    fn drop(&mut self) {
        let consent = self.consent.clone().unwrap_or_default();
        let output = powershell(
            self.scripts.path(),
            "remove.ps1",
            &self.name,
            &[("KROT_TEST_CONSENT", consent.as_ref())],
        );
        if !output.status.success() {
            eprintln!("Removing the test user failed: {}", combined(&output));
        }
    }
}

/// Task Scheduler 1.2 definition of a task of `user`, as an elevated process registers it. The
/// logon trigger is off: the test signs the user in, and the task must not start КРОТ then.
fn user_task_xml(user: &str, command: &Path, arguments: &str, logon: bool) -> String {
    let (triggers, level) = if logon {
        (
            format!(
                "<Triggers><LogonTrigger><Enabled>false</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>"
            ),
            "LeastPrivilege",
        )
    } else {
        (String::new(), "HighestAvailable")
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\
{triggers}\
<Principals><Principal id=\"Author\"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>{level}</RunLevel></Principal></Principals>\
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><Enabled>true</Enabled></Settings>\
<Actions Context=\"Author\"><Exec><Command>{}</Command><Arguments>{arguments}</Arguments></Exec></Actions>\
</Task>\r\n",
        command.display()
    )
}

/// Registers `task` from this elevated process, replacing a task of that name.
fn register_elevated(directory: &Path, task: &str, xml: &str) {
    let path = directory.join("task.xml");
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    std::fs::write(&path, bytes).unwrap();
    let output = schtasks(&["/create", "/tn", task, "/xml", path.to_str().unwrap(), "/f"]);
    assert!(output.status.success(), "{}", combined(&output));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn a_standard_user_keeps_the_choice_and_reports_tasks_that_an_elevated_process_registered() {
    if !ci() {
        return;
    }
    assert!(tasks::elevated(), "The CI runner runs as an administrator");
    let user = StandardUser::create();
    // A directory on the system drive that the user may use, with a copy of krot-cli: the
    // build directory and the administrator's profile are closed to other accounts.
    let drive = PathBuf::from(format!("{}\\", std::env::var("SystemDrive").unwrap()));
    let shared = tempfile::Builder::new()
        .prefix("krot-test-")
        .tempdir_in(&drive)
        .unwrap();
    let output = Command::new("icacls.exe")
        .arg(shared.path())
        .args(["/grant", &format!("*{}:(OI)(CI)F", user.sid)])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", combined(&output));
    let program = shared.path().join("krot-cli.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_krot-cli"), &program).unwrap();
    let directory = shared.path().join("config");
    std::fs::create_dir(&directory).unwrap();
    let config = Store::new(directory.join("config.json")).unwrap().path;
    let cleanup = Cleanup(vec![name(&config)]);
    let divert = prefix(&config, "divert");
    let logon = prefix(&config, "logon");

    // An elevated КРОТ remembered the rights in a task of the user, who may read and start it
    // but not delete it.
    let (ok, printed) = krot(&program, &config, &["elevation", "enable"], &[]);
    assert!(ok && printed.contains("включён"), "{printed}");
    let names = listed(&divert);
    assert_eq!(names.len(), 1, "{names:?}");
    let arguments = format!("--config \"{}\" divert", config.display());
    register_elevated(
        user.scripts.path(),
        &names[0],
        &user_task_xml(&user.sid, &program, &arguments, false),
    );
    let (ok, printed) = user.krot(&program, &config, &["elevation", "status"]);
    assert!(ok, "{printed}");
    assert!(printed.contains("включён"), "{printed}");

    // Windows refuses to delete the task and denies the elevation request: turning
    // remembering off fails and keeps the choice, so the status still tells the truth.
    let (ok, printed) = user.krot(&program, &config, &["elevation", "disable"]);
    assert!(!ok, "{printed}");
    assert!(printed.contains("задани"), "{printed}");
    assert_eq!(listed(&divert), names);
    assert!(tasks::remembering(&config), "{printed}");
    let (ok, printed) = user.krot(&program, &config, &["elevation", "status"]);
    assert!(ok && printed.contains("включён"), "{printed}");

    // #66: a logon task that an elevated КРОТ of an older version registered. Turning
    // autostart on or off fails instead of leaving the task and the Run key both to start КРОТ.
    let task = names[0].replacen("-divert-", "-logon-", 1);
    let arguments = format!("--config \"{}\" serve", config.display());
    register_elevated(
        user.scripts.path(),
        &task,
        &user_task_xml(&user.sid, &program, &arguments, true),
    );
    assert_eq!(listed(&logon), std::slice::from_ref(&task));
    let (ok, printed) = user.krot(&program, &config, &["autostart", "enable"]);
    assert!(!ok, "{printed}");
    assert!(printed.contains("задани"), "{printed}");
    assert!(!user.run_key(&config));
    assert_eq!(listed(&logon), std::slice::from_ref(&task));
    let (ok, printed) = user.krot(&program, &config, &["autostart", "disable"]);
    assert!(!ok, "{printed}");
    assert!(printed.contains("задани"), "{printed}");
    assert!(!user.run_key(&config));
    assert_eq!(listed(&logon), [task]);
    let (ok, printed) = user.krot(&program, &config, &["autostart", "status"]);
    assert!(ok && printed.contains("включён"), "{printed}");

    drop(cleanup);
    let left = listed(&format!("\\{}-", name(&config)));
    assert!(left.is_empty(), "{left:?}");
    let (account, sid) = (user.name.clone(), user.sid.clone());
    drop(user);
    let probe = scripts();
    let output = powershell(
        probe.path(),
        "left.ps1",
        &account,
        &[("KROT_TEST_SID", sid.as_ref())],
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "user=False profiles=0 hive=False",
        "{}",
        combined(&output)
    );
}
