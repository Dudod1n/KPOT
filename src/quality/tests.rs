use super::*;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KIB: u64 = 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shell {
    Runs,
    /// The server refuses exec channels.
    Refuses,
    /// Every command runs something else, like `ForceCommand`.
    Forced,
}

/// A server that answers pings and runs the test's commands with paced data.
struct Fake {
    shell: Shell,
    /// `None`: pings go unanswered.
    ping: Mutex<Option<Duration>>,
    /// Bytes per 10 ms of both directions.
    chunk: usize,
    /// The download ignores its argument and sends without end, like a broken `head`.
    endless: bool,
    /// The download stands still for this long after this many bytes.
    pause: Option<(u64, Duration)>,
    /// The download's channel closes after this many bytes.
    close_at: Option<u64>,
    /// Downloads whose reader went away before the end.
    abandoned: AtomicU64,
    commands: Mutex<Vec<String>>,
    gone: AtomicBool,
    /// The login shell prints a long greeting before every command's output.
    banner: bool,
}

impl Fake {
    fn new(shell: Shell) -> Self {
        Self {
            shell,
            ping: Mutex::new(Some(Duration::from_millis(20))),
            chunk: 16 * 1024,
            endless: false,
            pause: None,
            close_at: None,
            abandoned: AtomicU64::new(0),
            commands: Mutex::default(),
            gone: AtomicBool::new(false),
            banner: false,
        }
    }
}

async fn serve_download(fake: Arc<Fake>, mut server: tokio::io::DuplexStream, limit: u64) {
    let chunk = vec![7u8; fake.chunk];
    let mut sent = 0u64;
    let mut paused = false;
    loop {
        if !fake.endless && sent >= limit {
            break;
        }
        if let Some(close) = fake.close_at
            && sent >= close
        {
            return;
        }
        if let Some((at, pause)) = fake.pause
            && sent >= at
            && !paused
        {
            paused = true;
            tokio::time::sleep(pause).await;
        }
        let size = if fake.endless {
            chunk.len()
        } else {
            chunk.len().min((limit - sent) as usize)
        };
        if server.write_all(&chunk[..size]).await.is_err() {
            fake.abandoned.fetch_add(1, Ordering::Relaxed);
            return;
        }
        sent += size as u64;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let _ = server.shutdown().await;
}

/// What a chatty login shell prints before a command's own output.
fn greeting() -> String {
    "Welcome to the server! Unauthorized access is prohibited.\n".repeat(20)
}

async fn serve_upload(fake: Arc<Fake>, mut server: tokio::io::DuplexStream) {
    let mut buffer = vec![0u8; fake.chunk];
    let mut count = 0u64;
    loop {
        match server.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => count += read as u64,
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let banner = if fake.banner {
        greeting()
    } else {
        String::new()
    };
    let _ = server
        .write_all(format!("{banner}  {count}\n").as_bytes())
        .await;
    let _ = server.shutdown().await;
}

struct Served(Arc<Fake>);

impl Session for Served {
    fn ping(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            let delay = *self.0.ping.lock().unwrap();
            match delay {
                Some(delay) => tokio::time::sleep(delay).await,
                None => std::future::pending::<()>().await,
            }
            !self.0.gone.load(Ordering::Relaxed)
        })
    }
    fn exec(&self, command: String) -> BoxFuture<'_, Option<Pipe>> {
        Box::pin(async move {
            self.0.commands.lock().unwrap().push(command.clone());
            if self.0.shell == Shell::Refuses {
                return None;
            }
            let (client, mut server) = tokio::io::duplex(self.0.chunk);
            let fake = self.0.clone();
            if self.0.shell == Shell::Forced {
                tokio::spawn(async move {
                    let _ = server.write_all(b"This service allows sftp only.\n").await;
                    let _ = server.shutdown().await;
                });
            } else if command.contains(PROBE) {
                let banner = if fake.banner {
                    greeting()
                } else {
                    String::new()
                };
                tokio::spawn(async move {
                    let _ = server
                        .write_all(format!("{banner}KROT-TEST-OK\n").as_bytes())
                        .await;
                    let _ = server.shutdown().await;
                });
            } else if command.contains(DOWNLOAD) {
                let limit = command.rsplit(' ').next().unwrap().parse().unwrap();
                tokio::spawn(serve_download(fake, server, limit));
            } else if command.contains(UPLOAD) {
                tokio::spawn(serve_upload(fake, server));
            } else {
                panic!("unexpected command {command}");
            }
            Some(Box::new(client) as Pipe)
        })
    }
}

/// A tunnel whose current session is `fake`, as long as the returned task runs.
fn tunnel(fake: &Arc<Fake>) -> (Arc<Gate>, tokio::task::JoinHandle<()>) {
    let gate = Arc::new(Gate::default());
    let task = connect(&gate, fake);
    (gate, task)
}

fn connect(gate: &Arc<Gate>, fake: &Arc<Fake>) -> tokio::task::JoinHandle<()> {
    let (gate, session) = (gate.clone(), Arc::new(Served(fake.clone())));
    tokio::spawn(async move { gate.serve(session).await })
}

fn speed(tunnel: &str, limit_mb: u64) -> Request {
    Request {
        id: tunnel.into(),
        kind: Kind::Speed,
        duration: None,
        limit_mb: Some(limit_mb),
    }
}

async fn finished(tests: &Tests, id: &str) -> TestStatus {
    loop {
        let status = tests.status(id).unwrap();
        if status.finished() {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn published(gate: &Gate) {
    let mut sessions = gate.subscribe();
    sessions.wait_for(Option::is_some).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn speed_test_measures_both_directions_and_keeps_the_limit() {
    let mut fake = Fake::new(Shell::Runs);
    fake.endless = true;
    let fake = Arc::new(fake);
    let (gate, _session) = tunnel(&fake);
    published(&gate).await;
    let tests = Tests::new(None);
    let id = tests.start(&gate, speed("t", 1)).unwrap();
    let status = finished(&tests, &id).await;
    assert_eq!(status.state, "done", "{status:?}");
    let report = status.report;
    assert_eq!(report.kind, Kind::Speed);
    assert_eq!(report.limit_bytes, MIB);
    // The server would send without end: the client stops at the limit.
    assert_eq!(report.down_bytes, MIB);
    assert_eq!(report.up_bytes, MIB);
    assert!(report.down_bps.unwrap() > 0 && report.up_bps.unwrap() > 0);
    assert_eq!(report.idle_rtt.count, u64::from(IDLE_PINGS));
    assert_eq!(report.idle_rtt.p50_us, Some(20_000));
    assert!(report.loaded_rtt.count > 0, "{report:?}");
    assert!(report.stalls.is_empty() && report.skipped.is_empty() && report.notes.is_empty());
    let commands = fake.commands.lock().unwrap().clone();
    assert!(commands[1].starts_with("/bin/sh -c 'exec head -c \"$1\" /dev/urandom' krot 1048576"));
    assert!(commands[2].starts_with("/bin/sh -c 'exec wc -c' krot"));
    // The snapshot and the history see the finished test.
    assert_eq!(tests.snapshot()["t"].state, "done");
}

#[tokio::test(start_paused = true)]
async fn a_slow_transfer_ends_at_its_time() {
    let mut fake = Fake::new(Shell::Runs);
    fake.chunk = 1024;
    let fake = Arc::new(fake);
    let (gate, _session) = tunnel(&fake);
    published(&gate).await;
    let tests = Tests::new(None);
    let id = tests.start(&gate, speed("t", 100)).unwrap();
    let status = finished(&tests, &id).await;
    let report = status.report;
    // About 100 KiB/s for ten seconds in each direction.
    assert!(
        (900 * KIB..1100 * KIB).contains(&report.down_bytes),
        "{report:?}"
    );
    assert!(
        (900 * KIB..1100 * KIB).contains(&report.up_bytes),
        "{report:?}"
    );
    let down = report.down_bps.unwrap();
    assert!((700_000..900_000).contains(&down), "{down}");
    assert!((20..35).contains(&report.duration_s), "{report:?}");
}

#[tokio::test(start_paused = true)]
async fn without_commands_on_the_server_only_the_delay_is_measured() {
    for (shell, reason) in [(Shell::Refuses, NO_EXEC), (Shell::Forced, NO_SHELL)] {
        let fake = Arc::new(Fake::new(shell));
        let (gate, _session) = tunnel(&fake);
        published(&gate).await;
        let tests = Tests::new(None);
        let id = tests.start(&gate, speed("t", 1)).unwrap();
        let status = finished(&tests, &id).await;
        assert_eq!(status.state, "done");
        let report = status.report;
        assert_eq!(report.skipped, vec![reason.to_owned()]);
        assert_eq!((report.down_bps, report.up_bps), (None, None));
        assert_eq!(report.idle_rtt.count, u64::from(IDLE_PINGS));
        let text = report::render(&report).join("\n");
        assert!(
            text.contains("Задержка 20 мс") && text.contains(reason),
            "{text}"
        );
        // Only the probe ran.
        assert_eq!(fake.commands.lock().unwrap().len(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_test_closes_its_channel_and_leaves_the_session() {
    let mut fake = Fake::new(Shell::Runs);
    fake.endless = true;
    fake.chunk = 1024;
    let fake = Arc::new(fake);
    let (gate, session) = tunnel(&fake);
    published(&gate).await;
    let tests = Tests::new(None);
    let id = tests.start(&gate, speed("t", 100)).unwrap();
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(tests.status(&id).unwrap().phase.starts_with("Скачивание"));
    assert!(tests.cancel(&id));
    let status = finished(&tests, &id).await;
    assert_eq!(status.state, "cancelled");
    assert!(status.report.down_bytes == 0 && status.report.idle_rtt.count == 10);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        fake.abandoned.load(Ordering::Relaxed),
        1,
        "the download's channel is closed"
    );
    // The session is untouched, and a new test may start.
    assert!(!session.is_finished());
    let access = gate.subscribe().borrow().clone().unwrap();
    assert_eq!(access.session, 1);
    assert!(ping(&access).await.unwrap().is_some());
    tests.start(&gate, speed("t", 1)).unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_failed_test_channel_ends_its_step_and_not_the_session() {
    let mut fake = Fake::new(Shell::Runs);
    fake.close_at = Some(320 * KIB);
    let fake = Arc::new(fake);
    let (gate, session) = tunnel(&fake);
    published(&gate).await;
    let tests = Tests::new(None);
    let id = tests.start(&gate, speed("t", 1)).unwrap();
    let status = finished(&tests, &id).await;
    assert_eq!(status.state, "done");
    let report = status.report;
    assert_eq!(report.down_bytes, 320 * KIB);
    assert_eq!(report.up_bytes, MIB);
    assert!(
        report.notes[0].starts_with("Скачивание остановилось на 320,0 КБ"),
        "{report:?}"
    );
    let text = report::render(&report).join("\n");
    assert!(text.contains("krot-cli diagnose"), "{text}");
    assert!(!session.is_finished());
    assert_eq!(gate.subscribe().borrow().as_ref().unwrap().session, 1);
}

#[tokio::test(start_paused = true)]
async fn a_pause_in_a_transfer_is_a_stall_at_its_byte() {
    let mut fake = Fake::new(Shell::Runs);
    fake.pause = Some((256 * KIB, Duration::from_secs(3)));
    let fake = Arc::new(fake);
    let (gate, _session) = tunnel(&fake);
    published(&gate).await;
    let tests = Tests::new(None);
    let id = tests.start(&gate, speed("t", 1)).unwrap();
    let report = finished(&tests, &id).await.report;
    assert_eq!(report.stalls.len(), 1, "{report:?}");
    let stall = &report.stalls[0];
    assert_eq!(stall.direction, Direction::Down);
    assert_eq!(stall.at_byte, Some(256 * KIB));
    assert!((3000..3100).contains(&stall.duration_ms), "{stall:?}");
    assert!(
        report::render(&report)
            .iter()
            .any(|line| line.starts_with("Замирание: скачивание на 256,0 КБ"))
    );
}

#[tokio::test(start_paused = true)]
async fn the_stability_test_survives_a_reconnect_and_reports_minutes() {
    let first = Arc::new(Fake::new(Shell::Runs));
    let (gate, session) = tunnel(&first);
    published(&gate).await;
    let tests = Tests::new(None);
    let request = Request {
        id: "t".into(),
        kind: Kind::Stability,
        duration: Some(180),
        limit_mb: None,
    };
    let id = tests.start(&gate, request).unwrap();
    tokio::time::sleep(Duration::from_secs(70)).await;
    session.abort();
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(tests.status(&id).unwrap().state, "running");
    let second = Arc::new(Fake::new(Shell::Runs));
    let _session = connect(&gate, &second);
    let status = finished(&tests, &id).await;
    assert_eq!(status.state, "done", "{status:?}");
    let report = status.report;
    assert_eq!(report.duration_s, 180);
    assert_eq!(report.reconnects, 1);
    let kinds: Vec<_> = report
        .events
        .iter()
        .map(|event| event.kind.as_str())
        .collect();
    assert_eq!(kinds, ["disconnected", "reconnected"]);
    assert!((69.0..71.0).contains(&report.events[0].at_s), "{report:?}");
    // A transfer each minute, on whichever session there was.
    assert_eq!(report.samples.len(), 3);
    assert!(
        report
            .samples
            .iter()
            .all(|sample| sample.down_bps.is_some() && sample.up_bps.is_some()),
        "{report:?}"
    );
    assert_eq!(report.down_bytes, 3 * STABILITY_TRANSFER);
    assert!(
        report
            .samples
            .iter()
            .all(|sample| sample.rtt_p50_us == Some(20_000))
    );
    // Pings every two seconds, none while the tunnel reconnected.
    assert!((80..=88).contains(&report.ping_sent), "{report:?}");
    assert_eq!(report.ping_lost, 0);
    assert_eq!(second.commands.lock().unwrap().len(), 2, "the third minute");
    let text = report::render(&report).join("\n");
    assert!(
        text.contains("За 3 мин 00 с: замираний нет, 1 переподключение, потерь ping 0,0 %"),
        "{text}"
    );
    assert_eq!(report::minutes_table(&report).len(), 4);
}

#[tokio::test(start_paused = true)]
async fn lost_pings_in_a_row_are_a_stall() {
    let fake = Arc::new(Fake::new(Shell::Refuses));
    let (gate, _session) = tunnel(&fake);
    published(&gate).await;
    let tests = Tests::new(None);
    let request = Request {
        id: "t".into(),
        kind: Kind::Stability,
        duration: Some(60),
        limit_mb: None,
    };
    let id = tests.start(&gate, request).unwrap();
    tokio::time::sleep(Duration::from_secs(10)).await;
    *fake.ping.lock().unwrap() = None;
    tokio::time::sleep(Duration::from_secs(15)).await;
    *fake.ping.lock().unwrap() = Some(Duration::from_millis(20));
    let report = finished(&tests, &id).await.report;
    assert_eq!(report.stalls.len(), 1, "{report:?}");
    let stall = &report.stalls[0];
    assert_eq!(stall.direction, Direction::Ping);
    assert!(
        (9.0..13.0).contains(&stall.at_s) && (13_000..21_000).contains(&stall.duration_ms),
        "{stall:?}"
    );
    // A ping goes out every two seconds while earlier ones wait: 15 s without answers lose 7–8.
    assert!((7..=8).contains(&report.ping_lost), "{report:?}");
    assert_eq!(report.skipped, vec![NO_EXEC.to_owned()]);
}

#[tokio::test(start_paused = true)]
async fn a_stopped_tunnel_ends_its_test() {
    let fake = Arc::new(Fake::new(Shell::Runs));
    let (gate, session) = tunnel(&fake);
    published(&gate).await;
    let tests = Tests::new(None);
    let request = Request {
        id: "t".into(),
        kind: Kind::Stability,
        duration: Some(600),
        limit_mb: None,
    };
    let id = tests.start(&gate, request).unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    session.abort();
    let _ = session.await;
    drop(gate);
    let status = finished(&tests, &id).await;
    assert_eq!(status.state, "failed");
    assert_eq!(status.error, Stop::Tunnel.message());
    assert!(status.report.duration_s < 10);
}

#[tokio::test(start_paused = true)]
async fn one_test_per_tunnel_within_bounds() {
    let fake = Arc::new(Fake::new(Shell::Runs));
    let (gate, _session) = tunnel(&fake);
    let tests = Tests::new(None);
    let refused = |result: Result<String>| result.unwrap_err().downcast::<Refusal>().unwrap().0;
    assert!(refused(tests.start(&gate, speed("t", 1))).starts_with("Туннель не подключён"));
    published(&gate).await;
    assert!(refused(tests.start(&gate, speed("t", 0))).starts_with("Лимит"));
    assert!(refused(tests.start(&gate, speed("t", MAX_LIMIT_MB + 1))).starts_with("Лимит"));
    let short = Request {
        id: "t".into(),
        kind: Kind::Stability,
        duration: Some(5),
        limit_mb: None,
    };
    assert!(refused(tests.start(&gate, short)).starts_with("Длительность"));
    let id = tests.start(&gate, speed("t", 1)).unwrap();
    assert_eq!(
        refused(tests.start(&gate, speed("t", 1))),
        "Тест этого туннеля уже идёт."
    );
    // Another tunnel's test is independent.
    let (other, _other_session) = tunnel(&fake);
    published(&other).await;
    tests.start(&other, speed("u", 1)).unwrap();
    assert!(!tests.cancel("unknown"));
    assert!(tests.status("unknown").is_none());
    finished(&tests, &id).await;
}

#[tokio::test(start_paused = true)]
async fn an_operation_stops_with_its_session() {
    let fake = Arc::new(Fake::new(Shell::Runs));
    let (gate, session) = tunnel(&fake);
    published(&gate).await;
    let access = gate.subscribe().borrow().clone().unwrap();
    let pending = tokio::spawn(async move { access.run(|_| std::future::pending::<()>()).await });
    tokio::time::sleep(Duration::from_secs(1)).await;
    session.abort();
    assert_eq!(pending.await.unwrap(), None);
    assert!(gate.subscribe().borrow().is_none());
}

#[test]
fn durations_take_units_and_bounds() {
    assert_eq!(
        cli::parse_duration("30m").unwrap(),
        Duration::from_secs(1800)
    );
    assert_eq!(
        cli::parse_duration("1h").unwrap(),
        Duration::from_secs(3600)
    );
    assert_eq!(cli::parse_duration("90s").unwrap(), Duration::from_secs(90));
    assert_eq!(cli::parse_duration("10").unwrap(), Duration::from_secs(600));
    assert_eq!(
        cli::parse_duration("10 мин").unwrap(),
        Duration::from_secs(600)
    );
    for wrong in ["", "m", "5s", "25h", "10x", "-1m"] {
        assert!(cli::parse_duration(wrong).is_err(), "{wrong}");
    }
}

#[test]
fn the_warning_names_the_volume() {
    assert!(cli::warning(Kind::Speed, 0, 100).starts_with("Тест передаст до 200,0 МБ"));
    assert!(cli::warning(Kind::Stability, 1800, 100).starts_with("Тест передаст до 15,0 МБ"));
    assert!(cli::warning(Kind::Speed, 0, 1).contains("делит канал с трафиком приложений"));
}

#[test]
fn reports_read_in_plain_words() {
    let report = TestReport {
        kind: Kind::Speed,
        idle_rtt: Summary {
            count: 10,
            p50_us: Some(45_000),
            p95_us: Some(50_000),
            ..Default::default()
        },
        loaded_rtt: Summary {
            count: 20,
            p50_us: Some(380_000),
            p95_us: Some(500_000),
            ..Default::default()
        },
        down_bps: Some(42_000_000),
        up_bps: Some(8_000_000),
        down_bytes: 50 * MIB,
        up_bytes: 10 * MIB,
        ..Default::default()
    };
    let lines = report::render(&report);
    assert_eq!(
        lines,
        [
            "Задержка 45 мс (p95 50 мс), под нагрузкой — 380 мс (p95 500 мс).",
            "Скачивание 42,0 Мбит/с (50,0 МБ).",
            "Отдача 8,0 Мбит/с (10,0 МБ).",
            "Во время передачи: замираний нет.",
        ]
    );
    let stability = TestReport {
        kind: Kind::Stability,
        duration_s: 1800,
        ping_sent: 900,
        ping_lost: 4,
        reconnects: 1,
        stalls: vec![
            Stall {
                duration_ms: 6_000,
                direction: Direction::Ping,
                ..Default::default()
            },
            Stall {
                duration_ms: 9_000,
                direction: Direction::Ping,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    assert!(report::render(&stability)[0].starts_with(
        "За 30 мин 00 с: 2 замирания по 6,0–9,0 с, 1 переподключение, потерь ping 0,4 % (4 из 900)."
    ));
    // Reports of other versions still read.
    let partial: TestReport =
        serde_json::from_str(r#"{"kind": "stability", "future": 1}"#).unwrap();
    assert_eq!(partial.kind, Kind::Stability);
}

#[test]
fn history_keeps_the_latest_tests_and_leaves_a_broken_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("tunnels.json.tests.json");
    for index in 0..history::KEEP + 3 {
        let status = TestStatus {
            id: index.to_string(),
            state: "done".into(),
            ..Default::default()
        };
        history::append(&path, status).unwrap();
    }
    let saved = history::load(&path).unwrap();
    assert_eq!(saved.tests.len(), history::KEEP);
    assert_eq!(
        saved.tests.last().unwrap().id,
        (history::KEEP + 2).to_string()
    );
    std::fs::write(&path, "{broken").unwrap();
    assert!(history::append(&path, TestStatus::default()).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{broken");
}

#[test]
fn history_drops_the_oldest_tests_to_stay_within_its_size() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("tunnels.json.tests.json");
    let large = || TestStatus {
        state: "done".into(),
        report: TestReport {
            samples: vec![Sample::default(); 4000],
            ..Default::default()
        },
        ..Default::default()
    };
    for _ in 0..12 {
        history::append(&path, large()).unwrap();
    }
    let short = TestStatus {
        id: "short".into(),
        ..Default::default()
    };
    history::append(&path, short).unwrap();
    let saved = history::load(&path).unwrap();
    assert_eq!(saved.tests.last().unwrap().id, "short");
    assert!(saved.tests.len() < 13);
}

#[tokio::test(start_paused = true)]
async fn a_greeting_of_the_login_shell_hides_neither_the_marker_nor_the_count() {
    let mut fake = Fake::new(Shell::Runs);
    fake.banner = true;
    let fake = Arc::new(fake);
    let (gate, _session) = tunnel(&fake);
    published(&gate).await;
    let tests = Tests::new(None);
    let id = tests.start(&gate, speed("t", 1)).unwrap();
    let report = finished(&tests, &id).await.report;
    assert!(
        report.skipped.is_empty() && report.notes.is_empty(),
        "{report:?}"
    );
    assert_eq!(report.up_bytes, MIB);
}

#[tokio::test(start_paused = true)]
async fn a_speed_test_names_a_stopped_tunnel() {
    let mut fake = Fake::new(Shell::Runs);
    fake.chunk = 1024;
    let fake = Arc::new(fake);
    let (gate, session) = tunnel(&fake);
    published(&gate).await;
    let tests = Tests::new(None);
    let id = tests.start(&gate, speed("t", 100)).unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    // The session's agent stops first, the gate a moment later.
    session.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(gate);
    let status = finished(&tests, &id).await;
    assert_eq!(status.error, Stop::Tunnel.message());
}

#[tokio::test(start_paused = true)]
async fn a_finished_test_stays_readable_after_a_newer_one_starts() {
    let fake = Arc::new(Fake::new(Shell::Refuses));
    let (gate, _session) = tunnel(&fake);
    published(&gate).await;
    let tests = Tests::new(None);
    let first = tests.start(&gate, speed("t", 1)).unwrap();
    finished(&tests, &first).await;
    let second = tests.start(&gate, speed("t", 1)).unwrap();
    assert_eq!(tests.status(&first).unwrap().state, "done");
    assert_eq!(tests.snapshot()["t"].id, second);
}
