use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MS: Duration = Duration::from_millis(1);
const SECOND: Duration = Duration::from_secs(1);

/// A connected meter, the start instant and a clock that moves forward.
struct Run {
    meter: Meter,
    at: Instant,
    rx: u64,
    tx: u64,
}

impl Run {
    fn new() -> Self {
        let at = Instant::now();
        let mut meter = Meter::new(at, 1_000.0);
        meter.connected(at);
        meter.sample(at, 0, 0);
        Self {
            meter,
            at,
            rx: 0,
            tx: 0,
        }
    }
    /// Lets `seconds` pass, adding the given bytes every second.
    fn traffic(&mut self, seconds: u64, rx_per_second: u64, tx_per_second: u64) {
        for _ in 0..seconds {
            self.at += SECOND;
            self.rx += rx_per_second;
            self.tx += tx_per_second;
            self.meter.sample(self.at, self.rx, self.tx);
        }
    }
    fn stats(&self) -> LinkStats {
        self.meter.stats(self.at, self.rx, self.tx)
    }
    fn kinds(&self) -> Vec<String> {
        self.stats().events.into_iter().map(|e| e.kind).collect()
    }
}

#[test]
fn rtt_quantiles_forget_pings_older_than_the_window() {
    let mut run = Run::new();
    for _ in 0..6 {
        run.traffic(10, 0, 0);
        run.meter.ping_answered(run.at, 400 * MS);
    }
    assert_eq!(run.stats().rtt.p50_us, Some(400_000));
    // Over ten more minutes of fast answers push the slow minute out of the window.
    for _ in 0..70 {
        run.traffic(10, 0, 0);
        run.meter.ping_answered(run.at, 20 * MS);
    }
    let rtt = run.stats().rtt;
    assert_eq!((rtt.p50_us, rtt.p95_us), (Some(20_000), Some(20_000)));
    assert!(rtt.max_us < Some(400_000), "{rtt:?}");
}

#[test]
fn jitter_is_the_mean_change_between_consecutive_pings() {
    let mut run = Run::new();
    assert_eq!(run.stats().jitter_us, None);
    for rtt in [10, 30, 10, 30] {
        run.meter.ping_answered(run.at, rtt * MS);
    }
    assert_eq!(run.stats().jitter_us, Some(20_000));
    let mut steady = Run::new();
    for _ in 0..5 {
        steady.meter.ping_answered(steady.at, 50 * MS);
    }
    assert_eq!(steady.stats().jitter_us, Some(0));
}

#[test]
fn two_lost_pings_in_a_row_make_one_stall_until_an_answer() {
    let mut run = Run::new();
    run.meter.ping_lost(run.at);
    run.meter.ping_answered(run.at, 10 * MS);
    run.meter.ping_lost(run.at);
    assert_eq!(run.stats().stalls, 0, "losses apart are no stall");

    run.traffic(10, 0, 0);
    run.meter.ping_lost(run.at);
    let stats = run.stats();
    assert_eq!((stats.stalls, stats.stalled), (1, true));
    run.traffic(10, 0, 0);
    run.meter.ping_lost(run.at);
    assert_eq!(run.stats().stalls, 1, "a stall is counted once");

    run.traffic(10, 0, 0);
    run.meter.ping_answered(run.at, 10 * MS);
    let stats = run.stats();
    assert_eq!(
        (stats.stalled, stats.ping_lost, stats.ping_sent),
        (false, 4, 6)
    );
    let recovered = stats.events.last().unwrap();
    assert_eq!(recovered.kind, "recovered");
    assert!(recovered.detail.contains("20 с"), "{}", recovered.detail);
}

#[test]
fn silence_while_sending_is_a_stall_only_without_an_answered_ping() {
    // Incoming data stops while the applications keep sending, and pings go unanswered.
    let mut run = Run::new();
    run.traffic(5, 50_000, 1_000);
    run.traffic(STALL_SILENCE.as_secs() - 1, 0, 1_000);
    assert_eq!(run.stats().stalls, 0);
    run.traffic(1, 0, 1_000);
    assert!(run.stats().stalled);
    run.traffic(1, 10, 1_000);
    assert!(!run.stats().stalled, "data again ends the stall");
    assert_eq!(run.kinds(), ["connected", "stall", "recovered"]);

    // A ping answered during the silence shows the session alive.
    let mut alive = Run::new();
    alive.traffic(5, 50_000, 1_000);
    alive.traffic(5, 0, 1_000);
    alive.meter.ping_answered(alive.at, 30 * MS);
    alive.traffic(30, 0, 1_000);
    assert_eq!(alive.stats().stalls, 0);

    // An upload that never received anything, and a connection that went idle.
    let mut upload = Run::new();
    upload.traffic(60, 0, 100_000);
    let mut idle = Run::new();
    idle.traffic(5, 50_000, 1_000);
    idle.traffic(60, 0, 0);
    assert_eq!((upload.stats().stalls, idle.stats().stalls), (0, 0));
}

#[test]
fn the_rate_covers_the_last_five_seconds() {
    let mut run = Run::new();
    run.traffic(10, 125_000, 12_500);
    let stats = run.stats();
    assert_eq!((stats.rx_bps, stats.tx_bps), (1_000_000, 100_000));
    assert_eq!((stats.rx_total, stats.tx_total), (1_250_000, 125_000));

    // Three seconds of silence leave two of the last five seconds busy.
    run.traffic(3, 0, 0);
    assert_eq!(run.stats().rx_bps, 400_000);
    run.traffic(5, 0, 0);
    let stats = run.stats();
    assert_eq!((stats.rx_bps, stats.rx_total), (0, 1_250_000));

    // Readings that stopped coming say nothing about the current rate.
    run.traffic(5, 125_000, 0);
    run.at += 10 * SECOND;
    assert_eq!(run.stats().rx_bps, 0);
}

#[test]
fn reconnects_keep_their_reasons_and_uptime_restarts() {
    let mut run = Run::new();
    run.traffic(100, 0, 0);
    assert_eq!(run.stats().uptime_s, 100);
    assert_eq!(run.stats().connected_since, Some(1_000.0));

    run.meter.disconnected(run.at, "SSH-соединение прервано.");
    run.traffic(5, 0, 0);
    run.meter.ping_lost(run.at);
    let down = run.stats();
    assert_eq!(
        (down.connected_since, down.uptime_s, down.ping_lost),
        (None, 0, 0),
        "nothing is measured between sessions"
    );

    run.meter.connected(run.at);
    run.traffic(7, 0, 0);
    let stats = run.stats();
    assert_eq!((stats.reconnects, stats.uptime_s), (1, 7));
    assert_eq!(stats.connected_since, Some(1_105.0));
    assert_eq!(run.kinds(), ["connected", "disconnected", "reconnected"]);
    assert_eq!(stats.events[1].detail, "SSH-соединение прервано.");
    assert_eq!(stats.events[1].at, 1_100.0);
}

#[test]
fn the_event_journal_keeps_the_latest_entries() {
    let mut run = Run::new();
    for index in 0..40 {
        run.meter.disconnected(run.at, &format!("обрыв {index}"));
        run.meter.connected(run.at);
    }
    let stats = run.stats();
    assert_eq!(stats.events.len(), EVENTS);
    assert_eq!(stats.reconnects, 40);
    assert_eq!(stats.events.last().unwrap().detail, "Переподключение № 40.");
    assert!(stats.events.iter().all(|e| e.detail != "обрыв 0"));
}

#[tokio::test]
async fn counted_streams_add_what_passes_in_each_direction() {
    let counters = Arc::new(Counters::default());
    let (near, mut far) = tokio::io::duplex(4096);
    let mut counted = Counted::new(near, counters.clone());
    counted.write_all(&[1; 1000]).await.unwrap();
    let mut sink = vec![0; 1000];
    far.read_exact(&mut sink).await.unwrap();
    far.write_all(&[2; 300]).await.unwrap();
    drop(far);
    let mut received = Vec::new();
    counted.read_to_end(&mut received).await.unwrap();
    assert_eq!(received.len(), 300);
    assert_eq!(counters.totals(), (300, 1000));
}

#[tokio::test(start_paused = true)]
async fn the_probe_pings_after_each_pause_and_survives_unanswered_pings() {
    let link = Arc::new(Link::new());
    link.connected();
    let answers = Arc::new(Mutex::new(vec![true, true, false, false, true]));
    let calls = Arc::new(AtomicU64::new(0));
    let probe = {
        let (link, answers, calls) = (link.clone(), answers.clone(), calls.clone());
        tokio::spawn(async move {
            link.probe_with(
                || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    let answer = answers.lock().unwrap().remove(0);
                    async move {
                        if answer {
                            tokio::time::sleep(30 * MS).await;
                        } else {
                            // Never answers; the probe gives up on it after the timeout.
                            std::future::pending::<()>().await;
                        }
                        true
                    }
                },
                || 10 * SECOND,
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_secs(45)).await;
    let stats = link.stats();
    assert_eq!(
        calls.load(Ordering::Relaxed),
        5,
        "pings at 1, 11, 21, 31, 41 s"
    );
    assert_eq!((stats.ping_sent, stats.ping_lost, stats.stalls), (5, 2, 1));
    assert!(!stats.stalled, "the last answer ended the stall");
    assert_eq!(stats.rtt.count, 3);
    assert_eq!(stats.rtt.max_us, Some(30_000));
    assert!(!probe.is_finished());
    probe.abort();
}

#[test]
fn pauses_between_pings_vary_within_bounds() {
    let pauses: Vec<Duration> = (0..200).map(|_| ping_pause()).collect();
    assert!(
        pauses
            .iter()
            .all(|pause| (PING_INTERVAL_MIN..=PING_INTERVAL_MAX).contains(pause))
    );
    // Equal pauses would draw the periodic pattern the randomness is there to avoid.
    assert!(pauses.iter().any(|pause| *pause != pauses[0]));
}

#[tokio::test(start_paused = true)]
async fn the_probe_ends_with_the_session_and_reads_the_counters() {
    let link = Arc::new(Link::new());
    link.connected();
    let counters = link.counters();
    let probe = {
        let link = link.clone();
        tokio::spawn(async move { link.probe(|| async { true }).await })
    };
    // Between the probe's readings, which come every whole second.
    tokio::time::sleep(SECOND / 2).await;
    for _ in 0..6 {
        counters.rx.fetch_add(10_000, Ordering::Relaxed);
        tokio::time::sleep(SECOND).await;
    }
    let stats = link.stats();
    assert_eq!(stats.rx_total, 60_000);
    assert_eq!(stats.rx_bps, 80_000);
    assert!(!probe.is_finished());

    let gone = link.clone();
    let probe_gone = tokio::spawn(async move { gone.probe(|| async { false }).await });
    tokio::time::sleep(2 * SECOND).await;
    assert!(probe_gone.is_finished(), "a closed session ends the probe");
    probe.abort();
}

#[test]
fn snapshots_of_older_and_newer_versions_still_read() {
    let partial: LinkStats = serde_json::from_str(r#"{"rx_bps": 5, "future": true}"#).unwrap();
    assert_eq!((partial.rx_bps, partial.rtt.count), (5, 0));

    let mut older = serde_json::to_value(crate::background::Snapshot::default()).unwrap();
    older.as_object_mut().unwrap().remove("links");
    let snapshot: crate::background::Snapshot = serde_json::from_value(older).unwrap();
    assert!(snapshot.links.is_empty());
}

#[test]
fn texts_are_short_and_in_russian() {
    assert_eq!(rate_text(950), "950 бит/с");
    assert_eq!(rate_text(4_200_000), "4,2 Мбит/с");
    assert_eq!(duration_text(42), "42 с");
    assert_eq!(duration_text(187), "3 мин 07 с");
    assert_eq!(duration_text(3_900), "1 ч 05 мин");
    assert_eq!(bytes_text(1_572_864), "1,5 МБ");

    let mut run = Run::new();
    assert!(card_lines(&run.stats())[0].starts_with("Задержка: измеряется"));
    run.meter.ping_answered(run.at, 45 * MS);
    run.meter.ping_answered(run.at, 47 * MS);
    run.traffic(5, 500_000, 1_000);
    let lines = card_lines(&run.stats());
    assert_eq!(
        lines[0],
        "Задержка 47 мс, p95 47 мс · джиттер 2,0 мс · потеряно ping 0 из 2"
    );
    assert_eq!(
        lines[1],
        "Скорость ↓ 4,0 Мбит/с · ↑ 8,0 кбит/с · всего ↓ 2,4 МБ · ↑ 4,9 КБ"
    );
    assert_eq!(lines[2], "Сессия 5 с · переподключений 0 · замираний 0");
}
