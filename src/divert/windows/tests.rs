//! Measurements of the UDP owner lookup on a real system, printed to the test log.
use std::{
    io::Write,
    net::UdpSocket,
    sync::mpsc,
    time::{Duration, Instant},
};

use super::{SystemTables, performance_counter};
use crate::divert::owners::{REREAD_GAP, Snapshot, Tables};

/// New endpoints without a rule, one every `PACE`: 500 per second.
const ENDPOINTS: u32 = 500;
const PACE: Duration = Duration::from_millis(2);

/// Written past the test harness capture, so that a passing run shows it too.
fn report(text: &str) {
    let _ = writeln!(std::io::stderr(), "udp-owners: {text}");
}

/// Binds a new socket every `PACE` on another thread, as applications do, and hands each to
/// the receiver the way the driver queues their first datagrams for the packet loop. Each
/// comes with the moment it was bound and its capture stamp, taken after the bind.
fn new_endpoints() -> mpsc::Receiver<(UdpSocket, Instant, i64)> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let began = Instant::now();
        for index in 0..ENDPOINTS {
            while began.elapsed() < PACE * index {
                std::hint::spin_loop();
            }
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let bound = Instant::now();
            if sender.send((socket, bound, performance_counter())).is_err() {
                return;
            }
        }
    });
    receiver
}

/// The system tables, counted.
struct Counted<'a> {
    tables: SystemTables<'a>,
    reads: u32,
    waits: u32,
    waited: Duration,
}

impl Tables for Counted<'_> {
    fn read(&mut self, v6: bool) -> Option<Vec<u8>> {
        self.reads += 1;
        self.tables.read(v6)
    }

    fn stamp(&mut self) -> i64 {
        self.tables.stamp()
    }

    fn wait(&mut self, time: Duration) -> Instant {
        self.waits += 1;
        self.waited += time;
        self.tables.wait(time)
    }
}

#[test]
fn udp_tables_under_a_stream_of_new_endpoints() {
    let pid = std::process::id();
    let mut table = vec![0u8; 4096];
    let mut tables = Counted {
        tables: SystemTables { buffer: &mut table },
        reads: 0,
        waits: 0,
        waited: Duration::ZERO,
    };
    let mut sockets = Vec::new();
    let mut snapshot = Snapshot::default();
    let mut busy = Duration::ZERO;
    let mut delay = Duration::ZERO;
    let mut worst = Duration::ZERO;
    let began = Instant::now();
    for (socket, bound, captured) in new_endpoints() {
        let local = socket.local_addr().unwrap();
        sockets.push(socket);
        let now = Instant::now();
        let mut found = false;
        let rules = snapshot.rules(now, local, captured, &mut tables, |pids| {
            found = pids.contains(&pid);
            Vec::new()
        });
        busy += now.elapsed();
        delay += bound.elapsed();
        worst = worst.max(bound.elapsed());
        assert_eq!(rules, Some(vec![]));
        // A socket under a rule would be found the same way: its first datagram never passes
        // on a reading older than its capture.
        assert!(found, "the new socket {local} is in the last reading");
    }
    let elapsed = began.elapsed();
    let (reads, waits, waited) = (tables.reads / 2, tables.waits, tables.waited);
    // Both tables, read the way the packet loop reads them, with every socket above bound.
    let rounds = 200;
    let start = Instant::now();
    for _ in 0..rounds {
        for v6 in [false, true] {
            assert!(tables.tables.read(v6).is_some());
        }
    }
    let one = start.elapsed() / rounds;
    report(&format!(
        "one reading of both tables: {one:?} with {} own sockets bound",
        sockets.len()
    ));
    report(&format!(
        "{ENDPOINTS} new endpoints without a rule in {elapsed:?}: {reads} readings of both \
         tables, {waits} waits for the {REREAD_GAP:?} gap ({waited:?} in all), {busy:?} \
         spent in lookups; delay from bind to decision {:?} on average, {worst:?} at most",
        delay / ENDPOINTS,
    ));
    let limit = elapsed.as_millis() / REREAD_GAP.as_millis() + 2;
    assert!(u128::from(reads) <= limit, "{reads} readings");
}
