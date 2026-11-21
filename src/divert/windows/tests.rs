//! Measurements of the UDP owner lookup on a real system, printed to the test log.
use std::{
    io::Write,
    net::UdpSocket,
    sync::mpsc,
    time::{Duration, Instant},
};

use super::{SystemTables, performance_counter};
use crate::divert::owners::{Snapshot, Tables};

/// Written past the test harness capture, so that a passing run shows it too.
fn report(text: &str) {
    let _ = writeln!(std::io::stderr(), "udp-owners: {text}");
}

/// Binds `count` new sockets, one every `pace`, on another thread, as applications do, and hands each to
/// the receiver the way the driver queues their first datagrams for the packet loop. Each
/// comes with the moment it was bound and its capture stamp, taken after the bind.
fn new_endpoints(count: u32, pace: Duration) -> mpsc::Receiver<(UdpSocket, Instant, i64)> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let began = Instant::now();
        for index in 0..count {
            while began.elapsed() < pace * index {
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

/// The system tables, counted and timed.
struct Counted<'a> {
    tables: SystemTables<'a>,
    reads: u32,
    reading: Duration,
    waits: u32,
    waited: Duration,
}

impl Tables for Counted<'_> {
    fn read(&mut self, v6: bool) -> Option<Vec<u8>> {
        self.reads += 1;
        let start = Instant::now();
        let table = self.tables.read(v6);
        self.reading += start.elapsed();
        table
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

/// One second of new endpoints without a rule, `rate` per second, looked up with tables read
/// at most once per `gap`; reports the cost and checks the limit.
fn stream(rate: u32, gap: Duration) {
    let pid = std::process::id();
    let mut table = vec![0u8; 4096];
    let mut tables = Counted {
        tables: SystemTables { buffer: &mut table },
        reads: 0,
        reading: Duration::ZERO,
        waits: 0,
        waited: Duration::ZERO,
    };
    let mut sockets = Vec::new();
    let mut snapshot = Snapshot::with_gap(gap);
    let mut delay = Duration::ZERO;
    let mut worst = Duration::ZERO;
    let began = Instant::now();
    for (socket, bound, captured) in new_endpoints(rate, Duration::from_secs(1) / rate) {
        let local = socket.local_addr().unwrap();
        sockets.push(socket);
        let now = Instant::now();
        let mut found = false;
        let rules = snapshot.rules(now, local, captured, &mut tables, |pids| {
            found = pids.contains(&pid);
            Vec::new()
        });
        delay += bound.elapsed();
        worst = worst.max(bound.elapsed());
        assert_eq!(rules, Some(vec![]));
        // A socket under a rule would be found the same way: its first datagram never passes
        // on a reading older than its capture.
        assert!(found, "the new socket {local} is in the last reading");
    }
    let elapsed = began.elapsed();
    let reads = tables.reads / 2;
    report(&format!(
        "gap {gap:?}: {rate} new endpoints without a rule in {elapsed:?}: {reads} \
         readings of both tables taking {:?} ({:?} each), {} waits ({:?} in all); delay from \
         bind to decision {:?} on average, {worst:?} at most",
        tables.reading,
        tables.reading / reads.max(1),
        tables.waits,
        tables.waited,
        delay / rate,
    ));
    if !gap.is_zero() {
        let limit = elapsed.as_micros() / gap.as_micros() + 2;
        assert!(u128::from(reads) <= limit, "{reads} readings");
    }
}

#[test]
fn udp_tables_under_a_stream_of_new_endpoints() {
    // The capture stamp alone, then the limits considered for `REREAD_GAP`, for hundreds and
    // for thousands of new endpoints per second.
    for rate in [500, 2000] {
        for gap in [
            Duration::ZERO,
            Duration::from_millis(1),
            Duration::from_millis(2),
        ] {
            stream(rate, gap);
        }
    }
}
