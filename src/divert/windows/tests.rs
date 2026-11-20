//! Measurements of the UDP owner lookup on a real system, printed to the test log.
use std::{
    io::Write,
    net::UdpSocket,
    sync::mpsc,
    time::{Duration, Instant},
};

use super::{Snapshot, read_port_table};

/// New endpoints without a rule, one every `PACE`: 500 per second.
const ENDPOINTS: u32 = 500;
const PACE: Duration = Duration::from_millis(2);

/// Written past the test harness capture, so that a passing run shows it too.
fn report(text: &str) {
    let _ = writeln!(std::io::stderr(), "udp-owners: {text}");
}

/// Binds a new socket every `PACE` on another thread, as applications do, and hands each to
/// the receiver the way the driver queues their first datagrams for the packet loop.
fn new_endpoints() -> mpsc::Receiver<(UdpSocket, Instant)> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let began = Instant::now();
        for index in 0..ENDPOINTS {
            while began.elapsed() < PACE * index {
                std::hint::spin_loop();
            }
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            if sender.send((socket, Instant::now())).is_err() {
                return;
            }
        }
    });
    receiver
}

#[test]
fn udp_tables_under_a_stream_of_new_endpoints() {
    let pid = std::process::id();
    let mut table = vec![0u8; 4096];
    let mut sockets = Vec::new();
    let mut snapshot = Snapshot::default();
    let mut reads = 0u32;
    let mut busy = Duration::ZERO;
    let mut delay = Duration::ZERO;
    let mut worst = Duration::ZERO;
    let began = Instant::now();
    for (socket, bound) in new_endpoints() {
        let local = socket.local_addr().unwrap();
        sockets.push(socket);
        let now = Instant::now();
        let mut found = false;
        let rules = snapshot.rules(
            now,
            local,
            |v6| {
                reads += 1;
                read_port_table(false, v6, &mut table).map(<[u8]>::to_vec)
            },
            |pids| {
                found = pids.contains(&pid);
                Vec::new()
            },
        );
        busy += now.elapsed();
        delay += bound.elapsed();
        worst = worst.max(bound.elapsed());
        assert_eq!(rules, Some(vec![]));
        assert!(found, "the new socket {local} is in the last reading");
    }
    let elapsed = began.elapsed();
    // Both tables, read the way the packet loop reads them, with every socket above bound.
    let rounds = 200;
    let start = Instant::now();
    for _ in 0..rounds {
        for v6 in [false, true] {
            assert!(read_port_table(false, v6, &mut table).is_some());
        }
    }
    let one = start.elapsed() / rounds;
    report(&format!(
        "one reading of both tables: {one:?} with {} own sockets bound",
        sockets.len()
    ));
    report(&format!(
        "{ENDPOINTS} new endpoints without a rule in {elapsed:?}: {} readings of both tables, \
         {busy:?} spent in lookups; delay from bind to decision {:?} on average, {worst:?} at most",
        reads / 2,
        delay / ENDPOINTS,
    ));
}
