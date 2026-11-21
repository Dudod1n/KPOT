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

/// Writes a line of the driver test past the test harness capture.
fn driver_report(text: &str) {
    let _ = writeln!(std::io::stderr(), "windivert: {text}");
}

/// The real driver captures an application's outbound datagram. Runs with `--ignored` where
/// WinDivert.dll and WinDivert64.sys lie next to the test binary and the process is an
/// administrator, as on the CI Windows runner. Only datagrams to TEST-NET-1 are diverted, and
/// they never leave. A datagram larger than the MTU is reported, not checked: whether it is
/// captured whole or in fragments depends on the network adapter.
#[test]
#[ignore]
fn windivert_captures_outbound_udp() {
    use super::{Address, load};
    const TARGET: [u8; 4] = [192, 0, 2, 1];
    const PORT: u16 = 47999;
    let api = load().expect("WinDivert files next to the test binary");
    let filter = format!(
        "outbound and ip.DstAddr == {}.{}.{}.{}\0",
        TARGET[0], TARGET[1], TARGET[2], TARGET[3]
    );
    // SAFETY: the filter is NUL-terminated; layer 0 is the network layer, no flags.
    let device = unsafe { (api.open)(filter.as_ptr(), 0, 0, 0) };
    if device == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        // SAFETY: reads the calling thread's last error code.
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        panic!("WinDivertOpen failed with error {code}");
    }
    let device = device as usize;
    let (sender, receiver) = mpsc::channel();
    // The thread stays blocked in the driver after the test; the process ends with it.
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; 65535];
        loop {
            // SAFETY: a zeroed WINDIVERT_ADDRESS is valid; the buffer outlives the call.
            let mut address: Address = unsafe { std::mem::zeroed() };
            let mut length = 0u32;
            // SAFETY: the handle is never closed while the process runs; the pointers are
            // valid for the call.
            let received = unsafe {
                (api.recv)(
                    device as _,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut length,
                    &mut address,
                )
            };
            if received == 0 || sender.send(buffer[..length as usize].to_vec()).is_err() {
                return;
            }
        }
    });
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket
        .send_to(b"krot-capture", (std::net::Ipv4Addr::from(TARGET), PORT))
        .unwrap();
    let packet = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("the datagram was not captured");
    let header = usize::from(packet[0] & 0x0f) * 4;
    assert_eq!(packet[0] >> 4, 4, "IPv4");
    assert_eq!(packet[9], 17, "UDP");
    assert_eq!(packet[16..20], TARGET);
    assert_eq!(
        u16::from_be_bytes([packet[header + 2], packet[header + 3]]),
        PORT
    );
    assert_eq!(&packet[header + 8..], b"krot-capture");
    driver_report("the driver opened and captured the datagram");

    socket
        .send_to(&[7u8; 4000], (std::net::Ipv4Addr::from(TARGET), PORT))
        .unwrap();
    while let Ok(packet) = receiver.recv_timeout(Duration::from_secs(2)) {
        let field = u16::from_be_bytes([packet[6], packet[7]]);
        driver_report(&format!(
            "a 4000-byte datagram: captured {} bytes, fragment offset {}, more fragments {}",
            packet.len(),
            (field & 0x1fff) * 8,
            field & 0x2000 != 0
        ));
    }
}
