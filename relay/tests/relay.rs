//! The relay binary driven through its stdin/stdout, against UDP sockets on loopback.
#![cfg(target_os = "linux")]

use std::{
    io::{Read, Write},
    net::{SocketAddr, UdpSocket},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use krot_udp_proto::{
    self as proto, CloseReason, Frame, Refusal, Settings, VERSION,
    limits::{DATAGRAM_EXPIRY, IN_FLIGHT_WINDOW, RELAY_MAX_FLOWS},
    metrics::DropReason,
};

const WAIT: Duration = Duration::from_secs(5);

/// The relay binary, run through `KROT_RELAY_RUNNER` (e.g. `qemu-aarch64`) when it is set,
/// because a cross-built test cannot start the cross-built relay directly.
fn command() -> Command {
    let relay = env!("CARGO_BIN_EXE_krot-relay");
    match std::env::var_os("KROT_RELAY_RUNNER") {
        Some(runner) => {
            let mut command = Command::new(runner);
            command.arg(relay);
            command
        }
        None => Command::new(relay),
    }
}

struct Relay {
    child: Child,
    stdin: Option<ChildStdin>,
    frames: mpsc::Receiver<Vec<u8>>,
    closed: mpsc::Receiver<()>,
}

impl Relay {
    fn start() -> Self {
        let mut child = command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (send, frames) = mpsc::channel();
        let (closed_send, closed) = mpsc::channel();
        thread::spawn(move || {
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 65_536];
            loop {
                match stdout.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => buffer.extend_from_slice(&chunk[..count]),
                }
                loop {
                    let parsed = proto::parse(&buffer).expect("relay output must be valid frames");
                    let Some((_, used)) = parsed else { break };
                    let frame: Vec<u8> = buffer.drain(..used).collect();
                    if send.send(frame).is_err() {
                        return;
                    }
                }
            }
            assert!(buffer.is_empty(), "relay ended in the middle of a frame");
            let _ = closed_send.send(());
        });
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            frames,
            closed,
        }
    }

    fn started(settings: Settings) -> Self {
        let mut relay = Self::start();
        relay.write(&Frame::Hello {
            version: VERSION,
            settings,
        });
        let answer = relay.expect(|frame| matches!(frame, Frame::HelloOk { .. }));
        assert!(matches!(
            proto::parse(&answer).unwrap().unwrap().0,
            Frame::HelloOk {
                version: VERSION,
                ..
            }
        ));
        relay
    }

    fn write(&mut self, frame: &Frame<'_>) {
        let mut encoded = Vec::new();
        proto::encode(frame, &mut encoded);
        self.write_raw(&encoded);
    }

    fn write_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
    }

    /// The next frame `wanted` accepts; frames in between are skipped.
    fn expect(&self, wanted: impl Fn(&Frame<'_>) -> bool) -> Vec<u8> {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let frame = self
                .frames
                .recv_timeout(left)
                .expect("the expected frame did not arrive");
            let parsed = proto::parse(&frame).unwrap().unwrap().0;
            if wanted(&parsed) {
                return frame;
            }
        }
    }

    fn exit_code(&mut self) -> i32 {
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap();
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("the relay did not exit");
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn settings() -> Settings {
    Settings {
        max_flows: 16,
        idle_ms: 60_000,
        idle_bidirectional_ms: 120_000,
    }
}

/// Answers every datagram with `echo:` + payload and reports who sent it.
fn echo_server(address: &str) -> (SocketAddr, mpsc::Receiver<SocketAddr>) {
    let socket = UdpSocket::bind(address).unwrap();
    let local = socket.local_addr().unwrap();
    let (send, senders) = mpsc::channel();
    thread::spawn(move || {
        let mut buffer = [0u8; 65_536];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer) {
            let mut answer = b"echo:".to_vec();
            answer.extend_from_slice(&buffer[..length]);
            let _ = socket.send_to(&answer, peer);
            // The test may not care who sent; the server keeps answering anyway.
            let _ = send.send(peer);
        }
    });
    (local, senders)
}

fn received(frame: &[u8]) -> (u32, SocketAddr, Vec<u8>) {
    match proto::parse(frame).unwrap().unwrap().0 {
        Frame::Recv { flow, peer, data } => (flow, peer, data.to_vec()),
        other => panic!("not a datagram: {other:?}"),
    }
}

fn is_recv(frame: &Frame<'_>) -> bool {
    matches!(frame, Frame::Recv { .. })
}

#[test]
fn hello_is_answered_with_clamped_settings() {
    let mut relay = Relay::start();
    relay.write(&Frame::Hello {
        version: VERSION,
        settings: Settings {
            max_flows: u16::MAX,
            idle_ms: 10,
            idle_bidirectional_ms: u32::MAX,
        },
    });
    let answer = relay.expect(|frame| matches!(frame, Frame::HelloOk { .. }));
    assert_eq!(
        proto::parse(&answer).unwrap().unwrap().0,
        Frame::HelloOk {
            version: VERSION,
            settings: Settings {
                max_flows: RELAY_MAX_FLOWS,
                idle_ms: 1_000,
                idle_bidirectional_ms: 600_000,
            },
        }
    );
}

#[test]
fn another_version_is_refused_explicitly() {
    let mut relay = Relay::start();
    relay.write(&Frame::Hello {
        version: VERSION + 1,
        settings: settings(),
    });
    let answer = relay.expect(|_| true);
    assert_eq!(
        proto::parse(&answer).unwrap().unwrap().0,
        Frame::Refuse {
            reason: Refusal::Version,
            supported: VERSION,
        }
    );
    assert_eq!(relay.exit_code(), 5);
}

#[test]
fn garbage_and_frames_before_hello_end_the_session_without_output() {
    let mut garbage = Relay::start();
    garbage.write_raw(b"SSH-2.0-OpenSSH\r\n");
    assert_eq!(garbage.exit_code(), 3);
    garbage
        .closed
        .recv_timeout(WAIT)
        .expect("stdout must close");
    assert!(garbage.frames.try_recv().is_err());

    let mut early = Relay::start();
    early.write(&Frame::Send {
        flow: 1,
        peer: "127.0.0.1:9".parse().unwrap(),
        data: b"x",
    });
    assert_eq!(early.exit_code(), 3);

    let mut started = Relay::started(settings());
    started.write(&Frame::Open { flow: 1, rule: "r" });
    assert_eq!(started.exit_code(), 3);
}

#[test]
fn datagrams_reach_the_network_and_answers_come_back_on_both_families() {
    let mut relay = Relay::started(settings());
    let mut addresses = vec!["127.0.0.1:0"];
    if UdpSocket::bind("[::1]:0").is_ok() {
        addresses.push("[::1]:0");
    }
    for (flow, address) in addresses.into_iter().enumerate() {
        let (server, _) = echo_server(address);
        let flow = flow as u32 + 1;
        relay.write(&Frame::Send {
            flow,
            peer: server,
            data: b"ping",
        });
        let answer = relay.expect(is_recv);
        assert_eq!(received(&answer), (flow, server, b"echo:ping".to_vec()));
    }
}

#[test]
fn oversized_ipv6_replies_are_dropped_without_truncation() {
    let Ok(server) = UdpSocket::bind("[::1]:0") else {
        return;
    };
    server.set_read_timeout(Some(WAIT)).unwrap();
    let mut relay = Relay::started(settings());
    let peer = server.local_addr().unwrap();
    relay.write(&Frame::Send {
        flow: 1,
        peer,
        data: b"x",
    });
    let (_, mapped) = server.recv_from(&mut [0; 1]).unwrap();

    let oversized = vec![1; 65_527];
    assert_eq!(server.send_to(&oversized, mapped).unwrap(), oversized.len());
    let stats = relay.expect(|frame| {
        assert!(!is_recv(frame), "the oversized reply produced a RECV frame");
        matches!(frame, Frame::Stats(stats) if stats.from_network_datagrams == 1)
    });
    let Frame::Stats(stats) = proto::parse(&stats).unwrap().unwrap().0 else {
        unreachable!()
    };
    assert_eq!(stats.drops.get(DropReason::Size), 1);
    assert_eq!(stats.from_network_bytes, oversized.len() as u64);

    let largest = vec![2; proto::MAX_PAYLOAD];
    assert_eq!(server.send_to(&largest, mapped).unwrap(), largest.len());
    let (flow, from, data) = received(&relay.expect(is_recv));
    assert_eq!((flow, from), (1, peer));
    assert!(
        data == largest,
        "the largest valid reply must arrive intact"
    );
}

#[test]
fn answers_from_any_address_reach_the_flow() {
    let mut relay = Relay::started(settings());
    let (server, senders) = echo_server("127.0.0.1:0");
    relay.write(&Frame::Send {
        flow: 7,
        peer: server,
        data: b"hole",
    });
    relay.expect(is_recv);
    let mapped = senders.recv_timeout(WAIT).unwrap();
    // A host the flow never sent to reaches it through the same port, as STUN expects.
    let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
    let stranger_address = stranger.local_addr().unwrap();
    let mapped = SocketAddr::new("127.0.0.1".parse().unwrap(), mapped.port());
    stranger.send_to(b"hello", mapped).unwrap();
    let answer = relay.expect(is_recv);
    assert_eq!(received(&answer), (7, stranger_address, b"hello".to_vec()));
}

#[test]
fn flows_beyond_the_limit_are_refused_and_counted() {
    let mut relay = Relay::started(Settings {
        max_flows: 2,
        ..settings()
    });
    let (server, _) = echo_server("127.0.0.1:0");
    for flow in 1..=3 {
        relay.write(&Frame::Send {
            flow,
            peer: server,
            data: b"x",
        });
    }
    let close = relay.expect(|frame| matches!(frame, Frame::Close { .. }));
    assert_eq!(
        proto::parse(&close).unwrap().unwrap().0,
        Frame::Close {
            flow: 3,
            reason: CloseReason::Limit,
        }
    );
    let stats =
        relay.expect(|frame| matches!(frame, Frame::Stats(stats) if stats.flows_opened == 2));
    let Frame::Stats(stats) = proto::parse(&stats).unwrap().unwrap().0 else {
        unreachable!()
    };
    assert_eq!(
        (
            stats.flows_active,
            stats.flows_refused,
            stats.to_network_datagrams
        ),
        (2, 1, 2)
    );

    // A closed flow frees its place.
    relay.write(&Frame::Close {
        flow: 1,
        reason: CloseReason::Client,
    });
    relay.write(&Frame::Send {
        flow: 4,
        peer: server,
        data: b"y",
    });
    let answer = relay.expect(|frame| matches!(frame, Frame::Recv { flow: 4, .. }));
    assert_eq!(received(&answer).2, b"echo:y");
}

#[test]
fn idle_flows_are_closed() {
    let mut relay = Relay::started(Settings {
        idle_ms: 1_000,
        idle_bidirectional_ms: 1_000,
        ..settings()
    });
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    relay.write(&Frame::Send {
        flow: 9,
        peer: silent.local_addr().unwrap(),
        data: b"anyone?",
    });
    let started = Instant::now();
    let close = relay.expect(|frame| matches!(frame, Frame::Close { .. }));
    assert_eq!(
        proto::parse(&close).unwrap().unwrap().0,
        Frame::Close {
            flow: 9,
            reason: CloseReason::Idle,
        }
    );
    assert!(started.elapsed() >= Duration::from_millis(900));
}

#[test]
fn closed_stdin_ends_the_relay_at_once() {
    let mut relay = Relay::started(settings());
    let (server, _) = echo_server("127.0.0.1:0");
    relay.write(&Frame::Send {
        flow: 1,
        peer: server,
        data: b"x",
    });
    relay.expect(is_recv);
    let started = Instant::now();
    relay.stdin = None;
    assert_eq!(relay.exit_code(), 0);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn pings_are_echoed_and_datagram_bytes_acknowledged() {
    let mut relay = Relay::started(settings());
    relay.write(&Frame::Ping {
        sequence: 42,
        time_us: 123_456,
    });
    let pong = relay.expect(|frame| matches!(frame, Frame::Pong { .. }));
    assert!(matches!(
        proto::parse(&pong).unwrap().unwrap().0,
        Frame::Pong {
            sequence: 42,
            time_us: 123_456,
            held_us
        } if held_us < 1_000_000
    ));

    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut total = 0u64;
    for _ in 0..3 {
        let frame = Frame::Send {
            flow: 1,
            peer: silent.local_addr().unwrap(),
            data: &[7; 1000],
        };
        let mut encoded = Vec::new();
        proto::encode(&frame, &mut encoded);
        total += encoded.len() as u64;
        relay.write_raw(&encoded);
    }
    relay.expect(|frame| matches!(frame, Frame::Ack { received } if *received == total));
}

#[test]
fn answers_wait_for_acknowledgement_and_expire_instead_of_arriving_late() {
    let mut relay = Relay::started(settings());
    let (server, _) = echo_server("127.0.0.1:0");
    let payload = [1u8; 1000];
    // Without acknowledgements the relay may have only the window in flight.
    let count = 2 * IN_FLIGHT_WINDOW as usize / payload.len();
    let mut sent = Vec::new();
    // Paced, so that the answers wait in the relay's queue rather than overflow the kernel's
    // socket buffer while a loaded test machine is slow to schedule the relay.
    for _ in 0..count {
        relay.write(&Frame::Send {
            flow: 1,
            peer: server,
            data: &payload,
        });
        thread::sleep(Duration::from_micros(500));
    }
    let mut received_bytes = 0u64;
    let mut answers = 0;
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        if let Ok(frame) = relay.frames.recv_timeout(Duration::from_millis(20))
            && is_recv(&proto::parse(&frame).unwrap().unwrap().0)
        {
            received_bytes += frame.len() as u64;
            answers += 1;
            sent.push(frame);
        }
    }
    assert!(answers > 0 && answers < count, "{answers} of {count}");
    assert!(received_bytes <= IN_FLIGHT_WINDOW);

    // Everything still queued is older than the expiry by now and must not be delivered.
    thread::sleep(DATAGRAM_EXPIRY);
    relay.write(&Frame::Ack {
        received: received_bytes,
    });
    let stats = relay.expect(
        |frame| matches!(frame, Frame::Stats(stats) if stats.drops.get(DropReason::Expired) > 0),
    );
    let Frame::Stats(stats) = proto::parse(&stats).unwrap().unwrap().0 else {
        unreachable!()
    };
    let expired = stats.drops.get(DropReason::Expired);
    let late = relay
        .frames
        .try_iter()
        .filter(|frame| is_recv(&proto::parse(frame).unwrap().unwrap().0))
        .count() as u64;
    assert_eq!(late, 0, "{expired} expired");
    assert!(stats.to_client_delay.max_us < DATAGRAM_EXPIRY.as_micros() as u64);
}

#[test]
fn arguments_are_refused() {
    let status = command()
        .arg("127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}
