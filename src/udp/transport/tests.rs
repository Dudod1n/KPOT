use super::*;
use tokio::io::{DuplexStream, ReadHalf, WriteHalf, duplex, split};

/// How the fake relay on the other end of the stream behaves.
#[derive(Clone, Copy)]
struct Behaviour {
    version: u16,
    echo: bool,
    acknowledge: bool,
    pong: bool,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            version: VERSION,
            echo: true,
            acknowledge: true,
            pong: true,
        }
    }
}

/// What the fake relay saw.
#[derive(Default)]
struct Seen {
    sends: Vec<(u32, SocketAddr, usize)>,
    send_bytes: u64,
    closes: Vec<u32>,
    acks: Vec<u64>,
    pings: u32,
}

struct Fake {
    seen: Arc<Mutex<Seen>>,
    /// Frames to push to the client.
    push: mpsc::UnboundedSender<Vec<u8>>,
}

fn encoded(frame: &Frame<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    proto::encode(frame, &mut bytes);
    bytes
}

fn fake(stream: DuplexStream, behaviour: Behaviour) -> Fake {
    let (mut reader, mut writer) = split(stream);
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (push, mut pushed) = mpsc::unbounded_channel::<Vec<u8>>();
    let (out, mut outgoing) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(bytes) = tokio::select! {
            bytes = pushed.recv() => bytes,
            bytes = outgoing.recv() => bytes,
        } {
            if writer.write_all(&bytes).await.is_err() {
                return;
            }
        }
    });
    let recorder = seen.clone();
    tokio::spawn(async move {
        let mut buffer = Vec::new();
        let mut chunk = vec![0u8; 65_536];
        loop {
            let mut start = 0;
            while let Some((frame, used)) = proto::parse(&buffer[start..]).unwrap() {
                start += used;
                let mut seen = recorder.lock().unwrap();
                let reply = match frame {
                    Frame::Hello { settings, .. } if behaviour.version == VERSION => {
                        Some(encoded(&Frame::HelloOk {
                            version: VERSION,
                            settings,
                        }))
                    }
                    Frame::Hello { .. } => Some(encoded(&Frame::Refuse {
                        reason: Refusal::Version,
                        supported: behaviour.version,
                    })),
                    Frame::Send { flow, peer, data } => {
                        seen.sends.push((flow, peer, data.len()));
                        seen.send_bytes += used as u64;
                        let mut reply = Vec::new();
                        if behaviour.acknowledge {
                            proto::encode(
                                &Frame::Ack {
                                    received: seen.send_bytes,
                                },
                                &mut reply,
                            );
                        }
                        if behaviour.echo {
                            proto::encode(&Frame::Recv { flow, peer, data }, &mut reply);
                        }
                        Some(reply)
                    }
                    Frame::Close { flow, .. } => {
                        seen.closes.push(flow);
                        None
                    }
                    Frame::Ack { received } => {
                        seen.acks.push(received);
                        None
                    }
                    Frame::Ping { sequence, time_us } => {
                        seen.pings += 1;
                        behaviour.pong.then(|| {
                            encoded(&Frame::Pong {
                                sequence,
                                time_us,
                                held_us: 0,
                            })
                        })
                    }
                    other => panic!("unexpected frame {other:?}"),
                };
                drop(seen);
                if let Some(reply) = reply
                    && out.send(reply).is_err()
                {
                    return;
                }
            }
            buffer.drain(..start);
            match reader.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(count) => buffer.extend_from_slice(&chunk[..count]),
            }
        }
    });
    Fake { seen, push }
}

async fn connected(
    behaviour: Behaviour,
) -> Result<(Transport, mpsc::Receiver<Event>, Fake), Failure> {
    let (client, relay) = duplex(1 << 20);
    let fake = fake(relay, behaviour);
    let (reader, writer): (ReadHalf<DuplexStream>, WriteHalf<DuplexStream>) = split(client);
    let (transport, events) = Transport::start(reader, writer, default_settings()).await?;
    Ok((transport, events, fake))
}

fn peer() -> SocketAddr {
    "198.51.100.1:3478".parse().unwrap()
}

async fn next(events: &mut mpsc::Receiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("no event in time")
        .expect("events ended")
}

#[tokio::test]
async fn datagrams_go_out_and_answers_come_back_with_counters() {
    let (transport, mut events, fake) = connected(Behaviour::default()).await.unwrap();
    assert_eq!(transport.settings(), default_settings());
    transport.send(1, peer(), b"hello");
    transport.send(2, "[2001:db8::2]:53".parse().unwrap(), b"dns");
    assert_eq!(
        next(&mut events).await,
        Event::Datagram {
            flow: 1,
            peer: peer(),
            data: b"hello".to_vec()
        }
    );
    assert!(matches!(
        next(&mut events).await,
        Event::Datagram { flow: 2, .. }
    ));
    let counters = transport.flow(1).unwrap();
    assert_eq!((counters.sent.datagrams, counters.sent.bytes), (1, 5));
    assert_eq!(
        (counters.received.datagrams, counters.received.bytes),
        (1, 5)
    );
    let metrics = transport.metrics();
    assert_eq!(metrics.sent.datagrams, 2);
    assert_eq!(metrics.received.datagrams, 2);
    assert_eq!(metrics.flows_active, 2);
    assert_eq!(metrics.to_channel_delay.count, 2);
    assert!(metrics.drops.values().all(|count| *count == 0));
    assert_eq!(fake.seen.lock().unwrap().sends.len(), 2);
}

#[tokio::test]
async fn another_relay_version_is_reported() {
    let failure = connected(Behaviour {
        version: VERSION + 3,
        ..Default::default()
    })
    .await
    .err();
    assert_eq!(failure, Some(Failure::Version(VERSION + 3)));
}

#[tokio::test]
async fn without_acknowledgements_only_the_window_leaves_and_the_rest_expires() {
    let (transport, _events, fake) = connected(Behaviour {
        echo: false,
        acknowledge: false,
        ..Default::default()
    })
    .await
    .unwrap();
    let payload = [0u8; 1000];
    let count = 2 * IN_FLIGHT_WINDOW as usize / payload.len();
    for _ in 0..count {
        transport.send(1, peer(), &payload);
    }
    tokio::time::sleep(DATAGRAM_EXPIRY + Duration::from_millis(200)).await;
    let delivered = fake.seen.lock().unwrap().sends.len();
    assert!(delivered > 0 && delivered < count, "{delivered} of {count}");
    assert!(fake.seen.lock().unwrap().send_bytes <= IN_FLIGHT_WINDOW);
    let metrics = transport.metrics();
    assert_eq!(metrics.drops["expired"] as usize, count - delivered);
    assert_eq!(metrics.queue_datagrams, 0);
    assert_eq!(
        transport.flow(1).unwrap().drops.get(DropReason::Expired) as usize,
        count - delivered
    );
    assert!(metrics.to_channel_delay.max_us.unwrap() <= DATAGRAM_EXPIRY.as_micros() as u64);
}

#[tokio::test]
async fn a_full_queue_drops_its_oldest_datagrams() {
    let (transport, _events, _fake) = connected(Behaviour {
        echo: false,
        acknowledge: false,
        ..Default::default()
    })
    .await
    .unwrap();
    // Small datagrams: the count limit is reached long before the window.
    let extra = 100;
    for _ in 0..(IN_FLIGHT_WINDOW as usize / 20 + CHANNEL_QUEUE_DATAGRAMS + extra) {
        transport.send(1, peer(), b"x");
    }
    let metrics = transport.metrics();
    assert!(metrics.drops["overflow"] > 0);
    assert!(metrics.queue_datagrams as usize <= CHANNEL_QUEUE_DATAGRAMS);
    let oversized = vec![0u8; proto::MAX_PAYLOAD + 1];
    transport.send(2, peer(), &oversized);
    assert_eq!(transport.metrics().drops["size"], 1);
}

#[tokio::test]
async fn closes_travel_both_ways_and_late_answers_are_ignored() {
    let (transport, mut events, fake) = connected(Behaviour::default()).await.unwrap();
    transport.send(1, peer(), b"a");
    next(&mut events).await;
    let counters = transport.close(1).unwrap();
    assert_eq!(counters.sent.datagrams, 1);
    assert!(transport.close(1).is_none());
    // An answer that was already on its way for the closed flow is not delivered.
    fake.push
        .send(encoded(&Frame::Recv {
            flow: 1,
            peer: peer(),
            data: b"late",
        }))
        .unwrap();

    transport.send(2, peer(), b"b");
    assert!(matches!(
        next(&mut events).await,
        Event::Datagram { flow: 2, .. }
    ));
    fake.push
        .send(encoded(&Frame::Close {
            flow: 2,
            reason: CloseReason::Idle,
        }))
        .unwrap();
    match next(&mut events).await {
        Event::Closed {
            flow: 2,
            reason: CloseReason::Idle,
            counters,
        } => assert_eq!(counters.received.datagrams, 1),
        other => panic!("{other:?}"),
    }
    assert!(transport.flow(2).is_none());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(fake.seen.lock().unwrap().closes, [1]);
}

#[tokio::test]
async fn received_bytes_are_acknowledged_and_pings_measure_the_round_trip() {
    let (transport, mut events, fake) = connected(Behaviour::default()).await.unwrap();
    transport.send(5, peer(), b"open");
    next(&mut events).await;
    let mut expected = 0u64;
    for _ in 0..3 {
        let frame = encoded(&Frame::Recv {
            flow: 5,
            peer: peer(),
            data: &[1; 500],
        });
        fake.push.send(frame).unwrap();
        next(&mut events).await;
    }
    // The echo of "open" is a datagram frame too.
    expected += proto::datagram_frame_size(&peer(), 4) as u64;
    expected += 3 * proto::datagram_frame_size(&peer(), 500) as u64;
    tokio::time::sleep(ACK_INTERVAL * 3).await;
    assert_eq!(fake.seen.lock().unwrap().acks.last(), Some(&expected));

    tokio::time::sleep(REPORT_INTERVAL + Duration::from_millis(200)).await;
    assert!(fake.seen.lock().unwrap().pings >= 1);
    let metrics = transport.metrics();
    assert!(metrics.rtt.count >= 1);
    assert!(metrics.rtt.max_us.unwrap() < 1_000_000);
}

#[tokio::test]
async fn relay_reports_become_metrics() {
    let (transport, _events, fake) = connected(Behaviour::default()).await.unwrap();
    let mut stats = RelayStats {
        flows_active: 2,
        flows_opened: 3,
        to_network_datagrams: 10,
        ..Default::default()
    };
    stats.drops.add(DropReason::Expired);
    stats.to_network_delay.record(Duration::from_micros(300));
    fake.push
        .send(encoded(&Frame::Stats(Box::new(stats))))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let relay = transport.metrics().relay;
    assert_eq!((relay.flows_active, relay.flows_opened), (2, 3));
    assert_eq!(relay.to_network.datagrams, 10);
    assert_eq!(relay.drops["expired"], 1);
    assert_eq!(relay.to_network_delay.count, 1);
}

#[tokio::test]
async fn a_silent_or_broken_relay_stops_the_transport() {
    let (transport, _events, _fake) = connected(Behaviour {
        pong: false,
        ..Default::default()
    })
    .await
    .unwrap();
    let failure = tokio::time::timeout(SILENCE_TIMEOUT * 2, transport.failed())
        .await
        .unwrap();
    assert_eq!(failure, Failure::Timeout);

    let (transport, _events, fake) = connected(Behaviour::default()).await.unwrap();
    fake.push.send(vec![0, 0, 0, 1, 0x7f]).unwrap();
    let failure = tokio::time::timeout(Duration::from_secs(2), transport.failed())
        .await
        .unwrap();
    assert_eq!(failure, Failure::Protocol);
}
