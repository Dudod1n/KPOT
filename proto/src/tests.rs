use super::*;
use crate::metrics::{DropReason, Histogram, Window};
use std::time::Duration;

fn settings() -> Settings {
    Settings {
        max_flows: 512,
        idle_ms: 60_000,
        idle_bidirectional_ms: 120_000,
    }
}

fn stats() -> RelayStats {
    let mut stats = RelayStats {
        flows_active: 3,
        flows_opened: 7,
        flows_refused: 1,
        to_network_datagrams: 100,
        to_network_bytes: 12_345,
        from_network_datagrams: 90,
        from_network_bytes: 54_321,
        ..Default::default()
    };
    stats.drops.add(DropReason::Expired);
    stats.drops.add(DropReason::Overflow);
    stats.drops.add(DropReason::Overflow);
    stats.to_network_delay.record(Duration::from_micros(70));
    stats.to_client_delay.record(Duration::from_millis(3));
    stats
}

fn samples() -> Vec<Frame<'static>> {
    let payload: &'static [u8] = Box::leak(vec![0xa5; MAX_PAYLOAD].into_boxed_slice());
    vec![
        Frame::Hello {
            version: VERSION,
            settings: settings(),
        },
        Frame::HelloOk {
            version: VERSION,
            settings: settings(),
        },
        Frame::Refuse {
            reason: Refusal::Version,
            supported: VERSION,
        },
        Frame::Refuse {
            reason: Refusal::Other(9),
            supported: VERSION,
        },
        Frame::Send {
            flow: 1,
            peer: "203.0.113.5:3478".parse().unwrap(),
            data: b"stun",
        },
        Frame::Send {
            flow: u32::MAX,
            peer: "[2001:db8::1]:443".parse().unwrap(),
            data: payload,
        },
        Frame::Recv {
            flow: 2,
            peer: "198.51.100.7:53".parse().unwrap(),
            data: b"",
        },
        Frame::Recv {
            flow: 2,
            peer: "[::1]:9".parse().unwrap(),
            data: b"answer",
        },
        Frame::Close {
            flow: 5,
            reason: CloseReason::Idle,
        },
        Frame::Close {
            flow: 5,
            reason: CloseReason::Other(200),
        },
        Frame::Ping {
            sequence: 3,
            time_us: 1 << 40,
        },
        Frame::Pong {
            sequence: 3,
            time_us: 1 << 40,
            held_us: 17,
        },
        Frame::Ack { received: 999 },
        Frame::Stats(Box::new(stats())),
        Frame::Open {
            flow: 8,
            rule: "правило-1",
        },
    ]
}

#[test]
fn every_frame_type_survives_a_round_trip_in_one_stream() {
    let frames = samples();
    let mut stream = Vec::new();
    for frame in &frames {
        let before = stream.len();
        encode(frame, &mut stream);
        if let Frame::Send { peer, data, .. } | Frame::Recv { peer, data, .. } = frame {
            assert_eq!(stream.len() - before, datagram_frame_size(peer, data.len()));
        }
    }
    let mut at = 0;
    for expected in &frames {
        let (frame, used) = parse(&stream[at..]).unwrap().unwrap();
        assert_eq!(&frame, expected);
        at += used;
    }
    assert_eq!(at, stream.len());
    assert_eq!(parse(&stream[at..]), Ok(None));
}

#[test]
fn every_truncation_asks_for_more_bytes() {
    for frame in samples() {
        let mut encoded = Vec::new();
        encode(&frame, &mut encoded);
        for cut in 0..encoded.len() {
            assert_eq!(parse(&encoded[..cut]), Ok(None), "{frame:?} cut at {cut}");
        }
    }
}

#[test]
fn a_short_or_long_body_is_malformed_not_misread() {
    for frame in samples() {
        let mut encoded = Vec::new();
        encode(&frame, &mut encoded);
        let length = encoded.len() - LENGTH_SIZE;
        // Datagram frames take the rest of the body as payload, so only a body shorter than
        // their header is wrong; other frames have an exact size.
        let datagram = matches!(frame, Frame::Send { .. } | Frame::Recv { .. });
        let header = match &frame {
            Frame::Send { peer, .. } | Frame::Recv { peer, .. } => {
                datagram_frame_size(peer, 0) - LENGTH_SIZE
            }
            _ => length,
        };
        for shorter in 1..header {
            let mut cut = (shorter as u32).to_be_bytes().to_vec();
            cut.extend_from_slice(&encoded[LENGTH_SIZE..LENGTH_SIZE + shorter]);
            assert!(parse(&cut).is_err(), "{frame:?} shortened to {shorter}");
        }
        if !datagram {
            let mut longer = ((length + 1) as u32).to_be_bytes().to_vec();
            longer.extend_from_slice(&encoded[LENGTH_SIZE..]);
            longer.push(0);
            assert_eq!(parse(&longer), Err(Error::Malformed), "{frame:?}");
        }
    }
}

#[test]
fn limits_and_invalid_fields_are_errors() {
    assert_eq!(parse(&[0, 0, 0, 0]), Err(Error::Length));
    assert_eq!(
        parse(&((MAX_FRAME + 1) as u32).to_be_bytes()),
        Err(Error::Length)
    );
    assert_eq!(parse(&u32::MAX.to_be_bytes()), Err(Error::Length));
    assert_eq!(parse(&[0, 0, 0, 1, 0x7f]), Err(Error::UnknownKind(0x7f)));

    // A payload one byte above the limit still fits the frame limit with an IPv4 address.
    let mut oversized = Vec::new();
    let body_length = 1 + 4 + 7 + MAX_PAYLOAD + 1;
    oversized.extend_from_slice(&(body_length as u32).to_be_bytes());
    oversized.extend_from_slice(&[kind::SEND, 0, 0, 0, 1, 4, 127, 0, 0, 1, 0, 9]);
    oversized.resize(LENGTH_SIZE + body_length, 0);
    assert_eq!(parse(&oversized), Err(Error::Malformed));

    let family = [0, 0, 0, 12, kind::SEND, 0, 0, 0, 1, 5, 1, 2, 3, 4, 0, 9];
    assert_eq!(parse(&family), Err(Error::Malformed));

    let mut hello = Vec::new();
    encode(
        &Frame::Hello {
            version: VERSION,
            settings: settings(),
        },
        &mut hello,
    );
    hello[LENGTH_SIZE + 1] = b'X';
    assert_eq!(parse(&hello), Err(Error::Magic));

    let empty_rule = [0, 0, 0, 6, kind::OPEN, 0, 0, 0, 1, 0];
    assert_eq!(parse(&empty_rule), Err(Error::Malformed));
    let invalid_utf8 = [0, 0, 0, 7, kind::OPEN, 0, 0, 0, 1, 1, 0xff];
    assert_eq!(parse(&invalid_utf8), Err(Error::Malformed));
}

#[test]
fn random_bytes_never_panic_or_overread() {
    // A fixed xorshift sequence keeps the test reproducible without extra dependencies.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut valid = Vec::new();
    for frame in samples() {
        encode(&frame, &mut valid);
    }
    for round in 0..20_000 {
        let mut buffer = if round % 2 == 0 {
            // Valid stream with a few flipped bytes.
            let mut buffer = valid.clone();
            for _ in 0..1 + next() % 4 {
                let at = (next() as usize) % buffer.len();
                buffer[at] = next() as u8;
            }
            buffer
        } else {
            let length = (next() % 64) as usize;
            let mut buffer: Vec<u8> = (0..length).map(|_| next() as u8).collect();
            // Small lengths make the body reachable more often.
            if buffer.len() >= 4 {
                buffer[..3].fill(0);
                buffer[3] %= 60;
            }
            buffer
        };
        let mut at = 0;
        while let Ok(Some((_, used))) = parse(&buffer[at..]) {
            assert!(used > 0 && at + used <= buffer.len());
            at += used;
        }
        buffer.clear();
    }
}

#[test]
fn histogram_quantiles_follow_a_known_load() {
    let mut histogram = Histogram::default();
    assert_eq!(histogram.quantile_us(0.5), None);
    assert_eq!(histogram.mean_us(), None);
    // 90 fast samples in the 1 ms bucket, 9 in the 20 ms bucket and one slow outlier.
    for _ in 0..90 {
        histogram.record(Duration::from_micros(800));
    }
    for _ in 0..9 {
        histogram.record(Duration::from_millis(15));
    }
    histogram.record(Duration::from_secs(3));
    assert_eq!(histogram.count(), 100);
    assert_eq!(histogram.quantile_us(0.5), Some(1_000));
    assert_eq!(histogram.quantile_us(0.95), Some(20_000));
    assert_eq!(histogram.quantile_us(0.99), Some(20_000));
    assert_eq!(histogram.quantile_us(1.0), Some(3_000_000));
    assert_eq!(histogram.max_us, 3_000_000);
    assert_eq!(
        histogram.mean_us(),
        Some((90 * 800 + 9 * 15_000 + 3_000_000) / 100)
    );

    // A bound is never above the largest value seen.
    let mut small = Histogram::default();
    small.record(Duration::from_micros(30));
    assert_eq!(small.quantile_us(0.99), Some(30));
    // Exact bucket bounds land in their own bucket.
    let mut edge = Histogram::default();
    edge.record(Duration::from_micros(150_000));
    assert_eq!(edge.buckets[11], 1);
}

#[test]
fn window_keeps_only_the_latest_intervals() {
    let mut window = Window::default();
    for second in 0..15u64 {
        let mut interval = Histogram::default();
        interval.record(Duration::from_millis(second));
        window.push(interval);
    }
    let total = window.total();
    assert_eq!(total.count(), metrics::WINDOW_INTERVALS as u64);
    assert_eq!(total.max_us, 14_000);
    assert_eq!(total.sum_us, (5..15).map(|ms| ms * 1_000).sum::<u64>());
}

#[test]
fn drop_reasons_are_counted_separately() {
    let mut drops = metrics::Drops::default();
    for reason in DropReason::ALL {
        for _ in 0..=(reason as usize) {
            drops.add(reason);
        }
    }
    for reason in DropReason::ALL {
        assert_eq!(drops.get(reason), reason as u64 + 1, "{}", reason.name());
    }
}

#[test]
fn a_hello_of_another_version_is_read_for_its_version_only() {
    // A future version with one more field, and an older one with fewer.
    for (version, extra) in [(VERSION + 1, vec![1u8, 2, 3, 4]), (0, vec![])] {
        let mut body = vec![kind::HELLO];
        body.extend_from_slice(&MAGIC);
        body.extend_from_slice(&version.to_be_bytes());
        if version == 0 {
            body.extend_from_slice(&[0, 1]);
        } else {
            body.extend_from_slice(&[0; 10]);
            body.extend_from_slice(&extra);
        }
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        match parse(&frame) {
            Ok(Some((Frame::Hello { version: read, .. }, used))) => {
                assert_eq!((read, used), (version, frame.len()));
            }
            other => panic!("{other:?}"),
        }
    }
    // The current version keeps its exact layout.
    let mut body = vec![kind::HELLO];
    body.extend_from_slice(&MAGIC);
    body.extend_from_slice(&VERSION.to_be_bytes());
    body.extend_from_slice(&[0; 11]);
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    assert_eq!(parse(&frame), Err(Error::Malformed));
}
