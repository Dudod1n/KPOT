use super::*;

/// Internet checksum over `bytes`; zero when a packet's own checksum is included and valid.
fn verify(bytes: &[u8]) -> u16 {
    let mut sum = 0;
    add(&mut sum, bytes);
    fold(sum)
}

fn pseudo_and_udp(packet: &[u8]) -> Vec<u8> {
    let (addresses, udp) = if packet[0] >> 4 == 4 {
        (&packet[12..20], &packet[20..])
    } else {
        (&packet[8..40], &packet[40..])
    };
    let mut bytes = addresses.to_vec();
    bytes.extend_from_slice(&[0, UDP]);
    bytes.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    bytes.extend_from_slice(udp);
    bytes
}

#[test]
fn ipv4_answers_are_built_byte_for_byte_with_valid_checksums() {
    let packet = inbound(
        "203.0.113.5:3478".parse().unwrap(),
        "192.168.1.10:50000".parse().unwrap(),
        b"abc",
        0x1234,
    )
    .unwrap();
    assert_eq!(
        packet[..20],
        [
            0x45, 0, 0, 31, 0x12, 0x34, 0, 0, 64, 17, packet[10], packet[11], 203, 0, 113, 5, 192,
            168, 1, 10
        ]
    );
    assert_eq!(
        packet[20..28],
        [0x0d, 0x96, 0xc3, 0x50, 0, 11, packet[26], packet[27]]
    );
    assert_eq!(&packet[28..], b"abc");
    assert_eq!(verify(&packet[..20]), 0, "IPv4 header checksum");
    assert_eq!(verify(&pseudo_and_udp(&packet)), 0, "UDP checksum");
    // The builder and the parser agree.
    let (from, to, payload) = outbound(&packet).unwrap();
    assert_eq!(
        (from.to_string(), to.to_string(), payload),
        (
            "203.0.113.5:3478".into(),
            "192.168.1.10:50000".into(),
            &b"abc"[..]
        )
    );
}

#[test]
fn ipv6_answers_are_built_byte_for_byte_with_valid_checksums() {
    let packet = inbound(
        "[2001:db8::5]:443".parse().unwrap(),
        "[fd00::10]:50001".parse().unwrap(),
        b"quic",
        0,
    )
    .unwrap();
    assert_eq!(packet.len(), 40 + 8 + 4);
    assert_eq!(packet[..8], [0x60, 0, 0, 0, 0, 12, 17, 64]);
    assert_eq!(
        &packet[8..24],
        &"2001:db8::5"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
    );
    assert_eq!(
        &packet[24..40],
        &"fd00::10".parse::<std::net::Ipv6Addr>().unwrap().octets()
    );
    assert_eq!(packet[40..44], [0x01, 0xbb, 0xc3, 0x51]);
    assert_ne!(
        u16::from_be_bytes([packet[46], packet[47]]),
        0,
        "mandatory in IPv6"
    );
    assert_eq!(verify(&pseudo_and_udp(&packet)), 0);
    let (_, to, payload) = outbound(&packet).unwrap();
    assert_eq!((to.port(), payload), (50001, &b"quic"[..]));
}

#[test]
fn mixed_families_and_oversized_answers_are_refused() {
    assert!(
        inbound(
            "1.2.3.4:1".parse().unwrap(),
            "[::1]:2".parse().unwrap(),
            b"",
            0
        )
        .is_none()
    );
    let big = vec![0u8; 65_535 - 20 - 8 + 1];
    assert!(
        inbound(
            "1.2.3.4:1".parse().unwrap(),
            "5.6.7.8:2".parse().unwrap(),
            &big,
            0
        )
        .is_none()
    );
    let largest = vec![0u8; 65_535 - 20 - 8];
    assert!(
        inbound(
            "1.2.3.4:1".parse().unwrap(),
            "5.6.7.8:2".parse().unwrap(),
            &largest,
            0
        )
        .is_some()
    );
}

#[test]
fn payloads_follow_the_length_fields_not_the_buffer() {
    let mut packet = inbound(
        "1.2.3.4:1".parse().unwrap(),
        "5.6.7.8:2".parse().unwrap(),
        b"data",
        0,
    )
    .unwrap();
    // Padding after the datagram is not payload.
    packet.extend_from_slice(&[0xee; 6]);
    assert_eq!(outbound(&packet).unwrap().2, b"data");
    // A UDP length beyond the packet is refused.
    let mut lying = packet.clone();
    lying[24..26].copy_from_slice(&200u16.to_be_bytes());
    assert!(outbound(&lying).is_none());
    assert!(outbound(&packet[..25]).is_none());
    assert!(outbound(&[]).is_none());
}

#[test]
fn ipv4_fragments_are_recognised() {
    let mut packet = inbound(
        "1.2.3.4:1".parse().unwrap(),
        "5.6.7.8:2".parse().unwrap(),
        b"x",
        77,
    )
    .unwrap();
    assert_eq!(fragment(&packet), None);
    packet[6] = 0x20; // more fragments, offset 0
    let key = (IpAddr::from([1, 2, 3, 4]), IpAddr::from([5, 6, 7, 8]), 77);
    assert_eq!(fragment(&packet), Some((key, true)));
    packet[6] = 0x00;
    packet[7] = 0x10; // offset 16 * 8
    assert_eq!(fragment(&packet), Some((key, false)));
}

#[test]
fn flows_follow_sockets_rules_and_idle_timeouts() {
    let mut flows: Flows<u8> = Flows::default();
    let start = Instant::now();
    let app: SocketAddr = "192.168.1.10:50000".parse().unwrap();
    let first = flows.outbound(app, "r1", 1, start);
    assert_eq!((first.opened, first.replaced), (true, None));
    let again = flows.outbound(app, "r1", 2, start);
    assert_eq!((again.id, again.opened), (first.id, false));
    let (local, flow) = flows.inbound(first.id, start).unwrap();
    assert_eq!((local, flow.meta), (app, 2), "the latest interface is kept");
    assert!(flows.inbound(999, start).is_none());

    // The port now belongs to a process of another rule.
    let moved = flows.outbound(app, "r2", 3, start);
    assert_eq!((moved.opened, moved.replaced), (true, Some(first.id)));
    assert!(flows.inbound(first.id, start).is_none());
    assert!(flows.inbound(moved.id, start).is_some());

    let other: SocketAddr = "192.168.1.10:50001".parse().unwrap();
    let silent = flows.outbound(other, "r1", 0, start);
    // A flow that only sent ends earlier than one that also received.
    let later = start + Duration::from_secs(90);
    assert_eq!(
        flows.purge_after(later, Duration::from_secs(60), Duration::from_secs(120)),
        [silent.id]
    );
    assert_eq!(flows.len(), 1);
    assert_eq!(
        flows.close(moved.id).map(|flow| flow.rule),
        Some("r2".into())
    );
    assert!(flows.is_empty());
    flows.outbound(app, "r1", 0, start);
    assert_eq!(flows.clear().len(), 1);
}
