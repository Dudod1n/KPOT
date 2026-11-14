use super::*;
use std::cell::Cell;

fn table(rows: &[Vec<u8>]) -> Vec<u8> {
    let mut table = (rows.len() as u32).to_le_bytes().to_vec();
    table.extend(rows.iter().flatten());
    table
}

/// A row of `MIB_UDPTABLE_OWNER_PID` or `MIB_UDP6TABLE_OWNER_PID`.
fn row(endpoint: &str, pid: u32) -> Vec<u8> {
    let endpoint: SocketAddr = endpoint.parse().unwrap();
    let mut row = match endpoint {
        SocketAddr::V4(address) => address.ip().octets().to_vec(),
        SocketAddr::V6(address) => {
            let mut row = address.ip().octets().to_vec();
            row.extend(address.scope_id().to_be_bytes());
            row
        }
    };
    row.extend(endpoint.port().to_be_bytes());
    row.extend([0; 2]);
    row.extend(pid.to_le_bytes());
    row
}

fn owners(ipv4: &[Vec<u8>], ipv6: &[Vec<u8>], local: &str) -> Option<Vec<u32>> {
    let (ipv4, ipv6) = (table(ipv4), table(ipv6));
    endpoint_owners(Some(&ipv4), Some(&ipv6), local.parse().unwrap())
}

#[test]
fn rows_have_the_layout_of_the_owner_pid_tables() {
    assert_eq!(row("192.0.2.1:53", 7).len(), UDP4_ROW_SIZE);
    assert_eq!(row("[2001:db8::1]:53", 7).len(), UDP6_ROW_SIZE);
}

#[test]
fn owners_follow_the_local_address_not_only_the_port() {
    let ipv4 = [
        row("192.168.1.5:50003", 10),
        row("192.168.1.6:50003", 20),
        row("192.168.1.5:50004", 30),
        row("192.168.1.9:50003", 0),
    ];
    assert_eq!(owners(&ipv4, &[], "192.168.1.5:50003"), Some(vec![10]));
    assert_eq!(owners(&ipv4, &[], "192.168.1.6:50003"), Some(vec![20]));
    assert_eq!(owners(&ipv4, &[], "192.168.1.7:50003"), Some(vec![]));
    // A wildcard socket can send from any address.
    let wildcard = [row("192.168.1.5:50003", 10), row("0.0.0.0:50003", 40)];
    assert_eq!(
        owners(&wildcard, &[], "192.168.1.5:50003"),
        Some(vec![10, 40])
    );
    assert_eq!(owners(&wildcard, &[], "192.168.1.7:50003"), Some(vec![40]));

    let ipv6 = [
        row("[fd00::5]:50003", 10),
        row("[fd00::6]:50003", 20),
        row("[::]:50003", 30),
    ];
    assert_eq!(owners(&[], &ipv6, "[fd00::5]:50003"), Some(vec![10, 30]));
    assert_eq!(owners(&[], &ipv6, "[fd00::7]:50003"), Some(vec![30]));
}

#[test]
fn link_local_owners_follow_the_interface() {
    let ipv6 = [row("[fe80::5%3]:50003", 10), row("[fe80::5%8]:50003", 20)];
    assert_eq!(owners(&[], &ipv6, "[fe80::5%3]:50003"), Some(vec![10]));
    assert_eq!(owners(&[], &ipv6, "[fe80::5%8]:50003"), Some(vec![20]));
    assert_eq!(owners(&[], &ipv6, "[fe80::5%4]:50003"), Some(vec![]));
    let zone = 0x2000_0008u32;
    for bytes in [zone.to_be_bytes(), zone.to_ne_bytes()] {
        assert!(scope_matches(bytes, 8) && !scope_matches(bytes, 3));
    }
}

#[test]
fn ipv4_datagrams_also_match_mapped_and_dual_stack_sockets() {
    let ipv6 = [
        row("[::ffff:192.0.2.1]:50000", 50),
        row("[::ffff:192.0.2.2]:50000", 60),
        row("[fd00::1]:50000", 70),
        row("[::]:50000", 80),
    ];
    // An IPv6 wildcard may always be a dual-stack sender: it is a candidate next to the rest.
    assert_eq!(owners(&[], &ipv6, "192.0.2.1:50000"), Some(vec![50, 80]));
    assert_eq!(owners(&[], &ipv6, "192.0.2.3:50000"), Some(vec![80]));
    assert_eq!(
        owners(&[row("0.0.0.0:50000", 90)], &ipv6, "192.0.2.3:50000"),
        Some(vec![90, 80])
    );
}

#[test]
fn a_missing_table_leaves_the_owners_unknown() {
    let ipv4 = table(&[row("192.0.2.1:50000", 1)]);
    let ipv6 = table(&[]);
    let local_v4 = "192.0.2.1:50000".parse().unwrap();
    // Without the IPv6 table an IPv4 datagram is still matched against IPv4 sockets.
    assert_eq!(endpoint_owners(Some(&ipv4), None, local_v4), Some(vec![1]));
    assert_eq!(endpoint_owners(None, Some(&ipv6), local_v4), None);
    assert_eq!(
        endpoint_owners(Some(&ipv4), None, "[fd00::1]:5".parse().unwrap()),
        None
    );
    // Truncated buffers and counts beyond them are harmless.
    let mut short = table(&[row("192.0.2.1:50000", 1), row("192.0.2.2:50000", 2)]);
    short[0] = 200;
    short.truncate(UDP_TABLE_HEADER + UDP4_ROW_SIZE + 5);
    assert_eq!(
        endpoint_owners(Some(&short), Some(&ipv6), local_v4),
        Some(vec![1])
    );
    assert_eq!(
        endpoint_owners(Some(&[1]), Some(&ipv6), local_v4),
        Some(vec![])
    );
}

/// Decides with `rules` as the owners' rules and counts the lookups.
fn decide(
    owners: &mut UdpOwners,
    local: &str,
    at: Instant,
    rules: Option<&[&str]>,
    lookups: &Cell<u32>,
) -> Option<String> {
    owners.decide(local.parse().unwrap(), at, &|rule| rule == "direct", || {
        lookups.set(lookups.get() + 1);
        rules.map(|rules| rules.iter().map(|rule| rule.to_string()).collect())
    })
}

#[test]
fn let_through_decisions_are_reused_only_briefly() {
    let (mut owners, start, lookups) = (UdpOwners::default(), Instant::now(), Cell::new(0));
    for offset in [0, 10, 99] {
        let at = start + Duration::from_millis(offset);
        assert_eq!(
            decide(&mut owners, "192.0.2.1:5", at, Some(&[]), &lookups),
            None
        );
    }
    assert_eq!(lookups.get(), 1, "a burst of datagrams costs one lookup");
    // A blocked application that took the endpoint is noticed after the short hold.
    let later = start + PASS_HOLD;
    assert_eq!(
        decide(
            &mut owners,
            "192.0.2.1:5",
            later,
            Some(&["blocked"]),
            &lookups
        ),
        Some("blocked".into())
    );
    assert_eq!(lookups.get(), 2);
    // Endpoints are separate.
    decide(&mut owners, "192.0.2.2:5", later, Some(&[]), &lookups);
    assert_eq!(lookups.get(), 3);
}

#[test]
fn a_block_outlives_its_socket_by_the_driver_queue_time() {
    let (mut owners, start, lookups) = (UdpOwners::default(), Instant::now(), Cell::new(0));
    let local = "192.0.2.1:5";
    let blocked = Some("blocked".to_owned());
    assert_eq!(
        decide(&mut owners, local, start, Some(&["blocked"]), &lookups),
        blocked
    );
    // The socket closes and a bypassing application binds the endpoint at once.
    let gone = start + BLOCK_HOLD;
    assert_eq!(
        decide(&mut owners, local, gone, Some(&["direct"]), &lookups),
        blocked
    );
    let queued = gone + BLOCK_HOLD - Duration::from_millis(1);
    assert_eq!(
        decide(&mut owners, local, queued, Some(&["direct"]), &lookups),
        blocked
    );
    assert_eq!(lookups.get(), 2, "no lookups while the grace holds");
    // After the grace the new owner decides.
    let after = gone + BLOCK_HOLD;
    assert_eq!(
        decide(&mut owners, local, after, Some(&["direct"]), &lookups),
        Some("direct".into())
    );
    // A socket that keeps blocking stays blocked without a grace in between.
    let mut owners = UdpOwners::default();
    for step in 0..4 {
        let at = start + BLOCK_HOLD * step;
        assert_eq!(
            decide(&mut owners, local, at, Some(&["blocked"]), &lookups),
            blocked
        );
    }
}

#[test]
fn a_blocking_candidate_wins_and_unknown_owners_keep_the_last_answer() {
    let (mut owners, start, lookups) = (UdpOwners::default(), Instant::now(), Cell::new(0));
    assert_eq!(
        decide(
            &mut owners,
            "192.0.2.1:5",
            start,
            Some(&["direct", "blocked"]),
            &lookups
        ),
        Some("blocked".into())
    );
    assert_eq!(
        decide(
            &mut owners,
            "192.0.2.2:5",
            start,
            Some(&["direct"]),
            &lookups
        ),
        Some("direct".into())
    );
    let later = start + BLOCK_HOLD;
    assert_eq!(
        decide(&mut owners, "192.0.2.1:5", later, None, &lookups),
        Some("blocked".into())
    );
    assert_eq!(
        decide(&mut owners, "192.0.2.9:5", later, None, &lookups),
        None
    );
}

#[test]
fn rule_changes_keep_only_the_blocks_of_unchanged_rules() {
    let (mut owners, start, lookups) = (UdpOwners::default(), Instant::now(), Cell::new(0));
    decide(&mut owners, "192.0.2.1:5", start, Some(&["kept"]), &lookups);
    decide(
        &mut owners,
        "192.0.2.2:5",
        start,
        Some(&["edited"]),
        &lookups,
    );
    decide(&mut owners, "192.0.2.3:5", start, Some(&[]), &lookups);
    assert_eq!(owners.len(), 3);
    owners.rules_changed(&|rule| rule == "kept", false);
    assert_eq!(owners.len(), 1);
    let soon = start + Duration::from_millis(1);
    assert_eq!(
        decide(&mut owners, "192.0.2.1:5", soon, Some(&[]), &lookups),
        Some("kept".into()),
        "a queued datagram of the kept rule stays blocked"
    );
    assert_eq!(lookups.get(), 3);
    owners.purge(start + BLOCK_HOLD);
    assert!(owners.is_empty());
}

#[test]
fn nothing_is_looked_up_while_every_rule_bypasses() {
    let (mut owners, start, lookups) = (UdpOwners::default(), Instant::now(), Cell::new(0));
    owners.set_all_bypass(true);
    assert_eq!(
        decide(
            &mut owners,
            "192.0.2.1:5",
            start,
            Some(&["blocked"]),
            &lookups
        ),
        None
    );
    assert_eq!(lookups.get(), 0);
    owners.rules_changed(&|_| true, false);
    assert_eq!(
        decide(
            &mut owners,
            "192.0.2.1:5",
            start,
            Some(&["blocked"]),
            &lookups
        ),
        Some("blocked".into())
    );
}

#[test]
fn one_snapshot_serves_every_endpoint_for_its_hold() {
    let mut snapshot = Snapshot::default();
    let reads = Cell::new(0);
    let ipv4 = table(&[row("192.0.2.1:5", 1), row("192.0.2.2:5", 2)]);
    let read = |v6: bool| {
        reads.set(reads.get() + 1);
        Some(if v6 { table(&[]) } else { ipv4.clone() })
    };
    let start = Instant::now();
    assert_eq!(
        snapshot.owners(start, "192.0.2.1:5".parse().unwrap(), read),
        Some(vec![1])
    );
    let soon = start + SNAPSHOT_HOLD - Duration::from_millis(1);
    assert_eq!(
        snapshot.owners(soon, "192.0.2.2:5".parse().unwrap(), read),
        Some(vec![2])
    );
    assert_eq!(reads.get(), 2, "both tables read once for both endpoints");
    snapshot.owners(start + SNAPSHOT_HOLD, "192.0.2.1:5".parse().unwrap(), read);
    assert_eq!(reads.get(), 4);
}

#[test]
fn unknown_owners_are_asked_again_only_after_a_short_hold() {
    let (mut owners, start, lookups) = (UdpOwners::default(), Instant::now(), Cell::new(0));
    for offset in [0, 50, 99] {
        let at = start + Duration::from_millis(offset);
        assert_eq!(decide(&mut owners, "192.0.2.1:5", at, None, &lookups), None);
    }
    assert_eq!(lookups.get(), 1);
    decide(
        &mut owners,
        "192.0.2.1:5",
        start + PASS_HOLD,
        None,
        &lookups,
    );
    assert_eq!(lookups.get(), 2);
}

#[test]
fn a_block_whose_rule_turns_to_bypass_lasts_no_longer_than_a_pass() {
    let (mut owners, start, lookups) = (UdpOwners::default(), Instant::now(), Cell::new(0));
    let local: SocketAddr = "192.0.2.1:5".parse().unwrap();
    let decide = |owners: &mut UdpOwners, at: Instant, bypassed: bool, rules: &[&str]| {
        owners.decide(local, at, &|rule| bypassed && rule == "a", || {
            lookups.set(lookups.get() + 1);
            Some(rules.iter().map(|rule| rule.to_string()).collect())
        })
    };
    assert_eq!(decide(&mut owners, start, false, &["a"]), Some("a".into()));
    // Rule A's tunnel stops and A bypasses it; B, whose tunnel runs, takes the endpoint.
    let soon = start + Duration::from_millis(50);
    assert_eq!(decide(&mut owners, soon, true, &["b"]), Some("a".into()));
    let later = start + PASS_HOLD;
    assert_eq!(decide(&mut owners, later, true, &["b"]), Some("b".into()));
    assert_eq!(lookups.get(), 2);
}
