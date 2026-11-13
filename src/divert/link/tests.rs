use super::*;
use crate::{
    ssh::UdpNotice,
    udp::{
        router::Router,
        testing::{Behaviour, fake},
        transport::{Transport, default_settings},
    },
};
use tokio::io::{duplex, split};

/// A router with one tunnel whose fake relay echoes, and rule `r1` on it.
async fn router() -> Arc<Router> {
    let router = Arc::new(Router::default());
    let (notices, receive) = mpsc::unbounded_channel();
    tokio::spawn(router.clone().run(receive));
    let (client, relay) = duplex(1 << 20);
    let _ = fake(relay, Behaviour::default());
    let (reader, writer) = split(client);
    let (transport, events) = Transport::start(reader, writer, default_settings())
        .await
        .unwrap();
    notices
        .send(UdpNotice::Up {
            tunnel: "t1".into(),
            transport: Arc::new(transport),
            events,
        })
        .unwrap();
    // The notice channel must outlive the test, or the router stops.
    std::mem::forget(notices);
    router.set_rules(HashMap::from([("r1".to_owned(), "t1".to_owned())]));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !router.up("t1") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    router
}

/// Starts the link against `router`; each connection is a fresh in-memory channel.
fn start(link: &Arc<Link>, router: Arc<Router>) -> mpsc::Receiver<Inbound> {
    let (send, inbound) = mpsc::channel(INBOUND_QUEUE);
    let connect = move || {
        let router = router.clone();
        async move {
            let (helper, background) = duplex(1 << 20);
            let (read, write) = split(background);
            tokio::spawn(router.serve(read, write));
            Ok(split(helper))
        }
    };
    tokio::spawn(link.clone().run(connect, send));
    inbound
}

async fn next(inbound: &mut mpsc::Receiver<Inbound>) -> Inbound {
    tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .expect("nothing came back")
        .expect("the link stopped")
}

fn peer() -> SocketAddr {
    "198.51.100.3:3478".parse().unwrap()
}

#[tokio::test]
async fn captured_datagrams_come_back_as_answers_with_rule_counters() {
    let link = Arc::new(Link::default());
    let mut inbound = start(&link, router().await);
    link.send("r1", 5, true, peer(), b"hello");
    link.send("r1", 5, false, peer(), b"again");
    assert_eq!(
        next(&mut inbound).await,
        Inbound::Datagram {
            id: 5,
            peer: peer(),
            data: b"hello".to_vec()
        }
    );
    assert!(matches!(
        next(&mut inbound).await,
        Inbound::Datagram { id: 5, .. }
    ));
    assert!(link.up());
    link.injected("r1", 5);
    link.dropped("r1", DropReason::Quic);
    let stats = &link.stats()["r1"];
    assert_eq!(stats.flows, 1);
    assert_eq!((stats.captured.datagrams, stats.captured.bytes), (2, 10));
    assert_eq!(stats.injected.datagrams, 1);
    assert_eq!(stats.drops["quic"], 1);
    assert_eq!(stats.to_background_delay.count, 2);
}

#[tokio::test]
async fn flows_of_rules_without_a_relay_are_closed() {
    let link = Arc::new(Link::default());
    let mut inbound = start(&link, router().await);
    link.send("other", 1, true, peer(), b"x");
    assert_eq!(next(&mut inbound).await, Inbound::Closed { id: 1 });
}

#[tokio::test]
async fn datagrams_that_waited_too_long_for_the_channel_are_not_sent() {
    let link = Arc::new(Link::default());
    // Queued while no channel exists yet.
    link.send("r1", 1, true, peer(), b"stale");
    tokio::time::sleep(DATAGRAM_EXPIRY + Duration::from_millis(50)).await;
    let mut inbound = start(&link, router().await);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !link.up() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    link.send("r1", 2, true, peer(), b"fresh");
    assert_eq!(
        next(&mut inbound).await,
        Inbound::Datagram {
            id: 2,
            peer: peer(),
            data: b"fresh".to_vec()
        }
    );
    assert_eq!(link.stats()["r1"].drops["expired"], 1);
}

#[tokio::test]
async fn a_full_queue_gives_up_its_oldest_datagrams() {
    let link = Link::default();
    for _ in 0..CHANNEL_QUEUE_DATAGRAMS + 10 {
        link.send("r1", 1, false, peer(), b"x");
    }
    let stats = &link.stats()["r1"];
    assert_eq!(stats.drops["overflow"], 10);
    link.send("r1", 1, false, peer(), &vec![0; proto::MAX_PAYLOAD + 1]);
    assert_eq!(link.stats()["r1"].drops["size"], 1);
}

#[tokio::test]
async fn a_lost_channel_ends_every_flow_and_reconnects() {
    let link = Arc::new(Link::default());
    let (send, mut inbound) = mpsc::channel(INBOUND_QUEUE);
    let attempts = Arc::new(Mutex::new(0u32));
    let counted = attempts.clone();
    let router = router().await;
    let connect = move || {
        let router = router.clone();
        let attempts = counted.clone();
        async move {
            *attempts.lock().unwrap() += 1;
            let (helper, background) = duplex(1 << 20);
            let (read, write) = split(background);
            // The first channel breaks right away.
            if *attempts.lock().unwrap() == 1 {
                drop((read, write));
            } else {
                tokio::spawn(router.serve(read, write));
            }
            Ok(split(helper))
        }
    };
    tokio::spawn(link.clone().run(connect, send));
    assert_eq!(next(&mut inbound).await, Inbound::Lost);
    tokio::time::timeout(Duration::from_secs(3), async {
        while !link.up() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    link.send("r1", 9, true, peer(), b"later");
    assert!(matches!(
        next(&mut inbound).await,
        Inbound::Datagram { id: 9, .. }
    ));
    assert!(*attempts.lock().unwrap() >= 2);
}

#[tokio::test]
async fn a_saturated_channel_in_both_directions_keeps_moving() {
    let link = Arc::new(Link::default());
    let router = router().await;
    let (send, mut inbound) = mpsc::channel(INBOUND_QUEUE);
    // Tiny buffers: both sides fill them at once and must still read while they cannot write.
    let connect = move || {
        let router = router.clone();
        async move {
            let (helper, background) = duplex(512);
            let (read, write) = split(background);
            tokio::spawn(router.serve(read, write));
            Ok(split(helper))
        }
    };
    tokio::spawn(link.clone().run(connect, send));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !link.up() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    // Echoed answers come back while far more is still being sent; nobody reads `inbound`
    // during the burst, so answers also pile up on this side.
    let payload = vec![7u8; 1200];
    for round in 0..2000u32 {
        link.send("r1", 1 + round % 8, round < 8, peer(), &payload);
        if round % 100 == 0 {
            tokio::task::yield_now().await;
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    while inbound.try_recv().is_ok() {}
    // A fresh datagram still makes the round trip on the same channel.
    link.send("r1", 99, true, peer(), b"after");
    let answer = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match inbound.recv().await {
                Some(Inbound::Datagram { id: 99, data, .. }) => return data,
                Some(_) => {}
                None => panic!("the link stopped"),
            }
        }
    })
    .await
    .expect("the channel stalled under load");
    assert_eq!(answer, b"after");
    assert!(link.up());
}
