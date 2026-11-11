use super::*;
use crate::udp::{
    testing::{Behaviour, fake},
    transport::default_settings,
};
use tokio::io::{DuplexStream, ReadHalf, WriteHalf, duplex, split};

struct Helper {
    reader: ReadHalf<DuplexStream>,
    writer: WriteHalf<DuplexStream>,
    buffer: Vec<u8>,
}

impl Helper {
    async fn write(&mut self, frame: &Frame<'_>) {
        let mut bytes = Vec::new();
        proto::encode(frame, &mut bytes);
        self.writer.write_all(&bytes).await.unwrap();
    }
    /// The next frame from the router, encoded.
    async fn next(&mut self) -> Vec<u8> {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some((_, used)) = proto::parse(&self.buffer).unwrap() {
                    return self.buffer.drain(..used).collect();
                }
                let mut chunk = [0u8; 65_536];
                let count = self.reader.read(&mut chunk).await.unwrap();
                assert!(count > 0, "the router closed the channel");
                self.buffer.extend_from_slice(&chunk[..count]);
            }
        })
        .await
        .expect("no frame from the router")
    }
}

async fn setup() -> (Arc<Router>, mpsc::UnboundedSender<UdpNotice>, Helper) {
    let router = Arc::new(Router::default());
    let (notices, receive) = mpsc::unbounded_channel();
    tokio::spawn(router.clone().run(receive));
    let (client, relay) = duplex(1 << 20);
    let _fake = fake(relay, Behaviour::default());
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
    router.set_rules(HashMap::from([("r1".to_owned(), "t1".to_owned())]));
    let (helper, routed) = duplex(1 << 20);
    let (reader, writer) = split(routed);
    tokio::spawn(router.clone().serve(reader, writer));
    let (reader, writer) = split(helper);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !router.up("t1") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    (
        router,
        notices,
        Helper {
            reader,
            writer,
            buffer: Vec::new(),
        },
    )
}

fn peer() -> SocketAddr {
    "203.0.113.9:3478".parse().unwrap()
}

#[tokio::test]
async fn helper_flows_reach_their_tunnel_and_answers_come_back_counted_per_rule() {
    let (router, _notices, mut helper) = setup().await;
    helper
        .write(&Frame::Open {
            flow: 40,
            rule: "r1",
        })
        .await;
    helper
        .write(&Frame::Send {
            flow: 40,
            peer: peer(),
            data: b"stun",
        })
        .await;
    let answer = helper.next().await;
    assert_eq!(
        proto::parse(&answer).unwrap().unwrap().0,
        Frame::Recv {
            flow: 40,
            peer: peer(),
            data: b"stun",
        }
    );
    let metrics = router.rule_metrics();
    assert_eq!(metrics["r1"].flows_active, 1);
    assert_eq!(metrics["r1"].sent.datagrams, 1);
    assert_eq!(metrics["r1"].received.bytes, 4);

    helper
        .write(&Frame::Close {
            flow: 40,
            reason: CloseReason::Client,
        })
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let metrics = router.rule_metrics();
    assert_eq!(metrics["r1"].flows_active, 0);
    assert_eq!(metrics["r1"].flows_total, 1);
    assert_eq!(
        metrics["r1"].sent.datagrams, 1,
        "closed flows keep counting"
    );
    assert!(router.tunnel_metrics()["t1"].to_helper_delay.count >= 1);
}

#[tokio::test]
async fn flows_without_a_running_relay_are_closed_at_once() {
    let (router, _notices, mut helper) = setup().await;
    helper
        .write(&Frame::Open {
            flow: 1,
            rule: "unknown",
        })
        .await;
    assert_eq!(
        proto::parse(&helper.next().await).unwrap().unwrap().0,
        Frame::Close {
            flow: 1,
            reason: CloseReason::Socket,
        }
    );
    assert_eq!(router.rule_metrics()["unknown"].flows_refused, 1);
}

#[tokio::test]
async fn a_stopped_relay_closes_its_flows_in_the_helper() {
    let (router, notices, mut helper) = setup().await;
    helper
        .write(&Frame::Open {
            flow: 7,
            rule: "r1",
        })
        .await;
    helper
        .write(&Frame::Send {
            flow: 7,
            peer: peer(),
            data: b"x",
        })
        .await;
    helper.next().await;
    notices
        .send(UdpNotice::Down {
            tunnel: "t1".into(),
        })
        .unwrap();
    assert_eq!(
        proto::parse(&helper.next().await).unwrap().unwrap().0,
        Frame::Close {
            flow: 7,
            reason: CloseReason::Socket,
        }
    );
    assert!(!router.up("t1"));
    let metrics = router.rule_metrics();
    assert_eq!(
        (metrics["r1"].flows_active, metrics["r1"].sent.datagrams),
        (0, 1)
    );
    // A new flow of the rule is refused until the relay is back.
    helper
        .write(&Frame::Open {
            flow: 8,
            rule: "r1",
        })
        .await;
    assert!(matches!(
        proto::parse(&helper.next().await).unwrap().unwrap().0,
        Frame::Close { flow: 8, .. }
    ));
}

#[tokio::test]
async fn pings_are_answered_and_garbage_ends_the_channel() {
    let (_router, _notices, mut helper) = setup().await;
    helper
        .write(&Frame::Ping {
            sequence: 1,
            time_us: 5,
        })
        .await;
    assert!(matches!(
        proto::parse(&helper.next().await).unwrap().unwrap().0,
        Frame::Pong { sequence: 1, .. }
    ));
    helper.writer.write_all(&[0, 0, 0, 1, 0x7f]).await.unwrap();
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        helper.reader.read_to_end(&mut rest),
    )
    .await;
    assert!(closed.is_ok(), "the router must close a broken channel");
}
