//! A scripted relay on the other end of an in-memory stream, for transport and router tests.
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use krot_udp_proto::{self as proto, Frame, Refusal, VERSION};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, split},
    sync::mpsc,
};

/// How the fake relay on the other end of the stream behaves.
#[derive(Clone, Copy)]
pub struct Behaviour {
    pub version: u16,
    pub echo: bool,
    pub acknowledge: bool,
    pub pong: bool,
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
pub struct Seen {
    pub sends: Vec<(u32, SocketAddr, usize)>,
    pub send_bytes: u64,
    pub closes: Vec<u32>,
    pub acks: Vec<u64>,
    pub pings: u32,
}

pub struct Fake {
    pub seen: Arc<Mutex<Seen>>,
    /// Frames to push to the client.
    pub push: mpsc::UnboundedSender<Vec<u8>>,
}

pub fn encoded(frame: &Frame<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    proto::encode(frame, &mut bytes);
    bytes
}

pub fn fake(stream: DuplexStream, behaviour: Behaviour) -> Fake {
    let (mut reader, mut writer) = split(stream);
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (push, mut pushed) = mpsc::unbounded_channel::<Vec<u8>>();
    let (out, mut outgoing) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        // Pushing is optional: the fake keeps answering after its `Fake` is dropped.
        let mut pushing = true;
        loop {
            let bytes = tokio::select! {
                bytes = pushed.recv(), if pushing => match bytes {
                    Some(bytes) => bytes,
                    None => { pushing = false; continue; }
                },
                bytes = outgoing.recv() => match bytes {
                    Some(bytes) => bytes,
                    None => return,
                },
            };
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
