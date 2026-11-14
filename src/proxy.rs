//! Carries one intercepted TCP connection through the SOCKS5 port of a D tunnel.
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    Address(SocketAddr),
    /// Resolved on the SSH server side.
    Domain(String, u16),
}

#[derive(Debug, Default)]
pub struct Counters {
    pub connections: AtomicU64,
    pub total: AtomicU64,
    pub sent: AtomicU64,
    pub received: AtomicU64,
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, message)
}

/// Opens `destination` through the no-authentication SOCKS5 proxy at `proxy`.
pub async fn connect(proxy: SocketAddr, destination: &Destination) -> io::Result<TcpStream> {
    timeout(HANDSHAKE_TIMEOUT, async {
        let mut stream = TcpStream::connect(proxy).await?;
        handshake(&mut stream, destination).await?;
        Ok(stream)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 handshake timed out"))?
}

async fn handshake(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    destination: &Destination,
) -> io::Result<()> {
    let mut request = vec![5, 1, 0, 5, 1, 0];
    let port = match destination {
        Destination::Address(address) => {
            match address.ip() {
                IpAddr::V4(ip) => {
                    request.push(1);
                    request.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    request.push(4);
                    request.extend_from_slice(&ip.octets());
                }
            }
            address.port()
        }
        Destination::Domain(name, port) => {
            let length = u8::try_from(name.len())
                .ok()
                .filter(|length| *length > 0)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad domain name"))?;
            request.push(3);
            request.push(length);
            request.extend_from_slice(name.as_bytes());
            *port
        }
    };
    request.extend_from_slice(&port.to_be_bytes());
    // The greeting and the request go together: the proxy is local and offers one method.
    stream.write_all(&request).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 0] {
        return Err(refused("SOCKS5 proxy refused the greeting"));
    }
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 5 || reply[1] != 0 {
        return Err(refused("SOCKS5 proxy could not open the destination"));
    }
    let bound = match reply[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(stream.read_u8().await?),
        _ => return Err(refused("SOCKS5 proxy sent a malformed reply")),
    };
    let mut rest = vec![0u8; bound + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

/// Pipes `inbound` to `destination` through the proxy and accounts the traffic.
pub async fn relay(
    inbound: impl AsyncRead + AsyncWrite + Unpin,
    proxy: SocketAddr,
    destination: &Destination,
    counters: &Counters,
) -> io::Result<()> {
    relay_reporting(inbound, proxy, destination, counters, || {}).await
}

/// [`relay`] that calls `opened` once the proxy has opened the destination.
pub async fn relay_reporting(
    inbound: impl AsyncRead + AsyncWrite + Unpin,
    proxy: SocketAddr,
    destination: &Destination,
    counters: &Counters,
    opened: impl FnOnce(),
) -> io::Result<()> {
    counters.total.fetch_add(1, Ordering::Relaxed);
    let outbound = connect(proxy, destination).await?;
    opened();
    pipe(inbound, outbound, counters).await
}

/// Pipes `inbound` straight to `destination`, bypassing the tunnel.
pub async fn direct(
    inbound: impl AsyncRead + AsyncWrite + Unpin,
    destination: SocketAddr,
    counters: &Counters,
) -> io::Result<()> {
    counters.total.fetch_add(1, Ordering::Relaxed);
    let outbound = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(destination))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection timed out"))??;
    pipe(inbound, outbound, counters).await
}

async fn pipe(
    mut inbound: impl AsyncRead + AsyncWrite + Unpin,
    mut outbound: TcpStream,
    counters: &Counters,
) -> io::Result<()> {
    counters.connections.fetch_add(1, Ordering::Relaxed);
    let result = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    counters.connections.fetch_sub(1, Ordering::Relaxed);
    let (sent, received) = result?;
    counters.sent.fetch_add(sent, Ordering::Relaxed);
    counters.received.fetch_add(received, Ordering::Relaxed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Minimal SOCKS5 server: reports the requested destination, then echoes or refuses.
    async fn proxy(refuse: bool) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            let mut head = [0u8; 4];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[..3], [5, 1, 0]);
            let length = match head[3] {
                1 => 4,
                4 => 16,
                _ => usize::from(stream.read_u8().await.unwrap()),
            };
            let mut destination = vec![0u8; length + 2];
            stream.read_exact(&mut destination).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            if refuse {
                stream
                    .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                return destination;
            }
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            destination
        });
        (address, task)
    }

    #[tokio::test]
    async fn relay_passes_the_destination_and_counts_both_directions() {
        for (destination, expected) in [
            (
                Destination::Domain("db.internal".into(), 5432),
                [b"db.internal".as_slice(), &[0x15, 0x38]].concat(),
            ),
            (
                Destination::Address("10.1.2.3:443".parse().unwrap()),
                vec![10, 1, 2, 3, 1, 187],
            ),
            (
                Destination::Address("[::1]:80".parse().unwrap()),
                [[0u8; 15].as_slice(), &[1, 0, 80]].concat(),
            ),
        ] {
            let (address, server) = proxy(false).await;
            let (mut app, intercepted) = tokio::io::duplex(64);
            let counters = Counters::default();
            let client = async {
                app.write_all(b"ping").await.unwrap();
                let mut answer = [0u8; 4];
                app.read_exact(&mut answer).await.unwrap();
                drop(app);
                answer
            };
            let (result, answer) =
                tokio::join!(relay(intercepted, address, &destination, &counters), client);
            result.unwrap();
            assert_eq!(&answer, b"ping");
            assert_eq!(server.await.unwrap(), expected);
            assert_eq!(counters.total.load(Ordering::Relaxed), 1);
            assert_eq!(counters.connections.load(Ordering::Relaxed), 0);
            assert_eq!(counters.sent.load(Ordering::Relaxed), 4);
            assert_eq!(counters.received.load(Ordering::Relaxed), 4);
        }
    }

    #[tokio::test]
    async fn refused_destination_and_stopped_tunnel_fail_without_an_open_connection() {
        let (address, server) = proxy(true).await;
        let counters = Counters::default();
        let (_app, intercepted) = tokio::io::duplex(64);
        let destination = Destination::Domain("closed.internal".into(), 1);
        let error = relay(intercepted, address, &destination, &counters)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        server.await.unwrap();
        assert_eq!(counters.connections.load(Ordering::Relaxed), 0);

        // Nothing listens on the port of a stopped tunnel.
        let (_app, intercepted) = tokio::io::duplex(64);
        assert!(
            relay(intercepted, address, &destination, &counters)
                .await
                .is_err()
        );
        assert_eq!(counters.total.load(Ordering::Relaxed), 2);
        assert!(
            connect(address, &Destination::Domain(String::new(), 1))
                .await
                .is_err()
        );
    }
}
