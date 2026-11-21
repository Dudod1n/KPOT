//! Access of a test to the tunnel's current SSH session. The session is never handed out: a
//! test sends an operation to the session's agent, which runs it beside the forwardings and
//! is stopped with them. So a test never keeps a session or its channels alive past the
//! tunnel's teardown, and a reconnect simply brings a new agent.
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Standard input and output of a command on the server.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}
pub type Pipe = Box<dyn Stream>;

/// What a test needs from an SSH session.
pub trait Session: Send + Sync + 'static {
    /// Resolves `true` on the server's answer and `false` once the session is gone.
    fn ping(&self) -> BoxFuture<'_, bool>;
    /// Runs `command` in an exec channel of its own; `None` when the server refuses it.
    fn exec(&self, command: String) -> BoxFuture<'_, Option<Pipe>>;
}

/// How long the server may take to accept an exec request.
const EXEC_REPLY: Duration = Duration::from_secs(10);

impl<H: russh::client::Handler + 'static> Session for russh::client::Handle<H> {
    fn ping(&self) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.send_ping().await.is_ok() && !self.is_closed() })
    }
    fn exec(&self, command: String) -> BoxFuture<'_, Option<Pipe>> {
        Box::pin(async move {
            let mut guard = Closing(Some(self.channel_open_session().await.ok()?));
            let opened = async {
                let channel = guard.0.as_mut()?;
                channel.exec(true, command).await.ok()?;
                loop {
                    match channel.wait().await? {
                        russh::ChannelMsg::Success => return Some(()),
                        russh::ChannelMsg::Failure
                        | russh::ChannelMsg::Close
                        | russh::ChannelMsg::Eof => return None,
                        _ => {}
                    }
                }
            };
            tokio::time::timeout(EXEC_REPLY, opened).await.ok()??;
            // The stream closes the channel when it is dropped.
            Some(Box::new(guard.0.take()?.into_stream()) as Pipe)
        })
    }
}

/// Closes a channel that is dropped before it became a stream, so that the server ends its
/// command at once instead of with the session.
struct Closing(Option<russh::Channel<russh::client::Msg>>);

impl Drop for Closing {
    fn drop(&mut self) {
        if let Some(channel) = self.0.take() {
            tokio::spawn(async move {
                let _ = channel.close().await;
            });
        }
    }
}

type Op = Box<dyn FnOnce(Arc<dyn Session>) -> BoxFuture<'static, ()> + Send>;

/// The way to the agent of one session.
#[derive(Clone)]
pub struct Access {
    ops: mpsc::Sender<Op>,
    /// Counts the sessions of the tunnel, so that a test sees a reconnect.
    pub session: u64,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Access({})", self.session)
    }
}

impl Access {
    /// Runs `operation` on the session. `None` when the session ended before its result.
    /// Dropping the returned future stops the operation in the agent too.
    pub async fn run<T, F>(
        &self,
        operation: impl FnOnce(Arc<dyn Session>) -> F + Send + 'static,
    ) -> Option<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        let (reply, result) = oneshot::channel();
        let op: Op = Box::new(move |session| {
            Box::pin(async move {
                let mut reply = reply;
                tokio::select! {
                    value = operation(session) => { let _ = reply.send(value); },
                    () = reply.closed() => {},
                }
            })
        });
        self.ops.send(op).await.ok()?;
        result.await.ok()
    }
}

/// The current session of a tunnel, published for its tests. Dropping it, together with the
/// tunnel's measurement, tells every test that the tunnel stopped.
#[derive(Debug)]
pub struct Gate {
    current: watch::Sender<Option<Access>>,
    sessions: AtomicU64,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            current: watch::channel(None).0,
            sessions: AtomicU64::new(0),
        }
    }
}

impl Gate {
    pub fn subscribe(&self) -> watch::Receiver<Option<Access>> {
        self.current.subscribe()
    }
    /// Serves the tests while the session lasts. It runs among the session's forwardings and
    /// is dropped with them; whatever it runs is dropped at the same moment.
    pub async fn serve(&self, session: Arc<dyn Session>) {
        let number = self.sessions.fetch_add(1, Ordering::Relaxed) + 1;
        let (ops, mut received) = mpsc::channel::<Op>(8);
        self.current.send_replace(Some(Access {
            ops,
            session: number,
        }));
        struct Withdraw<'a>(&'a watch::Sender<Option<Access>>, u64);
        impl Drop for Withdraw<'_> {
            fn drop(&mut self) {
                self.0.send_if_modified(|current| {
                    let ours = current
                        .as_ref()
                        .is_some_and(|access| access.session == self.1);
                    if ours {
                        *current = None;
                    }
                    ours
                });
            }
        }
        let _withdraw = Withdraw(&self.current, number);
        // Operations run inside this future, not as tasks: dropping it drops them at once.
        let mut running: Vec<BoxFuture<'static, ()>> = Vec::new();
        loop {
            let op = poll_fn(|cx| {
                running.retain_mut(|operation| operation.as_mut().poll(cx).is_pending());
                match received.poll_recv(cx) {
                    Poll::Ready(Some(op)) => Poll::Ready(op),
                    _ => Poll::Pending,
                }
            })
            .await;
            running.push(op(session.clone()));
        }
    }
}
