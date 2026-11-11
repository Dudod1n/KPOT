//! Shared limits and timings. Values marked "tuned on the stand" are starting points that the
//! degraded-network measurements of stage A are expected to revise.
use std::time::Duration;

/// A datagram older than this in any queue is dropped instead of being sent late.
/// Tuned on the stand.
pub const DATAGRAM_EXPIRY: Duration = Duration::from_millis(150);

/// Flows a relay instance holds at most, whatever the client asks for.
pub const RELAY_MAX_FLOWS: u16 = 1024;
/// Flows the client asks for by default.
pub const DEFAULT_MAX_FLOWS: u16 = 512;
/// Idle timeout of a flow that has only sent so far.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(60);
/// Idle timeout of a flow that has both sent and received.
pub const DEFAULT_IDLE_BIDIRECTIONAL: Duration = Duration::from_secs(120);
/// Bounds the relay applies to the idle timeouts the client asks for.
pub const MIN_IDLE: Duration = Duration::from_secs(1);
pub const MAX_IDLE: Duration = Duration::from_secs(600);

/// Datagrams and bytes waiting for one flow socket in the relay.
pub const FLOW_QUEUE_DATAGRAMS: usize = 256;
pub const FLOW_QUEUE_BYTES: usize = 512 * 1024;
/// Datagrams and bytes waiting to be written to the channel, on either side.
pub const CHANNEL_QUEUE_DATAGRAMS: usize = 4096;
pub const CHANNEL_QUEUE_BYTES: usize = 4 * 1024 * 1024;
/// Bytes a single write to the channel carries at most.
pub const WRITE_BATCH: usize = 64 * 1024;

/// `SEND`/`RECV` bytes a side may have written but not yet seen acknowledged. Bytes beyond
/// it would wait in SSH and TCP buffers where no expiry applies. Tuned on the stand.
pub const IN_FLIGHT_WINDOW: u64 = 256 * 1024;
/// How often a side acknowledges received datagram bytes while they keep coming.
pub const ACK_INTERVAL: Duration = Duration::from_millis(20);

/// How often the relay reports `STATS` and the client sends `PING`.
pub const REPORT_INTERVAL: Duration = Duration::from_secs(1);
/// The relay gives up when no `HELLO` arrives within this time.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// A side that hears nothing for this long, `PONG` included, treats the channel as dead.
pub const SILENCE_TIMEOUT: Duration = Duration::from_secs(5);
/// Answers waiting for the consumer on the client side.
pub const DELIVERY_QUEUE_DATAGRAMS: usize = 4096;
