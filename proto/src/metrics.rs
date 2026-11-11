//! Fixed-bucket histograms and drop counters. Recording never allocates, and every part of the
//! path uses the same buckets and window so that values stay comparable.
use std::time::Duration;

/// Upper bounds of the histogram buckets in microseconds; the last bucket is unbounded.
pub const BUCKETS_US: [u64; 15] = [
    50, 100, 250, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 150_000, 250_000,
    500_000, 1_000_000,
];
pub const BUCKET_COUNT: usize = BUCKETS_US.len() + 1;
/// Length of the observation window, in report intervals.
pub const WINDOW_INTERVALS: usize = 10;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Histogram {
    pub buckets: [u64; BUCKET_COUNT],
    pub sum_us: u64,
    pub max_us: u64,
}

impl Histogram {
    pub fn record(&mut self, value: Duration) {
        let us = u64::try_from(value.as_micros()).unwrap_or(u64::MAX);
        let index = BUCKETS_US.partition_point(|bound| *bound < us);
        self.buckets[index] += 1;
        self.sum_us = self.sum_us.saturating_add(us);
        self.max_us = self.max_us.max(us);
    }
    pub fn count(&self) -> u64 {
        self.buckets.iter().sum()
    }
    pub fn merge(&mut self, other: &Self) {
        for (bucket, count) in self.buckets.iter_mut().zip(other.buckets) {
            *bucket += count;
        }
        self.sum_us = self.sum_us.saturating_add(other.sum_us);
        self.max_us = self.max_us.max(other.max_us);
    }
    pub fn mean_us(&self) -> Option<u64> {
        let count = self.count();
        (count > 0).then(|| self.sum_us / count)
    }
    /// The upper bound of the bucket holding quantile `q` (0..=1), capped by the maximum seen.
    /// It overestimates by at most one bucket width.
    pub fn quantile_us(&self, q: f64) -> Option<u64> {
        let count = self.count();
        if count == 0 {
            return None;
        }
        let rank = ((q.clamp(0.0, 1.0) * count as f64).ceil() as u64).max(1);
        let mut seen = 0;
        for (index, bucket) in self.buckets.iter().enumerate() {
            seen += bucket;
            if seen >= rank {
                let bound = BUCKETS_US.get(index).copied().unwrap_or(u64::MAX);
                return Some(bound.min(self.max_us));
            }
        }
        Some(self.max_us)
    }
}

/// Histograms of the last `WINDOW_INTERVALS` report intervals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Window {
    intervals: [Histogram; WINDOW_INTERVALS],
    next: usize,
}

impl Window {
    /// Adds one finished interval, forgetting the oldest.
    pub fn push(&mut self, interval: Histogram) {
        self.intervals[self.next] = interval;
        self.next = (self.next + 1) % WINDOW_INTERVALS;
    }
    pub fn total(&self) -> Histogram {
        let mut total = Histogram::default();
        for interval in &self.intervals {
            total.merge(interval);
        }
        total
    }
}

/// Why a datagram was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// It waited longer than `DATAGRAM_EXPIRY`.
    Expired,
    /// A newer datagram needed its place in a full queue.
    Overflow,
    /// The network or the system refused its size.
    Size,
    /// The channel or socket failed.
    Channel,
    /// UDP 443 of a rule that does not tunnel QUIC.
    Quic,
}

impl DropReason {
    pub const ALL: [Self; 5] = [
        Self::Expired,
        Self::Overflow,
        Self::Size,
        Self::Channel,
        Self::Quic,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Overflow => "overflow",
            Self::Size => "size",
            Self::Channel => "channel",
            Self::Quic => "quic",
        }
    }
}

/// Dropped datagrams by reason, indexed in the order of `DropReason::ALL`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Drops(pub [u64; DropReason::ALL.len()]);

impl Drops {
    pub fn add(&mut self, reason: DropReason) {
        self.0[reason as usize] += 1;
    }
    pub fn get(&self, reason: DropReason) -> u64 {
        self.0[reason as usize]
    }
}
