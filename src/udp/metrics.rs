//! Serializable summaries of the shared histograms and counters, for the snapshot and the CLI.
use std::collections::BTreeMap;

use krot_udp_proto::metrics::{DropReason, Drops, Histogram, Window};
use serde::{Deserialize, Serialize};

/// Queue delay or round-trip time over the observation window, in microseconds.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Summary {
    pub count: u64,
    pub mean_us: Option<u64>,
    pub p50_us: Option<u64>,
    pub p95_us: Option<u64>,
    pub p99_us: Option<u64>,
    pub max_us: Option<u64>,
}

impl Summary {
    pub fn of(histogram: &Histogram) -> Self {
        let count = histogram.count();
        Self {
            count,
            mean_us: histogram.mean_us(),
            p50_us: histogram.quantile_us(0.50),
            p95_us: histogram.quantile_us(0.95),
            p99_us: histogram.quantile_us(0.99),
            max_us: (count > 0).then_some(histogram.max_us),
        }
    }
}

/// A histogram that is rolled into a window once per report interval.
#[derive(Clone, Debug, Default)]
pub struct Windowed {
    current: Histogram,
    window: Window,
}

impl Windowed {
    pub fn record(&mut self, value: std::time::Duration) {
        self.current.record(value);
    }
    pub fn push_interval(&mut self, interval: Histogram) {
        self.window.push(interval);
    }
    /// Closes the current interval.
    pub fn roll(&mut self) {
        self.window.push(std::mem::take(&mut self.current));
    }
    pub fn summary(&self) -> Summary {
        let mut total = self.window.total();
        total.merge(&self.current);
        Summary::of(&total)
    }
}

/// Datagrams and bytes in one direction.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Traffic {
    pub datagrams: u64,
    pub bytes: u64,
}

impl Traffic {
    pub fn add(&mut self, bytes: usize) {
        self.datagrams += 1;
        self.bytes += bytes as u64;
    }
    pub fn merge(&mut self, other: &Self) {
        self.datagrams += other.datagrams;
        self.bytes += other.bytes;
    }
}

/// Dropped datagrams by reason name, with every reason present for a stable schema.
pub fn drops_map(drops: &Drops) -> BTreeMap<String, u64> {
    DropReason::ALL
        .iter()
        .map(|reason| (reason.name().to_owned(), drops.get(*reason)))
        .collect()
}

pub fn merge_drops(total: &mut Drops, other: &Drops) {
    for (sum, value) in total.0.iter_mut().zip(other.0) {
        *sum += value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn summaries_cover_the_window_and_the_open_interval() {
        let mut windowed = Windowed::default();
        assert_eq!(windowed.summary(), Summary::default());
        windowed.record(Duration::from_millis(1));
        windowed.roll();
        windowed.record(Duration::from_millis(40));
        let summary = windowed.summary();
        assert_eq!(summary.count, 2);
        assert_eq!(summary.max_us, Some(40_000));
        assert_eq!(summary.p50_us, Some(1_000));
        assert_eq!(summary.mean_us, Some(20_500));
    }

    #[test]
    fn drop_maps_name_every_reason() {
        let mut drops = Drops::default();
        drops.add(DropReason::Quic);
        let map = drops_map(&drops);
        assert_eq!(map.len(), DropReason::ALL.len());
        assert_eq!(map["quic"], 1);
        assert_eq!(map["expired"], 0);
    }
}
