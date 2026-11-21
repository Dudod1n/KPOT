//! Serializable summaries of the shared fixed-bucket histograms, for the snapshot and the CLI.
//! UDP and the tunnel's link measurement use the same buckets and window, so that their
//! numbers stay comparable.
use krot_udp_proto::metrics::{Histogram, Window};
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
}
