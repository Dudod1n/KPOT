//! UDP counters for the snapshot and the CLI; the histogram summaries live in `crate::metrics`.
use std::collections::BTreeMap;

use krot_udp_proto::metrics::{DropReason, Drops};
use serde::{Deserialize, Serialize};

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
