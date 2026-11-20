//! The machine-readable metrics of `krot-cli metrics`: everything the snapshot holds about
//! UDP, grouped by tunnel and by rule, and the session measurement of every tunnel. The schema
//! number changes with any incompatible change.
use serde_json::{Value, json};

use crate::background::Snapshot;

pub const SCHEMA: u32 = 1;

/// Metrics of every tunnel and rule, or of one tunnel and its rules.
pub fn metrics(snapshot: &Snapshot, tunnel: Option<&str>) -> Value {
    let tunnels: serde_json::Map<String, Value> = snapshot
        .config
        .tunnels
        .iter()
        .filter(|item| item.kind == "D" && tunnel.is_none_or(|id| id == item.id))
        .map(|item| {
            (
                item.id.clone(),
                json!({
                    "name": item.name,
                    "consent": snapshot.udp.consented(item),
                    "state": snapshot.udp_runtimes.get(&item.id).cloned().unwrap_or_default(),
                    "transport": snapshot.udp_metrics.get(&item.id),
                    "routing": snapshot.udp_routing.get(&item.id).cloned().unwrap_or_default(),
                }),
            )
        })
        .collect();
    let rules: serde_json::Map<String, Value> = snapshot
        .apps
        .iter()
        .filter(|rule| tunnel.is_none_or(|id| id == rule.tunnel_id))
        .map(|rule| {
            (
                rule.id.clone(),
                json!({
                    "name": rule.name,
                    "tunnel_id": rule.tunnel_id,
                    "quic": snapshot.udp.quic(&rule.id),
                    "helper": snapshot.udp_helper.get(&rule.id).cloned().unwrap_or_default(),
                    "tunnel": snapshot.udp_rules.get(&rule.id).cloned().unwrap_or_default(),
                }),
            )
        })
        .collect();
    // Every kind of tunnel has a session; a stopped one has no measurement.
    let link: serde_json::Map<String, Value> = snapshot
        .config
        .tunnels
        .iter()
        .filter(|item| tunnel.is_none_or(|id| id == item.id))
        .map(|item| (item.id.clone(), json!(snapshot.links.get(&item.id))))
        .collect();
    json!({
        "schema": SCHEMA,
        "version": snapshot.version,
        "udp_error": snapshot.udp_error,
        "helper_attached": snapshot.divert_attached,
        "tunnels": tunnels,
        "rules": rules,
        "link": link,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        apps::AppRule,
        config::{Config, Endpoint, Tunnel},
    };

    fn snapshot() -> Snapshot {
        let socks = Tunnel {
            id: "t1".into(),
            name: "socks".into(),
            kind: "D".into(),
            server: Endpoint {
                host: "example.org".into(),
                user: "me".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let local = Tunnel {
            id: "t2".into(),
            kind: "L".into(),
            ..socks.clone()
        };
        Snapshot {
            config: Config {
                tunnels: vec![socks, local],
                ..Default::default()
            },
            apps: vec![AppRule {
                id: "r1".into(),
                name: "browser".into(),
                tunnel_id: "t1".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn the_schema_is_stable_with_or_without_running_udp() {
        let mut snapshot = snapshot();
        let value = metrics(&snapshot, None);
        assert_eq!(value["schema"], 1);
        assert_eq!(
            value["tunnels"].as_object().unwrap().len(),
            1,
            "only SOCKS tunnels"
        );
        let tunnel = &value["tunnels"]["t1"];
        assert_eq!(tunnel["consent"], false);
        assert!(tunnel["transport"].is_null());
        assert!(tunnel["state"].is_object() && tunnel["routing"]["to_helper_delay"].is_object());
        let rule = &value["rules"]["r1"];
        assert_eq!(
            (rule["tunnel_id"].as_str(), rule["quic"].as_bool()),
            (Some("t1"), Some(false))
        );
        for part in ["helper", "tunnel"] {
            assert!(rule[part]["drops"].is_object(), "{part}");
        }

        let link = value["link"].as_object().unwrap();
        assert_eq!(link.len(), 2, "every tunnel");
        assert!(link["t2"].is_null(), "a stopped tunnel has no measurement");

        snapshot.links.insert(
            "t2".into(),
            crate::link::LinkStats {
                rx_bps: 8_000,
                ..Default::default()
            },
        );
        let value = metrics(&snapshot, Some("t2"));
        let link = value["link"].as_object().unwrap();
        assert_eq!(link.len(), 1);
        assert_eq!(link["t2"]["rx_bps"], 8_000);
        for key in [
            "rtt",
            "jitter_us",
            "ping_lost",
            "reconnects",
            "events",
            "tx_total",
        ] {
            assert!(link["t2"].get(key).is_some(), "{key}");
        }

        snapshot.udp_metrics.insert("t1".into(), Default::default());
        let value = metrics(&snapshot, Some("t1"));
        for key in [
            "sent",
            "received",
            "drops",
            "to_channel_delay",
            "rtt",
            "relay",
        ] {
            assert!(
                value["tunnels"]["t1"]["transport"].get(key).is_some(),
                "{key}"
            );
        }
        assert!(
            metrics(&snapshot, Some("other"))["rules"]
                .as_object()
                .unwrap()
                .is_empty()
        );
    }
}
