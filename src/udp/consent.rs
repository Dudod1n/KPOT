//! Which tunnels may upload and run the UDP relay, and which rules tunnel QUIC.
//!
//! Kept in its own sidecar file: `tunnels.json` and `*.apps.json` reject unknown fields, so a
//! new field there would stop version 0.5.8 from reading them after a downgrade.
use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::{Store, atomic_json};

const MAX_BYTES: usize = 256 * 1024;
const MAX_ENTRIES: usize = 512;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TunnelUdp {
    /// The user agreed that the relay is uploaded to and run on this tunnel's server.
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleUdp {
    /// UDP 443 of the rule goes through the tunnel instead of being blocked.
    pub quic: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UdpSettings {
    pub version: u32,
    #[serde(default)]
    pub tunnels: BTreeMap<String, TunnelUdp>,
    #[serde(default)]
    pub rules: BTreeMap<String, RuleUdp>,
}

impl Default for UdpSettings {
    fn default() -> Self {
        Self {
            version: 1,
            tunnels: BTreeMap::new(),
            rules: BTreeMap::new(),
        }
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

impl UdpSettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "Версия файла настроек UDP {} не поддерживается.",
            self.version
        );
        ensure!(
            self.tunnels.len() <= MAX_ENTRIES && self.rules.len() <= MAX_ENTRIES,
            "В настройках UDP слишком много записей."
        );
        ensure!(
            self.tunnels
                .keys()
                .chain(self.rules.keys())
                .all(|id| valid_id(id)),
            "Некорректный идентификатор в настройках UDP."
        );
        Ok(())
    }

    /// The user agreed to the relay on this tunnel and has not switched UDP off.
    pub fn tunnel_enabled(&self, tunnel: &str) -> bool {
        self.tunnels.get(tunnel).is_some_and(|entry| entry.enabled)
    }

    pub fn quic(&self, rule: &str) -> bool {
        self.rules.get(rule).is_some_and(|entry| entry.quic)
    }

    /// Drops entries of deleted tunnels and rules, and entries that only hold defaults.
    pub fn retain_known<'a>(
        &mut self,
        tunnels: impl IntoIterator<Item = &'a str>,
        rules: impl IntoIterator<Item = &'a str>,
    ) {
        let tunnels: std::collections::HashSet<&str> = tunnels.into_iter().collect();
        let rules: std::collections::HashSet<&str> = rules.into_iter().collect();
        self.tunnels
            .retain(|id, entry| entry.enabled && tunnels.contains(id.as_str()));
        self.rules
            .retain(|id, entry| entry.quic && rules.contains(id.as_str()));
    }
}

pub fn path(store: &Store) -> PathBuf {
    store.sidecar(".udp.json")
}

/// A missing file means UDP is off everywhere. A broken one is an error: the caller keeps UDP
/// off and must not overwrite the file.
pub fn load(store: &Store) -> Result<UdpSettings> {
    let path = path(store);
    let stream = match File::open(&path) {
        Ok(stream) => stream,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(UdpSettings::default());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Не удалось открыть настройки UDP {}", path.display()));
        }
    };
    let mut raw = Vec::new();
    stream.take((MAX_BYTES + 1) as u64).read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= MAX_BYTES,
        "Файл настроек UDP {} слишком большой.",
        path.display()
    );
    let settings: UdpSettings = serde_json::from_slice(&raw)
        .with_context(|| format!("Ошибка в настройках UDP {}", path.display()))?;
    settings
        .validate()
        .with_context(|| format!("Ошибка в настройках UDP {}", path.display()))?;
    Ok(settings)
}

pub fn save(store: &Store, settings: &UdpSettings) -> Result<()> {
    settings.validate()?;
    atomic_json(&path(store), settings, Some(MAX_BYTES))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path().join("tunnels.json")).unwrap();
        (directory, store)
    }

    #[test]
    fn missing_file_means_udp_off_and_a_round_trip_keeps_choices() {
        let (_directory, store) = store();
        let empty = load(&store).unwrap();
        assert!(!empty.tunnel_enabled("t1") && !empty.quic("r1"));

        let mut settings = UdpSettings::default();
        settings
            .tunnels
            .insert("t1".into(), TunnelUdp { enabled: true });
        settings.rules.insert("r1".into(), RuleUdp { quic: true });
        save(&store, &settings).unwrap();
        assert_eq!(path(&store), store.sidecar(".udp.json"));
        let loaded = load(&store).unwrap();
        assert_eq!(loaded, settings);
        assert!(loaded.tunnel_enabled("t1") && loaded.quic("r1"));
        assert!(!loaded.tunnel_enabled("t2") && !loaded.quic("r2"));
    }

    #[test]
    fn broken_or_foreign_files_are_errors_and_stay_untouched() {
        let (_directory, store) = store();
        for raw in [
            "{",
            r#"{"version":2}"#,
            r#"{"version":1,"tunnels":{"t1":{"enabled":true,"extra":1}}}"#,
            r#"{"version":1,"tunnels":{"bad id":{"enabled":true}}}"#,
        ] {
            std::fs::write(path(&store), raw).unwrap();
            assert!(load(&store).is_err(), "{raw}");
            assert_eq!(std::fs::read_to_string(path(&store)).unwrap(), raw);
        }
    }

    #[test]
    fn deleted_tunnels_rules_and_defaults_are_forgotten() {
        let mut settings = UdpSettings::default();
        for (id, enabled) in [("kept", true), ("gone", true), ("off", false)] {
            settings.tunnels.insert(id.into(), TunnelUdp { enabled });
        }
        for (id, quic) in [("rule", true), ("old", true), ("plain", false)] {
            settings.rules.insert(id.into(), RuleUdp { quic });
        }
        settings.retain_known(["kept", "off"], ["rule", "plain"]);
        assert_eq!(settings.tunnels.keys().collect::<Vec<_>>(), ["kept"]);
        assert_eq!(settings.rules.keys().collect::<Vec<_>>(), ["rule"]);
    }

    #[test]
    fn the_new_file_leaves_the_files_of_version_0_5_8_alone() {
        let (_directory, store) = store();
        let mut settings = UdpSettings::default();
        settings
            .tunnels
            .insert("t1".into(), TunnelUdp { enabled: true });
        save(&store, &settings).unwrap();
        assert!(!store.path.exists());
        assert!(!crate::apps::path(&store).exists());
    }
}
