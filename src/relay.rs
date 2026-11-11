//! The server UDP relay binaries embedded at build time, with their SHA-256 computed from the
//! embedded bytes. A build without `KROT_RELAY_DIR` embeds none.

pub struct Relay {
    /// The architecture as `uname -m` reports it.
    pub arch: &'static str,
    /// Lowercase hex SHA-256 of `bytes`.
    pub sha256: &'static str,
    pub bytes: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/relay.rs"));

/// The relay for a server whose `uname -m` printed `machine`.
pub fn for_machine(machine: &str) -> Option<&'static Relay> {
    let arch = match machine.trim() {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        _ => return None,
    };
    RELAYS.iter().find(|relay| relay.arch == arch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn embedded_hashes_describe_the_embedded_bytes() {
        for relay in RELAYS {
            assert_eq!(hex::encode(Sha256::digest(relay.bytes)), relay.sha256);
            assert_eq!(
                for_machine(relay.arch).map(|found| found.arch),
                Some(relay.arch)
            );
        }
        if std::env::var("KROT_REQUIRE_RELAY").as_deref() == Ok("1") {
            assert_eq!(RELAYS.len(), 2);
        }
    }

    #[test]
    fn unsupported_machines_have_no_relay() {
        for machine in ["armv7l", "i686", "riscv64", "", "x86_64 extra"] {
            assert!(for_machine(machine).is_none(), "{machine}");
        }
    }
}
