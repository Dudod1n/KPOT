use std::{env, fmt::Write as _, fs, path::PathBuf};

use sha2::{Digest, Sha256};

/// Architectures of the server relay, as `uname -m` names them, with their ELF machine.
const RELAYS: [(&str, u16); 2] = [("x86_64", 62), ("aarch64", 183)];

/// Embeds the relay binaries from `KROT_RELAY_DIR` with their SHA-256. Without the directory
/// the client is built without them, and UDP through the server is unavailable.
/// Whether a 64-bit little-endian ELF asks for a program interpreter (`PT_INTERP`), as
/// dynamically linked executables do. Malformed program headers count as "yes".
fn needs_interpreter(elf: &[u8]) -> bool {
    const PT_INTERP: u32 = 3;
    let u16_at = |at: usize| {
        elf.get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let u64_at = |at: usize| {
        elf.get(at..at + 8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    };
    let (Some(offset), Some(size), Some(count)) = (u64_at(32), u16_at(54), u16_at(56)) else {
        return true;
    };
    (0..usize::from(count)).any(|index| {
        let at = offset as usize + index * usize::from(size);
        elf.get(at..at + 4)
            .is_none_or(|kind| u32::from_le_bytes(kind.try_into().unwrap()) == PT_INTERP)
    })
}

fn embed_relays() {
    println!("cargo:rerun-if-env-changed=KROT_RELAY_DIR");
    println!("cargo:rerun-if-env-changed=KROT_REQUIRE_RELAY");
    let mut code = String::from("pub static RELAYS: &[Relay] = &[\n");
    let mut found = 0;
    if let Some(directory) = env::var_os("KROT_RELAY_DIR") {
        let directory = PathBuf::from(directory);
        for (arch, machine) in RELAYS {
            let path = directory.join(format!("krot-relay-{arch}"));
            println!("cargo:rerun-if-changed={}", path.display());
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    // A misnamed or unreadable file must not pass unnoticed.
                    println!(
                        "cargo:warning=KROT_RELAY_DIR has no usable {}: {error}; UDP through \
                         the server will not work on {arch} servers",
                        path.display()
                    );
                    continue;
                }
            };
            // A static ELF executable for the named architecture, not a swapped or host build.
            assert!(
                bytes.len() > 64
                    && bytes[..4] == *b"\x7fELF"
                    && bytes[4] == 2
                    && bytes[5] == 1
                    && u16::from_le_bytes([bytes[18], bytes[19]]) == machine,
                "{} is not a 64-bit little-endian ELF for {arch}",
                path.display()
            );
            assert!(
                !needs_interpreter(&bytes),
                "{} is dynamically linked; the relay must be a static musl build",
                path.display()
            );
            let path = path
                .canonicalize()
                .expect("relay path must resolve")
                .to_str()
                .expect("relay path must be UTF-8")
                .to_owned();
            let digest = Sha256::digest(&bytes);
            let hash = digest.iter().fold(String::new(), |mut hash, byte| {
                let _ = write!(hash, "{byte:02x}");
                hash
            });
            let _ = writeln!(
                code,
                "    Relay {{ arch: {arch:?}, sha256: {hash:?}, bytes: include_bytes!({path:?}) }},"
            );
            found += 1;
        }
    }
    code.push_str("];\n");
    assert!(
        found == RELAYS.len() || env::var("KROT_REQUIRE_RELAY").as_deref() != Ok("1"),
        "KROT_REQUIRE_RELAY=1, but KROT_RELAY_DIR does not hold krot-relay-x86_64 and krot-relay-aarch64"
    );
    let output =
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR")).join("relay.rs");
    fs::write(output, code).expect("generated relay table must be written");
}

fn main() {
    embed_relays();
    for path in [
        "build.rs",
        "scripts/build_icons.py",
        "assets/krot.svg",
        "assets/krot.png",
        "assets/krot-tray.png",
        "assets/krot.ico",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/krot.ico")
            .set("ProductName", "КРОТ")
            .set("FileDescription", "КРОТ — менеджер SSH-туннелей")
            .compile()
            .expect("Windows application resources must compile");
    }
}
