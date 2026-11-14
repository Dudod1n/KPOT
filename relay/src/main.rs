//! `krot-relay`: the server side of КРОТ's UDP channel. It talks only through stdin/stdout of
//! the SSH exec channel that started it, takes no arguments, opens no listening ports and
//! writes nothing to disk. It ends as soon as its stdin closes.
#[cfg(target_os = "linux")]
mod relay;

fn main() {
    // Nothing is configurable from the command line: addresses come only in frames.
    if std::env::args_os().len() > 1 {
        std::process::exit(2);
    }
    #[cfg(target_os = "linux")]
    std::process::exit(relay::run());
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("krot-relay works on Linux only");
        std::process::exit(1);
    }
}
