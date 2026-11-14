//! UDP of intercepted applications through a relay on the SSH server.
pub mod consent;
pub mod deliver;
pub mod metrics;
pub mod report;
pub mod router;
#[cfg(test)]
pub(crate) mod testing;
pub mod transport;

/// The UDP state of a tunnel in words, for the CLI and the window.
pub fn state_text(runtime: &crate::ssh::UdpRuntime) -> String {
    match runtime.state.as_str() {
        "running" => format!("работает, уровень {}", runtime.level.max(1)),
        "starting" => "запускается".into(),
        "waiting" => "ждёт подключения туннеля".into(),
        "unavailable" if runtime.message.is_empty() => "недоступен".into(),
        "unavailable" => format!("недоступен: {}", runtime.message),
        _ => "выключен".into(),
    }
}
