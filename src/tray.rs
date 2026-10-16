//! The background owner keeps the tray alive independently of desktop windows.
use crate::{background::Snapshot, icons};
use anyhow::Result;
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc as async_mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tray_icon::{
    Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

#[derive(Debug)]
pub enum Action {
    Open,
    Stop,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    running: usize,
    total: usize,
    waiting: usize,
    connecting: usize,
    errors: usize,
}

impl Status {
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        let mut status = Self {
            total: snapshot.config.tunnels.len(),
            ..Self::default()
        };
        for tunnel in &snapshot.config.tunnels {
            if snapshot.prompts.contains_key(&tunnel.id) {
                status.waiting += 1;
            } else if let Some(runtime) = snapshot.runtimes.get(&tunnel.id) {
                match runtime.state.as_str() {
                    "running" => status.running += 1,
                    "error" => status.errors += 1,
                    "connecting" | "reconnecting" => status.connecting += 1,
                    _ => {}
                }
            }
        }
        status
    }

    fn label(&self) -> String {
        let mut label = format!("Работает {} из {}", self.running, self.total);
        for (count, text) in [
            (self.waiting, "ожидают ответа"),
            (self.errors, "ошибок"),
            (self.connecting, "подключаются"),
        ] {
            if count > 0 {
                label.push_str(&format!(" · {text}: {count}"));
            }
        }
        label
    }

    fn badge(&self) -> Option<[u8; 4]> {
        if self.errors > 0 {
            Some([255, 155, 145, 255])
        } else if self.waiting > 0 || self.connecting > 0 {
            Some([227, 188, 124, 255])
        } else if self.running > 0 {
            Some([172, 208, 148, 255])
        } else {
            None
        }
    }
}

pub struct Tray {
    status: mpsc::SyncSender<Status>,
    stop: CancellationToken,
    done: oneshot::Receiver<()>,
    #[cfg(windows)]
    hwnd: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Tray {
    pub fn start(stop: CancellationToken) -> (Self, async_mpsc::UnboundedReceiver<Action>) {
        let (status, updates) = mpsc::sync_channel(1);
        let (actions, receiver) = async_mpsc::unbounded_channel();
        let (done, finished) = oneshot::channel();
        let worker_stop = stop.clone();
        #[cfg(windows)]
        let hwnd = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        #[cfg(windows)]
        let worker_hwnd = hwnd.clone();
        let spawned = std::thread::Builder::new()
            .name("krot-tray".into())
            .spawn(move || {
                let result = run(
                    updates,
                    actions,
                    worker_stop,
                    #[cfg(windows)]
                    worker_hwnd,
                );
                if result.is_err() {
                    eprintln!("КРОТ: системный трей недоступен; туннели продолжают работать.");
                }
                let _ = done.send(());
            });
        if spawned.is_err() {
            eprintln!("КРОТ: не удалось создать поток системного трея.");
        }
        (
            Self {
                status,
                stop,
                done: finished,
                #[cfg(windows)]
                hwnd,
            },
            receiver,
        )
    }

    pub fn update(&self, status: Status) {
        let _ = self.status.try_send(status);
    }

    pub async fn close(mut self) {
        self.stop.cancel();
        self.cancel_menu();
        // A stalled desktop session must not prevent SSH shutdown.
        let _ = tokio::time::timeout(Duration::from_secs(3), &mut self.done).await;
    }

    #[cfg(windows)]
    fn cancel_menu(&self) {
        use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CANCELMODE};
        let hwnd = self.hwnd.load(std::sync::atomic::Ordering::Acquire);
        if hwnd != 0 {
            unsafe {
                PostMessageW(hwnd as _, WM_CANCELMODE, 0, 0);
            }
        }
    }
    #[cfg(not(windows))]
    fn cancel_menu(&self) {}
}

impl Drop for Tray {
    fn drop(&mut self) {
        self.stop.cancel();
        self.cancel_menu();
    }
}

fn icon(status: &Status) -> Result<Icon> {
    let icon = icons::tray_icon(status.badge());
    Ok(Icon::from_rgba(icon.rgba, icon.width, icon.height)?)
}

fn run(
    updates: mpsc::Receiver<Status>,
    actions: async_mpsc::UnboundedSender<Action>,
    stop: CancellationToken,
    #[cfg(windows)] hwnd: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none()
        && std::env::var_os("XDG_RUNTIME_DIR").is_none()
    {
        return Ok(());
    }
    let status_item = MenuItem::new("КРОТ — фон работает", false, None);
    let open = MenuItem::with_id("open", "Открыть КРОТ", true, None);
    let stop_item = MenuItem::with_id("stop", "Остановить КРОТ", true, None);
    let menu = Menu::new();
    menu.append_items(&[
        &status_item,
        &PredefinedMenuItem::separator(),
        &open,
        &stop_item,
    ])?;
    let tray = TrayIconBuilder::new()
        .with_id("krot")
        .with_title("КРОТ")
        .with_tooltip("КРОТ — фон работает")
        .with_icon(icon(&Status::default())?)
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .build()?;
    #[cfg(windows)]
    hwnd.store(
        tray.window_handle() as usize,
        std::sync::atomic::Ordering::Release,
    );
    let mut previous = None;
    let mut last_open = Instant::now() - Duration::from_secs(1);
    while !stop.is_cancelled() {
        // Windows pauses status refresh while the native menu is open.
        pump_messages();
        match updates.recv_timeout(Duration::from_millis(80)) {
            Ok(status) if previous.as_ref() != Some(&status) => {
                let text = status.label();
                status_item.set_text(&text);
                if tray.set_tooltip(Some(format!("КРОТ — {text}"))).is_ok()
                    && tray.set_icon(Some(icon(&status)?)).is_ok()
                {
                    previous = Some(status);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            _ => {}
        }
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == open.id() {
                let _ = actions.send(Action::Open);
            } else if event.id == stop_item.id() {
                let _ = actions.send(Action::Stop);
            }
        }
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) && last_open.elapsed() >= Duration::from_millis(400)
            {
                last_open = Instant::now();
                let _ = actions.send(Action::Open);
            }
        }
    }
    #[cfg(windows)]
    hwnd.store(0, std::sync::atomic::Ordering::Release);
    drop(tray);
    Ok(())
}

#[cfg(windows)]
fn pump_messages() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
    };
    let mut message = MSG::default();
    unsafe {
        while PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}
#[cfg(not(windows))]
fn pump_messages() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Tunnel,
        ssh::{PendingPrompt, Prompt, Runtime},
    };
    #[test]
    fn summary_counts_configured_tunnels_and_prioritizes_attention() {
        let mut snapshot = Snapshot::default();
        let first = Tunnel {
            id: "first".into(),
            ..Tunnel::default()
        };
        let second = Tunnel {
            id: "second".into(),
            ..Tunnel::default()
        };
        snapshot.config.tunnels = vec![first.clone(), second];
        snapshot.runtimes.insert(
            "deleted".into(),
            Runtime {
                state: "error".into(),
                ..Runtime::default()
            },
        );
        snapshot.runtimes.insert(
            first.id.clone(),
            Runtime {
                state: "running".into(),
                ..Runtime::default()
            },
        );
        let status = Status::from_snapshot(&snapshot);
        assert_eq!(status.label(), "Работает 1 из 2");
        assert_eq!(status.badge(), Some([172, 208, 148, 255]));
        snapshot.runtimes.insert(
            "second".into(),
            Runtime {
                state: "reconnecting".into(),
                ..Runtime::default()
            },
        );
        assert_eq!(
            Status::from_snapshot(&snapshot).badge(),
            Some([227, 188, 124, 255])
        );
        snapshot.runtimes.get_mut("second").unwrap().state = "error".into();
        assert_eq!(
            Status::from_snapshot(&snapshot).badge(),
            Some([255, 155, 145, 255])
        );
        snapshot.prompts.insert(
            "second".into(),
            PendingPrompt {
                id: "prompt".into(),
                request: Prompt {
                    kind: "password".into(),
                    tunnel_id: "second".into(),
                    tunnel_name: "second".into(),
                    endpoint: first.server,
                    hop: String::new(),
                    message: String::new(),
                    old_fingerprint: String::new(),
                    new_fingerprint: String::new(),
                },
            },
        );
        let status = Status::from_snapshot(&snapshot);
        assert_eq!((status.errors, status.waiting), (0, 1));
        assert!(status.label().contains("ожидают ответа: 1"));
        assert_eq!(status.badge(), Some([227, 188, 124, 255]));
        assert_eq!(Status::default().badge(), None);
    }
}
