//! One native window for startup decisions and the dispatcher.
use std::{
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use anyhow::Result;
use eframe::egui;
use serde_json::Value;

use crate::{
    background::{self, Client},
    config::Store,
    desktop,
};

enum Startup {
    Ready {
        lease: File,
        client: Client,
    },
    Conflict {
        version: Option<String>,
        owner: Option<background::Owner>,
        error: Option<String>,
    },
    Activated,
}

async fn prepare(store: &Store, reuse_running: bool) -> Result<Startup> {
    let guard = crate::update::startup_guard().await?;
    let ui = Store::new(store.sidecar(".ui"))?;
    let Some(lease) = background::try_lease(&ui)? else {
        if reuse_running {
            Client::new(store).request("activate", Value::Null).await?;
            return Ok(Startup::Activated);
        }
        return Ok(conflict(store).await);
    };
    if !reuse_running && background::try_lease(store)?.is_none() {
        return Ok(conflict(store).await);
    }
    drop(guard);
    let client = background::ensure_running(store).await?;
    Ok(Startup::Ready { lease, client })
}

async fn conflict(store: &Store) -> Startup {
    let version = tokio::time::timeout(Duration::from_millis(500), Client::new(store).snapshot())
        .await
        .ok()
        .and_then(Result::ok)
        .and_then(|snapshot| snapshot.version)
        .filter(|version| version.len() <= 128);
    Startup::Conflict {
        version,
        owner: background::observe_owner(store).ok().flatten(),
        error: None,
    }
}

enum Phase {
    Checking,
    Conflict {
        version: Option<String>,
        error: Option<String>,
    },
    Failed(String),
    Desktop(Box<desktop::Desktop>),
}

struct Launcher {
    store: Store,
    runtime: Arc<tokio::runtime::Runtime>,
    no_splash: bool,
    reuse_running: bool,
    check_updates: bool,
    update_ready: Option<PathBuf>,
    completion: Arc<Mutex<Option<String>>>,
    phase: Phase,
    lease: Option<File>,
    tx: mpsc::Sender<Result<Startup>>,
    rx: mpsc::Receiver<Result<Startup>>,
    replacing: bool,
    owner: Option<background::Owner>,
}

impl Launcher {
    fn guard_close(&self, ctx: &egui::Context) {
        if self.replacing
            && matches!(self.phase, Phase::Checking)
            && ctx.input(|input| input.viewport().close_requested())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
    }

    fn start(&mut self, replace: bool, ctx: &egui::Context) {
        self.phase = Phase::Checking;
        self.replacing = replace;
        let store = self.store.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let reuse = self.reuse_running;
        let owner = self.owner.clone();
        self.runtime.spawn(async move {
            let result = async {
                if replace
                    && let Err(error) =
                        background::stop_selected_and_wait(&store, owner.as_ref()).await
                {
                    let mut state = conflict(&store).await;
                    if let Startup::Conflict { error: message, .. } = &mut state {
                        *message = Some(format!("{error:#}"));
                    }
                    return Ok(state);
                }
                prepare(&store, reuse).await
            }
            .await;
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }
}

impl eframe::App for Launcher {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.guard_close(ctx);
        while let Ok(result) = self.rx.try_recv() {
            self.phase = match result {
                Ok(Startup::Ready { lease, client }) => {
                    self.lease = Some(lease);
                    if let Some(path) = &self.update_ready
                        && let Err(error) =
                            crate::update::acknowledge_startup(path, &self.store, false)
                    {
                        *self.completion.lock().unwrap() = Some(format!("{error:#}"));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        return;
                    }
                    Phase::Desktop(desktop::build(
                        self.store.clone(),
                        client,
                        self.runtime.clone(),
                        self.no_splash,
                        self.check_updates,
                        ctx,
                    ))
                }
                Ok(Startup::Conflict {
                    version,
                    owner,
                    error,
                }) => {
                    self.owner = owner;
                    Phase::Conflict { version, error }
                }
                Ok(Startup::Activated) => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    Phase::Checking
                }
                Err(error) if self.replacing => Phase::Conflict {
                    version: None,
                    error: Some(format!("{error:#}")),
                },
                Err(error) => Phase::Failed(format!("{error:#}")),
            };
        }
        if self.update_ready.is_some()
            && matches!(self.phase, Phase::Conflict { .. } | Phase::Failed(_))
        {
            *self.completion.lock().unwrap() =
                Some("Не удалось получить владение окном или запустить новую версию.".into());
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if let Phase::Desktop(app) = &mut self.phase {
            app.update(ctx, frame);
            if app.initialized_for_update()
                && let Some(path) = self.update_ready.take()
            {
                match crate::update::acknowledge_startup(&path, &self.store, true) {
                    Ok(()) => *self.completion.lock().unwrap() = None,
                    Err(error) => {
                        *self.completion.lock().unwrap() = Some(format!("{error:#}"));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
            return;
        }
        let mut retry = None;
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("КРОТ");
            ui.add_space(16.0);
            match &self.phase {
                Phase::Checking => {
                    ui.spinner();
                    ui.label(if self.replacing { "Завершаем предыдущий КРОТ и ждём закрытия окна…" }
                        else { "Проверяем запущенный КРОТ…" });
                }
                Phase::Conflict { version, error } => {
                    ui.heading("КРОТ уже запущен");
                    ui.label(format!("Запускаемая версия: {}", env!("CARGO_PKG_VERSION")));
                    if let Some(version) = version { ui.label(format!("Версия предыдущего процесса: {version}")); }
                    ui.label("Можно завершить предыдущий КРОТ и запустить эту версию. Туннели закроются штатно; сохранённый выбор восстановится.");
                    if let Some(error) = error { ui.colored_label(ui.visuals().error_fg_color, error); }
                    ui.add_space(12.0);
                    if ui.button("Отменить запуск").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                    if ui.button("Завершить предыдущий и запустить").clicked() { retry = Some(true); }
                }
                Phase::Failed(error) => {
                    ui.heading("Не удалось открыть КРОТ");
                    ui.label(error);
                    if ui.button("Повторить").clicked() { retry = Some(false); }
                    if ui.button("Отменить запуск").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                }
                Phase::Desktop(_) => unreachable!(),
            }
        });
        if let Some(replace) = retry {
            self.start(replace, ctx);
        }
    }

    fn on_exit(&mut self, gl: Option<&eframe::glow::Context>) {
        if let Phase::Desktop(app) = &mut self.phase {
            app.on_exit(gl);
        }
    }
}

pub fn run(
    store: Store,
    runtime: Arc<tokio::runtime::Runtime>,
    no_splash: bool,
    reuse_running: bool,
    check_updates: bool,
    update_ready: Option<PathBuf>,
) -> Result<()> {
    // Tray activation must work even when this helper has no display connection.
    if reuse_running && background::try_lease(&Store::new(store.sidecar(".ui"))?)?.is_none() {
        runtime.block_on(Client::new(&store).request("activate", Value::Null))?;
        return Ok(());
    }
    let completion = Arc::new(Mutex::new(Some(
        "Новая версия закрылась до подтверждения готовности.".to_string(),
    )));
    let result_state = completion.clone();
    let needs_ack = update_ready.is_some();
    eframe::run_native(
        "КРОТ",
        desktop::native_options(),
        Box::new(move |cc| {
            desktop::configure(&cc.egui_ctx, "dark");
            let (tx, rx) = mpsc::channel();
            let mut app = Launcher {
                store,
                runtime,
                no_splash,
                reuse_running,
                check_updates,
                update_ready,
                completion,
                phase: Phase::Checking,
                lease: None,
                tx,
                rx,
                replacing: false,
                owner: None,
            };
            app.start(false, &cc.egui_ctx);
            Ok(Box::new(app))
        }),
    )
    .map_err(|error| anyhow::anyhow!("Не удалось открыть окно КРОТа: {error}"))?;
    if needs_ack && let Some(error) = result_state.lock().unwrap().as_ref() {
        anyhow::bail!("{error}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn manual_start_requires_a_choice_for_either_owner() {
        for daemon in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let store = Store::new(temp.path().join("config.json")).unwrap();
            let owner = if daemon {
                store.clone()
            } else {
                Store::new(store.sidecar(".ui")).unwrap()
            };
            let lease = owner.lock().unwrap();
            assert!(matches!(
                prepare(&store, false).await.unwrap(),
                Startup::Conflict { .. }
            ));
            assert!(
                owner.lock().is_err(),
                "cancel must leave the previous owner alone"
            );
            assert!(!store.sidecar(".background.json").exists());
            drop(lease);
        }
    }

    #[tokio::test]
    async fn tray_reuses_window_while_manual_cancel_preserves_the_service() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let daemon = tokio::spawn(background::serve(store.clone()));
        let client = Client::new(&store);
        tokio::time::timeout(Duration::from_secs(3), async {
            while client.snapshot().await.is_err() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let window = Store::new(store.sidecar(".ui")).unwrap().lock().unwrap();
        assert!(matches!(
            prepare(&store, false).await.unwrap(),
            Startup::Conflict { .. }
        ));
        assert_eq!(client.snapshot().await.unwrap().activation, 0);
        assert!(store.lock().is_err(), "cancel did not shut down the daemon");
        assert!(matches!(
            prepare(&store, true).await.unwrap(),
            Startup::Activated
        ));
        assert_eq!(client.snapshot().await.unwrap().activation, 1);
        client.request("shutdown", Value::Null).await.unwrap();
        drop(window);
        daemon.await.unwrap().unwrap();
    }

    #[test]
    fn accepted_replacement_keeps_its_window_until_bootstrap_finishes() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
        );
        let (tx, rx) = mpsc::channel();
        let mut app = Launcher {
            store,
            runtime,
            no_splash: true,
            reuse_running: false,
            check_updates: false,
            update_ready: None,
            completion: Arc::new(Mutex::new(None)),
            phase: Phase::Checking,
            lease: None,
            tx,
            rx,
            replacing: true,
            owner: None,
        };
        let ctx = egui::Context::default();
        for replacing in [true, false] {
            app.replacing = replacing;
            let mut input = egui::RawInput::default();
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .unwrap()
                .events
                .push(egui::ViewportEvent::Close);
            let output = ctx.run(input, |ctx| app.guard_close(ctx));
            let cancelled = output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .iter()
                .any(|command| matches!(command, egui::ViewportCommand::CancelClose));
            assert_eq!(cancelled, replacing);
        }
    }
}
