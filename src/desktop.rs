//! Native dispatcher. SSH and IPC work is always dispatched off the window thread.
use crate::{
    background::{Client, Snapshot},
    config::{Endpoint, Store, Tunnel, atomic_json},
    ssh::PendingPrompt,
};
use eframe::egui::{self, Color32, FontFamily, FontId, Key, RichText, Stroke};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    io::Read,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

const FRAME_TIME: Duration = Duration::from_millis(180);
const POLL_TIME: Duration = Duration::from_millis(450);
const MAX_DESKTOP_PREFERENCES_BYTES: usize = 4096;
const CLOSE_PREFERENCE_ERROR: &str =
    "Не удалось запомнить выбор. Повторите попытку или нажмите «Назад».";
const SKIP_UPDATE_ERROR: &str =
    "Не удалось запомнить пропущенную версию. Повторите попытку или нажмите «Позже».";
const INK: Color32 = Color32::from_rgb(225, 232, 232);
const DIM: Color32 = Color32::from_rgb(152, 169, 174);
const CYAN: Color32 = Color32::from_rgb(139, 205, 227);
const GREEN: Color32 = Color32::from_rgb(172, 208, 148);
const AMBER: Color32 = Color32::from_rgb(227, 188, 124);
const RED: Color32 = Color32::from_rgb(255, 155, 145);

pub fn run(
    store: Store,
    client: Client,
    runtime: Arc<tokio::runtime::Runtime>,
    no_splash: bool,
) -> anyhow::Result<()> {
    eframe::run_native(
        "КРОТ",
        native_options(),
        Box::new(move |cc| Ok(build(store, client, runtime, no_splash, true, &cc.egui_ctx))),
    )
    .map_err(|error| anyhow::anyhow!("Не удалось открыть окно КРОТа: {error}"))
}

pub(crate) fn build(
    store: Store,
    client: Client,
    runtime: Arc<tokio::runtime::Runtime>,
    no_splash: bool,
    check_updates: bool,
    ctx: &egui::Context,
) -> Box<Desktop> {
    configure(ctx, "dark");
    let mut desktop = Desktop::new(
        Some(Backend {
            store,
            client,
            runtime,
        }),
        no_splash,
    );
    if check_updates {
        desktop.check_updates(ctx, false);
    }
    Box::new(desktop)
}

pub fn show_error(message: String) -> anyhow::Result<()> {
    struct ErrorWindow(String);
    impl eframe::App for ErrorWindow {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Не удалось запустить КРОТ");
                ui.add_space(12.0);
                ui.label(&self.0);
                ui.add_space(16.0);
                if ui.button("Закрыть").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        }
    }
    eframe::run_native(
        "КРОТ — ошибка запуска",
        native_options(),
        Box::new(move |cc| {
            configure(&cc.egui_ctx, "dark");
            Ok(Box::new(ErrorWindow(message)))
        }),
    )
    .map_err(|error| anyhow::anyhow!("Не удалось показать ошибку запуска: {error}"))
}

pub(crate) fn native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(crate::icons::app_icon())
            .with_inner_size([1000.0, 800.0])
            .with_min_inner_size([700.0, 500.0]),
        ..Default::default()
    }
}

pub(crate) fn configure(ctx: &egui::Context, theme: &str) {
    for (mode, mut visuals) in [
        (egui::Theme::Dark, egui::Visuals::dark()),
        (egui::Theme::Light, egui::Visuals::light()),
    ] {
        if mode == egui::Theme::Dark {
            visuals.panel_fill = Color32::from_rgb(21, 27, 30);
            visuals.window_fill = Color32::from_rgb(28, 38, 43);
            visuals.extreme_bg_color = Color32::from_rgb(16, 23, 26);
            visuals.override_text_color = Some(INK);
            visuals.widgets.noninteractive.bg_stroke =
                Stroke::new(1.0_f32, Color32::from_rgb(52, 68, 75));
            visuals.selection.bg_fill = Color32::from_rgb(38, 59, 66);
            visuals.selection.stroke = Stroke::new(1.0_f32, CYAN);
            visuals.hyperlink_color = CYAN;
            visuals.warn_fg_color = AMBER;
            visuals.error_fg_color = RED;
        } else {
            visuals.panel_fill = Color32::from_rgb(243, 242, 236);
            visuals.window_fill = Color32::from_rgb(223, 235, 235);
            visuals.override_text_color = Some(Color32::from_rgb(38, 53, 58));
            visuals.selection.bg_fill = Color32::from_rgb(201, 225, 227);
        }
        visuals.window_corner_radius = 2.into();
        for widget in [
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
        ] {
            widget.corner_radius = 1.into();
        }
        ctx.set_visuals_of(mode, visuals);
    }
    ctx.all_styles_mut(|style| {
        style.override_font_id = Some(FontId::new(14.0, FontFamily::Monospace));
        style.spacing.item_spacing = egui::vec2(10.0, 9.0);
        style.spacing.button_padding = egui::vec2(10.0, 7.0);
        style
            .text_styles
            .insert(egui::TextStyle::Heading, FontId::monospace(19.0));
    });
    ctx.set_theme(match theme {
        "light" => egui::ThemePreference::Light,
        "system" => egui::ThemePreference::System,
        _ => egui::ThemePreference::Dark,
    });
}

fn tone(ui: &egui::Ui, color: Color32) -> Color32 {
    if ui.visuals().dark_mode {
        color
    } else if color == GREEN {
        Color32::from_rgb(51, 101, 66)
    } else if color == AMBER {
        Color32::from_rgb(130, 89, 28)
    } else if color == RED {
        Color32::from_rgb(171, 52, 64)
    } else if color == CYAN {
        Color32::from_rgb(22, 102, 121)
    } else {
        ui.visuals().weak_text_color()
    }
}

fn mascot(state: &str, frame: usize) -> String {
    match state {
        "running" => {
            let legs = [
                "   __     __   \n  (__)   (__)  \n    \\ \\_/ /    ",
                "  __           \n (__)      __  \n   \\ \\___/(__) ",
                "   __     __   \n  (__)   (__)  \n    \\ \\_/ /    ",
                "           __  \n  __      (__) \n (__)\\___/ /   ",
            ];
            format!("{}\n    .\\___/.    \n   .-(   )-.   \n__(_________)__", legs[frame % 4])
        }
        "error" => "   ┌───────┐   \n   │ ERROR │   \n   └───┬───┘   \n       │       \n   .---│---.   \n__(_________)__".into(),
        "connecting" | "reconnecting" | "waiting" => "     _____     \n   _/_____\\_   \n  / [#]─[#] \\  \n  |   \\v/   |  \n   .-------.   \n__(_________)__".into(),
        _ => "               \n               \n               \n               \n   .-------.   \n__(_________)__".into(),
    }
}

fn state_label(state: &str) -> (&'static str, Color32) {
    match state {
        "running" => ("↟ Работает", GREEN),
        "connecting" => ("◷ Подключение…", AMBER),
        "reconnecting" => ("◷ Восстановление…", AMBER),
        "waiting" => ("! Нужно ваше участие", AMBER),
        "error" => ("! Ошибка", RED),
        "stopped" => ("○ Остановлен", DIM),
        _ => ("◌ Создан", DIM),
    }
}

fn active(state: &str) -> bool {
    matches!(state, "running" | "connecting" | "reconnecting")
}

#[derive(Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct DesktopPreferences {
    show_close_notice: bool,
}
impl Default for DesktopPreferences {
    fn default() -> Self {
        Self {
            show_close_notice: true,
        }
    }
}
impl DesktopPreferences {
    fn load(store: &Store) -> Self {
        let load = || -> anyhow::Result<Self> {
            let mut raw = Vec::new();
            std::fs::File::open(store.sidecar(".desktop.json"))?
                .take((MAX_DESKTOP_PREFERENCES_BYTES + 1) as u64)
                .read_to_end(&mut raw)?;
            anyhow::ensure!(
                raw.len() <= MAX_DESKTOP_PREFERENCES_BYTES,
                "Файл настроек окна слишком большой."
            );
            Ok(serde_json::from_slice(&raw)?)
        };
        load().unwrap_or_default()
    }
}

struct Backend {
    store: Store,
    client: Client,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[derive(Clone)]
enum Operation {
    Toggle(String),
    SaveForm(String),
    Delete,
    Settings,
    Answer,
    Shutdown,
}
enum Event {
    Snapshot(Result<Snapshot, String>),
    Complete(Operation, Result<(), String>),
    AutostartLoaded(Result<bool, String>),
    AutostartChanged(Result<bool, String>),
    ClosePreferenceSaved(Result<(), String>),
    UpdateChecked {
        manual: bool,
        result: Result<Option<crate::update::Release>, String>,
    },
    UpdateSkipped(Result<(), String>),
    UpdatePrepared(Result<crate::update::PreparedUpdate, String>),
    InstallerLaunched(Result<(), String>),
}

enum UpdateStage {
    Offer,
    Skipping,
    Preparing,
    Launching,
    Failed(String),
}
enum UpdateCheck {
    Idle,
    Checking,
    Current,
    Failed,
}
struct UpdateDialog {
    release: crate::update::Release,
    manual: bool,
    stage: UpdateStage,
    error: String,
}
impl UpdateDialog {
    fn busy(&self) -> bool {
        matches!(
            self.stage,
            UpdateStage::Skipping | UpdateStage::Preparing | UpdateStage::Launching
        )
    }
}

pub(crate) struct Desktop {
    backend: Option<Backend>,
    preferences: DesktopPreferences,
    tx: mpsc::Sender<Event>,
    rx: mpsc::Receiver<Event>,
    snapshot: Option<Snapshot>,
    last_activation: u64,
    selected: Option<String>,
    dialog: Option<Dialog>,
    confirm: Option<Confirm>,
    deferred: HashSet<String>,
    busy_tunnels: HashSet<String>,
    error: String,
    polling: bool,
    next_poll: Instant,
    started: Instant,
    no_splash: bool,
    initialized: bool,
    allow_close: bool,
    shutdown_busy: bool,
    applied_theme: String,
    pending_update: Option<(crate::update::Release, bool)>,
    update_check: UpdateCheck,
    update: Option<UpdateDialog>,
    pending_operations: usize,
}

enum Dialog {
    Form(Box<TunnelForm>),
    Settings(SettingsDraft),
    Prompt(Box<PromptDialog>),
    Logs(String),
    Help,
    Splash,
}
enum Confirm {
    Delete {
        id: String,
        name: String,
    },
    Discard {
        after: AfterDiscard,
    },
    Exit,
    CloseNotice {
        dont_show_again: bool,
        busy: bool,
        error: String,
    },
}

#[derive(Clone, Copy)]
enum AfterDiscard {
    CloseDialog,
    Exit,
    Background,
}

struct SettingsDraft {
    theme: String,
    motion: bool,
    splash: bool,
    autostart: Option<bool>,
    initial_autostart: Option<bool>,
    error: String,
    busy: bool,
}

struct PromptDialog {
    pending: PendingPrompt,
    secret: String,
    verified: bool,
}
impl Drop for PromptDialog {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
impl PromptDialog {
    fn new(pending: PendingPrompt) -> Self {
        Self {
            pending,
            secret: String::new(),
            verified: false,
        }
    }
    fn may_accept(&self) -> bool {
        match self.pending.request.kind.as_str() {
            "hostchanged" => self.verified,
            "password" | "passphrase" => !self.secret.is_empty(),
            _ => true,
        }
    }
    fn answer(&mut self) -> Value {
        if matches!(
            self.pending.request.kind.as_str(),
            "password" | "passphrase"
        ) {
            let value = Value::String(self.secret.clone());
            self.secret.zeroize();
            value
        } else {
            Value::Bool(true)
        }
    }
}

struct TunnelForm {
    draft: Tunnel,
    port: String,
    target_port: String,
    server_port: String,
    jump_ports: Vec<String>,
    original: Value,
    editing: bool,
    error: String,
    busy: bool,
}
impl TunnelForm {
    fn new(tunnel: Option<Tunnel>) -> Self {
        let editing = tunnel.is_some();
        let draft = tunnel.unwrap_or_default();
        let mut form = Self {
            port: draft.port.to_string(),
            target_port: draft.target_port.to_string(),
            server_port: draft.server.port.to_string(),
            jump_ports: draft
                .jumps
                .iter()
                .map(|endpoint| endpoint.port.to_string())
                .collect(),
            draft,
            original: Value::Null,
            editing,
            error: String::new(),
            busy: false,
        };
        form.original = form.signature();
        form
    }
    fn signature(&self) -> Value {
        json!([
            self.draft,
            self.port,
            self.target_port,
            self.server_port,
            self.jump_ports
        ])
    }
    fn dirty(&self) -> bool {
        self.original != self.signature()
    }
    fn candidate(&self, tunnels: &[Tunnel], paused: bool) -> anyhow::Result<Tunnel> {
        let mut tunnel = self.draft.clone();
        tunnel.name = tunnel.name.trim().into();
        tunnel.bind = tunnel.bind.trim().into();
        tunnel.target = tunnel.target.trim().into();
        tunnel.port = parse_port(&self.port, "Порт прослушивания")?;
        tunnel.target_port = if tunnel.kind == "D" {
            80
        } else {
            parse_port(&self.target_port, "Порт назначения")?
        };
        trim_endpoint(&mut tunnel.server);
        tunnel.server.port = parse_port(&self.server_port, "SSH-порт сервера")?;
        for (index, endpoint) in tunnel.jumps.iter_mut().enumerate() {
            trim_endpoint(endpoint);
            endpoint.port = parse_port(
                &self.jump_ports[index],
                &format!("SSH-порт jump-хоста {}", index + 1),
            )?;
        }
        if let Some(current) = tunnels.iter().find(|current| current.id == tunnel.id) {
            tunnel.enabled = current.enabled;
        }
        if paused {
            tunnel.enabled = false;
        }
        crate::config::validate_tunnel(&tunnel, tunnels)?;
        Ok(tunnel)
    }
    fn swap_jump(&mut self, index: usize, other: usize) {
        self.draft.jumps.swap(index, other);
        self.jump_ports.swap(index, other);
    }
}
fn trim_endpoint(endpoint: &mut Endpoint) {
    endpoint.host = endpoint.host.trim().into();
    endpoint.user = endpoint.user.trim().into();
    endpoint.key = endpoint.key.trim().into();
}
fn parse_port(value: &str, label: &str) -> anyhow::Result<u16> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| anyhow::anyhow!("{label}: укажите целое число от 1 до 65535."))
}

impl Desktop {
    pub(crate) fn initialized_for_update(&self) -> bool {
        self.initialized
            && self.snapshot.is_some()
            && !self.error.starts_with("Нет связи с фоновым")
    }

    fn new(backend: Option<Backend>, no_splash: bool) -> Self {
        let (tx, rx) = mpsc::channel();
        let preferences = backend
            .as_ref()
            .map(|backend| DesktopPreferences::load(&backend.store))
            .unwrap_or_default();
        Self {
            backend,
            preferences,
            tx,
            rx,
            snapshot: None,
            last_activation: 0,
            selected: None,
            dialog: None,
            confirm: None,
            deferred: HashSet::new(),
            busy_tunnels: HashSet::new(),
            error: String::new(),
            polling: false,
            next_poll: Instant::now(),
            started: Instant::now(),
            no_splash,
            initialized: false,
            allow_close: false,
            shutdown_busy: false,
            applied_theme: "dark".into(),
            pending_update: None,
            update_check: UpdateCheck::Idle,
            update: None,
            pending_operations: 0,
        }
    }
    fn check_updates(&mut self, ctx: &egui::Context, manual: bool) {
        if matches!(self.update_check, UpdateCheck::Checking) || self.update.is_some() {
            return;
        }
        let Some(backend) = &self.backend else {
            return;
        };
        self.update_check = UpdateCheck::Checking;
        if manual {
            self.pending_update = None;
        }
        let (store, tx, ctx) = (backend.store.clone(), self.tx.clone(), ctx.clone());
        backend.runtime.spawn(async move {
            let result = crate::update::check(&store, manual)
                .await
                .map_err(|error| error.to_string());
            let _ = tx.send(Event::UpdateChecked { manual, result });
            ctx.request_repaint();
        });
    }
    fn poll(&mut self, ctx: &egui::Context) {
        if self.polling || Instant::now() < self.next_poll {
            return;
        }
        let Some(backend) = &self.backend else {
            return;
        };
        self.polling = true;
        let (client, tx, ctx) = (backend.client.clone(), self.tx.clone(), ctx.clone());
        backend.runtime.spawn(async move {
            let result = client.snapshot().await.map_err(|_| "Нет связи с фоновым КРОТом. Повторяем подключение; последнее состояние сохранено на экране.".into());
            let _ = tx.send(Event::Snapshot(result));
            ctx.request_repaint();
        });
    }
    fn request(
        &mut self,
        ctx: &egui::Context,
        operation: Operation,
        command: &'static str,
        payload: Value,
    ) {
        let Some(backend) = &self.backend else {
            return;
        };
        self.pending_operations += 1;
        let (client, tx, ctx) = (backend.client.clone(), self.tx.clone(), ctx.clone());
        backend.runtime.spawn(async move {
            let result = client
                .request(command, payload)
                .await
                .map(|_| ())
                .map_err(|error| {
                    if matches!(operation, Operation::Answer) {
                        "Не удалось передать ответ. Откройте запрос туннеля и повторите ввод."
                            .into()
                    } else {
                        format!("Действие не выполнено: {error}")
                    }
                });
            let _ = tx.send(Event::Complete(operation, result));
            ctx.request_repaint();
        });
    }
    fn drain(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::UpdateChecked { manual, result } => {
                    self.update_check = UpdateCheck::Idle;
                    match result {
                        Ok(Some(release)) => {
                            self.pending_update = Some((release, manual));
                            if manual && matches!(self.dialog, Some(Dialog::Help)) {
                                self.dialog = None;
                            }
                        }
                        Ok(None) if manual => self.update_check = UpdateCheck::Current,
                        Err(_) if manual => self.update_check = UpdateCheck::Failed,
                        _ => {}
                    }
                }
                Event::UpdateSkipped(result) => {
                    if result.is_ok() {
                        self.update = None;
                    } else if let Some(update) = &mut self.update {
                        update.stage = UpdateStage::Offer;
                        update.error = SKIP_UPDATE_ERROR.into();
                    }
                }
                Event::UpdatePrepared(result) => match result {
                    Ok(prepared) => {
                        if let Some(update) = &mut self.update {
                            update.stage = UpdateStage::Launching;
                        }
                        if let Some(backend) = &self.backend {
                            let (tx, ctx) = (self.tx.clone(), ctx.clone());
                            backend.runtime.spawn_blocking(move || {
                                let result = crate::update::launch_installer(prepared)
                                    .map_err(|error| error.to_string());
                                let _ = tx.send(Event::InstallerLaunched(result));
                                ctx.request_repaint();
                            });
                        }
                    }
                    Err(error) => self.update_failed("Не удалось подготовить обновление.", error),
                },
                Event::InstallerLaunched(result) => match result {
                    Ok(()) => self.close_window(ctx),
                    Err(error) => self.update_failed("Не удалось запустить установщик.", error),
                },
                Event::Snapshot(result) => {
                    self.polling = false;
                    self.next_poll = Instant::now() + POLL_TIME;
                    match result {
                        Ok(snapshot) => {
                            if snapshot.activation != self.last_activation {
                                self.last_activation = snapshot.activation;
                                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                            }
                            if self.selected.as_ref().is_none_or(|id| {
                                !snapshot.config.tunnels.iter().any(|t| &t.id == id)
                            }) {
                                self.selected =
                                    snapshot.config.tunnels.first().map(|t| t.id.clone());
                            }
                            self.deferred.retain(|id| {
                                snapshot.prompts.values().any(|prompt| &prompt.id == id)
                            });
                            if !self.initialized {
                                self.initialized = true;
                                if snapshot.config.settings.splash && !self.no_splash {
                                    self.dialog = Some(Dialog::Splash);
                                }
                            }
                            if self.applied_theme != snapshot.config.settings.theme {
                                self.applied_theme
                                    .clone_from(&snapshot.config.settings.theme);
                                configure(ctx, &self.applied_theme);
                            }
                            if self.error.starts_with("Нет связи с фоновым") {
                                self.error.clear();
                            }
                            if let Some(Dialog::Prompt(prompt)) = &self.dialog
                                && !snapshot
                                    .prompts
                                    .values()
                                    .any(|pending| pending.id == prompt.pending.id)
                            {
                                self.dialog = None;
                            }
                            self.snapshot = Some(snapshot);
                        }
                        Err(error) => {
                            if self.snapshot.is_some()
                                && !self.update.as_ref().is_some_and(UpdateDialog::busy)
                                && !matches!(&self.confirm, Some(Confirm::CloseNotice { busy, error, .. }) if *busy || !error.is_empty())
                                && self.backend.as_ref().is_some_and(|backend| {
                                    matches!(
                                        backend.store.sidecar(".background.json").try_exists(),
                                        Ok(false)
                                    )
                                })
                            {
                                self.allow_close = true;
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            } else {
                                self.error = error;
                            }
                        }
                    }
                }
                Event::Complete(operation, result) => {
                    self.pending_operations = self.pending_operations.saturating_sub(1);
                    if let Operation::Toggle(id) = &operation {
                        self.busy_tunnels.remove(id);
                    }
                    if matches!(operation, Operation::SaveForm(_))
                        && let Some(Dialog::Form(form)) = &mut self.dialog
                    {
                        form.busy = false;
                    }
                    if matches!(operation, Operation::Settings)
                        && let Some(Dialog::Settings(settings)) = &mut self.dialog
                    {
                        settings.busy = false;
                    }
                    match result {
                        Err(error) => {
                            match &mut self.dialog {
                                Some(Dialog::Form(form))
                                    if matches!(operation, Operation::SaveForm(_)) =>
                                {
                                    form.error = error
                                }
                                Some(Dialog::Settings(settings))
                                    if matches!(operation, Operation::Settings) =>
                                {
                                    settings.error = error
                                }
                                _ => self.error = error,
                            }
                            self.shutdown_busy = false;
                        }
                        Ok(()) => {
                            self.error.clear();
                            match operation {
                                Operation::SaveForm(id) => {
                                    self.selected = Some(id);
                                    self.dialog = None;
                                }
                                Operation::Delete => {
                                    self.confirm = None;
                                }
                                Operation::Settings => {
                                    self.finish_settings(ctx);
                                }
                                Operation::Shutdown => {
                                    self.allow_close = true;
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                }
                                _ => {}
                            }
                        }
                    }
                    self.next_poll = Instant::now();
                }
                Event::AutostartLoaded(result) => {
                    if let Some(Dialog::Settings(settings)) = &mut self.dialog {
                        match result {
                            Ok(enabled) => {
                                settings.autostart = Some(enabled);
                                settings.initial_autostart = Some(enabled);
                            }
                            Err(error) => settings.error = error,
                        }
                    }
                }
                Event::ClosePreferenceSaved(result) => {
                    if let Some(Confirm::CloseNotice { busy, error, .. }) = &mut self.confirm {
                        *busy = false;
                        match result {
                            Ok(()) => {
                                self.preferences.show_close_notice = false;
                                self.close_window(ctx);
                            }
                            Err(message) => *error = message,
                        }
                    }
                }
                Event::AutostartChanged(result) => {
                    if let Some(Dialog::Settings(settings)) = &mut self.dialog {
                        settings.busy = false;
                        match result {
                            Ok(_) => self.dialog = None,
                            Err(error) => settings.error = error,
                        }
                    }
                }
            }
        }
    }
    fn state<'a>(&'a self, tunnel: &'a Tunnel) -> &'a str {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.prompts.contains_key(&tunnel.id))
        {
            "waiting"
        } else {
            self.snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.runtimes.get(&tunnel.id))
                .map(|runtime| runtime.state.as_str())
                .unwrap_or("idle")
        }
    }
    fn frame(&self) -> usize {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.config.settings.motion)
        {
            (self.started.elapsed().as_millis() / FRAME_TIME.as_millis()) as usize % 4
        } else {
            0
        }
    }
    fn selected_tunnel(&self) -> Option<Tunnel> {
        self.snapshot
            .as_ref()?
            .config
            .tunnels
            .iter()
            .find(|tunnel| Some(&tunnel.id) == self.selected.as_ref())
            .cloned()
    }
    fn toggle(&mut self, ctx: &egui::Context, tunnel: &Tunnel) {
        if self.busy_tunnels.contains(&tunnel.id) {
            return;
        }
        let stop = active(self.state(tunnel)) || self.state(tunnel) == "waiting";
        self.busy_tunnels.insert(tunnel.id.clone());
        self.request(
            ctx,
            Operation::Toggle(tunnel.id.clone()),
            if stop { "stop" } else { "start" },
            json!(tunnel.id),
        );
    }
    fn resolve(&mut self, tunnel: &Tunnel) {
        if let Some(pending) = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.prompts.get(&tunnel.id))
            .cloned()
        {
            self.deferred.insert(pending.id.clone());
            self.dialog = Some(Dialog::Prompt(Box::new(PromptDialog::new(pending))));
        }
    }
    fn open_settings(&mut self, ctx: &egui::Context) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let settings = &snapshot.config.settings;
        self.dialog = Some(Dialog::Settings(SettingsDraft {
            theme: settings.theme.clone(),
            motion: settings.motion,
            splash: settings.splash,
            autostart: None,
            initial_autostart: None,
            error: String::new(),
            busy: false,
        }));
        let Some(backend) = &self.backend else {
            return;
        };
        let (path, tx, ctx) = (backend.store.path.clone(), self.tx.clone(), ctx.clone());
        backend.runtime.spawn_blocking(move || {
            let result = crate::autostart::is_enabled(&path)
                .map_err(|error| format!("Не удалось проверить автозапуск: {error}"));
            let _ = tx.send(Event::AutostartLoaded(result));
            ctx.request_repaint();
        });
    }
    fn finish_settings(&mut self, ctx: &egui::Context) {
        let Some(Dialog::Settings(settings)) = &mut self.dialog else {
            return;
        };
        if settings.autostart == settings.initial_autostart {
            self.dialog = None;
            return;
        }
        let Some(enabled) = settings.autostart else {
            self.dialog = None;
            return;
        };
        settings.busy = true;
        let Some(backend) = &self.backend else {
            return;
        };
        let (path, tx, ctx) = (backend.store.path.clone(), self.tx.clone(), ctx.clone());
        backend.runtime.spawn_blocking(move || {
            let result = crate::autostart::set_enabled(&path, enabled)
                .map(|_| enabled)
                .map_err(|error| format!("Настройки сохранены. Автозапуск не изменён: {error}"));
            let _ = tx.send(Event::AutostartChanged(result));
            ctx.request_repaint();
        });
    }
    fn close_busy(&self) -> bool {
        self.shutdown_busy
            || self.update.as_ref().is_some_and(UpdateDialog::busy)
            || matches!(&self.dialog, Some(Dialog::Form(form)) if form.busy)
            || matches!(&self.dialog, Some(Dialog::Settings(settings)) if settings.busy)
    }
    fn request_exit(&mut self) {
        if self.close_busy() || self.confirm.is_some() {
            return;
        }
        self.confirm = Some(
            if matches!(&self.dialog, Some(Dialog::Form(form)) if form.dirty()) {
                Confirm::Discard {
                    after: AfterDiscard::Exit,
                }
            } else {
                Confirm::Exit
            },
        );
    }
    fn request_background(&mut self, ctx: &egui::Context) {
        if self.close_busy() || self.confirm.is_some() {
            return;
        }
        if matches!(&self.dialog, Some(Dialog::Form(form)) if form.dirty()) {
            self.confirm = Some(Confirm::Discard {
                after: AfterDiscard::Background,
            });
        } else {
            self.leave_background(ctx);
        }
    }
    fn leave_background(&mut self, ctx: &egui::Context) {
        if self.preferences.show_close_notice {
            self.confirm = Some(Confirm::CloseNotice {
                dont_show_again: false,
                busy: false,
                error: String::new(),
            });
        } else {
            self.close_window(ctx);
        }
    }
    fn close_window(&mut self, ctx: &egui::Context) {
        self.dialog = None;
        self.confirm = None;
        self.allow_close = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }
    fn save_close_preference(&mut self, ctx: &egui::Context) {
        let Some(backend) = &self.backend else {
            self.confirm = Some(Confirm::CloseNotice {
                dont_show_again: true,
                busy: false,
                error: CLOSE_PREFERENCE_ERROR.into(),
            });
            return;
        };
        self.confirm = Some(Confirm::CloseNotice {
            dont_show_again: true,
            busy: true,
            error: String::new(),
        });
        let (path, tx, ctx) = (
            backend.store.sidecar(".desktop.json"),
            self.tx.clone(),
            ctx.clone(),
        );
        backend.runtime.spawn_blocking(move || {
            let result = atomic_json(
                &path,
                &DesktopPreferences {
                    show_close_notice: false,
                },
                Some(MAX_DESKTOP_PREFERENCES_BYTES),
            )
            .map_err(|_| CLOSE_PREFERENCE_ERROR.into());
            let _ = tx.send(Event::ClosePreferenceSaved(result));
            ctx.request_repaint();
        });
    }
    fn move_selection(&mut self, delta: isize) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        if snapshot.config.tunnels.is_empty() {
            return;
        }
        let index = snapshot
            .config
            .tunnels
            .iter()
            .position(|t| Some(&t.id) == self.selected.as_ref())
            .unwrap_or(0);
        let next = index
            .saturating_add_signed(delta)
            .min(snapshot.config.tunnels.len() - 1);
        self.selected = Some(snapshot.config.tunnels[next].id.clone());
    }
    fn shortcuts(&mut self, ctx: &egui::Context) {
        if self.confirm.is_some() || self.dialog.is_some() || self.update.is_some() {
            return;
        }
        let pressed = |key| ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, key));
        if pressed(Key::ArrowDown) {
            self.move_selection(1);
        }
        if pressed(Key::ArrowUp) {
            self.move_selection(-1);
        }
        if pressed(Key::Q) {
            self.request_exit();
        }
        if pressed(Key::N) && self.snapshot.is_some() {
            self.dialog = Some(Dialog::Form(Box::new(TunnelForm::new(None))));
        }
        if pressed(Key::S) {
            self.open_settings(ctx);
        }
        if pressed(Key::F1) || ctx.input_mut(|i| i.consume_key(egui::Modifiers::SHIFT, Key::Slash))
        {
            self.dialog = Some(Dialog::Help);
        }
        if let Some(tunnel) = self.selected_tunnel() {
            if pressed(Key::Space) {
                self.toggle(ctx, &tunnel);
            }
            if pressed(Key::Enter) {
                self.resolve(&tunnel);
            }
            if pressed(Key::E) {
                self.dialog = Some(Dialog::Form(Box::new(TunnelForm::new(Some(
                    tunnel.clone(),
                )))));
            }
            if pressed(Key::L) {
                self.dialog = Some(Dialog::Logs(tunnel.id.clone()));
            }
            if pressed(Key::Delete) {
                self.confirm = Some(Confirm::Delete {
                    id: tunnel.id,
                    name: tunnel.name,
                });
            }
        }
    }
    fn main_view(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("КРОТ / ДИСПЕТЧЕРСКАЯ").color(tone(ui, CYAN)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak(format!("v{}", env!("CARGO_PKG_VERSION")));
                });
            });
            ui.add_space(5.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        self.snapshot.is_some(),
                        egui::Button::new("N Новый туннель"),
                    )
                    .clicked()
                {
                    self.dialog = Some(Dialog::Form(Box::new(TunnelForm::new(None))));
                }
                if ui
                    .add_enabled(self.snapshot.is_some(), egui::Button::new("S Настройки"))
                    .clicked()
                {
                    self.open_settings(ctx);
                }
                if ui.button("? Справка").clicked() {
                    self.dialog = Some(Dialog::Help);
                }
                if ui.button("Q Выход").clicked() {
                    self.request_exit();
                }
            });
            ui.add_space(5.0);
        });
        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            let (running, waiting, total) = self
                .snapshot
                .as_ref()
                .map(|snapshot| {
                    (
                        snapshot
                            .runtimes
                            .values()
                            .filter(|runtime| runtime.state == "running")
                            .count(),
                        snapshot.prompts.len(),
                        snapshot.config.tunnels.len(),
                    )
                })
                .unwrap_or_default();
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(tone(ui, GREEN), format!("● Работают {running} из {total}"));
                if waiting > 0 {
                    ui.colored_label(tone(ui, AMBER), format!("Ждут участия: {waiting}"));
                }
                ui.weak("↑ ↓ Выбор   Space Пуск / стоп   Enter Запрос   L Журнал");
            });
            if !self.error.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(tone(ui, RED), &self.error);
                    if ui.small_button("Скрыть").clicked() {
                        self.error.clear();
                    }
                });
            }
        });
        let tunnels = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.config.tunnels.clone())
            .unwrap_or_default();
        egui::SidePanel::left("tunnels")
            .default_width(280.0)
            .min_width(210.0)
            .max_width(400.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.weak("Мои туннели");
                ui.add_space(5.0);
                egui::ScrollArea::vertical()
                    .id_salt("tunnel_scroll")
                    .show(ui, |ui| {
                        if tunnels.is_empty() {
                            ui.add_space(20.0);
                            ui.label(mascot("idle", 0));
                            ui.weak(if self.snapshot.is_some() {
                                "Здесь начнётся первый туннель.\nN — добавить подключение."
                            } else {
                                "Подключаемся к фоновому КРОТу…"
                            });
                        }
                        for tunnel in &tunnels {
                            let state = self.state(tunnel);
                            let (label, color) = state_label(state);
                            let text = format!(
                                "{}\n{}\n{} · {}:{}",
                                tunnel.name, label, tunnel.kind, tunnel.bind, tunnel.port
                            );
                            let button =
                                egui::Button::new(RichText::new(text).color(tone(ui, color)))
                                    .selected(self.selected.as_ref() == Some(&tunnel.id))
                                    .wrap();
                            let response = ui.add_sized([ui.available_width(), 80.0], button);
                            if response.clicked() {
                                self.selected = Some(tunnel.id.clone());
                            }
                            if response.double_clicked() {
                                self.selected = Some(tunnel.id.clone());
                                self.resolve(tunnel);
                            }
                        }
                    });
            });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            egui::ScrollArea::vertical()
                .id_salt("detail_scroll")
                .show(ui, |ui| {
                    if let Some(tunnel) = self.selected_tunnel() {
                        self.detail(ui, ctx, &tunnel);
                    } else {
                        ui.heading("На участке");
                        ui.add_space(24.0);
                        ui.label(RichText::new(mascot("idle", 0)).color(tone(ui, DIM)));
                        ui.add_space(16.0);
                        ui.label("Создайте туннель, чтобы открыть проход к нужному сервису.");
                        ui.weak("L — локальный порт, R — обратный, D — SOCKS5.");
                    }
                });
        });
    }
    fn detail(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, tunnel: &Tunnel) {
        let state = self.state(tunnel).to_owned();
        let (label, color) = state_label(&state);
        let runtime = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.runtimes.get(&tunnel.id))
            .cloned();
        ui.heading(&tunnel.name);
        ui.colored_label(tone(ui, color), label);
        ui.add_space(14.0);
        ui.label(
            RichText::new(mascot(&state, self.frame()))
                .monospace()
                .size(16.0)
                .color(tone(ui, color)),
        );
        ui.add_space(16.0);
        ui.colored_label(tone(ui, CYAN), tunnel.route());
        ui.weak(match tunnel.kind.as_str() {
            "R" => "Порт на SSH-сервере → сервис на вашем устройстве",
            "D" => "Локальный SOCKS5-прокси → сеть SSH-сервера",
            _ => "Локальный порт → сервис со стороны SSH-сервера",
        });
        ui.separator();
        ui.label(format!("SSH-узел: {}", tunnel.server.address()));
        ui.label(format!("Вход: {}", auth_label(&tunnel.server.auth)));
        if tunnel.server.auth == "key" {
            ui.weak(&tunnel.server.key);
        }
        if tunnel.jumps_enabled {
            for (index, jump) in tunnel.jumps.iter().enumerate() {
                ui.label(format!(
                    "Через {}: {} · {}",
                    index + 1,
                    jump.address(),
                    auth_label(&jump.auth)
                ));
            }
        }
        ui.weak(if tunnel.enabled {
            "При следующем запуске: восстановить туннель"
        } else {
            "При следующем запуске: оставить выключенным"
        });
        ui.weak(if tunnel.reconnect {
            "После разрыва: подключиться снова"
        } else {
            "После разрыва: ждать ручного запуска"
        });
        if let Some(runtime) = runtime {
            if !runtime.hop.is_empty() && active(&state) {
                ui.weak(&runtime.hop);
            }
            if !runtime.message.is_empty() {
                ui.colored_label(tone(ui, color), &runtime.message);
            }
        }
        if let Some(pending) = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.prompts.get(&tunnel.id))
        {
            ui.separator();
            ui.colored_label(tone(ui, AMBER), prompt_title(&pending.request.kind));
            ui.weak(format!(
                "{} · {}",
                pending.request.hop,
                pending.request.endpoint.address()
            ));
            ui.weak("Остальные туннели продолжают работать.");
        }
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            let action = match state.as_str() {
                "running" => "Остановить",
                "connecting" | "reconnecting" => "Отменить подключение",
                "waiting" => "Разобраться",
                "error" => "Повторить",
                _ => "Запустить",
            };
            if ui
                .add_enabled(
                    !self.busy_tunnels.contains(&tunnel.id),
                    egui::Button::new(RichText::new(action).color(tone(ui, CYAN))),
                )
                .clicked()
            {
                if state == "waiting" {
                    self.resolve(tunnel);
                } else {
                    self.toggle(ctx, tunnel);
                }
            }
            if state == "waiting" && ui.button("Выключить").clicked() {
                self.toggle(ctx, tunnel);
            }
            if ui.button("L Журнал").clicked() {
                self.dialog = Some(Dialog::Logs(tunnel.id.clone()));
            }
            if ui.button("E Изменить").clicked() {
                self.dialog = Some(Dialog::Form(Box::new(TunnelForm::new(Some(
                    tunnel.clone(),
                )))));
            }
            if ui
                .button(RichText::new("Удалить").color(tone(ui, RED)))
                .clicked()
            {
                self.confirm = Some(Confirm::Delete {
                    id: tunnel.id.clone(),
                    name: tunnel.name.clone(),
                });
            }
        });
    }
    fn dialog_view(&mut self, ctx: &egui::Context) {
        let Some(mut dialog) = self.dialog.take() else {
            return;
        };
        let max_height = (ctx.content_rect().height() - 140.0).max(180.0);
        let width = (ctx.content_rect().width() - 90.0).min(660.0);
        let mut action = DialogAction::None;
        let response = egui::Modal::new(egui::Id::new("dialog")).show(ctx, |ui| {
            ui.set_width(width);
            match &mut dialog {
                Dialog::Form(form) => { action = form_view(ui, form, max_height); }
                Dialog::Settings(settings) => {
                    ui.heading("Настройки");
                    if settings.busy { ui.disable(); }
                    egui::ComboBox::from_id_salt("theme").selected_text(theme_label(&settings.theme)).show_ui(ui, |ui| {
                        for (value, label) in [("dark", "Тёмное"), ("light", "Светлое"), ("system", "Системное")] {
                            ui.selectable_value(&mut settings.theme, value.into(), label);
                        }
                    });
                    ui.checkbox(&mut settings.motion, "Анимация кротов");
                    ui.checkbox(&mut settings.splash, "Заставка при запуске");
                    if let Some(enabled) = &mut settings.autostart {
                        ui.checkbox(enabled, "Запускать КРОТ в фоне после входа в систему");
                    } else {
                        ui.add_enabled(false, egui::Checkbox::new(&mut false, if settings.error.is_empty() { "Автозапуск: проверяем состояние…" } else { "Автозапуск недоступен" }));
                    }
                    if !settings.error.is_empty() { ui.colored_label(tone(ui, RED), &settings.error); }
                    ui.separator();
                    ui.horizontal_wrapped(|ui| {
                        if ui.add_enabled(!settings.busy, egui::Button::new("Отмена")).clicked() { action = DialogAction::Close; }
                        if ui.add_enabled(!settings.busy, egui::Button::new("Сохранить")).clicked() { action = DialogAction::SaveSettings; }
                    });
                }
                Dialog::Prompt(prompt) => {
                    let request = prompt.pending.request.clone();
                    ui.heading(prompt_title(&request.kind));
                    egui::ScrollArea::vertical().max_height(max_height).show(ui, |ui| {
                        ui.label(&request.tunnel_name);
                        ui.weak(&request.hop);
                        ui.label(request.endpoint.address());
                        if !request.message.is_empty() { ui.label(&request.message); }
                        match request.kind.as_str() {
                            "trust" | "hostchanged" => {
                                if request.kind == "hostchanged" {
                                    ui.label("Сохранённый ключ:");
                                    ui.colored_label(tone(ui, AMBER), &request.old_fingerprint);
                                }
                                ui.label("Полученный ключ:");
                                ui.colored_label(tone(ui, AMBER), &request.new_fingerprint);
                                ui.weak("Сверьте отпечаток с администратором по независимому каналу.");
                                if request.kind == "hostchanged" { ui.checkbox(&mut prompt.verified, "Я проверил новый отпечаток"); }
                            }
                            _ => {
                                ui.label(if request.kind == "passphrase" { "Пароль ключа" } else { "Пароль SSH" });
                                let mut edit = egui::TextEdit::singleline(&mut prompt.secret).password(true).desired_width(f32::INFINITY).show(ui);
                                // Passwords must not remain in the widget's undo history.
                                edit.state.clear_undoer();
                                edit.state.store(ctx, edit.response.id);
                                if !edit.response.has_focus() && ui.memory(|memory| memory.focused().is_none()) { edit.response.request_focus(); }
                                ui.weak("Секрет используется для подключения и не сохраняется.");
                                if (edit.response.has_focus() || edit.response.lost_focus()) && ctx.input(|input| input.key_pressed(Key::Enter)) && prompt.may_accept() {
                                    action = DialogAction::Answer;
                                }
                            }
                        }
                    });
                    ui.separator();
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Позже").clicked() { action = DialogAction::Close; }
                        if ui.button("Отменить подключение").clicked() { action = DialogAction::CancelPrompt; }
                        let accept = if prompt.pending.request.kind == "hostchanged" { "Заменить ключ и подключиться" } else { "Продолжить" };
                        if ui.add_enabled(prompt.may_accept(), egui::Button::new(accept)).clicked() { action = DialogAction::Answer; }
                    });
                }
                Dialog::Logs(id) => {
                    let tunnel = self.snapshot.as_ref().and_then(|snapshot| snapshot.config.tunnels.iter().find(|t| &t.id == id));
                    ui.heading(format!("Журнал · {}", tunnel.map(|t| t.name.as_str()).unwrap_or("туннель")));
                    egui::ScrollArea::vertical().stick_to_bottom(true).max_height(max_height).show(ui, |ui| {
                        if let Some(runtime) = self.snapshot.as_ref().and_then(|snapshot| snapshot.runtimes.get(id)) {
                            if runtime.logs.is_empty() { ui.weak("Журнал пока пуст."); }
                            for line in &runtime.logs { ui.label(line); }
                        } else { ui.weak("Журнал пока пуст."); }
                    });
                    if ui.button("Назад").clicked() { action = DialogAction::Close; }
                }
                Dialog::Help => {
                    ui.heading("Справка");
                    egui::ScrollArea::vertical().max_height((max_height - 100.0).max(80.0)).show(ui, |ui| { ui.label(HELP); });
                    ui.separator();
                    ui.horizontal_wrapped(|ui| {
                        if ui.add_enabled(!matches!(self.update_check, UpdateCheck::Checking), egui::Button::new("Проверить обновление")).clicked() {
                            action = DialogAction::CheckUpdates;
                        }
                        if matches!(self.update_check, UpdateCheck::Checking) {
                            ui.spinner();
                            ui.label("Проверяем обновления…");
                        }
                    });
                    match self.update_check {
                        UpdateCheck::Current => { ui.label("Обновлений нет."); }
                        UpdateCheck::Failed => { ui.colored_label(tone(ui, RED), "Не удалось проверить обновления. Проверьте подключение к сети и повторите попытку."); }
                        _ => {}
                    }
                    if ui.button("Назад").clicked() { action = DialogAction::Close; }
                }
                Dialog::Splash => { action = self.splash_view(ui, max_height); }
            }
        });
        let blocked = self.confirm.is_some()
            || matches!(&dialog, Dialog::Form(form) if form.busy)
            || matches!(&dialog, Dialog::Settings(settings) if settings.busy);
        if response.should_close() && !blocked {
            action = DialogAction::Close;
        }
        if !blocked
            && matches!(&dialog, Dialog::Form(_) | Dialog::Settings(_))
            && ctx.input_mut(|input| {
                input.consume_key(egui::Modifiers::CTRL, Key::S)
                    || input.consume_key(egui::Modifiers::CTRL, Key::Enter)
            })
        {
            action = if matches!(&dialog, Dialog::Form(_)) {
                DialogAction::SaveForm(false)
            } else {
                DialogAction::SaveSettings
            };
        }
        match action {
            DialogAction::None => self.dialog = Some(dialog),
            DialogAction::CheckUpdates => {
                self.dialog = Some(dialog);
                self.check_updates(ctx, true);
            }
            DialogAction::Close => {
                if matches!(&dialog, Dialog::Form(form) if form.dirty()) {
                    self.confirm = Some(Confirm::Discard {
                        after: AfterDiscard::CloseDialog,
                    });
                    self.dialog = Some(dialog);
                }
            }
            DialogAction::SaveForm(paused) => {
                if let (Dialog::Form(form), Some(snapshot)) = (&mut dialog, &self.snapshot) {
                    match form.candidate(&snapshot.config.tunnels, paused) {
                        Err(error) => form.error = error.to_string(),
                        Ok(tunnel) => {
                            let mut config = snapshot.config.clone();
                            config.tunnels.retain(|existing| existing.id != tunnel.id);
                            if form.editing {
                                let index = snapshot
                                    .config
                                    .tunnels
                                    .iter()
                                    .position(|existing| existing.id == tunnel.id)
                                    .unwrap_or(config.tunnels.len());
                                config
                                    .tunnels
                                    .insert(index.min(config.tunnels.len()), tunnel.clone());
                            } else {
                                config.tunnels.push(tunnel.clone());
                            }
                            form.busy = true;
                            form.error.clear();
                            self.request(
                                ctx,
                                Operation::SaveForm(tunnel.id),
                                "save_checked",
                                json!({"before": snapshot.config, "config": config}),
                            );
                        }
                    }
                }
                self.dialog = Some(dialog);
            }
            DialogAction::SaveSettings => {
                if let (Dialog::Settings(settings), Some(snapshot)) = (&mut dialog, &self.snapshot)
                {
                    let mut config = snapshot.config.clone();
                    config.settings.theme.clone_from(&settings.theme);
                    config.settings.motion = settings.motion;
                    config.settings.splash = settings.splash;
                    settings.busy = true;
                    settings.error.clear();
                    self.request(
                        ctx,
                        Operation::Settings,
                        "save_checked",
                        json!({"before": snapshot.config, "config": config}),
                    );
                }
                self.dialog = Some(dialog);
            }
            DialogAction::Answer | DialogAction::CancelPrompt => {
                if let Dialog::Prompt(prompt) = &mut dialog {
                    let value = if matches!(action, DialogAction::Answer) {
                        prompt.answer()
                    } else {
                        Value::Null
                    };
                    let mut payload = json!({"id": prompt.pending.id});
                    payload
                        .as_object_mut()
                        .expect("answer is an object")
                        .insert("value".into(), value);
                    self.request(ctx, Operation::Answer, "answer", payload);
                }
            }
            DialogAction::Resolve(id) => {
                if let Some(tunnel) = self
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.config.tunnels.iter().find(|t| t.id == id))
                    .cloned()
                {
                    if self.state(&tunnel) == "waiting" {
                        self.resolve(&tunnel);
                    } else {
                        self.toggle(ctx, &tunnel);
                        self.dialog = Some(dialog);
                    }
                }
            }
            DialogAction::Exit => {
                self.dialog = Some(dialog);
                self.request_exit();
            }
        }
    }
    fn splash_view(&mut self, ui: &mut egui::Ui, max_height: f32) -> DialogAction {
        if ui
            .ctx()
            .input_mut(|input| input.consume_key(egui::Modifiers::NONE, Key::ArrowDown))
        {
            self.move_selection(1);
        }
        if ui
            .ctx()
            .input_mut(|input| input.consume_key(egui::Modifiers::NONE, Key::ArrowUp))
        {
            self.move_selection(-1);
        }
        let mut action = DialogAction::None;
        ui.heading("КРОТ / ВОССТАНОВЛЕНИЕ");
        let tunnels = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.config.tunnels.clone())
            .unwrap_or_default();
        let enabled: Vec<_> = tunnels.iter().filter(|tunnel| tunnel.enabled).collect();
        let running = enabled
            .iter()
            .filter(|tunnel| self.state(tunnel) == "running")
            .count();
        let waiting = enabled
            .iter()
            .filter(|tunnel| self.state(tunnel) == "waiting")
            .count();
        let errors = enabled
            .iter()
            .filter(|tunnel| self.state(tunnel) == "error")
            .count();
        let busy = enabled
            .iter()
            .any(|tunnel| matches!(self.state(tunnel), "connecting" | "reconnecting"));
        let title = if enabled.is_empty() {
            "Сегодня без раскопок"
        } else if busy {
            "Возвращаем туннели в строй"
        } else if waiting + errors > 0 {
            "Часть проходов ждёт вас"
        } else {
            "Все проходы на месте"
        };
        ui.label(title);
        let art = format!(
            "         _______\n      __/__[{eye}]__\\__\n    _/_____________\\_\n   /    [#]---[#]    \\\n  /      \\     /      \\\n  |  \\====\\   /====/  |\n   \\      \\_v_/      /\n    `----._____.----'",
            eye = if self.frame() == 0 { "*" } else { "o" }
        );
        ui.label(
            RichText::new(art).color(tone(ui, if waiting + errors > 0 { AMBER } else { GREEN })),
        );
        ui.label(format!(
            "{} из {} работают · {} ждут вас · {} с ошибкой",
            running,
            enabled.len(),
            waiting,
            errors
        ));
        let completed = running + waiting + errors;
        ui.add(
            egui::ProgressBar::new(if enabled.is_empty() {
                1.0
            } else {
                completed as f32 / enabled.len() as f32
            })
            .text(format!("{completed} / {}", enabled.len())),
        );
        egui::ScrollArea::vertical()
            .max_height((max_height - 230.0).max(70.0))
            .show(ui, |ui| {
                for tunnel in tunnels {
                    let (state, color) = if tunnel.enabled {
                        state_label(self.state(&tunnel))
                    } else {
                        ("○ Выключен при запуске", DIM)
                    };
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .selectable_label(
                                self.selected.as_ref() == Some(&tunnel.id),
                                &tunnel.name,
                            )
                            .clicked()
                        {
                            self.selected = Some(tunnel.id.clone());
                        }
                        ui.colored_label(tone(ui, color), state);
                        if matches!(self.state(&tunnel), "waiting" | "error")
                            && ui
                                .button(if self.state(&tunnel) == "waiting" {
                                    "Разобраться"
                                } else {
                                    "Повторить"
                                })
                                .clicked()
                        {
                            self.selected = Some(tunnel.id.clone());
                            action = DialogAction::Resolve(tunnel.id.clone());
                        }
                    });
                }
            });
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            if ui.button("В диспетчерскую").clicked() {
                action = DialogAction::Close;
            }
            if ui.button("Выйти").clicked() {
                action = DialogAction::Exit;
            }
        });
        if ui
            .ctx()
            .input_mut(|input| input.consume_key(egui::Modifiers::NONE, Key::Enter))
        {
            action = DialogAction::Close;
        }
        action
    }
    fn confirm_view(&mut self, ctx: &egui::Context) {
        let Some(mut confirm) = self.confirm.take() else {
            return;
        };
        let mut choice = 0;
        let response = egui::Modal::new(egui::Id::new("confirmation")).show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 100.0).min(570.0));
            match &mut confirm {
                Confirm::Delete { name, .. } => {
                    ui.heading("Удалить туннель?");
                    ui.label(format!("«{name}» будет удалён из настроек. Его соединение и порт закроются."));
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Отмена").clicked() { choice = 1; }
                        if ui.button(RichText::new("Удалить").color(tone(ui, RED))).clicked() { choice = 2; }
                    });
                }
                Confirm::Discard { .. } => {
                    ui.heading("Несохранённые изменения");
                    ui.label("Отменить изменения в этом туннеле?");
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Продолжить редактирование").clicked() { choice = 1; }
                        if ui.button("Отменить изменения").clicked() { choice = 2; }
                    });
                }
                Confirm::CloseNotice { dont_show_again, busy, error } => {
                    ui.heading("КРОТ продолжит работать в фоне");
                    ui.label("Туннели останутся подключены. Чтобы открыть диспетчерскую, нажмите значок КРОТа в трее.");
                    ui.weak("Остановить КРОТ и закрыть соединения можно через меню значка в трее или «Q Выход».");
                    ui.add_enabled_ui(!*busy, |ui| {
                        ui.checkbox(dont_show_again, "Больше не показывать");
                        if !error.is_empty() { ui.colored_label(tone(ui, RED), error.as_str()); }
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Назад").clicked() { choice = 1; }
                            if ui.button(RichText::new("Понятно").color(tone(ui, CYAN))).clicked() { choice = 2; }
                        });
                    });
                    if *busy { ui.weak("Запоминаем выбор…"); }
                    if !*busy && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, Key::Enter)) { choice = 2; }
                }
                Confirm::Exit => {
                    ui.heading("Закрыть диспетчерскую?");
                    ui.label("В фоне КРОТ продолжит держать туннели. Повторный запуск откроет их текущее состояние.");
                    ui.weak("«Остановить КРОТ» закроет все соединения. Включённые туннели восстановятся при следующем запуске.");
                    ui.add_enabled_ui(!self.shutdown_busy, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Назад").clicked() { choice = 1; }
                            if ui.button(RichText::new("Оставить в фоне").color(tone(ui, CYAN))).clicked() { choice = 2; }
                            if ui.button(RichText::new("Остановить КРОТ").color(tone(ui, RED))).clicked() { choice = 3; }
                        });
                    });
                    if self.shutdown_busy { ui.weak("Закрываем соединения…"); }
                }
            }
        });
        if response.should_close()
            && !self.shutdown_busy
            && !matches!(&confirm, Confirm::CloseNotice { busy: true, .. })
        {
            choice = 1;
        }
        match choice {
            0 => self.confirm = Some(confirm),
            1 => {}
            2 => match confirm {
                Confirm::Delete { id, .. } => {
                    if let Some(snapshot) = &self.snapshot {
                        let mut config = snapshot.config.clone();
                        config.tunnels.retain(|tunnel| tunnel.id != id);
                        self.request(
                            ctx,
                            Operation::Delete,
                            "save_checked",
                            json!({"before": snapshot.config, "config": config}),
                        );
                    }
                }
                Confirm::Discard { after } => match after {
                    AfterDiscard::CloseDialog => self.dialog = None,
                    AfterDiscard::Exit => {
                        self.dialog = None;
                        self.confirm = Some(Confirm::Exit);
                    }
                    AfterDiscard::Background => self.leave_background(ctx),
                },
                Confirm::CloseNotice {
                    dont_show_again: true,
                    ..
                } => self.save_close_preference(ctx),
                Confirm::CloseNotice { .. } | Confirm::Exit => self.close_window(ctx),
            },
            3 => {
                self.shutdown_busy = true;
                self.request(ctx, Operation::Shutdown, "shutdown", Value::Null);
                self.confirm = Some(confirm);
            }
            _ => {}
        }
    }
    fn skip_update(&mut self, ctx: &egui::Context) {
        let Some(update) = &mut self.update else {
            return;
        };
        if update.busy() {
            return;
        }
        update.stage = UpdateStage::Skipping;
        update.error.clear();
        let Some(backend) = &self.backend else {
            return;
        };
        let (store, version, tx, ctx) = (
            backend.store.clone(),
            update.release.version.clone(),
            self.tx.clone(),
            ctx.clone(),
        );
        backend.runtime.spawn_blocking(move || {
            let result =
                crate::update::skip_version(&store, &version).map_err(|_| SKIP_UPDATE_ERROR.into());
            let _ = tx.send(Event::UpdateSkipped(result));
            ctx.request_repaint();
        });
    }
    fn prepare_update(&mut self, ctx: &egui::Context) {
        let Some(update) = &mut self.update else {
            return;
        };
        if update.busy() {
            return;
        }
        update.stage = UpdateStage::Preparing;
        update.error.clear();
        let Some(backend) = &self.backend else {
            return;
        };
        let (store, release, tx, ctx) = (
            backend.store.clone(),
            update.release.clone(),
            self.tx.clone(),
            ctx.clone(),
        );
        backend.runtime.spawn(async move {
            let result = crate::update::prepare(&release, &store)
                .await
                .map_err(|error| error.to_string());
            let _ = tx.send(Event::UpdatePrepared(result));
            ctx.request_repaint();
        });
    }
    fn update_failed(&mut self, message: &str, detail: String) {
        if let Some(update) = &mut self.update {
            update.stage = UpdateStage::Failed(message.into());
            update.error = detail;
        }
    }
    fn update_view(&mut self, ctx: &egui::Context) {
        if self.dialog.is_some() || self.confirm.is_some() {
            return;
        }
        if self.update.is_none()
            && self.snapshot.is_some()
            && !self.close_busy()
            && self.busy_tunnels.is_empty()
            && self.pending_operations == 0
            && let Some((release, manual)) = self.pending_update.take()
        {
            self.update = Some(UpdateDialog {
                release,
                manual,
                stage: UpdateStage::Offer,
                error: String::new(),
            });
        }
        let Some(update) = &self.update else {
            return;
        };
        let mut choice = 0;
        let response = egui::Modal::new(egui::Id::new("update")).show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 100.0).min(570.0));
            ui.heading(format!("Доступен КРОТ {}", update.release.version));
            match &update.stage {
                UpdateStage::Offer => {
                    ui.label("Обновить программу и перезапустить КРОТ?");
                    ui.weak(
                        "До завершения скачивания и проверки файлов туннели продолжат работать.",
                    );
                    if !update.error.is_empty() {
                        ui.colored_label(tone(ui, RED), &update.error);
                    }
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Обновить").clicked() {
                            choice = 1;
                        }
                        if !update.manual && ui.button("Пропустить версию").clicked()
                        {
                            choice = 2;
                        }
                        if ui.button("Позже").clicked() {
                            choice = 3;
                        }
                    });
                }
                UpdateStage::Skipping => {
                    ui.spinner();
                    ui.label("Запоминаем выбор…");
                }
                UpdateStage::Preparing => {
                    ui.spinner();
                    ui.label("Скачиваем и проверяем обновление…");
                    ui.weak("Туннели продолжают работать. Дождитесь завершения подготовки.");
                }
                UpdateStage::Launching => {
                    ui.spinner();
                    ui.label("Запускаем установщик…");
                }
                UpdateStage::Failed(error) => {
                    ui.colored_label(tone(ui, RED), error);
                    if !update.error.is_empty() {
                        ui.label(&update.error);
                    }
                    ui.label("Проверьте подключение к сети и права записи в каталог программы.");
                    ui.weak("Текущие файлы программы и туннели сохранены.");
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Повторить").clicked() {
                            choice = 1;
                        }
                        if ui.button("Вернуться в КРОТ").clicked() {
                            choice = 3;
                        }
                    });
                }
            }
        });
        if response.should_close() && !update.busy() {
            choice = 3;
        }
        match choice {
            1 => self.prepare_update(ctx),
            2 => self.skip_update(ctx),
            3 => self.update = None,
            _ => {}
        }
    }
    fn draw(&mut self, ctx: &egui::Context) {
        self.drain(ctx);
        if ctx.input(|input| input.viewport().close_requested()) && !self.allow_close {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.request_background(ctx);
        }
        self.shortcuts(ctx);
        self.main_view(ctx);
        if self.dialog.is_none()
            && self.confirm.is_none()
            && self.update.is_none()
            && let Some(tunnel) = self
                .snapshot
                .as_ref()
                .and_then(|snapshot| {
                    snapshot.config.tunnels.iter().find(|tunnel| {
                        snapshot
                            .prompts
                            .get(&tunnel.id)
                            .is_some_and(|pending| !self.deferred.contains(&pending.id))
                    })
                })
                .cloned()
        {
            self.resolve(&tunnel);
        }
        if self.confirm.is_none() {
            self.dialog_view(ctx);
        }
        self.update_view(ctx);
        self.confirm_view(ctx);
        self.poll(ctx);
        ctx.request_repaint_after(FRAME_TIME);
    }
}
impl eframe::App for Desktop {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.draw(ctx);
    }
}

enum DialogAction {
    None,
    Close,
    SaveForm(bool),
    SaveSettings,
    CheckUpdates,
    Answer,
    CancelPrompt,
    Resolve(String),
    Exit,
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(value).desired_width(f32::INFINITY));
}
fn auth_label(auth: &str) -> &str {
    match auth {
        "agent" => "SSH-agent",
        "key" => "Файл ключа",
        "password" => "Пароль",
        _ => auth,
    }
}
fn theme_label(theme: &str) -> &str {
    match theme {
        "light" => "Светлое",
        "system" => "Системное",
        _ => "Тёмное",
    }
}
fn prompt_title(kind: &str) -> &'static str {
    match kind {
        "trust" => "Новый SSH-узел",
        "hostchanged" => "Ключ SSH-узла изменился",
        "passphrase" => "Разблокировка ключа",
        _ => "Вход по паролю",
    }
}
fn endpoint_view(
    ui: &mut egui::Ui,
    endpoint: &mut Endpoint,
    port: &mut String,
    id: &str,
    title: &str,
) {
    ui.push_id(id, |ui| {
        ui.separator();
        ui.label(RichText::new(title).color(tone(ui, CYAN)));
        field(ui, "SSH-хост", &mut endpoint.host);
        ui.columns(2, |columns| {
            field(&mut columns[0], "SSH-порт", port);
            field(&mut columns[1], "Пользователь", &mut endpoint.user);
        });
        ui.label("Авторизация");
        egui::ComboBox::from_id_salt("auth")
            .selected_text(auth_label(&endpoint.auth))
            .show_ui(ui, |ui| {
                for auth in ["agent", "key", "password"] {
                    ui.selectable_value(&mut endpoint.auth, auth.into(), auth_label(auth));
                }
            });
        ui.add_enabled_ui(endpoint.auth == "key", |ui| {
            field(ui, "Файл приватного ключа", &mut endpoint.key);
        });
    });
}
fn form_view(ui: &mut egui::Ui, form: &mut TunnelForm, max_height: f32) -> DialogAction {
    let mut action = DialogAction::None;
    ui.heading(if form.editing {
        "Редактирование туннеля"
    } else {
        "Новый туннель"
    });
    if !form.error.is_empty() {
        ui.colored_label(tone(ui, RED), &form.error);
    }
    let content_height = max_height - if form.error.is_empty() { 0.0 } else { 45.0 };
    ui.add_enabled_ui(!form.busy, |ui| {
        egui::ScrollArea::vertical().id_salt("form_scroll").max_height(content_height).show(ui, |ui| {
            field(ui, "Название туннеля", &mut form.draft.name);
            ui.label("Тип туннеля");
            egui::ComboBox::from_id_salt("kind").selected_text(match form.draft.kind.as_str() { "R" => "Обратный · -R", "D" => "SOCKS5 · -D", _ => "Локальный · -L" }).show_ui(ui, |ui| {
                for (value, label) in [("L", "Локальный · -L"), ("R", "Обратный · -R"), ("D", "SOCKS5 · -D")] {
                    ui.selectable_value(&mut form.draft.kind, value.into(), label);
                }
            });
            endpoint_view(ui, &mut form.draft.server, &mut form.server_port, "server", "Конечный SSH-сервер");
            ui.separator();
            ui.label(RichText::new("Переадресация").color(tone(ui, CYAN)));
            ui.weak(match form.draft.kind.as_str() {
                "R" => "Порт на SSH-сервере → сервис на вашем устройстве.",
                "D" => "Локальный SOCKS5-прокси → сеть SSH-сервера.",
                _ => "Локальный порт → сервис со стороны SSH-сервера.",
            });
            ui.columns(2, |columns| {
                field(&mut columns[0], "Адрес прослушивания", &mut form.draft.bind);
                field(&mut columns[1], "Порт прослушивания", &mut form.port);
            });
            if form.draft.kind != "D" {
                ui.columns(2, |columns| {
                    field(&mut columns[0], "Адрес назначения", &mut form.draft.target);
                    field(&mut columns[1], "Порт назначения", &mut form.target_port);
                });
            }
            ui.checkbox(&mut form.draft.reconnect, "Восстанавливать после разрыва");
            if ui.checkbox(&mut form.draft.jumps_enabled, "Подключаться через jump-хосты").changed() && form.draft.jumps_enabled && form.draft.jumps.is_empty() {
                form.draft.jumps.push(Endpoint::default()); form.jump_ports.push("22".into());
            }
            if form.draft.jumps_enabled {
                ui.weak("Соединение проходит через узлы сверху вниз, затем к конечному SSH-серверу.");
                let mut jump_action = None;
                let count = form.draft.jumps.len();
                for index in 0..count {
                    endpoint_view(ui, &mut form.draft.jumps[index], &mut form.jump_ports[index], &format!("jump_{index}"), &format!("Jump-хост {}", index + 1));
                    ui.horizontal_wrapped(|ui| {
                        if ui.add_enabled(index > 0, egui::Button::new("↑ Выше")).clicked() { jump_action = Some((index, -1)); }
                        if ui.add_enabled(index + 1 < count, egui::Button::new("↓ Ниже")).clicked() { jump_action = Some((index, 1)); }
                        if ui.button("Удалить узел").clicked() { jump_action = Some((index, 0)); }
                    });
                }
                if let Some((index, delta)) = jump_action {
                    if delta == 0 {
                        form.draft.jumps.remove(index); form.jump_ports.remove(index);
                        if form.draft.jumps.is_empty() { form.draft.jumps_enabled = false; }
                    } else { form.swap_jump(index, index.saturating_add_signed(delta)); }
                }
                if ui.button("+ Добавить jump-хост").clicked() {
                    form.draft.jumps.push(Endpoint::default()); form.jump_ports.push("22".into());
                }
            }
        });
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            if ui.button("Отмена").clicked() { action = DialogAction::Close; }
            if ui.button("Сохранить").clicked() { action = DialogAction::SaveForm(false); }
            if form.editing && form.draft.enabled && ui.button("Сохранить выключенным").clicked() { action = DialogAction::SaveForm(true); }
        });
    });
    if form.busy {
        ui.weak("Сохраняем…");
    }
    action
}

const HELP: &str = "Диспетчерская\n↑ / ↓  Выбрать туннель\nSpace  Запуск / остановка / отмена подключения\nEnter  Открыть запрос ожидающего туннеля\nN / E  Создать / изменить\nL      Журнал\nDelete Удалить\nS      Настройки\n? / F1 Справка\nQ      Меню выхода\n\nВ формах\nTab / Shift+Tab  Следующее / предыдущее поле\nCtrl+S / Ctrl+Enter  Сохранить\nEsc  Назад / отмена\n\nL: локальный порт → сервис со стороны SSH-сервера.\nR: порт на SSH-сервере → сервис со стороны вашего устройства.\nD: локальный SOCKS5-прокси → сеть SSH-сервера.\n\nJump-хосты используются по порядку сверху вниз. У каждого собственные параметры входа.\n\nПароли не сохраняются. Новые и изменённые ключи узлов требуют проверки. «Позже» оставляет запрос на туннеле: откройте его кнопкой «Разобраться». Остальные туннели продолжают работать.\n\nКрестик закрывает диспетчерскую, а КРОТ и туннели продолжают работать в фоне. Открыть окно снова можно через значок в трее. Q или «Выход» открывают меню: оставить туннели в фоне или остановить КРОТа. Включённые туннели восстановятся после нового запуска. Ручная остановка выключает восстановление этого туннеля. Ошибка подключения не сбрасывает выбор.\n\nВ настройках можно включить запуск в фоне после входа в систему. Если требуется пароль или проверка узла, туннель ждёт открытия диспетчерской.\n\nНа заставке «В диспетчерскую» и Enter / Esc открывают список, подключение продолжается.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Config, Settings},
        ssh::Prompt,
    };
    use std::collections::HashMap;

    fn tunnel() -> Tunnel {
        Tunnel {
            id: "native-tunnel".into(),
            name: "postgres".into(),
            kind: "L".into(),
            server: Endpoint {
                host: "bastion.example".into(),
                user: "dev".into(),
                port: 22,
                auth: "agent".into(),
                key: String::new(),
            },
            bind: "127.0.0.1".into(),
            port: 15432,
            target: "db.internal".into(),
            target_port: 5432,
            reconnect: true,
            enabled: true,
            jumps_enabled: false,
            jumps: Vec::new(),
        }
    }
    fn pending(tunnel_id: &str, id: &str, kind: &str) -> PendingPrompt {
        PendingPrompt {
            id: id.into(),
            request: Prompt {
                kind: kind.into(),
                tunnel_id: tunnel_id.into(),
                tunnel_name: "postgres".into(),
                endpoint: tunnel().server,
                hop: "Конечный SSH-сервер".into(),
                message: String::new(),
                old_fingerprint: "SHA256:old".into(),
                new_fingerprint: "SHA256:new".into(),
            },
        }
    }
    fn snapshot() -> Snapshot {
        Snapshot {
            config: Config {
                version: 1,
                settings: Settings {
                    theme: "dark".into(),
                    motion: true,
                    splash: true,
                },
                tunnels: vec![tunnel()],
            },
            runtimes: HashMap::from([(
                "native-tunnel".into(),
                crate::ssh::Runtime {
                    state: "running".into(),
                    ..Default::default()
                },
            )]),
            prompts: HashMap::new(),
            activation: 0,
            version: None,
        }
    }
    fn render(app: &mut Desktop, ctx: &egui::Context, size: [f32; 2]) -> egui::FullOutput {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size.into())),
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        )
    }
    fn input_frame(
        app: &mut Desktop,
        ctx: &egui::Context,
        events: Vec<egui::Event>,
        close: bool,
    ) -> egui::FullOutput {
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(700.0, 500.0),
            )),
            events,
            ..Default::default()
        };
        if close {
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .unwrap()
                .events
                .push(egui::ViewportEvent::Close);
        }
        ctx.run(input, |ctx| app.draw(ctx))
    }
    fn key_frame(app: &mut Desktop, ctx: &egui::Context, key: Key) -> egui::FullOutput {
        input_frame(
            app,
            ctx,
            vec![egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            false,
        )
    }
    fn text_rect(output: &egui::FullOutput, label: &str) -> Option<egui::Rect> {
        fn find(shape: &egui::Shape, label: &str) -> Option<egui::Rect> {
            match shape {
                egui::Shape::Text(text) if text.galley.text() == label => {
                    Some(egui::Rect::from_min_size(text.pos, text.galley.size()))
                }
                egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| find(shape, label)),
                _ => None,
            }
        }
        output
            .shapes
            .iter()
            .find_map(|shape| find(&shape.shape, label))
    }
    fn click_label(app: &mut Desktop, ctx: &egui::Context, label: &str) -> egui::FullOutput {
        let output = render(app, ctx, [700.0, 500.0]);
        let pos = text_rect(&output, label)
            .unwrap_or_else(|| panic!("Missing {label}"))
            .center();
        input_frame(
            app,
            ctx,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            false,
        )
    }
    fn has_close(output: &egui::FullOutput) -> bool {
        output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .iter()
            .any(|command| matches!(command, egui::ViewportCommand::Close))
    }
    fn desktop_for_store(store: &Store) -> Desktop {
        Desktop::new(
            Some(Backend {
                store: store.clone(),
                client: Client::new(store),
                runtime: Arc::new(
                    tokio::runtime::Builder::new_current_thread()
                        .build()
                        .unwrap(),
                ),
            }),
            true,
        )
    }
    fn wait_for_close(app: &mut Desktop, ctx: &egui::Context) -> bool {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let output = render(app, ctx, [700.0, 500.0]);
            if has_close(&output) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn manual_update_check_reports_no_updates_and_can_be_repeated() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("config.json")).unwrap();
        let mut app = desktop_for_store(&store);
        app.snapshot = Some(snapshot());
        app.dialog = Some(Dialog::Help);
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        for _ in 0..10 {
            render(&mut app, &ctx, [700.0, 500.0]);
        }
        click_label(&mut app, &ctx, "Проверить обновление");
        app.tx
            .send(Event::UpdateChecked {
                manual: true,
                result: Ok(None),
            })
            .unwrap();
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "Обновлений нет.").is_some());
        assert!(app.update.is_none());
        assert!(matches!(app.dialog, Some(Dialog::Help)));
        click_label(&mut app, &ctx, "Проверить обновление");
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "Обновлений нет.").is_none());
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }
    #[test]
    fn manual_update_check_reports_failure_instead_of_no_updates() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("config.json")).unwrap();
        let mut app = desktop_for_store(&store);
        app.snapshot = Some(snapshot());
        app.dialog = Some(Dialog::Help);
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        for _ in 0..10 {
            render(&mut app, &ctx, [700.0, 500.0]);
        }
        click_label(&mut app, &ctx, "Проверить обновление");
        app.tx
            .send(Event::UpdateChecked {
                manual: true,
                result: Err("unsafe technical detail".into()),
            })
            .unwrap();
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(
            text_rect(
                &output,
                "Не удалось проверить обновления. Проверьте подключение к сети и повторите попытку."
            )
            .is_some()
        );
        assert!(text_rect(&output, "Обновлений нет.").is_none());
        assert!(text_rect(&output, "unsafe technical detail").is_none());
        assert!(!matches!(app.update_check, UpdateCheck::Checking));
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        for label in ["Назад", "Проверить обновление"] {
            assert!(
                ctx.content_rect()
                    .contains_rect(text_rect(&output, label).unwrap())
            );
        }
    }
    #[test]
    fn manual_update_offer_shows_version_and_later_preserves_preferences() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("config.json")).unwrap();
        crate::update::skip_version(&store, "0.6.0").unwrap();
        let original = std::fs::read(store.sidecar(".updates.json")).unwrap();
        let mut app = desktop_for_store(&store);
        app.snapshot = Some(snapshot());
        app.dialog = Some(Dialog::Help);
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        for _ in 0..10 {
            render(&mut app, &ctx, [700.0, 500.0]);
        }
        click_label(&mut app, &ctx, "Проверить обновление");
        app.tx
            .send(Event::UpdateChecked {
                manual: true,
                result: Ok(Some(crate::update::Release::for_test("0.6.0"))),
            })
            .unwrap();
        render(&mut app, &ctx, [700.0, 500.0]);
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        for label in ["Доступен КРОТ 0.6.0", "Обновить", "Позже"] {
            let rect = text_rect(&output, label).unwrap();
            assert!(ctx.content_rect().contains_rect(rect), "{label}");
        }
        assert!(text_rect(&output, "Пропустить версию").is_none());
        assert!(app.dialog.is_none());
        click_label(&mut app, &ctx, "Позже");
        assert!(app.update.is_none());
        assert_eq!(
            std::fs::read(store.sidecar(".updates.json")).unwrap(),
            original
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
    #[test]
    fn manual_update_result_preserves_a_form_opened_while_checking() {
        let ctx = egui::Context::default();
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        let mut form = TunnelForm::new(Some(tunnel()));
        form.draft.name = "unsaved".into();
        app.dialog = Some(Dialog::Form(Box::new(form)));
        app.tx
            .send(Event::UpdateChecked {
                manual: true,
                result: Ok(Some(crate::update::Release::for_test("0.6.0"))),
            })
            .unwrap();
        render(&mut app, &ctx, [700.0, 500.0]);
        assert!(matches!(&app.dialog, Some(Dialog::Form(form)) if form.draft.name == "unsaved"));
        assert!(app.pending_update.is_some());
        assert!(app.update.is_none());
        app.dialog = None;
        render(&mut app, &ctx, [700.0, 500.0]);
        assert!(app.update.as_ref().is_some_and(|update| update.manual));
    }
    #[test]
    fn update_offer_waits_for_a_dirty_form_and_later_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("config.json")).unwrap();
        let mut app = desktop_for_store(&store);
        app.snapshot = Some(snapshot());
        let mut form = TunnelForm::new(Some(tunnel()));
        form.draft.name = "unsaved".into();
        app.dialog = Some(Dialog::Form(Box::new(form)));
        app.tx
            .send(Event::UpdateChecked {
                manual: false,
                result: Ok(Some(crate::update::Release::for_test("0.6.0"))),
            })
            .unwrap();
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "Доступен КРОТ 0.6.0").is_none());
        assert!(matches!(&app.dialog, Some(Dialog::Form(form)) if form.draft.name == "unsaved"));
        app.dialog = None;
        render(&mut app, &ctx, [700.0, 500.0]);
        assert!(app.update.is_some());
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "Доступен КРОТ 0.6.0").is_some());
        click_label(&mut app, &ctx, "Позже");
        assert!(app.update.is_none());
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }
    #[test]
    fn update_offer_waits_for_prompts_settings_splash_confirmation_and_operations() {
        let ctx = egui::Context::default();
        for dialog in [
            Some(Dialog::Prompt(Box::new(PromptDialog::new(pending(
                "native-tunnel",
                "password",
                "password",
            ))))),
            Some(Dialog::Settings(SettingsDraft {
                theme: "dark".into(),
                motion: true,
                splash: true,
                autostart: Some(false),
                initial_autostart: Some(false),
                error: String::new(),
                busy: false,
            })),
            Some(Dialog::Splash),
        ] {
            let mut app = Desktop::new(None, true);
            app.snapshot = Some(snapshot());
            app.dialog = dialog;
            app.pending_update = Some((crate::update::Release::for_test("0.6.0"), false));
            let output = render(&mut app, &ctx, [700.0, 500.0]);
            assert!(text_rect(&output, "Доступен КРОТ 0.6.0").is_none());
            assert!(app.pending_update.is_some());
        }
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.pending_update = Some((crate::update::Release::for_test("0.6.0"), false));
        app.confirm = Some(Confirm::Delete {
            id: "native-tunnel".into(),
            name: "postgres".into(),
        });
        render(&mut app, &ctx, [700.0, 500.0]);
        assert!(app.update.is_none());
        app.confirm = None;
        app.pending_operations = 1;
        render(&mut app, &ctx, [700.0, 500.0]);
        assert!(app.update.is_none());
        app.pending_operations = 0;
        render(&mut app, &ctx, [700.0, 500.0]);
        assert!(app.update.is_some());
    }
    #[test]
    fn update_acceptance_blocks_close_and_failure_restores_access() {
        let ctx = egui::Context::default();
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.pending_update = Some((crate::update::Release::for_test("0.6.0"), false));
        render(&mut app, &ctx, [700.0, 500.0]);
        click_label(&mut app, &ctx, "Обновить");
        assert!(matches!(
            app.update.as_ref().map(|dialog| &dialog.stage),
            Some(UpdateStage::Preparing)
        ));
        for output in [
            input_frame(&mut app, &ctx, vec![], true),
            key_frame(&mut app, &ctx, Key::Q),
        ] {
            assert!(!has_close(&output));
        }
        assert!(app.confirm.is_none());
        app.tx
            .send(Event::UpdatePrepared(Err(
                "В релизе отсутствует файл для этой платформы.".into(),
            )))
            .unwrap();
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(!app.close_busy());
        assert!(!has_close(&output));
        assert!(text_rect(&output, "Не удалось подготовить обновление.").is_some());
        assert!(text_rect(&output, "В релизе отсутствует файл для этой платформы.").is_some());
        click_label(&mut app, &ctx, "Вернуться в КРОТ");
        assert!(app.update.is_none());
    }
    #[test]
    fn update_skip_persists_exact_release_and_save_failure_retains_offer() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("config.json")).unwrap();
        let ctx = egui::Context::default();
        let mut app = desktop_for_store(&store);
        app.snapshot = Some(snapshot());
        app.pending_update = Some((crate::update::Release::for_test("0.6.0"), false));
        render(&mut app, &ctx, [700.0, 500.0]);
        click_label(&mut app, &ctx, "Пропустить версию");
        let deadline = Instant::now() + Duration::from_secs(3);
        while app.update.as_ref().is_some_and(UpdateDialog::busy) && Instant::now() < deadline {
            render(&mut app, &ctx, [700.0, 500.0]);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(app.update.is_none());
        let saved: Value =
            serde_json::from_slice(&std::fs::read(store.sidecar(".updates.json")).unwrap())
                .unwrap();
        assert_eq!(saved["skipped_version"], "0.6.0");
        app.pending_update = Some((crate::update::Release::for_test("0.7.0"), false));
        render(&mut app, &ctx, [700.0, 500.0]);
        app.tx
            .send(Event::UpdateSkipped(Err("unsafe technical detail".into())))
            .unwrap();
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(app.update.is_some());
        assert!(
            text_rect(
                &output,
                "Не удалось запомнить пропущенную версию. Повторите попытку или нажмите «Позже»."
            )
            .is_some()
        );
        assert!(text_rect(&output, "unsafe technical detail").is_none());
    }
    #[test]
    fn update_handoff_closes_only_after_success_and_service_loss_waits() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("config.json")).unwrap();
        let ctx = egui::Context::default();
        for stage in [
            UpdateStage::Skipping,
            UpdateStage::Preparing,
            UpdateStage::Launching,
        ] {
            let mut app = desktop_for_store(&store);
            app.snapshot = Some(snapshot());
            app.update = Some(UpdateDialog {
                release: crate::update::Release::for_test("0.6.0"),
                manual: false,
                stage,
                error: String::new(),
            });
            app.tx
                .send(Event::Snapshot(Err("service stopped".into())))
                .unwrap();
            let output = input_frame(&mut app, &ctx, vec![], true);
            assert!(!has_close(&output));
            assert!(!app.allow_close);
            assert!(app.confirm.is_none());
            app.tx
                .send(Event::InstallerLaunched(Err("spawn failed".into())))
                .unwrap();
            let output = render(&mut app, &ctx, [700.0, 500.0]);
            assert!(!has_close(&output));
            assert!(!app.close_busy());
            app.tx.send(Event::InstallerLaunched(Ok(()))).unwrap();
            assert!(has_close(&render(&mut app, &ctx, [700.0, 500.0])));
            assert!(app.allow_close);
        }
    }
    #[test]
    fn update_check_with_no_release_keeps_the_dispatcher_quiet() {
        let ctx = egui::Context::default();
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.tx
            .send(Event::UpdateChecked {
                manual: false,
                result: Ok(None),
            })
            .unwrap();
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(app.pending_update.is_none());
        assert!(app.update.is_none());
        assert!(app.dialog.is_none());
        assert!(app.error.is_empty());
        assert!(!has_close(&output));
        app.check_updates(&ctx, false);
        assert!(app.rx.try_recv().is_err());
    }
    #[test]
    fn native_close_notice_fits_minimum_window_and_enter_leaves_tunnels_running() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.initialized = true;
        let _ = input_frame(&mut app, &ctx, vec![], true);
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        for label in [
            "КРОТ продолжит работать в фоне",
            "Больше не показывать",
            "Понятно",
            "Назад",
        ] {
            let rect = text_rect(&output, label).unwrap_or_else(|| panic!("Missing {label}"));
            assert!(
                egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(700.0, 500.0))
                    .contains_rect(rect)
            );
        }
        assert!(text_rect(&output, "Остановить КРОТ").is_none());
        assert!(!app.allow_close);
        assert!(!app.shutdown_busy);
        let output = key_frame(&mut app, &ctx, Key::Enter);
        assert!(has_close(&output));
        assert!(app.allow_close);
        assert!(!app.shutdown_busy);
        assert_eq!(
            app.snapshot.as_ref().unwrap().runtimes["native-tunnel"].state,
            "running"
        );
    }
    #[test]
    fn unchecked_close_notice_creates_no_preferences_file() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let ctx = egui::Context::default();
        let mut app = desktop_for_store(&store);
        let _ = input_frame(&mut app, &ctx, vec![], true);
        let output = key_frame(&mut app, &ctx, Key::Enter);
        assert!(has_close(&output));
        assert!(!store.sidecar(".desktop.json").exists());
        assert!(!store.path.exists());
    }
    #[test]
    fn checked_notice_is_saved_before_close_and_skipped_by_next_desktop() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let ctx = egui::Context::default();
        let mut app = desktop_for_store(&store);
        let _ = input_frame(&mut app, &ctx, vec![], true);
        let _ = click_label(&mut app, &ctx, "Больше не показывать");
        let _ = input_frame(&mut app, &ctx, vec![], true);
        let output = key_frame(&mut app, &ctx, Key::Enter);
        assert!(
            !has_close(&output),
            "Close must wait for the preferences write"
        );
        assert!(wait_for_close(&mut app, &ctx));
        let saved: Value =
            serde_json::from_slice(&std::fs::read(store.sidecar(".desktop.json")).unwrap())
                .unwrap();
        assert_eq!(saved, json!({"show_close_notice": false}));
        assert!(!store.path.exists());
        let ctx = egui::Context::default();
        let mut reopened = desktop_for_store(&store);
        let output = input_frame(&mut reopened, &ctx, vec![], true);
        assert!(has_close(&output));
        assert!(reopened.confirm.is_none());
        assert!(!reopened.shutdown_busy);
        let mut other = desktop_for_store(&Store::new(temp.path().join("other.json")).unwrap());
        let ctx = egui::Context::default();
        let _ = input_frame(&mut other, &ctx, vec![], true);
        assert!(
            other.confirm.is_some(),
            "Preference belongs to one config path"
        );
    }
    #[test]
    fn malformed_oversized_and_unreadable_desktop_preferences_keep_the_notice() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let sidecar = store.sidecar(".desktop.json");
        for raw in [
            "{}".to_owned(),
            "{invalid".to_owned(),
            r#"{"show_close_notice": "false"}"#.to_owned(),
            r#"{"show_close_notice": false, "extra": true}"#.to_owned(),
            format!("{}{}", r#"{"show_close_notice": false}"#, " ".repeat(4096)),
        ] {
            std::fs::write(&sidecar, raw).unwrap();
            let ctx = egui::Context::default();
            let mut app = desktop_for_store(&store);
            let _ = input_frame(&mut app, &ctx, vec![], true);
            let output = render(&mut app, &ctx, [700.0, 500.0]);
            assert!(text_rect(&output, "Понятно").is_some());
            assert!(!app.allow_close);
        }
        std::fs::remove_file(&sidecar).unwrap();
        std::fs::create_dir(&sidecar).unwrap();
        let ctx = egui::Context::default();
        let mut app = desktop_for_store(&store);
        let _ = input_frame(&mut app, &ctx, vec![], true);
        assert!(!app.allow_close);
        assert!(app.confirm.is_some());
    }
    #[test]
    fn failed_close_preference_save_keeps_notice_and_draft_until_user_goes_back() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        std::fs::create_dir(store.sidecar(".desktop.json")).unwrap();
        let ctx = egui::Context::default();
        let mut app = desktop_for_store(&store);
        app.dialog = Some(Dialog::Settings(SettingsDraft {
            theme: "light".into(),
            motion: false,
            splash: false,
            autostart: Some(false),
            initial_autostart: Some(false),
            error: String::new(),
            busy: false,
        }));
        let _ = input_frame(&mut app, &ctx, vec![], true);
        let _ = click_label(&mut app, &ctx, "Больше не показывать");
        let output = key_frame(&mut app, &ctx, Key::Enter);
        assert!(!has_close(&output));
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let output = render(&mut app, &ctx, [700.0, 500.0]);
            assert!(!has_close(&output));
            assert!(!app.allow_close);
            if text_rect(
                &output,
                "Не удалось запомнить выбор. Повторите попытку или нажмите «Назад».",
            )
            .is_some()
            {
                break;
            }
            assert!(Instant::now() < deadline, "Missing preference save failure");
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = click_label(&mut app, &ctx, "Назад");
        assert!(app.confirm.is_none());
        assert!(
            matches!(&app.dialog, Some(Dialog::Settings(settings)) if settings.theme == "light" && !settings.motion && !settings.splash)
        );
    }
    #[test]
    fn dirty_native_close_preserves_draft_when_notice_is_cancelled() {
        let ctx = egui::Context::default();
        let mut app = Desktop::new(None, true);
        let mut form = TunnelForm::new(Some(tunnel()));
        form.port = "unfinished".into();
        app.dialog = Some(Dialog::Form(Box::new(form)));
        let _ = input_frame(&mut app, &ctx, vec![], true);
        assert!(matches!(app.confirm, Some(Confirm::Discard { .. })));
        assert!(!app.allow_close);
        let _ = click_label(&mut app, &ctx, "Продолжить редактирование");
        assert!(app.confirm.is_none());
        let _ = input_frame(&mut app, &ctx, vec![], true);
        let _ = click_label(&mut app, &ctx, "Отменить изменения");
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "Понятно").is_some());
        let _ = click_label(&mut app, &ctx, "Назад");
        assert!(matches!(&app.dialog, Some(Dialog::Form(form)) if form.port == "unfinished"));
        assert!(!app.allow_close);
    }
    #[test]
    fn native_close_waits_for_form_settings_and_shutdown_operations() {
        for operation in [0, 1, 2] {
            let ctx = egui::Context::default();
            let mut app = Desktop::new(None, true);
            if operation == 0 {
                let mut form = TunnelForm::new(Some(tunnel()));
                form.busy = true;
                app.dialog = Some(Dialog::Form(Box::new(form)));
            } else if operation == 1 {
                app.dialog = Some(Dialog::Settings(SettingsDraft {
                    theme: "dark".into(),
                    motion: true,
                    splash: true,
                    autostart: Some(false),
                    initial_autostart: Some(false),
                    error: String::new(),
                    busy: true,
                }));
            } else {
                app.shutdown_busy = true;
            }
            let output = input_frame(&mut app, &ctx, vec![], true);
            assert!(!has_close(&output));
            assert!(!app.allow_close);
            assert!(app.confirm.is_none());
        }
    }
    #[test]
    fn animation_has_four_positions_and_180ms_cadence() {
        assert_eq!(FRAME_TIME, Duration::from_millis(180));
        assert_eq!(mascot("running", 0), mascot("running", 2));
        assert_eq!(mascot("running", 0), mascot("running", 4));
        assert_ne!(mascot("running", 0), mascot("running", 1));
        assert_ne!(mascot("running", 1), mascot("running", 3));
        assert!(mascot("running", 3).contains("(__)\\___/ /"));
        assert_eq!(mascot("running", 1).lines().count(), 6);
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.snapshot.as_mut().unwrap().config.settings.motion = false;
        app.started = Instant::now() - Duration::from_millis(550);
        assert_eq!(app.frame(), 0);
    }
    #[test]
    fn invalid_ports_survive_validation_and_jump_reordering() {
        let mut form = TunnelForm::new(Some(tunnel()));
        assert!(!form.dirty());
        form.port = "не порт".into();
        assert!(form.candidate(&[], false).is_err());
        assert_eq!(form.port, "не порт");
        assert!(form.dirty());
        form.draft.jumps = vec![
            Endpoint {
                host: "first".into(),
                ..Default::default()
            },
            Endpoint {
                host: "second".into(),
                ..Default::default()
            },
        ];
        form.jump_ports = vec!["broken".into(), "2222".into()];
        form.swap_jump(0, 1);
        assert_eq!(form.draft.jumps[1].host, "first");
        assert_eq!(form.jump_ports, ["2222", "broken"]);
        for invalid in ["", "0", "-1", "65536", "1.5"] {
            assert!(parse_port(invalid, "Порт").is_err());
        }
        assert_eq!(parse_port(" 65535 ", "Порт").unwrap(), 65535);
    }
    #[test]
    fn form_uses_shared_validation_and_preserves_current_enabled_state() {
        let mut form = TunnelForm::new(Some(tunnel()));
        form.draft.name = "  database  ".into();
        let mut current = tunnel();
        current.enabled = false;
        let candidate = form.candidate(&[current], false).unwrap();
        assert_eq!(candidate.name, "database");
        assert!(!candidate.enabled);
        assert_eq!(form.draft.name, "  database  ");
        form.draft.kind = "D".into();
        form.target_port = "hidden-invalid".into();
        assert_eq!(form.candidate(&[], false).unwrap().target_port, 80);
        form.draft.server.host.clear();
        assert!(form.candidate(&[], false).is_err());
    }
    #[test]
    fn secret_is_cleared_after_answer_and_changed_key_needs_confirmation() {
        let mut dialog = PromptDialog::new(pending("native-tunnel", "password", "password"));
        assert!(!dialog.may_accept());
        dialog.secret = "only-in-memory".into();
        assert!(dialog.may_accept());
        let mut answer = dialog.answer();
        assert_eq!(answer.as_str(), Some("only-in-memory"));
        assert!(dialog.secret.is_empty());
        if let Value::String(value) = &mut answer {
            value.zeroize();
        }
        let mut changed = PromptDialog::new(pending("native-tunnel", "hostchanged", "hostchanged"));
        assert!(!changed.may_accept());
        changed.verified = true;
        assert!(changed.may_accept());
        assert_eq!(changed.answer(), Value::Bool(true));
    }
    #[test]
    fn default_window_shows_last_form_row_and_buttons_without_scrolling() {
        let size = native_options().viewport.inner_size.unwrap();
        for editing in [false, true] {
            let ctx = egui::Context::default();
            configure(&ctx, "dark");
            let mut app = Desktop::new(None, true);
            app.snapshot = Some(snapshot());
            app.initialized = true;
            app.dialog = Some(Dialog::Form(Box::new(TunnelForm::new(
                editing.then(tunnel),
            ))));
            for _ in 0..10 {
                render(&mut app, &ctx, size.into());
            }
            let output = render(&mut app, &ctx, size.into());
            for label in ["Подключаться через jump-хосты", "Отмена", "Сохранить"]
            {
                let rect = text_rect(&output, label).unwrap_or_else(|| panic!("Missing {label}"));
                assert!(
                    output.shapes.iter().any(|shape| {
                        matches!(&shape.shape, egui::Shape::Text(text) if text.galley.text() == label)
                            && shape.clip_rect.contains_rect(rect)
                    }),
                    "{label} is clipped at the default window size: {rect:?}"
                );
                assert!(egui::Rect::from_min_size(egui::Pos2::ZERO, size).contains_rect(rect));
            }
        }
    }
    #[test]
    fn native_views_render_headlessly_at_minimum_window_size() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.selected = Some("native-tunnel".into());
        app.initialized = true;
        for size in [[700.0, 500.0], [1000.0, 720.0]] {
            for dialog in [
                None,
                Some(Dialog::Form(Box::new(TunnelForm::new(Some(tunnel()))))),
                Some(Dialog::Settings(SettingsDraft {
                    theme: "dark".into(),
                    motion: true,
                    splash: true,
                    autostart: Some(false),
                    initial_autostart: Some(false),
                    error: String::new(),
                    busy: false,
                })),
                Some(Dialog::Prompt(Box::new(PromptDialog::new(pending(
                    "native-tunnel",
                    "request",
                    "hostchanged",
                ))))),
                Some(Dialog::Logs("native-tunnel".into())),
                Some(Dialog::Help),
                Some(Dialog::Splash),
            ] {
                let has_dialog = dialog.is_some();
                app.dialog = dialog;
                let output = render(&mut app, &ctx, size);
                if has_dialog {
                    let rect = egui::AreaState::load(&ctx, egui::Id::new("dialog"))
                        .unwrap()
                        .rect();
                    assert!(
                        rect.width() <= size[0] && rect.height() <= size[1],
                        "Dialog {rect:?} exceeds {size:?}"
                    );
                }
                assert!(!output.shapes.is_empty());
                assert!(
                    !ctx.tessellate(output.shapes, output.pixels_per_point)
                        .is_empty()
                );
            }
        }
        for confirm in [
            Confirm::Delete {
                id: "native-tunnel".into(),
                name: "postgres".into(),
            },
            Confirm::Discard {
                after: AfterDiscard::CloseDialog,
            },
            Confirm::Exit,
        ] {
            app.confirm = Some(confirm);
            assert!(!render(&mut app, &ctx, [700.0, 500.0]).shapes.is_empty());
        }
    }
    #[test]
    fn bundled_fonts_cover_cyrillic_ascii_and_status_symbols() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            ctx.fonts_mut(|fonts| {
                let text = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя_()[]/#\\.<>-↟◷◌○→↑↓┌─┐│└┬┘";
                for character in text.chars() {
                    assert!(fonts.has_glyph(&FontId::monospace(14.0), character), "Missing bundled glyph {character}");
                }
            });
        });
    }
    #[test]
    fn deferred_requests_do_not_reopen_and_do_not_block_other_tunnels() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        let mut snapshot = snapshot();
        let mut second = tunnel();
        second.id = "second".into();
        second.name = "redis".into();
        snapshot.config.tunnels.push(second);
        snapshot.prompts.insert(
            "native-tunnel".into(),
            pending("native-tunnel", "first", "password"),
        );
        snapshot
            .prompts
            .insert("second".into(), pending("second", "second", "trust"));
        app.snapshot = Some(snapshot);
        app.initialized = true;
        app.deferred.insert("first".into());
        let _ = render(&mut app, &ctx, [1000.0, 720.0]);
        assert!(
            matches!(&app.dialog, Some(Dialog::Prompt(prompt)) if prompt.pending.id == "second")
        );
        app.dialog = None;
        let _ = render(&mut app, &ctx, [1000.0, 720.0]);
        assert!(app.dialog.is_none());
        assert_eq!(app.snapshot.as_ref().unwrap().prompts.len(), 2);
    }
    #[test]
    fn explicit_exit_from_dirty_form_requires_discard_then_exit_choice() {
        let ctx = egui::Context::default();
        let mut app = Desktop::new(None, true);
        let mut form = TunnelForm::new(Some(tunnel()));
        form.port = "2000".into();
        app.dialog = Some(Dialog::Form(Box::new(form)));
        app.request_exit();
        assert!(matches!(
            app.confirm,
            Some(Confirm::Discard {
                after: AfterDiscard::Exit
            })
        ));
        assert!(!app.allow_close);
        let _ = render(&mut app, &ctx, [700.0, 500.0]);
        let _ = click_label(&mut app, &ctx, "Отменить изменения");
        assert!(matches!(app.confirm, Some(Confirm::Exit)));
        assert!(app.dialog.is_none());
        assert!(!app.allow_close);
    }
    #[test]
    fn q_keeps_exit_choice_and_background_needs_no_second_notice() {
        let ctx = egui::Context::default();
        let mut app = Desktop::new(None, true);
        let _ = key_frame(&mut app, &ctx, Key::Q);
        assert!(matches!(app.confirm, Some(Confirm::Exit)));
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "Остановить КРОТ").is_some());
        let output = click_label(&mut app, &ctx, "Оставить в фоне");
        assert!(has_close(&output));
        assert!(app.confirm.is_none());
        assert!(!app.shutdown_busy);
    }
    #[test]
    fn native_close_is_cancelled_until_the_notice_is_acknowledged() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        let mut input = egui::RawInput::default();
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .unwrap()
            .events
            .push(egui::ViewportEvent::Close);
        let output = ctx.run(input, |ctx| app.draw(ctx));
        assert!(!matches!(app.confirm, Some(Confirm::Exit)));
        assert!(app.confirm.is_some());
        assert!(!app.allow_close);
        assert!(
            output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .iter()
                .any(|command| matches!(command, egui::ViewportCommand::CancelClose))
        );
    }
    #[test]
    fn polling_keeps_secret_input_and_new_request_ids_are_not_deferred() {
        let ctx = egui::Context::default();
        let mut app = Desktop::new(None, true);
        let mut snapshot = snapshot();
        snapshot.prompts.insert(
            "native-tunnel".into(),
            pending("native-tunnel", "first", "password"),
        );
        app.snapshot = Some(snapshot.clone());
        app.initialized = true;
        app.resolve(&tunnel());
        if let Some(Dialog::Prompt(prompt)) = &mut app.dialog {
            prompt.secret = "unfinished".into();
        }
        app.tx.send(Event::Snapshot(Ok(snapshot.clone()))).unwrap();
        app.drain(&ctx);
        assert!(
            matches!(&app.dialog, Some(Dialog::Prompt(prompt)) if prompt.secret == "unfinished")
        );
        snapshot.prompts.insert(
            "native-tunnel".into(),
            pending("native-tunnel", "replacement", "password"),
        );
        app.tx.send(Event::Snapshot(Ok(snapshot))).unwrap();
        app.drain(&ctx);
        assert!(app.dialog.is_none());
        assert!(!app.deferred.contains("first"));
        assert!(!app.deferred.contains("replacement"));
    }
    #[test]
    fn activation_restores_existing_window_without_losing_a_dirty_form() {
        let ctx = egui::Context::default();
        let mut app = Desktop::new(None, true);
        let mut state = snapshot();
        app.snapshot = Some(state.clone());
        app.selected = Some("native-tunnel".into());
        app.initialized = true;
        let mut form = TunnelForm::new(Some(tunnel()));
        form.port = "unfinished".into();
        app.dialog = Some(Dialog::Form(Box::new(form)));
        for (activation, expected_activation) in [(1, true), (1, false), (2, true)] {
            state.activation = activation;
            app.tx.send(Event::Snapshot(Ok(state.clone()))).unwrap();
            let output = ctx.run(egui::RawInput::default(), |ctx| app.drain(ctx));
            let commands = &output.viewport_output[&egui::ViewportId::ROOT].commands;
            for present in [
                commands
                    .iter()
                    .any(|cmd| matches!(cmd, egui::ViewportCommand::Visible(true))),
                commands
                    .iter()
                    .any(|cmd| matches!(cmd, egui::ViewportCommand::Minimized(false))),
                commands
                    .iter()
                    .any(|cmd| matches!(cmd, egui::ViewportCommand::Focus)),
            ] {
                assert_eq!(present, expected_activation);
            }
            assert!(matches!(&app.dialog, Some(Dialog::Form(form)) if form.port == "unfinished"));
            assert_eq!(app.selected.as_deref(), Some("native-tunnel"));
            assert_eq!(
                app.snapshot.as_ref().unwrap().runtimes["native-tunnel"].state,
                "running"
            );
        }
    }
    #[test]
    fn service_stop_waits_for_pending_or_failed_close_preference_save() {
        for (busy, save_error, should_close) in [
            (false, "", true),
            (true, "", false),
            (false, CLOSE_PREFERENCE_ERROR, false),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let store = Store::new(temp.path().join("config.json")).unwrap();
            let endpoint = store.sidecar(".background.json");
            std::fs::write(&endpoint, "{}").unwrap();
            let ctx = egui::Context::default();
            let mut app = desktop_for_store(&store);
            app.snapshot = Some(snapshot());
            app.initialized = true;
            app.confirm = Some(Confirm::CloseNotice {
                dont_show_again: true,
                busy: busy || !save_error.is_empty(),
                error: String::new(),
            });
            std::fs::remove_file(endpoint).unwrap();
            if !save_error.is_empty() {
                app.tx
                    .send(Event::ClosePreferenceSaved(Err(save_error.into())))
                    .unwrap();
            }
            app.tx
                .send(Event::Snapshot(Err("service stopped".into())))
                .unwrap();
            let output = input_frame(&mut app, &ctx, vec![], false);
            assert_eq!(has_close(&output), should_close);
            assert_eq!(app.allow_close, should_close);
            if busy {
                app.tx.send(Event::ClosePreferenceSaved(Ok(()))).unwrap();
                assert!(has_close(&input_frame(&mut app, &ctx, vec![], false)));
            } else if !save_error.is_empty() {
                let output = render(&mut app, &ctx, [700.0, 500.0]);
                assert!(text_rect(&output, CLOSE_PREFERENCE_ERROR).is_some());
                let _ = click_label(&mut app, &ctx, "Назад");
                assert!(app.confirm.is_none());
                app.tx
                    .send(Event::Snapshot(Err("service stopped".into())))
                    .unwrap();
                assert!(has_close(&input_frame(&mut app, &ctx, vec![], false)));
            }
        }
    }
    #[test]
    fn escape_cancels_close_notice_but_waits_for_pending_preference_save() {
        for busy in [false, true] {
            let ctx = egui::Context::default();
            let mut app = Desktop::new(None, true);
            app.dialog = Some(Dialog::Help);
            let _ = input_frame(&mut app, &ctx, vec![], true);
            if busy && let Some(Confirm::CloseNotice { busy, .. }) = &mut app.confirm {
                *busy = true;
            }
            let _ = render(&mut app, &ctx, [700.0, 500.0]);
            let output = key_frame(&mut app, &ctx, Key::Escape);
            assert!(!has_close(&output));
            assert!(!app.allow_close);
            assert_eq!(app.confirm.is_some(), busy);
            assert!(matches!(app.dialog, Some(Dialog::Help)));
        }
    }
    #[test]
    fn daemon_loss_closes_idle_updates_but_preserves_active_work_and_preferences() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        for preference in [
            None,
            Some((false, "")),
            Some((true, "")),
            Some((false, "save failed")),
        ] {
            for (stage, update_idle) in [
                (UpdateStage::Offer, true),
                (UpdateStage::Failed("download failed".into()), true),
                (UpdateStage::Skipping, false),
                (UpdateStage::Preparing, false),
                (UpdateStage::Launching, false),
            ] {
                let mut app = desktop_for_store(&store);
                app.snapshot = Some(snapshot());
                app.update = Some(UpdateDialog {
                    release: crate::update::Release::for_test("0.6.0"),
                    manual: false,
                    stage,
                    error: String::new(),
                });
                if let Some((busy, error)) = preference {
                    app.confirm = Some(Confirm::CloseNotice {
                        dont_show_again: true,
                        busy,
                        error: error.into(),
                    });
                }
                app.tx
                    .send(Event::Snapshot(Err("service stopped".into())))
                    .unwrap();
                let ctx = egui::Context::default();
                let output = ctx.run(egui::RawInput::default(), |ctx| app.drain(ctx));
                let should_close =
                    update_idle && preference.is_none_or(|(busy, error)| !busy && error.is_empty());
                assert_eq!(has_close(&output), should_close);
                assert_eq!(app.allow_close, should_close);
                if !should_close {
                    assert_eq!(app.error, "service stopped");
                }
                assert!(app.update.is_some());
                assert_eq!(app.confirm.is_some(), preference.is_some());
            }
        }
    }

    #[test]
    fn poll_failure_closes_only_an_initialized_window_after_service_endpoint_removal() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::new(temp.path().join("config.json")).unwrap();
        let endpoint = store.sidecar(".background.json");
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
        );
        for (has_snapshot, endpoint_exists, should_close) in [
            (false, false, false),
            (false, true, false),
            (true, true, false),
            (true, false, true),
        ] {
            if endpoint_exists {
                std::fs::write(&endpoint, "{}").unwrap();
            } else if endpoint.try_exists().unwrap() {
                std::fs::remove_file(&endpoint).unwrap();
            }
            let mut app = Desktop::new(
                Some(Backend {
                    store: Store::new(&store.path).unwrap(),
                    client: Client::new(&store),
                    runtime: runtime.clone(),
                }),
                true,
            );
            if has_snapshot {
                app.snapshot = Some(snapshot());
                app.initialized = true;
            }
            let mut form = TunnelForm::new(Some(tunnel()));
            form.port = "unfinished".into();
            app.dialog = Some(Dialog::Form(Box::new(form)));
            app.tx
                .send(Event::Snapshot(Err("connection lost".into())))
                .unwrap();
            let ctx = egui::Context::default();
            let output = ctx.run(egui::RawInput::default(), |ctx| app.drain(ctx));
            assert_eq!(app.allow_close, should_close);
            assert_eq!(
                output.viewport_output[&egui::ViewportId::ROOT]
                    .commands
                    .iter()
                    .any(|cmd| matches!(cmd, egui::ViewportCommand::Close)),
                should_close
            );
            if !should_close {
                assert_eq!(app.error, "connection lost");
            }
            assert!(matches!(&app.dialog, Some(Dialog::Form(form)) if form.port == "unfinished"));
        }
    }
    #[test]
    fn theme_switches_preserve_terminal_typography_and_palette() {
        let ctx = egui::Context::default();
        for theme in ["dark", "light", "dark", "system"] {
            configure(&ctx, theme);
            for mode in [egui::Theme::Dark, egui::Theme::Light] {
                assert_eq!(
                    ctx.style_of(mode).override_font_id.as_ref().unwrap().family,
                    FontFamily::Monospace
                );
                assert_eq!(
                    ctx.style_of(mode).visuals.dark_mode,
                    mode == egui::Theme::Dark
                );
            }
        }
        assert_eq!(
            ctx.style_of(egui::Theme::Dark).visuals.panel_fill,
            Color32::from_rgb(21, 27, 30)
        );
    }
}
