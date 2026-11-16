//! Native dispatcher. SSH and IPC work is always dispatched off the window thread.
use crate::{
    background::{Client, Snapshot},
    config::{Endpoint, Store, Tunnel, atomic_json},
    ssh::PendingPrompt,
};
use eframe::egui::{self, Color32, Key, RichText, Stroke};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    io::Read,
    path::PathBuf,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

mod apps_view;
#[cfg(test)]
mod screenshots;
mod style;
use apps_view::{AppForm, app_form_view};
use style::Pal;

const FRAME_TIME: Duration = Duration::from_millis(180);
const POLL_TIME: Duration = Duration::from_millis(450);
const MAX_DESKTOP_PREFERENCES_BYTES: usize = 4096;
const CLOSE_PREFERENCE_ERROR: &str =
    "Не удалось запомнить выбор. Повторите попытку или нажмите «Назад».";
const KEY_DIALOG_ERROR: &str =
    "Не удалось открыть диалог выбора файла. Введите путь к ключу вручную.";
const COMPONENTS_ERROR: &str = "Не удалось скачать файлы WinDivert. Проверьте подключение к сети или скопируйте WinDivert.dll и WinDivert64.sys из архива релиза в каталог КРОТа.";
const SKIP_UPDATE_ERROR: &str =
    "Не удалось запомнить пропущенную версию. Повторите попытку или нажмите «Позже».";
const INK: Color32 = Color32::from_rgb(225, 232, 232);
const DIM: Color32 = Color32::from_rgb(152, 169, 174);
const CYAN: Color32 = Color32::from_rgb(139, 205, 227);
const GREEN: Color32 = Color32::from_rgb(172, 208, 148);
const AMBER: Color32 = Color32::from_rgb(227, 188, 124);
const RED: Color32 = Color32::from_rgb(255, 155, 145);
const ABOUT_QUOTES: &[&str] = &[
    "Я не спал. Я держал канал.",
    "Не зря же мы это всё копали.",
    "Лопата сегодня отдыхает.",
    "Каска на месте. Пакеты под присмотром.",
    "Это не баг. Это запасной выход из туннеля.",
];

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
    configure(ctx, crate::config::THEMES[0]);
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

/// Смысловой цвет интерфейса; конкретный цвет выбирает `tone` по теме.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tone {
    Ok,
    Warn,
    Error,
    Dim,
}

/// Палитра цветной темы.
#[derive(Clone, Copy)]
struct Palette {
    bg: Color32,
    panel: Color32,
    extreme: Color32,
    line: Color32,
    raised: Color32,
    selected: Color32,
    ink: Color32,
    dim: Color32,
    accent: Color32,
    ok: Color32,
    warn: Color32,
    error: Color32,
}

fn palette_id() -> egui::Id {
    egui::Id::new("krot-palette")
}

fn palette(theme: &str) -> Option<Palette> {
    let rgb = Color32::from_rgb;
    Some(match theme {
        "build" => Palette {
            bg: rgb(23, 24, 26),
            panel: rgb(32, 34, 37),
            extreme: rgb(16, 17, 19),
            line: rgb(58, 61, 66),
            raised: rgb(44, 47, 51),
            selected: rgb(74, 63, 18),
            ink: rgb(241, 239, 233),
            dim: rgb(166, 168, 171),
            accent: rgb(255, 196, 0),
            ok: rgb(124, 214, 108),
            warn: rgb(255, 159, 69),
            error: rgb(255, 90, 54),
        },
        "night" => Palette {
            bg: rgb(10, 13, 20),
            panel: rgb(18, 23, 35),
            extreme: rgb(6, 8, 13),
            line: rgb(42, 51, 72),
            raised: rgb(26, 33, 50),
            selected: rgb(37, 52, 90),
            ink: rgb(230, 234, 242),
            dim: rgb(154, 166, 189),
            accent: rgb(169, 196, 255),
            ok: rgb(120, 220, 170),
            warn: rgb(255, 180, 84),
            error: rgb(255, 122, 107),
        },
        "danger" => Palette {
            bg: rgb(20, 10, 10),
            panel: rgb(31, 16, 16),
            extreme: rgb(12, 6, 6),
            line: rgb(74, 38, 38),
            raised: rgb(43, 22, 22),
            selected: rgb(90, 31, 23),
            ink: rgb(245, 236, 232),
            dim: rgb(196, 168, 162),
            accent: rgb(255, 177, 153),
            ok: rgb(160, 220, 130),
            warn: rgb(255, 210, 63),
            error: rgb(255, 75, 43),
        },
        "stealth" => Palette {
            bg: rgb(16, 18, 13),
            panel: rgb(24, 27, 19),
            extreme: rgb(10, 11, 8),
            line: rgb(52, 58, 40),
            raised: rgb(33, 37, 26),
            selected: rgb(61, 59, 32),
            ink: rgb(228, 230, 216),
            dim: rgb(163, 168, 142),
            accent: rgb(194, 184, 106),
            ok: rgb(150, 196, 110),
            warn: rgb(232, 135, 90),
            error: rgb(255, 95, 109),
        },
        _ => return None,
    })
}

fn apply_palette(visuals: &mut egui::Visuals, colors: &Palette) {
    visuals.panel_fill = colors.bg;
    visuals.window_fill = colors.panel;
    visuals.faint_bg_color = colors.panel;
    visuals.extreme_bg_color = colors.extreme;
    visuals.override_text_color = Some(colors.ink);
    visuals.window_stroke = Stroke::new(1.0_f32, colors.line);
    visuals.widgets.noninteractive.bg_fill = colors.panel;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, colors.line);
    for widget in [&mut visuals.widgets.inactive, &mut visuals.widgets.open] {
        widget.bg_fill = colors.raised;
        widget.weak_bg_fill = colors.raised;
        widget.bg_stroke = Stroke::new(1.0_f32, colors.line);
    }
    for widget in [&mut visuals.widgets.hovered, &mut visuals.widgets.active] {
        widget.bg_fill = colors.selected;
        widget.weak_bg_fill = colors.selected;
        widget.bg_stroke = Stroke::new(1.0_f32, colors.accent);
    }
    visuals.selection.bg_fill = colors.selected;
    visuals.selection.stroke = Stroke::new(1.0_f32, colors.accent);
    visuals.hyperlink_color = colors.accent;
    visuals.warn_fg_color = colors.warn;
    visuals.error_fg_color = colors.error;
}

pub(crate) fn configure(ctx: &egui::Context, theme: &str) {
    let colors = palette(theme);
    ctx.data_mut(|data| match colors {
        Some(colors) => data.insert_temp(palette_id(), colors),
        None => data.remove::<Palette>(palette_id()),
    });
    for (mode, mut visuals) in [
        (egui::Theme::Dark, egui::Visuals::dark()),
        (egui::Theme::Light, egui::Visuals::light()),
    ] {
        if let (egui::Theme::Dark, Some(colors)) = (mode, &colors) {
            apply_palette(&mut visuals, colors);
        } else if mode == egui::Theme::Dark {
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
    style::sync_fonts(ctx);
    ctx.all_styles_mut(|style| {
        style::text_styles(style);
        style.spacing.item_spacing = egui::vec2(10.0, 9.0);
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
        style.spacing.interact_size.y = 36.0;
    });
    ctx.set_theme(match theme {
        "light" => egui::ThemePreference::Light,
        "system" => egui::ThemePreference::System,
        _ => egui::ThemePreference::Dark,
    });
}

fn state_label(state: &str) -> (&'static str, Tone) {
    match state {
        "running" => ("↟ Работает", Tone::Ok),
        "connecting" => ("◷ Подключение…", Tone::Warn),
        "reconnecting" => ("◷ Восстановление…", Tone::Warn),
        "waiting" => ("! Нужно ваше участие", Tone::Warn),
        "error" => ("! Ошибка", Tone::Error),
        "stopped" => ("○ Остановлен", Tone::Dim),
        _ => ("◌ Создан", Tone::Dim),
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
    ToggleApp(String),
    SaveApp(String),
    /// A UDP choice for a tunnel or a rule.
    Udp,
    Settings,
    Answer,
    Shutdown,
}
enum Event {
    Snapshot(Result<Box<Snapshot>, String>),
    Complete(Operation, Result<(), String>),
    AutostartLoaded(Result<bool, String>),
    ComponentsFetched(Result<(), String>),
    AutostartChanged(Result<bool, String>),
    ClosePreferenceSaved(Result<(), String>),
    UpdateChecked {
        manual: bool,
        result: Result<Option<crate::update::Release>, String>,
    },
    UpdateSkipped(Result<(), String>),
    UpdatePrepared(Result<crate::update::PreparedUpdate, String>),
    InstallerLaunched(Result<(), String>),
    #[cfg(target_os = "linux")]
    KeyPicked {
        id: u64,
        result: Result<Option<PathBuf>, ()>,
    },
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
    view: View,
    selected_app: Option<String>,
    busy_apps: HashSet<String>,
    fetching_components: bool,
    #[cfg(not(target_os = "linux"))]
    browse_app: bool,
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
    about_quote: Option<usize>,
    filter: Group,
    app_filter: Group,
    #[cfg(target_os = "linux")]
    key_picks: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Tunnels,
    Apps,
}

enum Dialog {
    Form(Box<TunnelForm>),
    AppForm(Box<AppForm>),
    Settings(SettingsDraft),
    Prompt(Box<PromptDialog>),
    Logs(String),
    Help,
    About,
    Splash,
}
impl Dialog {
    fn dirty(&self) -> bool {
        match self {
            Dialog::Form(form) => form.dirty(),
            Dialog::AppForm(form) => form.dirty(),
            _ => false,
        }
    }
    fn saving(&self) -> bool {
        match self {
            Dialog::Form(form) => form.busy,
            Dialog::AppForm(form) => form.busy,
            Dialog::Settings(settings) => settings.busy,
            _ => false,
        }
    }
}
enum Confirm {
    Delete {
        id: String,
        name: String,
    },
    DeleteApp {
        id: String,
        name: String,
    },
    /// Uploading the relay to a tunnel's server needs the user's consent.
    UdpConsent {
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
    #[cfg(target_os = "linux")]
    picking: Option<KeyPick>,
}
/// A file dialog running off the window thread; dropping it closes the dialog.
#[cfg(target_os = "linux")]
struct KeyPick {
    id: u64,
    target: KeyTarget,
    _cancel: tokio_util::sync::DropGuard,
}
#[derive(Clone, Copy, Debug, PartialEq)]
enum KeyTarget {
    Server,
    Jump(usize),
}
impl KeyTarget {
    fn endpoint(self, draft: &mut Tunnel) -> Option<&mut Endpoint> {
        match self {
            Self::Server => Some(&mut draft.server),
            Self::Jump(index) => draft.jumps.get_mut(index),
        }
    }
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
            #[cfg(target_os = "linux")]
            picking: None,
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
    fn picking(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.picking.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
    fn swap_jump(&mut self, index: usize, other: usize) {
        self.draft.jumps.swap(index, other);
        self.jump_ports.swap(index, other);
    }
    fn select_key(&mut self, target: KeyTarget, path: Option<PathBuf>) {
        let Some(path) = path else { return };
        let Ok(path) = path.into_os_string().into_string() else {
            self.error =
                "Не удалось использовать путь к ключу: имя файла должно быть в Unicode.".into();
            return;
        };
        if let Some(endpoint) = target.endpoint(&mut self.draft) {
            endpoint.key = path;
        }
    }
}
fn trim_endpoint(endpoint: &mut Endpoint) {
    endpoint.host = endpoint.host.trim().into();
    endpoint.user = endpoint.user.trim().into();
}
fn key_directory(key: &str) -> Option<PathBuf> {
    if key.contains('\0') {
        return None;
    }
    crate::ssh::expand_key_path(key)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
}
/// Exports the window handle for the portal; the dialog itself runs off this thread.
#[cfg(target_os = "linux")]
fn window_identifier(
    frame: &eframe::Frame,
    runtime: &tokio::runtime::Runtime,
) -> Option<ashpd::WindowIdentifier> {
    use raw_window_handle::{HasDisplayHandle, HasWindowHandle};
    let window = frame.window_handle().ok()?.as_raw();
    let display = frame.display_handle().ok()?.as_raw();
    runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(2),
            ashpd::WindowIdentifier::from_raw_handle(&window, Some(&display)),
        )
        .await
        .ok()
        .flatten()
    })
}
#[cfg(target_os = "linux")]
const PORTAL: &str = "org.freedesktop.portal.Desktop";
/// Asks the desktop portal for a key file. Cancelling closes the dialog through
/// `Request.Close`, so the request is made directly to keep its handle.
#[cfg(target_os = "linux")]
async fn portal_key_file(
    parent: Option<ashpd::WindowIdentifier>,
    directory: Option<&std::path::Path>,
    cancel: tokio_util::sync::CancellationToken,
) -> anyhow::Result<Option<PathBuf>> {
    use anyhow::Context;
    use futures_util::StreamExt;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
    let connection = zbus::Connection::session().await?;
    let bus = zbus::fdo::DBusProxy::new(&connection).await?;
    let mut owners = bus
        .receive_name_owner_changed_with_args(&[(0, PORTAL)])
        .await?;
    let token = format!("krot{}", uuid::Uuid::new_v4().simple());
    let sender = connection
        .unique_name()
        .context("Нет имени на шине D-Bus.")?
        .trim_start_matches(':')
        .replace('.', "_");
    let mut handle = OwnedObjectPath::try_from(format!(
        "/org/freedesktop/portal/desktop/request/{sender}/{token}"
    ))?;
    // Subscribe before the call so a fast response is not missed.
    let mut responses = portal_responses(&connection, &handle).await?;
    let mut options = std::collections::HashMap::from([
        ("handle_token", Value::from(token.as_str())),
        ("multiple", Value::from(false)),
    ]);
    if let Some(directory) = directory {
        let mut bytes = directory.as_os_str().as_encoded_bytes().to_vec();
        bytes.push(0);
        options.insert("current_folder", Value::from(bytes));
    }
    let parent = parent.map(|parent| parent.to_string()).unwrap_or_default();
    let reply = connection
        .call_method(
            Some(PORTAL),
            "/org/freedesktop/portal/desktop",
            Some("org.freedesktop.portal.FileChooser"),
            "OpenFile",
            &(parent, "Выберите приватный ключ", options),
        )
        .await?;
    let returned: OwnedObjectPath = reply.body().deserialize()?;
    // Older portals choose the handle themselves.
    if returned != handle {
        handle = returned;
        responses = portal_responses(&connection, &handle).await?;
    }
    // The portal can disappear without answering an accepted request.
    let disappeared = async {
        while let Some(change) = owners.next().await {
            if change.args()?.old_owner().is_some() {
                break;
            }
        }
        anyhow::bail!("Служба выбора файлов завершилась.")
    };
    tokio::select! {
        response = responses.next() => {
            let message = response.context("Служба выбора файлов не ответила.")?;
            let (code, results): (u32, std::collections::HashMap<String, OwnedValue>) =
                message.body().deserialize()?;
            match code {
                0 => {
                    let uris: Vec<String> = results
                        .get("uris")
                        .map(|uris| uris.try_clone()?.try_into())
                        .transpose()?
                        .unwrap_or_default();
                    uris.first()
                        .map(|uri| {
                            reqwest::Url::parse(uri)
                                .ok()
                                .and_then(|uri| uri.to_file_path().ok())
                                .context("Диалог вернул недопустимый путь.")
                        })
                        .transpose()
                }
                1 => Ok(None),
                _ => anyhow::bail!("Диалог выбора файла завершился с ошибкой."),
            }
        },
        result = disappeared => result,
        _ = cancel.cancelled() => {
            let _ = connection
                .call_method(Some(PORTAL), &handle, Some("org.freedesktop.portal.Request"), "Close", &())
                .await;
            Ok(None)
        },
    }
}
#[cfg(target_os = "linux")]
async fn portal_responses(
    connection: &zbus::Connection,
    handle: &zbus::zvariant::OwnedObjectPath,
) -> zbus::Result<zbus::proxy::SignalStream<'static>> {
    zbus::Proxy::new(
        connection,
        PORTAL,
        handle.clone(),
        "org.freedesktop.portal.Request",
    )
    .await?
    .receive_signal("Response")
    .await
}
#[cfg(not(target_os = "linux"))]
fn pick_key_file(
    frame: &eframe::Frame,
    directory: Option<&std::path::Path>,
) -> anyhow::Result<Option<PathBuf>> {
    let mut dialog = rfd::FileDialog::new()
        .set_title("Выберите приватный ключ")
        .set_parent(frame);
    if let Some(directory) = directory {
        dialog = dialog.set_directory(directory);
    }
    Ok(dialog.pick_file())
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
            view: View::Tunnels,
            selected_app: None,
            busy_apps: HashSet::new(),
            fetching_components: false,
            #[cfg(not(target_os = "linux"))]
            browse_app: false,
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
            // Пусто: первый снимок всегда применяет сохранённую тему.
            applied_theme: String::new(),
            pending_update: None,
            update_check: UpdateCheck::Idle,
            update: None,
            pending_operations: 0,
            about_quote: None,
            filter: Group::All,
            app_filter: Group::All,
            #[cfg(target_os = "linux")]
            key_picks: 0,
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
            let _ = tx.send(Event::Snapshot(result.map(Box::new)));
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
                #[cfg(target_os = "linux")]
                Event::KeyPicked { id, result } => {
                    if let Some(Dialog::Form(form)) = &mut self.dialog
                        && let Some(pick) = form.picking.take_if(|pick| pick.id == id)
                    {
                        match result {
                            Ok(path) => form.select_key(pick.target, path),
                            Err(()) => form.error = KEY_DIALOG_ERROR.into(),
                        }
                    }
                }
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
                            if self
                                .selected_app
                                .as_ref()
                                .is_none_or(|id| !snapshot.apps.iter().any(|rule| &rule.id == id))
                            {
                                self.selected_app = snapshot.apps.first().map(|r| r.id.clone());
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
                            self.snapshot = Some(*snapshot);
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
                    if let Operation::ToggleApp(id) = &operation {
                        self.busy_apps.remove(id);
                    }
                    if matches!(operation, Operation::SaveApp(_))
                        && let Some(Dialog::AppForm(form)) = &mut self.dialog
                    {
                        form.busy = false;
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
                                Some(Dialog::AppForm(form))
                                    if matches!(operation, Operation::SaveApp(_)) =>
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
                                Operation::SaveApp(id) => {
                                    self.selected_app = Some(id);
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
                Event::ComponentsFetched(result) => {
                    self.fetching_components = false;
                    match result {
                        Ok(()) => self.launch_divert(),
                        Err(error) => self.error = error,
                    }
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
    /// Milliseconds since start for animations, or `None` when «Анимация кротов» is off.
    fn anim_ms(&self) -> Option<u128> {
        self.snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.config.settings.motion)
            .then(|| self.started.elapsed().as_millis())
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
        if settings.autostart == settings.initial_autostart && settings.autostart != Some(true) {
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
                .map_err(|error| format!("Настройки сохранены. Ошибка автозапуска: {error}"));
            let _ = tx.send(Event::AutostartChanged(result));
            ctx.request_repaint();
        });
    }
    fn close_busy(&self) -> bool {
        self.shutdown_busy
            || self.update.as_ref().is_some_and(UpdateDialog::busy)
            || self.dialog.as_ref().is_some_and(Dialog::saving)
    }
    fn request_exit(&mut self) {
        if self.close_busy() || self.confirm.is_some() {
            return;
        }
        self.confirm = Some(if self.dialog.as_ref().is_some_and(Dialog::dirty) {
            Confirm::Discard {
                after: AfterDiscard::Exit,
            }
        } else {
            Confirm::Exit
        });
    }
    fn request_background(&mut self, ctx: &egui::Context) {
        if self.close_busy() || self.confirm.is_some() {
            return;
        }
        if self.dialog.as_ref().is_some_and(Dialog::dirty) {
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
        if pressed(Key::Num1) {
            self.view = View::Tunnels;
        }
        if pressed(Key::Num2) {
            self.view = View::Apps;
        }
        let apps = self.view == View::Apps;
        for (key, delta) in [(Key::ArrowDown, 1), (Key::ArrowUp, -1)] {
            if pressed(key) {
                if apps {
                    self.move_app_selection(delta);
                } else {
                    self.move_selection(delta);
                }
            }
        }
        if pressed(Key::Q) {
            self.request_exit();
        }
        if pressed(Key::N) && self.snapshot.is_some() {
            self.dialog = Some(if apps {
                Dialog::AppForm(Box::new(AppForm::new(None)))
            } else {
                Dialog::Form(Box::new(TunnelForm::new(None)))
            });
        }
        if pressed(Key::S) {
            self.open_settings(ctx);
        }
        if pressed(Key::F1) || ctx.input_mut(|i| i.consume_key(egui::Modifiers::SHIFT, Key::Slash))
        {
            self.dialog = Some(Dialog::Help);
        }
        if apps {
            if let Some(rule) = self.selected_app() {
                if pressed(Key::Space) {
                    self.toggle_app(ctx, &rule);
                }
                if pressed(Key::E) {
                    self.dialog = Some(Dialog::AppForm(Box::new(AppForm::new(Some(rule.clone())))));
                }
                if pressed(Key::Delete) {
                    self.confirm = Some(Confirm::DeleteApp {
                        id: rule.id,
                        name: rule.name,
                    });
                }
            }
        } else if let Some(tunnel) = self.selected_tunnel() {
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
        let pal = style::pal(ctx);
        egui::TopBottomPanel::top("header")
            .frame(
                egui::Frame::new()
                    .fill(pal.bg)
                    .inner_margin(egui::Margin::symmetric(20, 10)),
            )
            .show(ctx, |ui| {
                let mut narrow = true;
                ui.horizontal(|ui| {
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                    ui.spacing_mut().button_padding = egui::vec2(10.0, 6.0);
                    ui.spacing_mut().item_spacing.x = 6.0;
                    style::mole(ui, 2.0, style::Pose::default(), &pal);
                    ui.label(
                        RichText::new("КРОТ / ДИСПЕТЧЕРСКАЯ")
                            .family(style::bold())
                            .size(18.0)
                            .color(pal.ink),
                    );
                    ui.add_space(8.0);
                    for (view, label) in
                        [(View::Tunnels, "1 Туннели"), (View::Apps, "2 Приложения")]
                    {
                        if ui
                            .add(style::choice(label, self.view == view, &pal))
                            .clicked()
                        {
                            self.view = view;
                        }
                    }
                    let actions_id = egui::Id::new("header_actions_width");
                    let need = ctx
                        .data(|data| data.get_temp::<f32>(actions_id))
                        .unwrap_or(0.0);
                    if ui.available_width() >= need {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            self.header_actions(ui, ctx, &pal);
                        });
                        narrow = false;
                    }
                });
                if narrow {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        self.header_actions(ui, ctx, &pal);
                    });
                }
            });
        self.summary(ctx, &pal);
        if !self.error.is_empty() {
            egui::TopBottomPanel::bottom("footer")
                .frame(
                    egui::Frame::new()
                        .fill(pal.panel)
                        .inner_margin(egui::Margin::symmetric(20, 8)),
                )
                .show(ctx, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(pal.error, &self.error);
                        if ui.small_button("Скрыть").clicked() {
                            self.error.clear();
                        }
                    });
                });
        }
        egui::SidePanel::left("tunnels")
            .default_width(330.0)
            .min_width(260.0)
            .max_width(520.0)
            .resizable(true)
            .frame(
                egui::Frame::new()
                    .fill(pal.bg)
                    .inner_margin(egui::Margin::symmetric(16, 14)),
            )
            .show(ctx, |ui| {
                if self.view == View::Apps {
                    self.apps_side(ui, ctx, &pal);
                } else {
                    self.tunnel_list(ui, ctx, &pal);
                }
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(pal.bg)
                    .inner_margin(egui::Margin::symmetric(16, 14)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("detail_scroll")
                    .show(ui, |ui| {
                        if self.view == View::Apps {
                            self.apps_main(ui, ctx, &pal);
                        } else if let Some(tunnel) = self.selected_tunnel() {
                            style::card(&pal).show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                self.detail(ui, ctx, &tunnel, &pal);
                            });
                        } else {
                            style::card(&pal).show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                style::caps(ui, "На участке", pal.dim);
                                ui.add_space(12.0);
                                style::mole(ui, 4.0, style::Pose::default(), &pal);
                                ui.add_space(12.0);
                                ui.label(
                                    "Создайте туннель, чтобы открыть проход к нужному сервису.",
                                );
                                ui.label(
                                    RichText::new("L — локальный порт, R — обратный, D — SOCKS5.")
                                        .color(pal.dim),
                                );
                            });
                        }
                    });
            });
    }
    /// Header actions from the right edge: version, then Q, ?, S and N.
    fn header_actions(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, pal: &Pal) {
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
        ui.spacing_mut().button_padding = egui::vec2(10.0, 6.0);
        ui.spacing_mut().item_spacing.x = 6.0;
        let version_response = ui
            .add_enabled(
                self.dialog.is_none() && self.confirm.is_none() && self.update.is_none(),
                egui::Link::new(
                    RichText::new(concat!("v", env!("CARGO_PKG_VERSION")))
                        .monospace()
                        .color(pal.dim),
                ),
            )
            .on_hover_text("О программе");
        if version_response.clicked() {
            self.about_quote = Some(match self.about_quote {
                Some(previous) => {
                    (previous + rand::random_range(1..ABOUT_QUOTES.len())) % ABOUT_QUOTES.len()
                }
                None => rand::random_range(0..ABOUT_QUOTES.len()),
            });
            self.dialog = Some(Dialog::About);
        }
        if ui.add(style::secondary("Q Выход", pal)).clicked() {
            self.request_exit();
        }
        if ui.add(style::secondary("? Справка", pal)).clicked() {
            self.dialog = Some(Dialog::Help);
        }
        if ui
            .add_enabled(
                self.snapshot.is_some(),
                style::secondary("S Настройки", pal),
            )
            .clicked()
        {
            self.open_settings(ctx);
        }
        let apps = self.view == View::Apps;
        if ui
            .add_enabled(
                self.snapshot.is_some(),
                style::secondary(
                    if apps {
                        "N Новое правило"
                    } else {
                        "N Новый туннель"
                    },
                    pal,
                ),
            )
            .clicked()
        {
            self.dialog = Some(if apps {
                Dialog::AppForm(Box::new(AppForm::new(None)))
            } else {
                Dialog::Form(Box::new(TunnelForm::new(None)))
            });
        }
        // The first pass only measures; layout settles before anything is shown or clicked.
        let width = ui.min_rect().width() + 12.0;
        let id = egui::Id::new("header_actions_width");
        let known = ctx.data(|data| data.get_temp::<f32>(id));
        if known.is_none_or(|known| (known - width).abs() > 0.5) {
            ctx.data_mut(|data| data.insert_temp(id, width));
            ctx.request_discard("header actions measured");
        }
    }
    /// The line under the header: state lights, «РАБОТАЮТ N ИЗ M» and, for long lists, filters.
    fn summary(&mut self, ctx: &egui::Context, pal: &Pal) {
        let apps = self.view == View::Apps;
        let (lamps, running, waiting) = if apps {
            self.app_lamps(pal)
        } else {
            self.tunnel_lamps(pal)
        };
        let total = lamps.len();
        let blink_on = self.anim_ms().is_none_or(|ms| ms / 600 % 2 == 0);
        egui::TopBottomPanel::top("summary")
            .frame(
                egui::Frame::new()
                    .fill(pal.panel)
                    .inner_margin(egui::Margin::symmetric(20, 8)),
            )
            .show(ctx, |ui| {
                // Two floors from the left: lights and the count on top, buttons below.
                ui.spacing_mut().item_spacing.y = 6.0;
                ui.horizontal_wrapped(|ui| {
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                    if total > 0 {
                        style::lamps(ui, &lamps, blink_on, pal);
                        ui.add_space(6.0);
                    }
                    ui.label(
                        RichText::new(if apps {
                            format!("ЧЕРЕЗ ТУННЕЛЬ {running} ИЗ {total}")
                        } else {
                            format!("РАБОТАЮТ {running} ИЗ {total}")
                        })
                        .family(style::bold())
                        .size(17.0)
                        .color(pal.ink),
                    );
                    if waiting > 0 {
                        ui.label(
                            RichText::new(if apps {
                                format!("! Без туннеля: {waiting}")
                            } else {
                                format!("! Ждут участия: {waiting}")
                            })
                            .color(pal.warn),
                        );
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                    if total > 8 {
                        let filter = if apps {
                            &mut self.app_filter
                        } else {
                            &mut self.filter
                        };
                        let counts =
                            |group: Group| lamps.iter().filter(|lamp| lamp.group == group).count();
                        let names = if apps {
                            ["Через туннель", "Без туннеля"]
                        } else {
                            ["Работают", "Ждут"]
                        };
                        for (group, label) in [
                            (Group::All, "Все".to_owned()),
                            (
                                Group::Live,
                                format!("{} · {}", names[0], counts(Group::Live)),
                            ),
                            (
                                Group::Attention,
                                format!("{} · {}", names[1], counts(Group::Attention)),
                            ),
                            (Group::Off, format!("Выключены · {}", counts(Group::Off))),
                        ] {
                            let text = if group == Group::All {
                                format!("{label} · {total}")
                            } else {
                                label
                            };
                            if ui
                                .add(style::choice(&text, *filter == group, pal))
                                .clicked()
                            {
                                *filter = group;
                            }
                        }
                    } else {
                        ui.label(
                            RichText::new(if apps {
                                "↑ ↓ Выбор · Space Вкл / выкл · 1 2 Вкладки"
                            } else {
                                "↑ ↓ Выбор · Space Пуск / стоп · Enter Запрос · L Журнал"
                            })
                            .size(13.0)
                            .color(pal.dim),
                        );
                    }
                });
            });
    }
    fn tunnel_group(state: &str) -> Group {
        match state {
            "running" | "connecting" | "reconnecting" => Group::Live,
            "waiting" | "error" => Group::Attention,
            _ => Group::Off,
        }
    }
    fn tunnel_lamps(&self, pal: &Pal) -> (Vec<style::Lamp>, usize, usize) {
        let Some(snapshot) = &self.snapshot else {
            return (Vec::new(), 0, 0);
        };
        let mut running = 0;
        let mut waiting = 0;
        let lamps = snapshot
            .config
            .tunnels
            .iter()
            .map(|tunnel| {
                let state = self.state(tunnel);
                let (label, color) = state_label(state);
                running += usize::from(state == "running");
                waiting += usize::from(state == "waiting");
                style::Lamp {
                    color: tone_of(pal, color),
                    filled: !matches!(state, "stopped" | "idle"),
                    blink: matches!(state, "waiting" | "connecting" | "reconnecting"),
                    selected: self.selected.as_ref() == Some(&tunnel.id),
                    name: format!("{}: {label}", tunnel.name),
                    group: Self::tunnel_group(state),
                }
            })
            .collect();
        (lamps, running, waiting)
    }
    fn tunnel_list(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, pal: &Pal) {
        let tunnels = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.config.tunnels.clone())
            .unwrap_or_default();
        style::caps(ui, "Мои туннели", pal.dim);
        ui.add_space(6.0);
        egui::ScrollArea::vertical()
            .id_salt("tunnel_scroll")
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 6.0;
                if tunnels.is_empty() {
                    ui.add_space(16.0);
                    style::mole(ui, 3.0, style::Pose::default(), pal);
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(if self.snapshot.is_some() {
                            "Здесь начнётся первый туннель.\nN — добавить подключение."
                        } else {
                            "Подключаемся к фоновому КРОТу…"
                        })
                        .color(pal.dim),
                    );
                }
                let filter = if tunnels.len() > 8 {
                    self.filter
                } else {
                    Group::All
                };
                for tunnel in &tunnels {
                    let state = self.state(tunnel).to_owned();
                    if filter != Group::All && Self::tunnel_group(&state) != filter {
                        continue;
                    }
                    let (label, color) = state_label(&state);
                    let color = tone_of(pal, color);
                    let selected = self.selected.as_ref() == Some(&tunnel.id);
                    let busy = self.busy_tunnels.contains(&tunnel.id);
                    let row = list_row(
                        ui,
                        pal,
                        &tunnel.id,
                        selected,
                        &tunnel.kind,
                        &tunnel.name,
                        &tunnel.route(),
                        label,
                        color,
                        |ui| {
                            ui.add_enabled_ui(!busy, |ui| {
                                style::lever(
                                    ui,
                                    active(&state),
                                    matches!(state.as_str(), "connecting" | "reconnecting"),
                                    color,
                                    pal,
                                    &if active(&state) {
                                        format!("Остановить туннель «{}»", tunnel.name)
                                    } else {
                                        format!("Запустить туннель «{}»", tunnel.name)
                                    },
                                    self.anim_ms().is_some(),
                                )
                                .clicked()
                            })
                            .inner
                        },
                    );
                    if row.lever {
                        self.selected = Some(tunnel.id.clone());
                        self.toggle(ctx, tunnel);
                    }
                    if row.response.clicked() {
                        self.selected = Some(tunnel.id.clone());
                    }
                    if row.response.double_clicked() {
                        self.selected = Some(tunnel.id.clone());
                        self.resolve(tunnel);
                    }
                }
            });
    }
    fn detail(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, tunnel: &Tunnel, pal: &Pal) {
        let state = self.state(tunnel).to_owned();
        let (label, color) = state_label(&state);
        let color = tone_of(pal, color);
        let runtime = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.runtimes.get(&tunnel.id))
            .cloned();
        let pending = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.prompts.get(&tunnel.id))
            .cloned();
        if let Some(pending) = &pending {
            let banner = egui::Frame::new()
                .fill(pal.warn)
                .corner_radius(4)
                .inner_margin(egui::Margin::symmetric(14, 10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(
                        RichText::new(format!(
                            "{} · {} — без вас туннель не откроется.",
                            prompt_title(&pending.request.kind),
                            pending.request.endpoint.address()
                        ))
                        .family(style::bold())
                        .color(pal.on_accent),
                    );
                    ui.label(
                        RichText::new("Остальные туннели продолжают работать.")
                            .color(pal.on_accent),
                    );
                })
                .response
                .interact(egui::Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand);
            if banner.clicked() {
                self.resolve(tunnel);
            }
            ui.add_space(12.0);
        }
        style::caps(ui, &format!("На участке · режим {}", tunnel.kind), pal.dim);
        ui.label(
            RichText::new(&tunnel.name)
                .family(style::bold())
                .size(30.0)
                .color(pal.ink),
        );
        ui.label(
            RichText::new(match tunnel.kind.as_str() {
                "R" => "Порт на SSH-сервере → сервис на вашем устройстве",
                "D" => "Локальный SOCKS5-прокси → сеть SSH-сервера",
                _ => "Локальный порт → сервис со стороны SSH-сервера",
            })
            .color(pal.dim),
        );
        ui.label(RichText::new(label).family(style::bold()).color(color));
        ui.add_space(6.0);
        let listen = format!(
            "{}:{}",
            crate::config::display_host(&tunnel.bind),
            tunnel.port
        );
        let far = format!(
            "{}:{}",
            crate::config::display_host(&tunnel.target),
            tunnel.target_port
        );
        let (first, last) = match tunnel.kind.as_str() {
            "R" => (("Порт на сервере", listen), ("Ваш сервис", far)),
            "D" => (
                ("SOCKS5 у вас", listen),
                ("Выход", "сеть SSH-сервера".to_owned()),
            ),
            _ => (("Ваш компьютер", listen), ("Сервис за сервером", far)),
        };
        let live = state == "running";
        let trying = matches!(state.as_str(), "connecting" | "reconnecting");
        let middle = if tunnel.jumps_enabled && !tunnel.jumps.is_empty() {
            format!(
                "{}\nчерез {} jump-хост(а)",
                tunnel.server.address(),
                tunnel.jumps.len()
            )
        } else {
            tunnel.server.address()
        };
        style::route(
            ui,
            &[
                style::Node {
                    title: first.0.into(),
                    value: first.1,
                    lit: live || trying,
                },
                style::Node {
                    title: "SSH-узел".into(),
                    value: middle,
                    lit: live,
                },
                style::Node {
                    title: last.0.into(),
                    value: last.1,
                    lit: live,
                },
            ],
            if live {
                [style::Wire::Live; 2]
            } else if trying {
                [style::Wire::Trying, style::Wire::Idle]
            } else {
                [style::Wire::Idle; 2]
            },
            color,
            self.anim_ms().map(|ms| ms as f64 / 1000.0),
            pal,
        );
        ui.add_space(10.0);
        style::facts(
            ui,
            &[
                ("SSH-узел", tunnel.server.address()),
                (
                    "Вход",
                    if tunnel.server.auth == "key" {
                        format!(
                            "{} · {}",
                            auth_label(&tunnel.server.auth),
                            tunnel.server.key
                        )
                    } else {
                        auth_label(&tunnel.server.auth).to_owned()
                    },
                ),
                (
                    "При следующем запуске",
                    if tunnel.enabled {
                        "восстановить туннель"
                    } else {
                        "оставить выключенным"
                    }
                    .to_owned(),
                ),
                (
                    "После разрыва",
                    if tunnel.reconnect {
                        "подключиться снова"
                    } else {
                        "ждать ручного запуска"
                    }
                    .to_owned(),
                ),
            ],
            pal,
        );
        if tunnel.jumps_enabled {
            for (index, jump) in tunnel.jumps.iter().enumerate() {
                ui.label(
                    RichText::new(format!(
                        "Через {}: {} · {}",
                        index + 1,
                        jump.address(),
                        auth_label(&jump.auth)
                    ))
                    .color(pal.dim),
                );
            }
        }
        if let Some(runtime) = runtime {
            if !runtime.hop.is_empty() && active(&state) {
                ui.label(RichText::new(&runtime.hop).color(pal.dim));
            }
            if !runtime.message.is_empty() {
                ui.colored_label(color, &runtime.message);
            }
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
                    style::primary(action, pal),
                )
                .clicked()
            {
                if state == "waiting" {
                    self.resolve(tunnel);
                } else {
                    self.toggle(ctx, tunnel);
                }
            }
            if state == "waiting" && ui.add(style::secondary("Выключить", pal)).clicked() {
                self.toggle(ctx, tunnel);
            }
            if ui.add(style::secondary("L Журнал", pal)).clicked() {
                self.dialog = Some(Dialog::Logs(tunnel.id.clone()));
            }
            if ui.add(style::secondary("E Изменить", pal)).clicked() {
                self.dialog = Some(Dialog::Form(Box::new(TunnelForm::new(Some(
                    tunnel.clone(),
                )))));
            }
            if ui.add(style::danger("Удалить", pal)).clicked() {
                self.confirm = Some(Confirm::Delete {
                    id: tunnel.id.clone(),
                    name: tunnel.name.clone(),
                });
            }
        });
        // After the tunnel's own actions, so that they stay in view in a small window.
        if tunnel.kind == "D" {
            ui.add_space(12.0);
            self.tunnel_udp(ui, ctx, tunnel, pal);
        }
    }
    /// UDP through the server relay: its state, its numbers and the switch.
    fn tunnel_udp(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, tunnel: &Tunnel, pal: &Pal) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let consent = snapshot.udp.consented(tunnel);
        let runtime = snapshot
            .udp_runtimes
            .get(&tunnel.id)
            .cloned()
            .unwrap_or_default();
        let (text, color) = if !consent {
            ("выключен".to_owned(), pal.dim)
        } else {
            let color = match runtime.state.as_str() {
                "running" => pal.ok,
                "unavailable" => pal.error,
                _ => pal.warn,
            };
            (crate::udp::state_text(&runtime), color)
        };
        let udp_error = snapshot.udp_error.clone();
        let metrics = snapshot.udp_metrics.get(&tunnel.id).cloned();
        let busy = self.pending_operations > 0;
        let mut clicked = false;
        egui::Frame::new()
            .stroke(Stroke::new(1.0_f32, pal.line))
            .corner_radius(4)
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(format!("UDP через сервер: {text}"))
                        .family(style::bold())
                        .color(color),
                );
                if !udp_error.is_empty() {
                    ui.colored_label(pal.error, &udp_error);
                }
                if let Some(metrics) = &metrics {
                    let lost: u64 = metrics.drops.values().sum::<u64>()
                        + metrics.relay.drops.values().sum::<u64>();
                    ui.label(
                        RichText::new(format!(
                            "Датаграмм ↑ {} · ↓ {} · потоков {} · потеряно {}",
                            metrics.sent.datagrams,
                            metrics.received.datagrams,
                            metrics.flows_active,
                            lost
                        ))
                        .monospace()
                        .color(pal.dim),
                    );
                    if let (Some(rtt), Some(queue)) =
                        (metrics.rtt.p95_us, metrics.to_channel_delay.p95_us)
                    {
                        ui.label(
                            RichText::new(format!(
                                "До сервера p95 {} мс · ожидание в очереди p95 {} мс",
                                rtt / 1000,
                                queue / 1000
                            ))
                            .monospace()
                            .color(pal.dim),
                        );
                    }
                }
                if !consent {
                    ui.label(
                        RichText::new("UDP приложений этого туннеля сейчас блокируется. Включение загрузит на сервер помощник КРОТа.")
                            .color(pal.dim),
                    );
                }
                let button = if consent {
                    style::secondary("Выключить UDP", pal)
                } else {
                    egui::Button::new(
                        RichText::new("Включить UDP через сервер…")
                            .family(style::bold())
                            .color(pal.accent),
                    )
                    .fill(Color32::TRANSPARENT)
                    .stroke(Stroke::new(1.0_f32, pal.accent))
                    .corner_radius(4)
                    .min_size(egui::vec2(0.0, 40.0))
                };
                clicked = ui
                    .add_enabled(!busy && udp_error.is_empty(), button)
                    .clicked();
            });
        if clicked {
            if consent {
                self.request(
                    ctx,
                    Operation::Udp,
                    "udp_tunnel",
                    json!({"id": tunnel.id, "enabled": false}),
                );
            } else {
                self.confirm = Some(Confirm::UdpConsent {
                    id: tunnel.id.clone(),
                    name: tunnel.name.clone(),
                });
            }
        }
    }
    fn dialog_view(&mut self, ctx: &egui::Context) -> Option<KeyTarget> {
        let mut dialog = self.dialog.take()?;
        let max_height = (ctx.content_rect().height() - 140.0).max(180.0);
        let width = (ctx.content_rect().width() - 90.0).min(660.0);
        let mut action = DialogAction::None;
        let pal = style::pal(ctx);
        let strip = match &dialog {
            Dialog::Prompt(prompt) if prompt.pending.request.kind == "hostchanged" => pal.warn,
            _ => pal.accent,
        };
        let width = match &dialog {
            Dialog::Help | Dialog::Logs(_) => (ctx.content_rect().width() - 70.0).min(940.0),
            _ => width,
        };
        let response = style::modal(ctx, "dialog", strip, |ui| {
            ui.set_width(width);
            match &mut dialog {
                Dialog::Form(form) => {
                    action = form_view(ui, form, max_height);
                }
                Dialog::AppForm(form) => {
                    let tunnels = self
                        .snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.config.tunnels.as_slice())
                        .unwrap_or_default();
                    action = app_form_view(ui, form, tunnels, max_height);
                }
                Dialog::Settings(settings) => {
                    action = settings_view(ui, settings, max_height, &pal);
                }
                Dialog::Prompt(prompt) => {
                    action = prompt_view(ui, ctx, prompt, max_height, &pal);
                }
                Dialog::Logs(id) => {
                    let tunnel = self
                        .snapshot
                        .as_ref()
                        .and_then(|snapshot| snapshot.config.tunnels.iter().find(|t| &t.id == id));
                    ui.horizontal_wrapped(|ui| {
                        ui.heading(format!(
                            "Журнал · {}",
                            tunnel.map(|t| t.name.as_str()).unwrap_or("туннель")
                        ));
                        ui.label(
                            RichText::new("Последние 300 записей · новые снизу")
                                .size(13.0)
                                .color(pal.dim),
                        );
                    });
                    ui.add_space(6.0);
                    egui::Frame::new()
                        .fill(pal.bg)
                        .stroke(Stroke::new(1.0_f32, pal.line))
                        .corner_radius(4)
                        .inner_margin(egui::Margin {
                            left: 22,
                            right: 12,
                            top: 10,
                            bottom: 10,
                        })
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            egui::ScrollArea::vertical()
                                .stick_to_bottom(true)
                                .max_height((max_height - 90.0).max(80.0))
                                .show(ui, |ui| {
                                    match self
                                        .snapshot
                                        .as_ref()
                                        .and_then(|snapshot| snapshot.runtimes.get(id))
                                    {
                                        Some(runtime) if !runtime.logs.is_empty() => {
                                            for line in &runtime.logs {
                                                log_line(ui, line, &pal);
                                            }
                                        }
                                        _ => {
                                            ui.label(
                                                RichText::new("Журнал пока пуст.").color(pal.dim),
                                            );
                                        }
                                    }
                                });
                        });
                    ui.add_space(8.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(style::primary("Назад", &pal)).clicked() {
                            action = DialogAction::Close;
                        }
                    });
                }
                Dialog::Help => {
                    action = help_view(ui, &self.update_check, max_height, &pal);
                }
                Dialog::Splash => {
                    action = self.splash_view(ui, max_height);
                }
                Dialog::About => {
                    action = self.about_view(ui, max_height);
                }
            }
        });
        let blocked = self.confirm.is_some()
            || dialog.saving()
            || matches!(&dialog, Dialog::Form(form) if form.picking());
        if response.should_close() && !blocked {
            action = DialogAction::Close;
        }
        if !blocked
            && matches!(
                &dialog,
                Dialog::Form(_) | Dialog::AppForm(_) | Dialog::Settings(_)
            )
            && ctx.input_mut(|input| {
                input.consume_key(egui::Modifiers::CTRL, Key::S)
                    || input.consume_key(egui::Modifiers::CTRL, Key::Enter)
            })
        {
            action = match &dialog {
                Dialog::Form(_) => DialogAction::SaveForm(false),
                Dialog::AppForm(_) => DialogAction::SaveApp,
                _ => DialogAction::SaveSettings,
            };
        }
        match action {
            DialogAction::None => self.dialog = Some(dialog),
            DialogAction::BrowseKey(target) => {
                self.dialog = Some(dialog);
                return Some(target);
            }
            DialogAction::NextAboutQuote => {
                self.about_quote = Some((self.about_quote.unwrap_or(0) + 1) % ABOUT_QUOTES.len());
                self.dialog = Some(dialog);
                ctx.request_repaint();
            }
            DialogAction::CheckUpdates => {
                self.dialog = Some(dialog);
                self.check_updates(ctx, true);
            }
            DialogAction::Close => {
                if dialog.dirty() {
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
            DialogAction::BrowseApp => {
                #[cfg(not(target_os = "linux"))]
                {
                    self.browse_app = true;
                }
                self.dialog = Some(dialog);
            }
            DialogAction::SaveApp => {
                if let (Dialog::AppForm(form), Some(snapshot)) = (&mut dialog, &self.snapshot) {
                    match form.candidate(&snapshot.apps, &snapshot.config.tunnels) {
                        Err(error) => form.error = error.to_string(),
                        Ok(rules) => {
                            form.busy = true;
                            form.error.clear();
                            self.request(
                                ctx,
                                Operation::SaveApp(form.draft.id.clone()),
                                "apps_save",
                                json!({"before": snapshot.apps, "rules": rules}),
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
        None
    }
    fn about_view(&mut self, ui: &mut egui::Ui, max_height: f32) -> DialogAction {
        let pal = style::pal(ui.ctx());
        let mut action = DialogAction::None;
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("О программе")
                    .family(style::bold())
                    .size(18.0)
                    .color(pal.dim),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(style::secondary("×", &pal).min_size(egui::vec2(40.0, 40.0)))
                    .on_hover_text("Закрыть")
                    .clicked()
                {
                    action = DialogAction::Close;
                }
            });
        });
        egui::ScrollArea::vertical()
            .id_salt("about")
            .max_height((max_height - 60.0).max(120.0))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    style::mole(
                        ui,
                        if max_height < 450.0 { 5.0 } else { 7.0 },
                        style::Pose::at(self.anim_ms(), true),
                        &pal,
                    );
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 4.0;
                        ui.label(
                            RichText::new("КРОТ")
                                .family(style::bold())
                                .size(52.0)
                                .color(pal.ink),
                        );
                        ui.label(
                            RichText::new(concat!("Версия ", env!("CARGO_PKG_VERSION")))
                                .monospace()
                                .color(pal.dim),
                        );
                        ui.label(RichText::new("Ваши туннели. Наша работа.").family(style::bold()));
                    });
                });
                ui.add_space(10.0);
                let quote = self.about_quote.unwrap_or(0);
                let frame = egui::Frame::new()
                    .fill(pal.bg)
                    .stroke(Stroke::new(1.0_f32, pal.line))
                    .corner_radius(4)
                    .inner_margin(egui::Margin {
                        left: 20,
                        right: 14,
                        top: 14,
                        bottom: 14,
                    })
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(format!("«{}»", ABOUT_QUOTES[quote]))
                                    .family(style::bold())
                                    .size(18.0)
                                    .color(pal.ink),
                            );
                            if ui.add(style::secondary("Ещё фраза", &pal)).clicked() {
                                action = DialogAction::NextAboutQuote;
                            }
                        });
                    });
                let rect = frame.response.rect;
                ui.painter().rect_filled(
                    egui::Rect::from_min_size(rect.min, egui::vec2(4.0, rect.height())),
                    egui::CornerRadius {
                        nw: 4,
                        sw: 4,
                        ne: 0,
                        se: 0,
                    },
                    pal.accent,
                );
                ui.add_space(8.0);
                ui.label(RichText::new("Менеджер SSH-туннелей от Dudod1n").color(pal.dim));
                ui.hyperlink_to(
                    RichText::new("github.com/Dudod1n/KPOT").monospace(),
                    env!("CARGO_PKG_REPOSITORY"),
                );
            });
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(RichText::new("GPL-3.0-only").color(pal.dim));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(style::primary("В диспетчерскую", &pal)).clicked() {
                    action = DialogAction::Close;
                }
            });
        });
        action
    }
    fn splash_view(&mut self, ui: &mut egui::Ui, max_height: f32) -> DialogAction {
        let pal = style::pal(ui.ctx());
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
        let tunnels = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.config.tunnels.clone())
            .unwrap_or_default();
        let enabled: Vec<_> = tunnels.iter().filter(|tunnel| tunnel.enabled).collect();
        let count = |state: &str| {
            enabled
                .iter()
                .filter(|tunnel| self.state(tunnel) == state)
                .count()
        };
        let (running, waiting, errors) = (count("running"), count("waiting"), count("error"));
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
        let small = max_height < 450.0;
        ui.vertical_centered(|ui| {
            style::mole(
                ui,
                if small { 4.0 } else { 7.0 },
                style::Pose::at(self.anim_ms(), true),
                &pal,
            );
            style::caps(ui, "КРОТ / ВОССТАНОВЛЕНИЕ", pal.dim);
            ui.label(
                RichText::new(title)
                    .family(style::bold())
                    .size(if small { 22.0 } else { 30.0 })
                    .color(pal.ink),
            );
            ui.label(
                RichText::new(format!(
                    "{} из {} работают · {} ждут вас · {} с ошибкой",
                    running,
                    enabled.len(),
                    waiting,
                    errors
                ))
                .color(pal.dim),
            );
        });
        ui.add_space(8.0);
        let blink_on = self.anim_ms().is_none_or(|ms| ms / 600 % 2 == 0);
        egui::ScrollArea::vertical()
            .max_height((max_height - if small { 200.0 } else { 300.0 }).max(70.0))
            .show(ui, |ui| {
                for tunnel in tunnels {
                    let state = self.state(&tunnel).to_owned();
                    let (label, tone) = if tunnel.enabled {
                        state_label(&state)
                    } else {
                        ("○ Выключен при запуске", Tone::Dim)
                    };
                    let color = tone_of(&pal, tone);
                    let selected = self.selected.as_ref() == Some(&tunnel.id);
                    let frame = egui::Frame::new()
                        .fill(if selected { pal.raised } else { pal.bg })
                        .stroke(Stroke::new(1.0_f32, pal.line))
                        .corner_radius(6)
                        .inner_margin(egui::Margin {
                            left: 18,
                            right: 10,
                            top: 8,
                            bottom: 8,
                        })
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                let (dot, _) = ui.allocate_exact_size(
                                    egui::vec2(18.0, 18.0),
                                    egui::Sense::hover(),
                                );
                                let blinking = matches!(
                                    state.as_str(),
                                    "connecting" | "reconnecting" | "waiting"
                                );
                                let shown = if blinking && !blink_on {
                                    color.gamma_multiply(0.3)
                                } else {
                                    color
                                };
                                if tunnel.enabled && !matches!(state.as_str(), "stopped" | "idle") {
                                    ui.painter().circle_filled(dot.center(), 7.0, shown);
                                }
                                ui.painter().circle_stroke(
                                    dot.center(),
                                    7.0,
                                    Stroke::new(2.0_f32, shown),
                                );
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 2.0;
                                    ui.label(
                                        RichText::new(format!("{} · {}", tunnel.kind, tunnel.name))
                                            .family(style::bold()),
                                    );
                                    ui.label(
                                        RichText::new(tunnel.route())
                                            .monospace()
                                            .size(13.0)
                                            .color(pal.dim),
                                    );
                                });
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if matches!(state.as_str(), "waiting" | "error")
                                            && ui
                                                .add(
                                                    egui::Button::new(
                                                        RichText::new(if state == "waiting" {
                                                            "Разобраться"
                                                        } else {
                                                            "Повторить"
                                                        })
                                                        .family(style::bold())
                                                        .color(color),
                                                    )
                                                    .fill(Color32::TRANSPARENT)
                                                    .stroke(Stroke::new(1.0_f32, color))
                                                    .corner_radius(4)
                                                    .min_size(egui::vec2(0.0, 36.0)),
                                                )
                                                .clicked()
                                        {
                                            self.selected = Some(tunnel.id.clone());
                                            action = DialogAction::Resolve(tunnel.id.clone());
                                        }
                                        ui.label(RichText::new(label).color(color));
                                    },
                                );
                            });
                        });
                    let rect = frame.response.rect;
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(rect.min, egui::vec2(6.0, rect.height())),
                        egui::CornerRadius {
                            nw: 6,
                            sw: 6,
                            ne: 0,
                            se: 0,
                        },
                        if tunnel.enabled { color } else { pal.line },
                    );
                    if ui
                        .interact(
                            egui::Rect::from_min_max(
                                rect.min,
                                egui::pos2(rect.center().x, rect.max.y),
                            ),
                            ui.id().with(("splash_row", &tunnel.id)),
                            egui::Sense::click(),
                        )
                        .clicked()
                    {
                        self.selected = Some(tunnel.id.clone());
                    }
                    ui.add_space(2.0);
                }
            });
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            if ui.add(style::primary("В диспетчерскую", &pal)).clicked() {
                action = DialogAction::Close;
            }
            if ui.add(style::secondary("Выйти", &pal)).clicked() {
                action = DialogAction::Exit;
            }
        });
        ui.label(
            RichText::new("Enter или Esc — в диспетчерскую, подключение продолжится.")
                .size(13.0)
                .color(pal.dim),
        );
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
        let pal = style::pal(ctx);
        let strip = match &confirm {
            Confirm::Delete { .. } | Confirm::DeleteApp { .. } | Confirm::UdpConsent { .. } => {
                pal.warn
            }
            _ => pal.accent,
        };
        let dialog_is_app = matches!(self.dialog, Some(Dialog::AppForm(_)));
        let shutdown_busy = self.shutdown_busy;
        let width = match &confirm {
            Confirm::UdpConsent { .. } => (ctx.content_rect().width() - 100.0).min(760.0),
            _ => (ctx.content_rect().width() - 100.0).min(600.0),
        };
        let response = style::modal(ctx, "confirmation", strip, |ui| {
            ui.set_width(width);
            let row = |ui: &mut egui::Ui, add: &mut dyn FnMut(&mut egui::Ui)| {
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| add(ui));
            };
            match &mut confirm {
                Confirm::Delete { name, .. } => {
                    ui.heading("Удалить туннель?");
                    ui.label(format!(
                        "«{name}» будет удалён из настроек. Его соединение и порт закроются."
                    ));
                    row(ui, &mut |ui| {
                        if ui.add(style::secondary("Отмена", &pal)).clicked() {
                            choice = 1;
                        }
                        if ui.add(style::filled("Удалить", pal.error, &pal)).clicked() {
                            choice = 2;
                        }
                    });
                }
                Confirm::DeleteApp { name, .. } => {
                    ui.heading("Удалить правило?");
                    ui.label(format!(
                        "«{name}» будет удалено. Приложение снова пойдёт в сеть напрямую."
                    ));
                    row(ui, &mut |ui| {
                        if ui.add(style::secondary("Отмена", &pal)).clicked() {
                            choice = 1;
                        }
                        if ui.add(style::filled("Удалить", pal.error, &pal)).clicked() {
                            choice = 2;
                        }
                    });
                }
                Confirm::UdpConsent { name, .. } => {
                    ui.heading("Включить UDP через сервер?");
                    ui.label(format!("Для туннеля «{name}» КРОТ загрузит на SSH-сервер свой помощник krot-relay (около 0,4 МиБ) в каталог ~/.cache/krot и будет запускать его, пока туннель работает. UDP приложений из правил этого туннеля пойдёт в сеть с адреса сервера."));
                    for (text, border) in [
                        (
                            "Помощник работает с правами вашей учётной записи на сервере и ничего не записывает, кроме своего файла. Управление идёт через отдельное SSH-соединение, снаружи это по-прежнему SSH. Для каждого UDP-потока приложения помощник открывает на сервере временный UDP-порт и принимает на него ответы с любого адреса — так работают звонки и WebRTC.",
                            pal.line,
                        ),
                        (
                            "Помощник даёт UDP-выход и там, где администратор сервера запретил переадресацию портов (AllowTcpForwarding no). Убедитесь, что это допустимо на этом сервере.",
                            pal.warn,
                        ),
                        (
                            "Согласие действует только для этого сервера и учётной записи. Выключение UDP, смена сервера или удаление туннеля удаляют помощник с сервера, если он доступен.",
                            pal.line,
                        ),
                    ] {
                        egui::Frame::new()
                            .fill(pal.bg)
                            .stroke(Stroke::new(1.0_f32, border))
                            .corner_radius(4)
                            .inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(text).size(14.0).color(
                                            if border == pal.warn { pal.ink } else { pal.dim },
                                        ),
                                    )
                                    .wrap(),
                                );
                            });
                    }
                    row(ui, &mut |ui| {
                        if ui.add(style::secondary("Отмена", &pal)).clicked() {
                            choice = 1;
                        }
                        if ui.add(style::alarm("Загрузить и включить", &pal)).clicked()
                        {
                            choice = 2;
                        }
                    });
                }
                Confirm::Discard { .. } => {
                    ui.heading("Несохранённые изменения");
                    ui.label(if dialog_is_app {
                        "Отменить изменения в этом правиле?"
                    } else {
                        "Отменить изменения в этом туннеле?"
                    });
                    row(ui, &mut |ui| {
                        if ui
                            .add(style::primary("Продолжить редактирование", &pal))
                            .clicked()
                        {
                            choice = 1;
                        }
                        if ui.add(style::danger("Отменить изменения", &pal)).clicked()
                        {
                            choice = 2;
                        }
                    });
                }
                Confirm::CloseNotice {
                    dont_show_again,
                    busy,
                    error,
                } => {
                    ui.heading("КРОТ продолжит работать в фоне");
                    ui.label("Туннели останутся подключены. Чтобы открыть диспетчерскую, нажмите значок КРОТа в трее.");
                    ui.label(RichText::new("Остановить КРОТ и закрыть соединения можно через меню значка в трее или «Q Выход».").color(pal.dim));
                    ui.add_enabled_ui(!*busy, |ui| {
                        ui.checkbox(dont_show_again, "Больше не показывать");
                        if !error.is_empty() {
                            ui.colored_label(pal.error, error.as_str());
                        }
                        row(ui, &mut |ui| {
                            if ui.add(style::secondary("Назад", &pal)).clicked() {
                                choice = 1;
                            }
                            if ui.add(style::primary("Понятно", &pal)).clicked() {
                                choice = 2;
                            }
                        });
                    });
                    if *busy {
                        ui.label(RichText::new("Запоминаем выбор…").color(pal.dim));
                    }
                    if !*busy
                        && ctx
                            .input_mut(|input| input.consume_key(egui::Modifiers::NONE, Key::Enter))
                    {
                        choice = 2;
                    }
                }
                Confirm::Exit => {
                    ui.heading("Закрыть диспетчерскую?");
                    ui.label("В фоне КРОТ продолжит держать туннели. Значок в трее или повторный запуск откроет их текущее состояние.");
                    ui.label(RichText::new("«Остановить КРОТ» закроет все соединения. Включённые туннели восстановятся при следующем запуске.").color(pal.dim));
                    ui.add_enabled_ui(!shutdown_busy, |ui| {
                        row(ui, &mut |ui| {
                            if ui.add(style::secondary("Назад", &pal)).clicked() {
                                choice = 1;
                            }
                            if ui.add(style::primary("Оставить в фоне", &pal)).clicked()
                            {
                                choice = 2;
                            }
                            if ui.add(style::danger("Остановить КРОТ", &pal)).clicked()
                            {
                                choice = 3;
                            }
                        });
                    });
                    if shutdown_busy {
                        ui.label(RichText::new("Закрываем соединения…").color(pal.dim));
                    }
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
                Confirm::DeleteApp { id, .. } => {
                    if let Some(snapshot) = &self.snapshot {
                        let rules: Vec<_> = snapshot
                            .apps
                            .iter()
                            .filter(|rule| rule.id != id)
                            .cloned()
                            .collect();
                        self.request(
                            ctx,
                            Operation::Delete,
                            "apps_save",
                            json!({"before": snapshot.apps, "rules": rules}),
                        );
                    }
                }
                Confirm::UdpConsent { id, .. } => {
                    self.request(
                        ctx,
                        Operation::Udp,
                        "udp_tunnel",
                        json!({"id": id, "enabled": true}),
                    );
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
        let pal = style::pal(ctx);
        let strip = if matches!(update.stage, UpdateStage::Failed(_)) {
            pal.error
        } else {
            pal.accent
        };
        let response = style::modal(ctx, "update", strip, |ui| {
            ui.set_width((ctx.content_rect().width() - 100.0).min(600.0));
            ui.heading(format!("Доступен КРОТ {}", update.release.version));
            match &update.stage {
                UpdateStage::Offer => {
                    ui.label("Обновить программу и перезапустить КРОТ?");
                    ui.label(
                        RichText::new(
                            "До завершения скачивания и проверки файлов туннели продолжат работать.",
                        )
                        .color(pal.dim),
                    );
                    if !update.error.is_empty() {
                        ui.colored_label(pal.error, &update.error);
                    }
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.add(style::primary("Обновить", &pal)).clicked() {
                            choice = 1;
                        }
                        if !update.manual
                            && ui
                                .add(style::secondary("Пропустить версию", &pal))
                                .clicked()
                        {
                            choice = 2;
                        }
                        if ui.add(style::secondary("Позже", &pal)).clicked() {
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
                    ui.label(
                        RichText::new(
                            "Туннели продолжают работать. Дождитесь завершения подготовки.",
                        )
                        .color(pal.dim),
                    );
                }
                UpdateStage::Launching => {
                    ui.spinner();
                    ui.label("Запускаем установщик…");
                }
                UpdateStage::Failed(error) => {
                    ui.colored_label(pal.error, error);
                    if !update.error.is_empty() {
                        ui.label(&update.error);
                    }
                    ui.label("Проверьте подключение к сети и права записи в каталог программы.");
                    ui.label(
                        RichText::new("Текущие файлы программы и туннели сохранены.")
                            .color(pal.dim),
                    );
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.add(style::primary("Повторить", &pal)).clicked() {
                            choice = 1;
                        }
                        if ui.add(style::secondary("Вернуться в КРОТ", &pal)).clicked()
                        {
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
    fn draw(&mut self, ctx: &egui::Context) -> Option<KeyTarget> {
        style::sync_fonts(ctx);
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
        let key_target = if self.confirm.is_none() {
            self.dialog_view(ctx)
        } else {
            None
        };
        self.update_view(ctx);
        self.confirm_view(ctx);
        self.poll(ctx);
        ctx.request_repaint_after(FRAME_TIME);
        key_target
    }
}
impl eframe::App for Desktop {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        let key_target = self.draw(ctx);
        // The native dialog runs its own modal loop.
        #[cfg(not(target_os = "linux"))]
        if std::mem::take(&mut self.browse_app)
            && let Some(Dialog::AppForm(form)) = &mut self.dialog
        {
            let picked = rfd::FileDialog::new()
                .set_title("Выберите исполняемый файл")
                .set_parent(frame)
                .pick_file();
            if let Some(path) = picked {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_owned();
                match path.into_os_string().into_string() {
                    Ok(path) => form.select_path(path, &name),
                    Err(_) => {
                        form.error =
                            "Не удалось использовать путь: имя файла должно быть в Unicode.".into()
                    }
                }
            }
            ctx.request_repaint();
        }
        if let Some(target) = key_target
            && let Some(Dialog::Form(form)) = &mut self.dialog
            && let Some(backend) = &self.backend
        {
            let directory = target
                .endpoint(&mut form.draft)
                .and_then(|endpoint| key_directory(&endpoint.key));
            #[cfg(target_os = "linux")]
            {
                let parent = window_identifier(frame, &backend.runtime);
                self.key_picks += 1;
                let (id, tx, ctx) = (self.key_picks, self.tx.clone(), ctx.clone());
                let cancel = tokio_util::sync::CancellationToken::new();
                let closed = cancel.clone();
                backend.runtime.spawn(async move {
                    let result = portal_key_file(parent, directory.as_deref(), closed)
                        .await
                        .map_err(|_| ());
                    let _ = tx.send(Event::KeyPicked { id, result });
                    ctx.request_repaint();
                });
                form.picking = Some(KeyPick {
                    id,
                    target,
                    _cancel: cancel.drop_guard(),
                });
            }
            // The native dialog runs its own modal loop.
            #[cfg(not(target_os = "linux"))]
            {
                let _ = backend;
                match pick_key_file(frame, directory.as_deref()) {
                    Ok(path) => form.select_key(target, path),
                    Err(_) => form.error = KEY_DIALOG_ERROR.into(),
                }
            }
            ctx.request_repaint();
        }
    }
}

/// Filter of long lists by what a row needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Group {
    All,
    Live,
    Attention,
    Off,
}

fn tone_of(pal: &Pal, tone: Tone) -> Color32 {
    match tone {
        Tone::Ok => pal.ok,
        Tone::Warn => pal.warn,
        Tone::Error => pal.error,
        Tone::Dim => pal.dim,
    }
}

struct Row {
    response: egui::Response,
    lever: bool,
}

/// A list card: side strip, mode badge, name, route, state and the lever on the right.
#[allow(clippy::too_many_arguments)]
fn list_row(
    ui: &mut egui::Ui,
    pal: &Pal,
    id: &str,
    selected: bool,
    badge: &str,
    name: &str,
    detail: &str,
    status: &str,
    color: Color32,
    lever: impl FnOnce(&mut egui::Ui) -> bool,
) -> Row {
    let mut lever_clicked = false;
    let mut lever_left = f32::INFINITY;
    let frame = egui::Frame::new()
        .fill(if selected { pal.raised } else { pal.panel })
        .stroke(Stroke::new(1.0_f32, pal.line))
        .corner_radius(6)
        .inner_margin(egui::Margin {
            left: 14,
            right: 6,
            top: 6,
            bottom: 6,
        });
    let inner = frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_top(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(40.0, 40.0), egui::Sense::hover());
            ui.painter().rect(
                rect,
                4,
                pal.bg,
                Stroke::new(1.0_f32, pal.line),
                egui::StrokeKind::Inside,
            );
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                badge,
                egui::FontId::new(20.0, style::bold()),
                pal.ink,
            );
            let text_width = (ui.available_width() - 84.0).max(80.0);
            ui.allocate_ui_with_layout(
                egui::vec2(text_width, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.add(
                        egui::Label::new(
                            RichText::new(name)
                                .family(style::bold())
                                .size(16.0)
                                .color(pal.ink),
                        )
                        .truncate(),
                    );
                    ui.add(
                        egui::Label::new(
                            RichText::new(detail).monospace().size(13.0).color(pal.dim),
                        )
                        .truncate(),
                    );
                    ui.add(egui::Label::new(RichText::new(status).size(14.0).color(color)).wrap());
                },
            );
        });
        // Text starts at the top next to the badge; the lever stays centred on the right.
        let content = ui.min_rect();
        let lever_rect = egui::Rect::from_min_max(
            egui::pos2(content.right() - 84.0, content.top()),
            content.max,
        );
        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(lever_rect)
                .layout(egui::Layout::right_to_left(egui::Align::Center)),
            |ui| {
                let scope = ui.scope(lever);
                lever_clicked = scope.inner;
                lever_left = scope.response.rect.left();
            },
        );
    });
    let rect = inner.response.rect;
    ui.painter().rect_filled(
        egui::Rect::from_min_size(rect.min, egui::vec2(6.0, rect.height())),
        egui::CornerRadius {
            nw: 6,
            sw: 6,
            ne: 0,
            se: 0,
        },
        if selected { pal.accent } else { pal.line },
    );
    let click_rect = egui::Rect::from_min_max(
        rect.min,
        egui::pos2(lever_left.min(rect.right()), rect.max.y),
    );
    let response = ui.interact(click_rect, ui.id().with(("row", id)), egui::Sense::click());
    Row {
        response,
        lever: lever_clicked,
    }
}

/// A journal line: monospace, with a coloured mark on success and warning lines.
fn log_line(ui: &mut egui::Ui, line: &str, pal: &Pal) {
    let lower = line.to_lowercase();
    let mark = if ["ошибк", "не удалось", "потерян", "разрыв", "отказ"]
        .iter()
        .any(|word| lower.contains(word))
    {
        Some(pal.warn)
    } else if ["слушаем", "открыт", "выполнен", "загружен", "работает"]
        .iter()
        .any(|word| lower.contains(word))
    {
        Some(pal.ok)
    } else {
        None
    };
    let response = ui.add(
        egui::Label::new(
            RichText::new(line)
                .monospace()
                .color(mark.unwrap_or(pal.ink)),
        )
        .wrap(),
    );
    if let Some(color) = mark {
        let rect = response.rect;
        ui.painter().rect_filled(
            egui::Rect::from_min_size(
                egui::pos2(rect.left() - 10.0, rect.top()),
                egui::vec2(3.0, rect.height()),
            ),
            0,
            color,
        );
    }
}

/// Settings: colour themes as cards with samples, classic themes in a row of their own.
fn settings_view(
    ui: &mut egui::Ui,
    settings: &mut SettingsDraft,
    max_height: f32,
    pal: &Pal,
) -> DialogAction {
    let mut action = DialogAction::None;
    ui.heading("Настройки");
    if settings.busy {
        ui.disable();
    }
    egui::ScrollArea::vertical()
        .id_salt("settings_scroll")
        .max_height((max_height - 70.0).max(120.0))
        .show(ui, |ui| {
            ui.add_space(6.0);
            ui.label(RichText::new("Тема оформления").family(style::bold()));
            ui.horizontal_wrapped(|ui| {
                for theme in ["build", "night", "danger", "stealth"] {
                    let Some(colors) = palette(theme) else {
                        continue;
                    };
                    let selected = settings.theme == theme;
                    let mark = if selected {
                        "● выбрана"
                    } else if theme == "build" {
                        "по умолчанию"
                    } else {
                        ""
                    };
                    if style::theme_card(ui, theme_label(theme), mark, &colors, selected).clicked()
                    {
                        settings.theme = theme.into();
                    }
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Классические:").color(pal.dim));
                for theme in ["dark", "light", "system"] {
                    if ui
                        .add(style::choice(
                            theme_label(theme),
                            settings.theme == theme,
                            pal,
                        ))
                        .clicked()
                    {
                        settings.theme = theme.into();
                    }
                }
            });
            ui.add_space(6.0);
            ui.separator();
            ui.checkbox(&mut settings.motion, "Анимация кротов");
            ui.checkbox(&mut settings.splash, "Восстановление туннелей при запуске");
            if let Some(enabled) = &mut settings.autostart {
                ui.checkbox(enabled, "Запускать КРОТ в фоне после входа в систему");
            } else {
                ui.add_enabled(
                    false,
                    egui::Checkbox::new(
                        &mut false,
                        if settings.error.is_empty() {
                            "Автозапуск: проверяем состояние…"
                        } else {
                            "Автозапуск недоступен"
                        },
                    ),
                );
            }
        });
    if !settings.error.is_empty() {
        ui.colored_label(pal.error, &settings.error);
    }
    ui.separator();
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new("Тема применяется после сохранения.")
                .size(13.0)
                .color(pal.dim),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add_enabled(!settings.busy, style::primary("Сохранить", pal))
                .clicked()
            {
                action = DialogAction::SaveSettings;
            }
            if ui
                .add_enabled(!settings.busy, style::secondary("Отмена", pal))
                .clicked()
            {
                action = DialogAction::Close;
            }
        });
    });
    action
}

/// A login request: a changed host key with both fingerprints, or a password.
fn prompt_view(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    prompt: &mut PromptDialog,
    max_height: f32,
    pal: &Pal,
) -> DialogAction {
    let mut action = DialogAction::None;
    let request = prompt.pending.request.clone();
    let key = matches!(request.kind.as_str(), "trust" | "hostchanged");
    let changed = request.kind == "hostchanged";
    ui.horizontal(|ui| {
        style::sign(
            ui,
            if key { '!' } else { '*' },
            if changed { pal.warn } else { pal.accent },
        );
        ui.heading(prompt_title(&request.kind));
    });
    egui::ScrollArea::vertical()
        .max_height((max_height - 70.0).max(120.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new(&request.tunnel_name)
                    .family(style::bold())
                    .size(17.0),
            );
            ui.label(RichText::new(&request.hop).color(pal.dim));
            ui.label(RichText::new(request.endpoint.address()).monospace());
            if !request.message.is_empty() {
                ui.label(&request.message);
            }
            ui.add_space(6.0);
            if key {
                egui::Frame::new()
                    .fill(pal.bg)
                    .stroke(Stroke::new(1.0_f32, pal.line))
                    .corner_radius(4)
                    .inner_margin(egui::Margin::same(14))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        if changed {
                            ui.label(RichText::new("Сохранённый ключ").size(13.0).color(pal.dim));
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&request.old_fingerprint)
                                        .monospace()
                                        .strikethrough()
                                        .color(pal.dim),
                                )
                                .wrap(),
                            );
                            ui.add_space(4.0);
                        }
                        ui.label(RichText::new("Полученный ключ").size(13.0).color(pal.dim));
                        ui.add(
                            egui::Label::new(
                                RichText::new(&request.new_fingerprint)
                                    .monospace()
                                    .color(pal.warn),
                            )
                            .wrap(),
                        );
                    });
                ui.label(
                    RichText::new("Сверьте отпечаток с администратором по независимому каналу.")
                        .color(pal.dim),
                );
                if changed {
                    ui.checkbox(&mut prompt.verified, "Я проверил новый отпечаток");
                }
            } else {
                ui.label(
                    RichText::new(if request.kind == "passphrase" {
                        "Пароль ключа"
                    } else {
                        "Пароль SSH"
                    })
                    .size(13.0)
                    .color(pal.dim),
                );
                let mut edit = egui::TextEdit::singleline(&mut prompt.secret)
                    .password(true)
                    .margin(egui::vec2(10.0, 10.0))
                    .desired_width(f32::INFINITY)
                    .show(ui);
                // Passwords must not remain in the widget's undo history.
                edit.state.clear_undoer();
                edit.state.store(ctx, edit.response.id);
                if !edit.response.has_focus() && ui.memory(|memory| memory.focused().is_none()) {
                    edit.response.request_focus();
                }
                ui.label(
                    RichText::new("Секрет используется для подключения и не сохраняется.")
                        .color(pal.dim),
                );
                if (edit.response.has_focus() || edit.response.lost_focus())
                    && ctx.input(|input| input.key_pressed(Key::Enter))
                    && prompt.may_accept()
                {
                    action = DialogAction::Answer;
                }
            }
        });
    ui.separator();
    ui.horizontal_wrapped(|ui| {
        if ui.add(style::secondary("Позже", pal)).clicked() {
            action = DialogAction::Close;
        }
        if ui
            .add(style::secondary("Отменить подключение", pal))
            .clicked()
        {
            action = DialogAction::CancelPrompt;
        }
        let accept = if changed {
            style::alarm("Заменить ключ и подключиться", pal)
        } else {
            style::primary("Продолжить", pal)
        };
        if ui.add_enabled(prompt.may_accept(), accept).clicked() {
            action = DialogAction::Answer;
        }
    });
    action
}

const HELP_KEYS: [(&str, &str); 10] = [
    ("1 / 2", "Вкладки «Туннели» и «Приложения»"),
    ("↑ / ↓", "Выбрать туннель или правило"),
    ("Space", "Запуск / остановка / отмена подключения"),
    ("Enter", "Открыть запрос ожидающего туннеля"),
    ("N / E", "Создать / изменить"),
    ("L", "Журнал"),
    ("Delete", "Удалить"),
    ("S", "Настройки"),
    ("? / F1", "Справка"),
    ("Q", "Меню выхода"),
];
const HELP_FORM_KEYS: [(&str, &str); 3] = [
    ("Tab / Shift+Tab", "Следующее / предыдущее поле"),
    ("Ctrl+S / Ctrl+Enter", "Сохранить"),
    ("Esc", "Назад / отмена"),
];
const HELP_MODES: [(&str, &str); 3] = [
    ("L", "Локальный порт → сервис со стороны SSH-сервера."),
    (
        "R",
        "Порт на SSH-сервере → сервис со стороны вашего устройства.",
    ),
    ("D", "Локальный SOCKS5-прокси → сеть SSH-сервера."),
];
const HELP_NOTES: [&str; 6] = [
    "Приложения: правило направляет трафик выбранного исполняемого файла через туннель типа D. UDP идёт через туннель, если в карточке туннеля включён «UDP через сервер» (на сервер загружается помощник КРОТа); иначе UDP блокируется. QUIC (UDP 443) блокируется, пока в карточке правила не включено его туннелирование. Если туннель не работает, сеть приложения закрыта, пока в правиле не выбрано «Пускать напрямую»: тогда напрямую идёт весь трафик, включая UDP.",
    "Jump-хосты используются по порядку сверху вниз. У каждого собственные параметры входа.",
    "Пароли не сохраняются. Новые и изменённые ключи узлов требуют проверки. «Позже» оставляет запрос на туннеле: откройте его кнопкой «Разобраться». Остальные туннели продолжают работать.",
    "Крестик закрывает диспетчерскую, а КРОТ и туннели продолжают работать в фоне. Открыть окно снова можно через значок в трее или повторным запуском КРОТа. Q или «Выход» открывают меню: оставить туннели в фоне или остановить КРОТа. Включённые туннели восстановятся после нового запуска. Ручная остановка выключает восстановление этого туннеля. Ошибка подключения не сбрасывает выбор.",
    "В настройках можно включить запуск в фоне после входа в систему. Если требуется пароль или проверка узла, туннель ждёт открытия диспетчерской.",
    "На заставке «В диспетчерскую» и Enter / Esc открывают список, подключение продолжается.",
];

/// Help: keys as a table, modes and notes, and the update check.
fn help_view(ui: &mut egui::Ui, check: &UpdateCheck, max_height: f32, pal: &Pal) -> DialogAction {
    let mut action = DialogAction::None;
    ui.heading("Справка");
    let keys = |ui: &mut egui::Ui, id: &str, rows: &[(&str, &str)]| {
        egui::Grid::new(id)
            .num_columns(2)
            .spacing([14.0, 8.0])
            .show(ui, |ui| {
                for (key, text) in rows {
                    ui.horizontal(|ui| {
                        for (index, part) in key.split(" / ").enumerate() {
                            if index > 0 {
                                ui.label(RichText::new("/").color(pal.dim));
                            }
                            style::kbd(ui, part, pal);
                        }
                    });
                    ui.label(*text);
                    ui.end_row();
                }
            });
    };
    let left = |ui: &mut egui::Ui| {
        style::caps(ui, "Диспетчерская", pal.dim);
        keys(ui, "help_keys", &HELP_KEYS);
        ui.add_space(8.0);
        style::caps(ui, "В формах", pal.dim);
        keys(ui, "help_form_keys", &HELP_FORM_KEYS);
    };
    let right = |ui: &mut egui::Ui| {
        style::caps(ui, "Режимы", pal.dim);
        for (mode, text) in HELP_MODES {
            ui.horizontal_top(|ui| {
                ui.add_sized(
                    [22.0, 22.0],
                    egui::Label::new(
                        RichText::new(mode)
                            .family(style::bold())
                            .size(17.0)
                            .color(pal.accent),
                    ),
                );
                ui.add(egui::Label::new(text).wrap());
            });
        }
        ui.add_space(8.0);
        style::caps(ui, "Важно знать", pal.dim);
        for note in HELP_NOTES {
            ui.add(egui::Label::new(note).wrap());
        }
    };
    egui::ScrollArea::vertical()
        .id_salt("help_scroll")
        .max_height((max_height - 110.0).max(80.0))
        .show(ui, |ui| {
            if ui.available_width() >= 760.0 {
                ui.columns(2, |columns| {
                    // Columns justify their layout, which would stretch the notes word by word.
                    let plain = egui::Layout::top_down(egui::Align::Min);
                    columns[0].with_layout(plain, left);
                    columns[1].with_layout(plain, right);
                });
            } else {
                left(ui);
                ui.add_space(8.0);
                right(ui);
            }
        });
    ui.separator();
    ui.horizontal_wrapped(|ui| {
        let checking = matches!(check, UpdateCheck::Checking);
        if ui
            .add_enabled(!checking, style::secondary("Проверить обновление", pal))
            .clicked()
        {
            action = DialogAction::CheckUpdates;
        }
        if checking {
            ui.spinner();
            ui.label("Проверяем обновления…");
        }
        match check {
            UpdateCheck::Current => {
                ui.label("Обновлений нет.");
            }
            UpdateCheck::Failed => {
                ui.colored_label(
                    pal.error,
                    "Не удалось проверить обновления. Проверьте подключение к сети и повторите попытку.",
                );
            }
            _ => {}
        }
    });
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        if ui.add(style::primary("Назад", pal)).clicked() {
            action = DialogAction::Close;
        }
    });
    action
}

enum DialogAction {
    None,
    BrowseKey(KeyTarget),
    NextAboutQuote,
    Close,
    SaveForm(bool),
    SaveApp,
    BrowseApp,
    SaveSettings,
    CheckUpdates,
    Answer,
    CancelPrompt,
    Resolve(String),
    Exit,
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    let pal = style::pal(ui.ctx());
    style::field(ui, label, value, &pal);
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
        "build" => "Стройка",
        "night" => "Тьма, ночь",
        "danger" => "Опасность",
        "stealth" => "Скрытность",
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
) -> bool {
    let pal = style::pal(ui.ctx());
    let mut browse = false;
    ui.push_id(id, |ui| {
        style::group(ui, title, pal.ink, &pal, |ui| {
            ui.columns(3, |columns| {
                field(&mut columns[0], "SSH-хост", &mut endpoint.host);
                field(&mut columns[1], "SSH-порт", port);
                field(&mut columns[2], "Пользователь", &mut endpoint.user);
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Авторизация").size(13.0).color(pal.dim));
                for auth in ["agent", "password", "key"] {
                    if ui
                        .add(style::choice(auth_label(auth), endpoint.auth == auth, &pal))
                        .clicked()
                    {
                        endpoint.auth = auth.into();
                    }
                }
            });
            match endpoint.auth.as_str() {
                "agent" => {
                    ui.label(
                        RichText::new("Нужен работающий SSH-agent с добавленным ключом.")
                            .size(13.0)
                            .color(pal.dim),
                    );
                }
                "password" => {
                    ui.label(
                        RichText::new("Пароль спросим при подключении. Он не сохраняется.")
                            .size(13.0)
                            .color(pal.dim),
                    );
                }
                _ => {}
            }
            ui.add_enabled_ui(endpoint.auth == "key", |ui| {
                ui.label(
                    RichText::new("Файл приватного ключа")
                        .size(13.0)
                        .color(pal.dim),
                );
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        browse = ui.add(style::secondary("Обзор…", &pal)).clicked();
                        ui.add(
                            egui::TextEdit::singleline(&mut endpoint.key)
                                .font(egui::TextStyle::Monospace)
                                .margin(egui::vec2(10.0, 9.0))
                                .desired_width(ui.available_width()),
                        );
                    });
                });
            });
        });
    });
    browse
}
fn form_view(ui: &mut egui::Ui, form: &mut TunnelForm, max_height: f32) -> DialogAction {
    let pal = style::pal(ui.ctx());
    let mut action = DialogAction::None;
    ui.heading(if form.editing {
        "Редактирование туннеля"
    } else {
        "Новый туннель"
    });
    if !form.error.is_empty() {
        ui.colored_label(pal.error, &form.error);
    }
    let content_height = max_height - if form.error.is_empty() { 0.0 } else { 45.0 };
    ui.add_enabled_ui(!form.busy && !form.picking(), |ui| {
        egui::ScrollArea::vertical()
            .id_salt("form_scroll")
            .max_height(content_height)
            .show(ui, |ui| {
                field(ui, "Название туннеля", &mut form.draft.name);
                ui.add_space(4.0);
                ui.label(RichText::new("Тип туннеля").size(13.0).color(pal.dim));
                ui.columns(3, |columns| {
                    for (column, (value, name, flag)) in columns.iter_mut().zip([
                        ("L", "Локальный", "-L"),
                        ("R", "Обратный", "-R"),
                        ("D", "SOCKS5", "-D"),
                    ]) {
                        let selected = form.draft.kind == value;
                        if column
                            .add_sized(
                                [column.available_width(), 44.0],
                                style::choice(&format!("{value}   {name} · {flag}"), selected, &pal),
                            )
                            .clicked()
                        {
                            form.draft.kind = value.into();
                        }
                    }
                });
                ui.add_space(6.0);
                if endpoint_view(
                    ui,
                    &mut form.draft.server,
                    &mut form.server_port,
                    "server",
                    "Конечный SSH-сервер",
                ) {
                    action = DialogAction::BrowseKey(KeyTarget::Server);
                }
                ui.add_space(6.0);
                style::group(ui, "Переадресация", pal.accent, &pal, |ui| {
                    ui.label(
                        RichText::new(match form.draft.kind.as_str() {
                            "R" => "Порт на SSH-сервере → сервис на вашем устройстве.",
                            "D" => "Локальный SOCKS5-прокси → сеть SSH-сервера.",
                            _ => "Локальный порт → сервис со стороны SSH-сервера.",
                        })
                        .color(pal.dim),
                    );
                    let target = form.draft.kind != "D";
                    ui.columns(if target { 4 } else { 2 }, |columns| {
                        field(&mut columns[0], "Адрес прослушивания", &mut form.draft.bind);
                        field(&mut columns[1], "Порт прослушивания", &mut form.port);
                        if target {
                            field(&mut columns[2], "Адрес назначения", &mut form.draft.target);
                            field(&mut columns[3], "Порт назначения", &mut form.target_port);
                        }
                    });
                    let mut jumps_changed = false;
                    ui.horizontal_wrapped(|ui| {
                        ui.checkbox(&mut form.draft.reconnect, "Восстанавливать после разрыва");
                        jumps_changed = ui
                            .checkbox(&mut form.draft.jumps_enabled, "Подключаться через jump-хосты")
                            .changed();
                    });
                    if jumps_changed && form.draft.jumps_enabled && form.draft.jumps.is_empty() {
                        form.draft.jumps.push(Endpoint::default());
                        form.jump_ports.push("22".into());
                    }
                    if form.draft.jumps_enabled {
                        ui.label(
                            RichText::new(
                                "Соединение проходит через узлы сверху вниз, затем к конечному SSH-серверу.",
                            )
                            .color(pal.dim),
                        );
                        let mut jump_action = None;
                        let count = form.draft.jumps.len();
                        for index in 0..count {
                            if endpoint_view(
                                ui,
                                &mut form.draft.jumps[index],
                                &mut form.jump_ports[index],
                                &format!("jump_{index}"),
                                &format!("Jump-хост {}", index + 1),
                            ) {
                                action = DialogAction::BrowseKey(KeyTarget::Jump(index));
                            }
                            ui.horizontal_wrapped(|ui| {
                                if ui
                                    .add_enabled(index > 0, style::secondary("↑ Выше", &pal))
                                    .clicked()
                                {
                                    jump_action = Some((index, -1));
                                }
                                if ui
                                    .add_enabled(index + 1 < count, style::secondary("↓ Ниже", &pal))
                                    .clicked()
                                {
                                    jump_action = Some((index, 1));
                                }
                                if ui.add(style::secondary("Удалить узел", &pal)).clicked() {
                                    jump_action = Some((index, 0));
                                }
                            });
                        }
                        if let Some((index, delta)) = jump_action {
                            if delta == 0 {
                                form.draft.jumps.remove(index);
                                form.jump_ports.remove(index);
                                if form.draft.jumps.is_empty() {
                                    form.draft.jumps_enabled = false;
                                }
                            } else {
                                form.swap_jump(index, index.saturating_add_signed(delta));
                            }
                        }
                        if ui
                            .add(style::choice("+ Добавить jump-хост", false, &pal))
                            .clicked()
                        {
                            form.draft.jumps.push(Endpoint::default());
                            form.jump_ports.push("22".into());
                        }
                    }
                });
            });
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("Ctrl+S — сохранить · Esc — отмена")
                    .monospace()
                    .size(13.0)
                    .color(pal.dim),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(style::primary("Сохранить", &pal)).clicked() {
                    action = DialogAction::SaveForm(false);
                }
                if form.editing
                    && form.draft.enabled
                    && ui.add(style::secondary("Сохранить выключенным", &pal)).clicked()
                {
                    action = DialogAction::SaveForm(true);
                }
                if ui.add(style::secondary("Отмена", &pal)).clicked() {
                    action = DialogAction::Close;
                }
            });
        });
    });
    if form.busy {
        ui.label(RichText::new("Сохраняем…").color(pal.dim));
    }
    #[cfg(target_os = "linux")]
    if form.picking.is_some() {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Выберите файл ключа в открывшемся диалоге…").color(pal.dim));
            if ui.add(style::secondary("Отменить выбор", &pal)).clicked() {
                form.picking = None;
            }
        });
    }
    action
}

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
            ..Default::default()
        }
    }
    fn render(app: &mut Desktop, ctx: &egui::Context, size: [f32; 2]) -> egui::FullOutput {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size.into())),
                ..Default::default()
            },
            |ctx| {
                app.draw(ctx);
            },
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
        ctx.run(input, |ctx| {
            app.draw(ctx);
        })
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
                // Main buttons are drawn in capitals, so labels are found regardless of case.
                egui::Shape::Text(text)
                    if text.galley.text().to_uppercase() == label.to_uppercase() =>
                {
                    Some(text.galley.rect.translate(text.pos.to_vec2()))
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
    fn about_quote(output: &egui::FullOutput) -> String {
        fn find(shape: &egui::Shape) -> Option<String> {
            match shape {
                egui::Shape::Text(text) => text
                    .galley
                    .text()
                    .strip_prefix('«')
                    .and_then(|text| text.strip_suffix('»'))
                    .map(str::to_owned),
                egui::Shape::Vec(shapes) => shapes.iter().find_map(find),
                _ => None,
            }
        }
        output
            .shapes
            .iter()
            .find_map(|shape| find(&shape.shape))
            .expect("Visible mole quote")
    }
    #[test]
    fn key_file_browse_button_fits_next_to_the_path() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        let mut form = TunnelForm::new(Some(tunnel()));
        form.draft.server.auth = "key".into();
        app.dialog = Some(Dialog::Form(Box::new(form)));
        let _ = render(&mut app, &ctx, [700.0, 900.0]);
        let output = render(&mut app, &ctx, [700.0, 900.0]);
        let button = text_rect(&output, "Обзор…").expect("Key path has a browse button");
        let label = text_rect(&output, "Файл приватного ключа").unwrap();
        assert!(button.top() > label.bottom());
        assert!(button.right() < 700.0);
    }
    #[test]
    fn selected_key_changes_only_the_requested_endpoint_and_marks_form_dirty() {
        let mut draft = tunnel();
        draft.server.auth = "key".into();
        draft.server.key = "~/.ssh/server".into();
        draft.jumps_enabled = true;
        draft.jumps = vec![draft.server.clone(), draft.server.clone()];
        draft.jumps[0].host = "jump-one.example".into();
        draft.jumps[1].host = "jump-two.example".into();
        let mut form = TunnelForm::new(Some(draft));
        form.select_key(KeyTarget::Jump(1), Some("/keys/Работа/id_ed25519 ".into()));
        assert_eq!(form.draft.server.key, "~/.ssh/server");
        assert_eq!(form.draft.jumps[0].key, "~/.ssh/server");
        assert_eq!(form.draft.jumps[1].key, "/keys/Работа/id_ed25519 ");
        assert!(form.dirty());
        let candidate = form.candidate(&[], false).unwrap();
        assert_eq!(candidate.jumps[1].key, "/keys/Работа/id_ed25519 ");
        form.select_key(KeyTarget::Server, Some("/keys/server key".into()));
        assert_eq!(form.draft.server.key, "/keys/server key");
        assert_eq!(form.draft.jumps[1].key, "/keys/Работа/id_ed25519 ");
    }
    #[test]
    fn cancelled_key_selection_keeps_the_manual_path_and_clean_form() {
        let mut draft = tunnel();
        draft.server.key = "~/.ssh/manual_key".into();
        let mut form = TunnelForm::new(Some(draft));
        form.select_key(KeyTarget::Server, None);
        assert_eq!(form.draft.server.key, "~/.ssh/manual_key");
        assert!(!form.dirty());
        assert!(form.error.is_empty());
    }
    #[test]
    fn key_dialog_directory_preserves_paths_and_rejects_nul() {
        assert_eq!(
            key_directory("keys/Работа/id_ed25519"),
            Some("keys/Работа".into())
        );
        assert_eq!(key_directory("id_ed25519"), None);
        assert_eq!(key_directory(""), None);
        assert_eq!(key_directory("keys\0/invalid"), None);
    }
    /// Portal tests share one well-known bus name, so they run one at a time.
    #[cfg(target_os = "linux")]
    static PORTAL_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    /// A fake desktop portal that reports `OpenFile` and `Request.Close` calls.
    #[cfg(target_os = "linux")]
    async fn fake_portal() -> (
        zbus::Connection,
        tokio::sync::mpsc::UnboundedReceiver<&'static str>,
    ) {
        const HANDLE: &str = "/org/freedesktop/portal/desktop/request/pending";
        struct Portal(tokio::sync::mpsc::UnboundedSender<&'static str>);
        #[zbus::interface(name = "org.freedesktop.portal.FileChooser")]
        impl Portal {
            fn open_file(
                &self,
                _parent: &str,
                _title: &str,
                _options: HashMap<String, zbus::zvariant::OwnedValue>,
            ) -> zbus::zvariant::OwnedObjectPath {
                self.0.send("open").unwrap();
                HANDLE.try_into().unwrap()
            }
            #[zbus(property)]
            fn version(&self) -> u32 {
                4
            }
        }
        struct Request(tokio::sync::mpsc::UnboundedSender<&'static str>);
        #[zbus::interface(name = "org.freedesktop.portal.Request")]
        impl Request {
            fn close(&self) {
                self.0.send("close").unwrap();
            }
        }
        let (tx, calls) = tokio::sync::mpsc::unbounded_channel();
        let service = zbus::connection::Builder::session()
            .unwrap()
            .name(PORTAL)
            .unwrap()
            .serve_at("/org/freedesktop/portal/desktop", Portal(tx.clone()))
            .unwrap()
            .serve_at(HANDLE, Request(tx))
            .unwrap()
            .build()
            .await
            .unwrap();
        (service, calls)
    }
    #[cfg(target_os = "linux")]
    async fn portal_opened(
        selection: &mut std::pin::Pin<
            &mut impl std::future::Future<Output = anyhow::Result<Option<PathBuf>>>,
        >,
        calls: &mut tokio::sync::mpsc::UnboundedReceiver<&'static str>,
    ) {
        tokio::select! {
            result = selection => panic!("Request ended before portal accepted it: {result:?}"),
            call = calls.recv() => assert_eq!(call, Some("open")),
            _ = tokio::time::sleep(Duration::from_secs(3)) => panic!("Portal did not receive OpenFile"),
        }
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "dbus-run-session -- cargo test --lib key_portal -- --ignored"]
    async fn key_portal_disappearance_returns_error_instead_of_blocking_the_form() {
        let _serial = PORTAL_TESTS.lock().await;
        let (service, mut calls) = fake_portal().await;
        let selection = portal_key_file(None, None, tokio_util::sync::CancellationToken::new());
        tokio::pin!(selection);
        portal_opened(&mut selection, &mut calls).await;
        tokio::select! {
            result = &mut selection => panic!("Request ended without Response: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(100)) => {},
        }
        service.release_name(PORTAL).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), selection)
            .await
            .expect("Portal disappearance must return control to the form");
        assert!(result.is_err());
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "dbus-run-session -- cargo test --lib key_portal -- --ignored"]
    async fn key_portal_cancel_closes_the_dialog_and_response_returns_the_file() {
        let _serial = PORTAL_TESTS.lock().await;
        let (service, mut calls) = fake_portal().await;
        let cancel = tokio_util::sync::CancellationToken::new();
        let selection = portal_key_file(None, None, cancel.clone());
        tokio::pin!(selection);
        portal_opened(&mut selection, &mut calls).await;
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(1), selection)
            .await
            .expect("Cancelling must return control to the form");
        assert_eq!(result.unwrap(), None);
        assert_eq!(
            calls.recv().await,
            Some("close"),
            "the portal dialog is closed"
        );

        let selection = portal_key_file(None, None, tokio_util::sync::CancellationToken::new());
        tokio::pin!(selection);
        portal_opened(&mut selection, &mut calls).await;
        // Let the client subscribe to the handle the portal returned.
        tokio::select! {
            result = &mut selection => panic!("Request ended without Response: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(100)) => {},
        }
        let results = HashMap::from([(
            "uris",
            zbus::zvariant::Value::from(vec!["file:///keys/%D0%BA%D0%BB%D1%8E%D1%87"]),
        )]);
        service
            .emit_signal(
                None::<()>,
                "/org/freedesktop/portal/desktop/request/pending",
                "org.freedesktop.portal.Request",
                "Response",
                &(0u32, results),
            )
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), selection)
            .await
            .expect("The response must reach the form");
        assert_eq!(result.unwrap(), Some(PathBuf::from("/keys/ключ")));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn key_dialog_result_arrives_as_an_event_and_stale_or_cancelled_picks_are_ignored() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        let pick = |id| KeyPick {
            id,
            target: KeyTarget::Server,
            _cancel: tokio_util::sync::CancellationToken::new().drop_guard(),
        };
        let mut form = TunnelForm::new(Some(tunnel()));
        form.draft.server.auth = "key".into();
        form.picking = Some(pick(2));
        app.dialog = Some(Dialog::Form(Box::new(form)));
        let picked = |app: &mut Desktop, id, result| {
            app.tx.send(Event::KeyPicked { id, result }).unwrap();
            let _ = render(app, &ctx, [700.0, 900.0]);
            let output = render(app, &ctx, [700.0, 900.0]);
            let Some(Dialog::Form(form)) = &app.dialog else {
                panic!("The form stays open");
            };
            (
                form.draft.server.key.clone(),
                form.picking(),
                form.error.clone(),
                text_rect(&output, "Отменить выбор").is_some(),
            )
        };
        // The window keeps drawing while the dialog is open.
        let _ = render(&mut app, &ctx, [700.0, 900.0]);
        let output = render(&mut app, &ctx, [700.0, 900.0]);
        assert!(text_rect(&output, "Отменить выбор").is_some());
        assert_eq!(
            picked(&mut app, 1, Ok(Some("/keys/stale".into()))),
            (String::new(), true, String::new(), true),
            "an answer to an earlier dialog must not touch the form"
        );
        assert_eq!(
            picked(&mut app, 2, Ok(Some("/keys/id_ed25519".into()))),
            ("/keys/id_ed25519".into(), false, String::new(), false)
        );
        let Some(Dialog::Form(form)) = &mut app.dialog else {
            unreachable!()
        };
        form.picking = Some(pick(3));
        let (key, picking, error, _) = picked(&mut app, 3, Err(()));
        assert_eq!((key.as_str(), picking), ("/keys/id_ed25519", false));
        assert_eq!(error, KEY_DIALOG_ERROR);
        let Some(Dialog::Form(form)) = &mut app.dialog else {
            unreachable!()
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        form.picking = Some(KeyPick {
            id: 4,
            target: KeyTarget::Server,
            _cancel: cancel.clone().drop_guard(),
        });
        form.picking = None;
        assert!(
            cancel.is_cancelled(),
            "cancelling the choice closes the dialog"
        );
    }
    #[test]
    fn browse_request_is_emitted_only_for_an_editable_key_endpoint() {
        for (auth, busy, expected) in [
            ("key", false, Some(KeyTarget::Server)),
            ("agent", false, None),
            ("password", false, None),
            ("key", true, None),
        ] {
            let ctx = egui::Context::default();
            configure(&ctx, "dark");
            let mut app = Desktop::new(None, true);
            app.snapshot = Some(snapshot());
            let mut form = TunnelForm::new(Some(tunnel()));
            form.draft.server.auth = auth.into();
            form.busy = busy;
            app.dialog = Some(Dialog::Form(Box::new(form)));
            let _ = render(&mut app, &ctx, [700.0, 900.0]);
            let output = render(&mut app, &ctx, [700.0, 900.0]);
            let pos = text_rect(&output, "Обзор…").unwrap().center();
            let mut request = None;
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(700.0, 900.0),
                    )),
                    events: vec![
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
                    ..Default::default()
                },
                |ctx| request = app.draw(ctx),
            );
            assert_eq!(request, expected, "auth={auth}, busy={busy}");
            assert!(matches!(app.dialog, Some(Dialog::Form(_))));
        }
    }
    #[cfg(unix)]
    #[test]
    fn non_unicode_key_path_reports_error_without_replacing_the_previous_path() {
        use std::os::unix::ffi::OsStringExt;
        let mut form = TunnelForm::new(Some(tunnel()));
        form.draft.server.key = "~/.ssh/manual_key".into();
        let before = form.signature();
        form.select_key(
            KeyTarget::Server,
            Some(std::ffi::OsString::from_vec(b"/keys/\xff".to_vec()).into()),
        );
        assert_eq!(form.signature(), before);
        assert!(!form.error.is_empty());
    }

    #[test]
    fn version_opens_about_with_current_build_and_public_repository() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.initialized = true;
        render(&mut app, &ctx, [700.0, 500.0]);
        click_label(&mut app, &ctx, concat!("v", env!("CARGO_PKG_VERSION")));
        assert!(
            app.about_quote.is_some(),
            "Version click must select a quote"
        );
        assert!(matches!(app.dialog, Some(Dialog::About)));
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "О программе").is_some());
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, concat!("Версия ", env!("CARGO_PKG_VERSION"))).is_some());
        assert!(text_rect(&output, "Менеджер SSH-туннелей от Dudod1n").is_some());
        assert!(text_rect(&output, "GPL-3.0-only").is_some());
        let output = click_label(&mut app, &ctx, "github.com/Dudod1n/KPOT");
        assert!(output.platform_output.commands.iter().any(|command| matches!(command,
            egui::OutputCommand::OpenUrl(url) if url.url == "https://github.com/Dudod1n/KPOT"
        )));
        click_label(&mut app, &ctx, "В диспетчерскую");
        assert!(app.dialog.is_none());
    }
    #[test]
    fn about_quotes_change_only_on_open_or_manual_request_without_immediate_repeats() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.initialized = true;
        render(&mut app, &ctx, [700.0, 500.0]);
        let version = concat!("v", env!("CARGO_PKG_VERSION"));
        click_label(&mut app, &ctx, version);
        assert!(matches!(app.dialog, Some(Dialog::About)));
        render(&mut app, &ctx, [700.0, 500.0]);
        let mut previous = about_quote(&render(&mut app, &ctx, [700.0, 500.0]));
        let initial = previous.clone();
        let mut seen = HashSet::from([initial.clone()]);
        for _ in 1..ABOUT_QUOTES.len() {
            click_label(&mut app, &ctx, "Ещё фраза");
            previous = about_quote(&render(&mut app, &ctx, [700.0, 500.0]));
            assert!(
                seen.insert(previous.clone()),
                "Manual cycle repeated a quote early"
            );
        }
        click_label(&mut app, &ctx, "Ещё фраза");
        previous = about_quote(&render(&mut app, &ctx, [700.0, 500.0]));
        assert_eq!(previous, initial);
        for _ in 0..12 {
            app.started = Instant::now() - Duration::from_secs(10);
            app.tx
                .send(Event::Snapshot(Ok(Box::new(snapshot()))))
                .unwrap();
            assert_eq!(
                about_quote(&render(&mut app, &ctx, [700.0, 500.0])),
                previous
            );
            click_label(&mut app, &ctx, "Ещё фраза");
            let next = about_quote(&render(&mut app, &ctx, [700.0, 500.0]));
            assert_ne!(next, previous);
            previous = next;
            key_frame(&mut app, &ctx, Key::Escape);
            assert!(app.dialog.is_none());
            click_label(&mut app, &ctx, version);
            let next = about_quote(&render(&mut app, &ctx, [700.0, 500.0]));
            assert_ne!(next, previous);
            previous = next;
        }
    }
    #[test]
    fn closing_about_does_not_remember_an_unseen_quote_from_the_same_frame() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.dialog = Some(Dialog::About);
        app.about_quote = Some(0);
        render(&mut app, &ctx, [700.0, 500.0]);
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        let previous = about_quote(&output);
        let pos = text_rect(&output, "Ещё фраза").unwrap().center();
        let output = input_frame(
            &mut app,
            &ctx,
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
                egui::Event::Key {
                    key: Key::Escape,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            false,
        );
        assert!(app.dialog.is_none());
        assert_eq!(about_quote(&output), previous);
        assert_eq!(
            app.about_quote,
            Some(0),
            "Only the displayed quote may be excluded on reopen"
        );
    }
    #[test]
    fn about_link_preserves_an_open_dirty_form() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        let mut form = TunnelForm::new(Some(tunnel()));
        form.draft.name = "unsaved change".into();
        app.dialog = Some(Dialog::Form(Box::new(form)));
        render(&mut app, &ctx, [700.0, 500.0]);
        click_label(&mut app, &ctx, concat!("v", env!("CARGO_PKG_VERSION")));
        assert!(
            matches!(&app.dialog, Some(Dialog::Form(form)) if form.draft.name == "unsaved change" && form.dirty())
        );
        assert!(app.about_quote.is_none());
    }
    #[test]
    fn about_fits_both_themes_and_animation_follows_settings() {
        for theme in ["dark", "light"] {
            for size in [[700.0, 500.0], [1000.0, 800.0]] {
                let ctx = egui::Context::default();
                configure(&ctx, theme);
                let mut app = Desktop::new(None, true);
                app.snapshot = Some(snapshot());
                app.dialog = Some(Dialog::About);
                app.about_quote = Some(ABOUT_QUOTES.len() - 1);
                render(&mut app, &ctx, size);
                render(&mut app, &ctx, size);
                app.started = Instant::now() - Duration::from_millis(200);
                let output = render(&mut app, &ctx, size);
                assert!(app.anim_ms().is_some_and(|ms| ms >= 200));
                for label in ["Ещё фраза", "github.com/Dudod1n/KPOT", "В диспетчерскую"]
                {
                    assert!(
                        ctx.content_rect()
                            .contains_rect(text_rect(&output, label).unwrap()),
                        "{theme} {size:?}: {label}"
                    );
                }
                app.snapshot.as_mut().unwrap().config.settings.motion = false;
                render(&mut app, &ctx, size);
                assert!(app.anim_ms().is_none());
                assert_eq!(style::Pose::at(app.anim_ms(), true).look, 0);
            }
        }
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
    fn saving_enabled_autostart_refreshes_registration_and_shows_failure() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.dialog = Some(Dialog::Settings(SettingsDraft {
            theme: "dark".into(),
            motion: true,
            splash: true,
            autostart: Some(true),
            initial_autostart: Some(true),
            error: String::new(),
            busy: true,
        }));
        for _ in 0..3 {
            render(&mut app, &ctx, [700.0, 500.0]);
        }
        app.tx
            .send(Event::Complete(Operation::Settings, Ok(())))
            .unwrap();
        app.tx
            .send(Event::AutostartChanged(Err(
                "Не удалось обновить путь автозапуска.".into(),
            )))
            .unwrap();
        render(&mut app, &ctx, [700.0, 500.0]);
        assert!(
            matches!(&app.dialog, Some(Dialog::Settings(settings)) if !settings.busy && !settings.error.is_empty())
        );
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "Не удалось обновить путь автозапуска.").is_some());
        assert!(matches!(&app.dialog, Some(Dialog::Settings(settings)) if !settings.busy));
        assert!(!has_close(&output));
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
            Some(Dialog::About),
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
    fn mole_looks_left_right_centre_and_stays_still_without_motion() {
        assert_eq!(FRAME_TIME, Duration::from_millis(180));
        let looks: Vec<i8> = [0, 1499, 1500, 3000, 4500]
            .map(|ms| style::Pose::at(Some(ms), false).look)
            .to_vec();
        assert_eq!(looks, [-1, -1, 1, 0, -1]);
        assert_ne!(
            style::Pose::at(Some(0), true).rays,
            style::Pose::at(Some(800), true).rays
        );
        assert!(style::Pose::at(Some(0), false).rays.is_none());
        let still = style::Pose::at(None, true);
        assert_eq!(
            (still.look, still.lamp_dim, still.rays),
            (0, false, Some(true))
        );
        let mut app = Desktop::new(None, true);
        app.snapshot = Some(snapshot());
        app.snapshot.as_mut().unwrap().config.settings.motion = false;
        app.started = Instant::now() - Duration::from_millis(550);
        assert!(app.anim_ms().is_none());
        app.snapshot.as_mut().unwrap().config.settings.motion = true;
        assert!(app.anim_ms().is_some());
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
                        matches!(&shape.shape, egui::Shape::Text(text) if text.galley.text().to_uppercase() == label.to_uppercase())
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
                Some(Dialog::About),
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
                let text = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя_()[]/#\\.<>-↟◷◌○●◐!→←↑↓«»·…—×┌─┐│└┬┘";
                for font in [
                    egui::FontId::monospace(14.0),
                    egui::FontId::proportional(15.0),
                    egui::FontId::new(23.0, style::bold_family()),
                ] {
                    for character in text.chars() {
                        assert!(fonts.has_glyph(&font, character), "Missing bundled glyph {character} in {font:?}");
                    }
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
        let output = ctx.run(input, |ctx| {
            app.draw(ctx);
        });
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
        app.tx
            .send(Event::Snapshot(Ok(Box::new(snapshot.clone()))))
            .unwrap();
        app.drain(&ctx);
        assert!(
            matches!(&app.dialog, Some(Dialog::Prompt(prompt)) if prompt.secret == "unfinished")
        );
        snapshot.prompts.insert(
            "native-tunnel".into(),
            pending("native-tunnel", "replacement", "password"),
        );
        app.tx
            .send(Event::Snapshot(Ok(Box::new(snapshot))))
            .unwrap();
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
            app.tx
                .send(Event::Snapshot(Ok(Box::new(state.clone()))))
                .unwrap();
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
    fn theme_switches_preserve_medeo_typography_and_palette() {
        let ctx = egui::Context::default();
        for theme in ["dark", "light", "build", "dark", "system"] {
            configure(&ctx, theme);
            for mode in [egui::Theme::Dark, egui::Theme::Light] {
                let style = ctx.style_of(mode);
                assert!(style.override_font_id.is_none());
                let family = |text: egui::TextStyle| style.text_styles[&text].family.clone();
                assert_eq!(
                    family(egui::TextStyle::Body),
                    egui::FontFamily::Proportional
                );
                assert_eq!(
                    family(egui::TextStyle::Monospace),
                    egui::FontFamily::Monospace
                );
                assert_eq!(style.visuals.dark_mode, mode == egui::Theme::Dark);
            }
        }
        let fonts = style::fonts();
        for (family, first) in [
            (egui::FontFamily::Proportional, "MedeoSans-Regular"),
            (style::bold_family(), "MedeoSans-Bold"),
            (egui::FontFamily::Monospace, "MedeoMono-Regular"),
        ] {
            let chain = &fonts.families[&family];
            assert_eq!(chain[0], first);
            assert!(
                chain.iter().any(|name| name == "Hack"),
                "{family:?} keeps the fallback"
            );
        }
        assert_eq!(
            ctx.style_of(egui::Theme::Dark).visuals.panel_fill,
            Color32::from_rgb(21, 27, 30)
        );
    }
    #[test]
    fn colour_themes_replace_palette_and_classic_restores_it() {
        let ctx = egui::Context::default();
        let toned = |ctx: &egui::Context| {
            let mut colors = Vec::new();
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let pal = style::pal(ui.ctx());
                    colors = [pal.accent, pal.ok, pal.warn, pal.error].to_vec();
                });
            });
            colors
        };
        assert_eq!(crate::config::Settings::default().theme, "build");
        let mut seen = Vec::new();
        for theme in ["build", "night", "danger", "stealth"] {
            assert!(crate::config::THEMES.contains(&theme));
            assert_ne!(theme_label(theme), "Тёмное");
            configure(&ctx, theme);
            let visuals = ctx.style_of(egui::Theme::Dark).visuals.clone();
            assert!(visuals.dark_mode);
            assert_eq!(visuals.panel_fill, palette(theme).unwrap().bg);
            let colors = toned(&ctx);
            assert_ne!(colors[2], colors[3], "{theme}: ожидание и ошибка совпали");
            assert_ne!(colors[0], colors[3], "{theme}: акцент и ошибка совпали");
            assert_ne!(colors[0], colors[1], "{theme}: акцент и «работает» совпали");
            assert_eq!(
                visuals.widgets.inactive.bg_stroke.color,
                palette(theme).unwrap().line
            );
            assert_ne!(colors[0], CYAN);
            assert!(!seen.contains(&colors), "{theme}: палитра повторяется");
            seen.push(colors);
        }
        configure(&ctx, "dark");
        assert_eq!(toned(&ctx), [CYAN, GREEN, AMBER, RED]);
    }
    #[test]
    fn first_snapshot_applies_default_theme_on_startup() {
        let build = palette(crate::config::THEMES[0]).unwrap().bg;
        let panel = |ctx: &egui::Context| ctx.style_of(egui::Theme::Dark).visuals.panel_fill;
        for startup in [crate::config::THEMES[0], "dark"] {
            let ctx = egui::Context::default();
            configure(&ctx, startup);
            let mut app = Desktop::new(None, true);
            let mut snapshot = snapshot();
            snapshot.config.settings = Settings::default();
            app.tx
                .send(Event::Snapshot(Ok(Box::new(snapshot))))
                .unwrap();
            app.drain(&ctx);
            assert_eq!(panel(&ctx), build, "запуск в теме {startup}");
        }
    }
    fn app_snapshot(state: &str) -> Snapshot {
        let mut snapshot = snapshot();
        let mut socks = tunnel();
        socks.id = "socks".into();
        socks.name = "стенд".into();
        socks.kind = "D".into();
        socks.port = 1080;
        snapshot.config.tunnels.push(socks);
        snapshot.apps = vec![crate::apps::AppRule {
            id: "rule".into(),
            name: "браузер".into(),
            path: r"C:\Program Files\Mozilla Firefox\firefox.exe".into(),
            tunnel_id: "socks".into(),
            enabled: true,
            ..Default::default()
        }];
        snapshot.app_runtimes = HashMap::from([(
            "rule".into(),
            crate::apps::AppRuntime {
                state: state.into(),
                logs: vec!["10:02:11 Правило включено".into()],
                ..Default::default()
            },
        )]);
        snapshot
    }
    #[test]
    fn apps_tab_renders_every_state_and_its_form_at_minimum_window_size() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.initialized = true;
        app.view = View::Apps;
        for (state, label) in [
            ("running", "↟ Работает"),
            ("stopped", "○ Остановлено"),
            ("orphan", "! Туннель удалён"),
            ("unavailable", "◌ Перехват недоступен"),
        ] {
            let mut snapshot = app_snapshot(state);
            if state == "unavailable" {
                snapshot.apps_unavailable = "Нет драйвера.".into();
            }
            app.snapshot = Some(snapshot);
            app.selected_app = Some("rule".into());
            let output = render(&mut app, &ctx, [700.0, 500.0]);
            assert!(text_rect(&output, label).is_some(), "Missing {label}");
            assert!(text_rect(&output, "браузер").is_some());
            assert_eq!(
                text_rect(&output, "Нет драйвера.").is_some(),
                state == "unavailable"
            );
        }
        for size in [[700.0, 500.0], [1000.0, 720.0]] {
            let mut form = AppForm::new(None);
            form.error = "Укажите путь к исполняемому файлу.".into();
            app.dialog = Some(Dialog::AppForm(Box::new(form)));
            // The modal is measured on its first frame and shown on the next.
            render(&mut app, &ctx, size);
            let output = render(&mut app, &ctx, size);
            let rect = egui::AreaState::load(&ctx, egui::Id::new("dialog"))
                .unwrap()
                .rect();
            assert!(rect.width() <= size[0] && rect.height() <= size[1]);
            assert!(text_rect(&output, "Сохранить").is_some());
        }
        app.dialog = None;
        app.confirm = Some(Confirm::DeleteApp {
            id: "rule".into(),
            name: "браузер".into(),
        });
        assert!(!render(&mut app, &ctx, [700.0, 500.0]).shapes.is_empty());
    }

    #[test]
    fn udp_is_offered_only_with_consent_and_its_state_shows_on_tunnel_and_rule() {
        let ctx = egui::Context::default();
        configure(&ctx, "dark");
        let mut app = Desktop::new(None, true);
        app.initialized = true;
        app.snapshot = Some(app_snapshot("running"));
        app.selected = Some("socks".into());
        // A local tunnel has no UDP block at all.
        app.selected = Some("native-tunnel".into());
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "UDP через сервер: выключен").is_none());
        app.selected = Some("socks".into());
        let output = render(&mut app, &ctx, [1000.0, 720.0]);
        assert!(text_rect(&output, "UDP через сервер: выключен").is_some());
        // In the smallest window the block lies below the tunnel's own actions: scroll to it.
        let over_details = egui::pos2(520.0, 300.0);
        for _ in 0..3 {
            input_frame(
                &mut app,
                &ctx,
                vec![
                    egui::Event::PointerMoved(over_details),
                    egui::Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        delta: egui::vec2(0.0, -400.0),
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                false,
            );
        }
        click_label(&mut app, &ctx, "Включить UDP через сервер…");
        assert!(matches!(&app.confirm, Some(Confirm::UdpConsent { id, .. }) if id == "socks"));
        render(&mut app, &ctx, [700.0, 500.0]);
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "Загрузить и включить").is_some());
        app.confirm = None;

        let mut snapshot = app_snapshot("running");
        snapshot.udp.tunnels.insert(
            "socks".into(),
            crate::udp::consent::TunnelUdp {
                enabled: true,
                server: crate::udp::consent::server(&app_snapshot("running").config.tunnels[1]),
            },
        );
        snapshot.udp_runtimes.insert(
            "socks".into(),
            crate::ssh::UdpRuntime {
                state: "running".into(),
                level: 1,
                ..Default::default()
            },
        );
        snapshot
            .udp_metrics
            .insert("socks".into(), Default::default());
        snapshot
            .udp_helper
            .insert("rule".into(), Default::default());
        app.snapshot = Some(snapshot.clone());
        // The first frame at a new size still applies the offset scrolled in the small window.
        render(&mut app, &ctx, [1000.0, 720.0]);
        let output = render(&mut app, &ctx, [1000.0, 720.0]);
        assert!(text_rect(&output, "UDP через сервер: работает, уровень 1").is_some());
        assert!(text_rect(&output, "Выключить UDP").is_some());

        app.view = View::Apps;
        app.selected_app = Some("rule".into());
        // A tall window shows the whole card; smaller ones scroll to it.
        let output = render(&mut app, &ctx, [1000.0, 1200.0]);
        assert!(text_rect(&output, "Туннелировать QUIC (UDP 443)").is_some());
        assert!(
            text_rect(
                &output,
                "Трафик: TCP и UDP через туннель; QUIC (UDP 443) блокируется, браузер переходит на TCP"
            )
            .is_some()
        );
        // The numbers line follows the helper's report.
        assert!(text_rect(&output, "UDP: ↑ 0 · ↓ 0 датаграмм · потоков 0").is_some());
        // A stopped rule or a missing helper does not claim tunnelling, relay or not.
        for state in ["stopped", "elevation"] {
            let mut stopped = snapshot.clone();
            stopped.app_runtimes.get_mut("rule").unwrap().state = state.into();
            app.snapshot = Some(stopped);
            let output = render(&mut app, &ctx, [1000.0, 1200.0]);
            assert!(
                text_rect(
                    &output,
                    "Трафик: правило сейчас не перехватывает приложение"
                )
                .is_some(),
                "{state}"
            );
            assert!(
                text_rect(
                    &output,
                    "Трафик: TCP и UDP через туннель; QUIC (UDP 443) блокируется, браузер переходит на TCP"
                )
                .is_none()
            );
        }
        snapshot.udp_runtimes.clear();
        app.snapshot = Some(snapshot);
        let output = render(&mut app, &ctx, [1000.0, 1200.0]);
        assert!(
            text_rect(
                &output,
                "Трафик: только TCP; UDP через сервер ещё не работает, поэтому UDP блокируется"
            )
            .is_some()
        );
    }
    #[test]
    fn apps_tab_without_socks_tunnels_offers_one_and_keys_follow_the_active_tab() {
        let ctx = egui::Context::default();
        let mut app = Desktop::new(None, true);
        app.initialized = true;
        app.snapshot = Some(snapshot());
        key_frame(&mut app, &ctx, Key::Num2);
        assert!(app.view == View::Apps);
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "Создать туннель D").is_some());
        click_label(&mut app, &ctx, "Создать туннель D");
        assert!(app.view == View::Tunnels);
        assert!(
            matches!(&app.dialog, Some(Dialog::Form(form)) if form.draft.kind == "D" && !form.dirty())
        );
        app.dialog = None;

        app.view = View::Apps;
        key_frame(&mut app, &ctx, Key::N);
        assert!(matches!(&app.dialog, Some(Dialog::AppForm(form)) if !form.editing));
        app.dialog = None;
        app.snapshot = Some(app_snapshot("running"));
        app.selected_app = Some("rule".into());
        key_frame(&mut app, &ctx, Key::Delete);
        assert!(matches!(&app.confirm, Some(Confirm::DeleteApp { id, .. }) if id == "rule"));
        app.confirm = None;
        key_frame(&mut app, &ctx, Key::E);
        assert!(matches!(&app.dialog, Some(Dialog::AppForm(form)) if form.editing));
        app.dialog = None;
        key_frame(&mut app, &ctx, Key::Num1);
        key_frame(&mut app, &ctx, Key::N);
        assert!(matches!(&app.dialog, Some(Dialog::Form(_))));
    }
    #[test]
    fn dirty_app_form_asks_before_discard_and_reports_validation_in_place() {
        let ctx = egui::Context::default();
        let mut app = Desktop::new(None, true);
        app.initialized = true;
        app.view = View::Apps;
        app.snapshot = Some(app_snapshot("running"));
        let mut form = AppForm::new(None);
        form.draft.name = "curl".into();
        assert!(form.dirty());
        app.dialog = Some(Dialog::AppForm(Box::new(form)));
        render(&mut app, &ctx, [700.0, 500.0]);
        click_label(&mut app, &ctx, "Сохранить");
        assert!(
            matches!(&app.dialog, Some(Dialog::AppForm(form)) if form.error.contains("Укажите путь") && !form.busy)
        );
        click_label(&mut app, &ctx, "Отмена");
        assert!(matches!(app.confirm, Some(Confirm::Discard { .. })));
        let output = render(&mut app, &ctx, [700.0, 500.0]);
        assert!(text_rect(&output, "Отменить изменения в этом правиле?").is_some());
        assert!(matches!(&app.dialog, Some(Dialog::AppForm(form)) if form.draft.name == "curl"));
        app.confirm = None;
        app.request_exit();
        assert!(matches!(
            app.confirm,
            Some(Confirm::Discard {
                after: AfterDiscard::Exit
            })
        ));
    }
    #[test]
    fn app_form_keeps_the_saved_switch_and_fills_the_name_from_the_executable() {
        let snapshot = app_snapshot("running");
        let mut form = AppForm::new(Some(snapshot.apps[0].clone()));
        form.draft.enabled = false;
        form.draft.on_tunnel_down = "direct".into();
        let rules = form
            .candidate(&snapshot.apps, &snapshot.config.tunnels)
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].enabled && rules[0].on_tunnel_down == "direct");

        let mut form = AppForm::new(None);
        form.select_path(r"C:\Tools\curl.exe".into(), "curl.exe");
        assert_eq!(form.draft.name, "curl");
        form.select_path(r"C:\Tools\wget.exe".into(), "wget.exe");
        assert_eq!(form.draft.name, "curl", "a typed name is kept");
        form.draft.tunnel_id = "native-tunnel".into();
        let error = form
            .candidate(&snapshot.apps, &snapshot.config.tunnels)
            .unwrap_err()
            .to_string();
        assert!(error.contains("типа D"), "{error}");
        form.draft.tunnel_id = "socks".into();
        assert_eq!(
            form.candidate(&snapshot.apps, &snapshot.config.tunnels)
                .unwrap()
                .len(),
            2
        );
    }
}
