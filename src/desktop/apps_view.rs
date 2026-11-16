//! The «Приложения» tab: rules that send one executable through a SOCKS5 tunnel.
use super::*;
use crate::apps::{AppRule, Process};

pub(super) struct AppForm {
    pub(super) draft: AppRule,
    original: Value,
    pub(super) editing: bool,
    pub(super) error: String,
    pub(super) busy: bool,
    from_process: bool,
    filter: String,
    processes: Vec<Process>,
}

impl AppForm {
    pub(super) fn new(rule: Option<AppRule>) -> Self {
        let editing = rule.is_some();
        let mut form = Self {
            draft: rule.unwrap_or_default(),
            original: Value::Null,
            editing,
            error: String::new(),
            busy: false,
            from_process: false,
            filter: String::new(),
            processes: Vec::new(),
        };
        form.original = json!(form.draft);
        form
    }
    pub(super) fn dirty(&self) -> bool {
        self.original != json!(self.draft)
    }
    /// The full rule list to save, with this rule added or replaced in place.
    pub(super) fn candidate(
        &self,
        rules: &[AppRule],
        tunnels: &[Tunnel],
    ) -> anyhow::Result<Vec<AppRule>> {
        let mut rule = self.draft.clone();
        rule.name = rule.name.trim().into();
        rule.path = rule.path.trim().into();
        if let Some(current) = rules.iter().find(|current| current.id == rule.id) {
            rule.enabled = current.enabled;
        }
        crate::apps::validate_rule(&rule, rules, tunnels)?;
        let mut next = rules.to_vec();
        match next.iter_mut().find(|current| current.id == rule.id) {
            Some(current) => *current = rule,
            None => next.push(rule),
        }
        Ok(next)
    }
    pub(super) fn select_path(&mut self, path: String, name: &str) {
        self.draft.path = path;
        if self.draft.name.trim().is_empty() {
            let name = name
                .strip_suffix(".exe")
                .or_else(|| name.strip_suffix(".EXE"))
                .unwrap_or(name);
            self.draft.name = name.into();
        }
    }
}

pub(super) fn app_state_label(state: &str) -> (&'static str, Tone) {
    match state {
        "running" => ("↟ Работает", Tone::Ok),
        "blocked" => ("! Туннель не работает, сеть приложения закрыта", Tone::Warn),
        "direct" => ("! Туннель не работает, трафик идёт напрямую", Tone::Warn),
        "orphan" => ("! Туннель удалён", Tone::Error),
        "elevation" => (
            "! Нужны права администратора, трафик идёт напрямую",
            Tone::Warn,
        ),
        "unavailable" => ("◌ Перехват недоступен", Tone::Dim),
        _ => ("○ Остановлено", Tone::Dim),
    }
}

fn bytes(value: u64) -> String {
    const UNITS: [&str; 4] = ["Б", "КБ", "МБ", "ГБ"];
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit < UNITS.len() - 1 {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} Б")
    } else {
        format!("{amount:.1} {}", UNITS[unit])
    }
}

impl Desktop {
    pub(super) fn app_state<'a>(&'a self, rule: &AppRule) -> &'a str {
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.app_runtimes.get(&rule.id))
            .map(|runtime| runtime.state.as_str())
            .unwrap_or("stopped")
    }
    pub(super) fn selected_app(&self) -> Option<AppRule> {
        self.snapshot
            .as_ref()?
            .apps
            .iter()
            .find(|rule| Some(&rule.id) == self.selected_app.as_ref())
            .cloned()
    }
    pub(super) fn move_app_selection(&mut self, delta: isize) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        if snapshot.apps.is_empty() {
            return;
        }
        let index = snapshot
            .apps
            .iter()
            .position(|rule| Some(&rule.id) == self.selected_app.as_ref())
            .unwrap_or(0);
        let next = index
            .saturating_add_signed(delta)
            .min(snapshot.apps.len() - 1);
        self.selected_app = Some(snapshot.apps[next].id.clone());
    }
    pub(super) fn toggle_app(&mut self, ctx: &egui::Context, rule: &AppRule) {
        if !self.busy_apps.insert(rule.id.clone()) {
            return;
        }
        self.request(
            ctx,
            Operation::ToggleApp(rule.id.clone()),
            if rule.enabled {
                "app_stop"
            } else {
                "app_start"
            },
            json!(rule.id),
        );
    }
    /// Starts the elevated helper, first fetching its driver files if this copy lacks them.
    pub(super) fn grant_divert(&mut self, ctx: &egui::Context) {
        let Some(backend) = &self.backend else {
            return;
        };
        let directory = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(std::path::Path::to_path_buf));
        let missing = match &directory {
            Some(directory) if cfg!(windows) => crate::divert::missing_components(directory),
            _ => Vec::new(),
        };
        let (Some(directory), false) = (directory, missing.is_empty()) else {
            self.launch_divert();
            return;
        };
        self.fetching_components = true;
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        backend.runtime.spawn(async move {
            let result = crate::update::fetch_components(&directory, &missing)
                .await
                .map_err(|_| COMPONENTS_ERROR.to_owned());
            let _ = tx.send(Event::ComponentsFetched(result));
            ctx.request_repaint();
        });
    }
    pub(super) fn launch_divert(&mut self) {
        if let Some(backend) = &self.backend
            && let Err(error) = crate::divert::launch(&backend.store.path)
        {
            self.error = error.to_string();
        }
    }
    pub(super) fn new_socks_tunnel(&mut self) {
        let mut form = TunnelForm::new(None);
        form.draft.kind = "D".into();
        form.original = form.signature();
        self.view = View::Tunnels;
        self.dialog = Some(Dialog::Form(Box::new(form)));
    }
    pub(super) fn app_group(state: &str) -> Group {
        match state {
            "running" => Group::Live,
            "blocked" | "direct" | "orphan" | "elevation" => Group::Attention,
            _ => Group::Off,
        }
    }
    /// State lights of the rules, the number going through a tunnel and the number without one.
    pub(super) fn app_lamps(&self, pal: &Pal) -> (Vec<style::Lamp>, usize, usize) {
        let Some(snapshot) = &self.snapshot else {
            return (Vec::new(), 0, 0);
        };
        let mut running = 0;
        let mut trouble = 0;
        let lamps = snapshot
            .apps
            .iter()
            .map(|rule| {
                let state = self.app_state(rule);
                let (label, color) = app_state_label(state);
                running += usize::from(state == "running");
                trouble += usize::from(Self::app_group(state) == Group::Attention);
                style::Lamp {
                    color: tone_of(pal, color),
                    filled: !matches!(state, "stopped" | "unavailable"),
                    blink: matches!(state, "blocked" | "direct" | "elevation"),
                    selected: self.selected_app.as_ref() == Some(&rule.id),
                    name: format!("{}: {label}", rule.name),
                    group: Self::app_group(state),
                }
            })
            .collect();
        (lamps, running, trouble)
    }
    pub(super) fn apps_side(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, pal: &Pal) {
        let rules = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.apps.clone())
            .unwrap_or_default();
        style::caps(ui, "Мои приложения", pal.dim);
        ui.add_space(6.0);
        egui::ScrollArea::vertical()
            .id_salt("app_scroll")
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 6.0;
                if rules.is_empty() {
                    ui.add_space(16.0);
                    style::mole(ui, 3.0, style::Pose::default(), pal);
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(if self.snapshot.is_some() {
                            "Здесь появится первое правило.\nN — добавить приложение."
                        } else {
                            "Подключаемся к фоновому КРОТу…"
                        })
                        .color(pal.dim),
                    );
                }
                let filter = if rules.len() > 8 {
                    self.app_filter
                } else {
                    Group::All
                };
                for rule in &rules {
                    let state = self.app_state(rule).to_owned();
                    if filter != Group::All && Self::app_group(&state) != filter {
                        continue;
                    }
                    let (label, color) = app_state_label(&state);
                    let color = tone_of(pal, color);
                    let tunnel = self
                        .snapshot
                        .as_ref()
                        .and_then(|snapshot| {
                            snapshot
                                .config
                                .tunnels
                                .iter()
                                .find(|tunnel| tunnel.id == rule.tunnel_id)
                        })
                        .map(|tunnel| tunnel.name.clone())
                        .unwrap_or_else(|| "туннель удалён".into());
                    let initial = rule
                        .name
                        .chars()
                        .next()
                        .map(|first| first.to_uppercase().to_string())
                        .unwrap_or_default();
                    let busy = self.busy_apps.contains(&rule.id);
                    let motion = self.anim_ms().is_some();
                    let row = list_row(
                        ui,
                        pal,
                        &rule.id,
                        self.selected_app.as_ref() == Some(&rule.id),
                        &initial,
                        &rule.name,
                        &format!("→ {tunnel}"),
                        label,
                        color,
                        |ui| {
                            ui.add_enabled_ui(!busy, |ui| {
                                style::lever(
                                    ui,
                                    rule.enabled,
                                    false,
                                    if rule.enabled { color } else { pal.dim },
                                    pal,
                                    &if rule.enabled {
                                        format!("Выключить правило «{}»", rule.name)
                                    } else {
                                        format!("Включить правило «{}»", rule.name)
                                    },
                                    motion,
                                )
                                .clicked()
                            })
                            .inner
                        },
                    );
                    if row.lever {
                        self.selected_app = Some(rule.id.clone());
                        self.toggle_app(ctx, rule);
                    }
                    if row.response.clicked() {
                        self.selected_app = Some(rule.id.clone());
                    }
                }
            });
    }
    pub(super) fn apps_main(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, pal: &Pal) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let unavailable = snapshot.apps_unavailable.clone();
        let has_socks = snapshot.config.tunnels.iter().any(|t| t.kind == "D");
        let detached = unavailable.is_empty() && !snapshot.divert_attached;
        let failure = snapshot.divert_error.clone();
        if !unavailable.is_empty() || detached {
            egui::Frame::new()
                .stroke(Stroke::new(1.0_f32, pal.warn))
                .corner_radius(4)
                .inner_margin(egui::Margin::same(14))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if !unavailable.is_empty() {
                        ui.colored_label(pal.warn, &unavailable);
                    }
                    if detached {
                        ui.colored_label(
                            pal.warn,
                            "Перехват не запущен: приложения ходят в сеть напрямую. Для перехвата нужны права администратора.",
                        );
                        if !failure.is_empty() {
                            ui.colored_label(pal.error, &failure);
                        }
                        if self.fetching_components {
                            ui.horizontal_wrapped(|ui| {
                                ui.spinner();
                                ui.label("Скачиваем файлы WinDivert…");
                            });
                        } else if ui.add(style::primary("Предоставить права…", pal)).clicked() {
                            self.grant_divert(ctx);
                        }
                        ui.label(
                            RichText::new("Если файлов WinDivert нет рядом с КРОТом, они будут скачаны из его релиза на GitHub.")
                                .color(pal.dim),
                        );
                    }
                });
            ui.add_space(12.0);
        }
        style::card(pal).show(ui, |ui| {
            ui.set_width(ui.available_width());
            if let Some(rule) = self.selected_app() {
                self.app_detail(ui, ctx, &rule, pal);
                return;
            }
            style::caps(ui, "На участке", pal.dim);
            ui.add_space(12.0);
            style::mole(ui, 4.0, style::Pose::default(), pal);
            ui.add_space(12.0);
            if has_socks {
                ui.label("Добавьте приложение, чтобы направить его трафик через туннель.");
                ui.label(
                    RichText::new("Через туннель идёт TCP. UDP идёт через туннель, если для него включён «UDP через сервер»; иначе блокируется.")
                        .color(pal.dim),
                );
            } else {
                ui.label("Приложения ходят через туннели типа D (SOCKS5). Таких туннелей пока нет.");
                if ui.add(style::primary("Создать туннель D", pal)).clicked() {
                    self.new_socks_tunnel();
                }
            }
        });
    }
    fn app_detail(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, rule: &AppRule, pal: &Pal) {
        let state = self.app_state(rule).to_owned();
        let (label, color) = app_state_label(&state);
        let color = tone_of(pal, color);
        let (tunnel, runtime) = self
            .snapshot
            .as_ref()
            .map(|snapshot| {
                (
                    snapshot
                        .config
                        .tunnels
                        .iter()
                        .find(|tunnel| tunnel.id == rule.tunnel_id)
                        .cloned(),
                    snapshot.app_runtimes.get(&rule.id).cloned(),
                )
            })
            .unwrap_or_default();
        let runtime = runtime.unwrap_or_default();
        style::caps(ui, "На участке · правило", pal.dim);
        ui.label(
            RichText::new(&rule.name)
                .family(style::bold())
                .size(30.0)
                .color(pal.ink),
        );
        ui.add(
            egui::Label::new(
                RichText::new(&rule.path)
                    .monospace()
                    .size(13.0)
                    .color(pal.dim),
            )
            .wrap(),
        );
        ui.add_space(4.0);
        ui.label(RichText::new(label).family(style::bold()).color(color));
        ui.add_space(8.0);
        match (state.as_str(), &tunnel) {
            ("orphan", _) => {
                ui.label("Туннель этого правила удалён или больше не SOCKS5. Выберите другой туннель типа D.");
                if ui.add(style::primary("Выбрать туннель", pal)).clicked() {
                    self.dialog = Some(Dialog::AppForm(Box::new(AppForm::new(Some(rule.clone())))));
                }
            }
            ("blocked" | "direct", Some(tunnel)) => {
                ui.label(if state == "blocked" {
                    "Соединения приложения отклоняются: мимо туннеля ничего не уходит."
                } else {
                    "По настройке правила трафик приложения сейчас идёт напрямую."
                });
                let tunnel_state = self.state(tunnel).to_owned();
                if tunnel_state == "waiting" {
                    if ui
                        .add(style::primary("Разобраться с туннелем", pal))
                        .clicked()
                    {
                        self.resolve(tunnel);
                    }
                } else if !active(&tunnel_state)
                    && ui
                        .add_enabled(
                            !self.busy_tunnels.contains(&tunnel.id),
                            style::primary("Запустить туннель", pal),
                        )
                        .clicked()
                {
                    self.toggle(ctx, tunnel);
                }
            }
            _ => {}
        }
        ui.add_space(8.0);
        egui::Frame::new()
            .fill(pal.bg)
            .stroke(Stroke::new(1.0_f32, pal.line))
            .corner_radius(4)
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                match &tunnel {
                    Some(tunnel) => {
                        let (tunnel_label, _) = state_label(self.state(tunnel));
                        ui.label(
                            RichText::new(format!(
                                "Туннель: {} · {} · {}:{} · {}",
                                tunnel.name, tunnel.kind, tunnel.bind, tunnel.port, tunnel_label
                            ))
                            .monospace(),
                        );
                    }
                    None => {
                        ui.colored_label(pal.error, "Туннель: удалён");
                    }
                }
                self.rule_udp(ui, ctx, rule, tunnel.as_ref());
                ui.label(
                    RichText::new(format!(
                        "Соединений {} · всего {} · ↑ {} · ↓ {}",
                        runtime.connections,
                        runtime.total,
                        bytes(runtime.sent),
                        bytes(runtime.received)
                    ))
                    .monospace()
                    .color(pal.dim),
                );
            });
        ui.add_space(8.0);
        for text in [
            if rule.on_tunnel_down == "direct" {
                "Без туннеля: пускать напрямую"
            } else {
                "Без туннеля: блокировать сеть приложения"
            },
            if rule.children {
                "Дочерние процессы: включены"
            } else {
                "Дочерние процессы: не включены"
            },
            "Способ: перехват по пути файла, включая уже запущенные процессы",
        ] {
            ui.label(RichText::new(text).color(pal.dim));
        }
        ui.add_space(12.0);
        ui.horizontal_wrapped(|ui| {
            let action = if rule.enabled {
                "Выключить правило"
            } else {
                "Включить правило"
            };
            if ui
                .add_enabled(
                    !self.busy_apps.contains(&rule.id),
                    style::primary(action, pal),
                )
                .clicked()
            {
                self.toggle_app(ctx, rule);
            }
            if ui.add(style::secondary("E Изменить", pal)).clicked() {
                self.dialog = Some(Dialog::AppForm(Box::new(AppForm::new(Some(rule.clone())))));
            }
            if ui.add(style::danger("Удалить", pal)).clicked() {
                self.confirm = Some(Confirm::DeleteApp {
                    id: rule.id.clone(),
                    name: rule.name.clone(),
                });
            }
        });
        ui.add_space(12.0);
        style::caps(ui, "Журнал", pal.dim);
        if runtime.logs.is_empty() {
            ui.label(RichText::new("Записей пока нет.").color(pal.dim));
        }
        for line in &runtime.logs {
            log_line(ui, line, pal);
        }
    }
}

impl Desktop {
    /// What happens to the rule's UDP right now, its numbers and the QUIC switch.
    fn rule_udp(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        rule: &AppRule,
        tunnel: Option<&crate::config::Tunnel>,
    ) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let quic = snapshot.udp.quic(&rule.id);
        let running = tunnel.is_some_and(|tunnel| {
            snapshot
                .udp_runtimes
                .get(&tunnel.id)
                .is_some_and(|runtime| runtime.state == "running")
        });
        let consent = tunnel.is_some_and(|tunnel| snapshot.udp.consented(tunnel));
        // What the rule does right now: a stopped rule or a missing helper moves nothing.
        let state = snapshot
            .app_runtimes
            .get(&rule.id)
            .map(|runtime| runtime.state.as_str())
            .unwrap_or("stopped");
        let text = match (state, running, consent) {
            ("direct", ..) => "Трафик: туннель не работает, всё идёт напрямую, включая UDP",
            ("blocked", ..) => "Трафик: туннель не работает, сеть приложения закрыта",
            ("running", ..) => match (running, consent) {
                (true, _) if quic => "Трафик: TCP и UDP через туннель, включая QUIC",
                (true, _) => {
                    "Трафик: TCP и UDP через туннель; QUIC (UDP 443) блокируется, браузер переходит на TCP"
                }
                (false, true) => {
                    "Трафик: только TCP; UDP через сервер ещё не работает, поэтому UDP блокируется"
                }
                (false, false) => {
                    "Трафик: только TCP; UDP блокируется — включите «UDP через сервер» в туннеле"
                }
            },
            _ => "Трафик: правило сейчас не перехватывает приложение",
        };
        ui.weak(text);
        ui.weak("Имена для приложения разрешает система Windows (служба DNS-клиент) напрямую; через туннель идут только DNS-запросы, которые приложение отправляет само.");
        let helper = snapshot.udp_helper.get(&rule.id);
        let routed = snapshot.udp_rules.get(&rule.id);
        if helper.is_some() || routed.is_some() {
            let captured = helper.map_or(0, |stats| stats.captured.datagrams);
            let injected = helper.map_or(0, |stats| stats.injected.datagrams);
            let drops = |map: Option<&std::collections::BTreeMap<String, u64>>, reason: &str| {
                map.and_then(|map| map.get(reason)).copied().unwrap_or(0)
            };
            let helper_drops = helper.map(|stats| &stats.drops);
            let routed_drops = routed.map(|stats| &stats.drops);
            let lost = |reason: &str| drops(helper_drops, reason) + drops(routed_drops, reason);
            ui.weak(format!(
                "UDP: ↑ {captured} · ↓ {injected} датаграмм · потоков {}",
                routed.map_or(0, |stats| stats.flows_active)
            ));
            ui.weak(format!(
                "Потери: срок годности {} · переполнение {} · размер {} · канал {} · QUIC заблокирован {}",
                lost("expired"),
                lost("overflow"),
                lost("size"),
                lost("channel"),
                lost("quic")
            ));
        }
        let mut wanted = quic;
        if ui
            .add_enabled(
                self.pending_operations == 0 && snapshot.udp_error.is_empty(),
                egui::Checkbox::new(&mut wanted, "Туннелировать QUIC (UDP 443)"),
            )
            .changed()
        {
            self.request(
                ctx,
                Operation::Udp,
                "udp_rule",
                json!({"id": rule.id, "quic": wanted}),
            );
        }
    }
}

pub(super) fn app_form_view(
    ui: &mut egui::Ui,
    form: &mut AppForm,
    tunnels: &[Tunnel],
    max_height: f32,
) -> DialogAction {
    let pal = style::pal(ui.ctx());
    let mut action = DialogAction::None;
    ui.heading(if form.editing {
        "Изменить правило"
    } else {
        "Новое правило"
    });
    if !form.error.is_empty() {
        ui.colored_label(pal.error, &form.error);
    }
    let content_height = max_height - if form.error.is_empty() { 0.0 } else { 45.0 };
    let small = |text: &str| RichText::new(text).size(13.0).color(pal.dim);
    ui.add_enabled_ui(!form.busy, |ui| {
        egui::ScrollArea::vertical()
            .id_salt("app_form_scroll")
            .max_height(content_height)
            .show(ui, |ui| {
                ui.label(small("Источник"));
                ui.columns(2, |columns| {
                    if columns[0]
                        .add_sized(
                            [columns[0].available_width(), 44.0],
                            style::choice("Исполняемый файл", !form.from_process, &pal),
                        )
                        .clicked()
                    {
                        form.from_process = false;
                    }
                    if columns[1]
                        .add_sized(
                            [columns[1].available_width(), 44.0],
                            style::choice("Запущенный процесс", form.from_process, &pal),
                        )
                        .clicked()
                    {
                        form.from_process = true;
                        form.processes = crate::apps::processes();
                    }
                });
                if form.from_process {
                    ui.horizontal(|ui| {
                        if ui.add(style::secondary("Обновить", &pal)).clicked() {
                            form.processes = crate::apps::processes();
                        }
                        ui.add(
                            egui::TextEdit::singleline(&mut form.filter)
                                .hint_text("имя, PID или путь")
                                .font(egui::TextStyle::Monospace)
                                .margin(egui::vec2(10.0, 9.0))
                                .desired_width(f32::INFINITY),
                        );
                    });
                    let filter = form.filter.trim().to_lowercase();
                    let mut picked = None;
                    egui::Frame::new()
                        .fill(pal.bg)
                        .stroke(Stroke::new(1.0_f32, pal.line))
                        .corner_radius(4)
                        .inner_margin(egui::Margin::same(6))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            egui::ScrollArea::vertical()
                                .id_salt("process_scroll")
                                .max_height(150.0)
                                .show(ui, |ui| {
                                    let mut shown = 0;
                                    for process in &form.processes {
                                        let line = format!(
                                            "{:>6}  {}  {}",
                                            process.pid, process.name, process.path
                                        );
                                        if !filter.is_empty()
                                            && !line.to_lowercase().contains(&filter)
                                        {
                                            continue;
                                        }
                                        shown += 1;
                                        if ui
                                            .selectable_label(
                                                form.draft.path == process.path,
                                                RichText::new(line).monospace().size(13.0),
                                            )
                                            .clicked()
                                        {
                                            picked = Some(process.clone());
                                        }
                                    }
                                    if shown == 0 {
                                        ui.label(RichText::new("Ничего не найдено.").color(pal.dim));
                                    }
                                });
                        });
                    if let Some(process) = picked {
                        form.select_path(process.path, &process.name);
                    }
                }
                ui.label(small("Путь к исполняемому файлу"));
                ui.horizontal(|ui| {
                    let browse = cfg!(not(target_os = "linux"));
                    let reserved = if browse { 110.0 } else { 0.0 };
                    ui.add(
                        egui::TextEdit::singleline(&mut form.draft.path)
                            .font(egui::TextStyle::Monospace)
                            .margin(egui::vec2(10.0, 9.0))
                            .desired_width((ui.available_width() - reserved).max(80.0)),
                    );
                    if browse && ui.add(style::secondary("Обзор…", &pal)).clicked() {
                        action = DialogAction::BrowseApp;
                    }
                });
                field(ui, "Название правила", &mut form.draft.name);
                ui.label(small("Туннель"));
                let socks: Vec<&Tunnel> = tunnels.iter().filter(|t| t.kind == "D").collect();
                if socks.is_empty() {
                    ui.colored_label(
                        pal.warn,
                        "Нет туннелей типа D. Сначала создайте SOCKS5-туннель.",
                    );
                } else {
                    if !socks.iter().any(|tunnel| tunnel.id == form.draft.tunnel_id) {
                        ui.label(small("выберите туннель D"));
                    }
                    for tunnel in socks {
                        let selected = form.draft.tunnel_id == tunnel.id;
                        let text = format!("{} · {}:{}", tunnel.name, tunnel.bind, tunnel.port);
                        if ui
                            .add_sized(
                                [ui.available_width(), 44.0],
                                style::choice(&text, selected, &pal),
                            )
                            .clicked()
                        {
                            form.draft.tunnel_id = tunnel.id.clone();
                        }
                    }
                }
                ui.add_space(4.0);
                style::group(ui, "Если туннель не работает", pal.ink, &pal, |ui| {
                    ui.radio_value(
                        &mut form.draft.on_tunnel_down,
                        "block".into(),
                        "Блокировать сеть приложения",
                    );
                    ui.radio_value(
                        &mut form.draft.on_tunnel_down,
                        "direct".into(),
                        "Пускать напрямую",
                    );
                    ui.label(small(if form.draft.on_tunnel_down == "direct" {
                        "По настройке правила трафик приложения сейчас идёт напрямую."
                    } else {
                        "Соединения приложения отклоняются: мимо туннеля ничего не уходит."
                    }));
                });
                ui.checkbox(&mut form.draft.children, "Включая дочерние процессы");
                ui.label(small("Через туннель идёт TCP, а UDP — если для туннеля включён «UDP через сервер»; иначе UDP блокируется. QUIC (UDP 443) блокируется, пока в карточке правила не включено его туннелирование. «Пускать напрямую» без туннеля пропускает и TCP, и UDP."));
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
                    action = DialogAction::SaveApp;
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
    action
}
