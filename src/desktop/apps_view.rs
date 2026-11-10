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

pub(super) fn app_state_label(state: &str) -> (&'static str, Color32) {
    match state {
        "running" => ("↟ Работает", GREEN),
        "blocked" => ("! Туннель не работает, сеть приложения закрыта", AMBER),
        "direct" => ("! Туннель не работает, трафик идёт напрямую", AMBER),
        "orphan" => ("! Туннель удалён", RED),
        "unavailable" => ("◌ Перехват недоступен", DIM),
        _ => ("○ Остановлено", DIM),
    }
}

fn app_mascot(state: &str) -> &'static str {
    match state {
        "running" => "running",
        "blocked" | "direct" => "waiting",
        "orphan" => "error",
        _ => "idle",
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
    pub(super) fn new_socks_tunnel(&mut self) {
        let mut form = TunnelForm::new(None);
        form.draft.kind = "D".into();
        form.original = form.signature();
        self.view = View::Tunnels;
        self.dialog = Some(Dialog::Form(Box::new(form)));
    }
    pub(super) fn apps_side(&mut self, ui: &mut egui::Ui) {
        let rules = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.apps.clone())
            .unwrap_or_default();
        ui.add_space(12.0);
        ui.weak("Мои приложения");
        ui.add_space(5.0);
        egui::ScrollArea::vertical()
            .id_salt("app_scroll")
            .show(ui, |ui| {
                if rules.is_empty() {
                    ui.add_space(20.0);
                    ui.label(mascot("idle", 0));
                    ui.weak(if self.snapshot.is_some() {
                        "Здесь появится первое правило.\nN — добавить приложение."
                    } else {
                        "Подключаемся к фоновому КРОТу…"
                    });
                }
                for rule in &rules {
                    let (label, color) = app_state_label(self.app_state(rule));
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
                        .map(|tunnel| tunnel.name.as_str())
                        .unwrap_or("туннель удалён");
                    let text = format!("{}\n{}\n→ {}", rule.name, label, tunnel);
                    let button = egui::Button::new(RichText::new(text).color(tone(ui, color)))
                        .selected(self.selected_app.as_ref() == Some(&rule.id))
                        .wrap();
                    if ui.add_sized([ui.available_width(), 80.0], button).clicked() {
                        self.selected_app = Some(rule.id.clone());
                    }
                }
            });
    }
    pub(super) fn apps_main(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let unavailable = snapshot.apps_unavailable.clone();
        let has_socks = snapshot.config.tunnels.iter().any(|t| t.kind == "D");
        if !unavailable.is_empty() {
            ui.colored_label(tone(ui, AMBER), &unavailable);
            ui.add_space(8.0);
        }
        if let Some(rule) = self.selected_app() {
            self.app_detail(ui, ctx, &rule);
            return;
        }
        ui.heading("На участке");
        ui.add_space(24.0);
        ui.label(RichText::new(mascot("idle", 0)).color(tone(ui, DIM)));
        ui.add_space(16.0);
        if has_socks {
            ui.label("Добавьте приложение, чтобы направить его трафик через туннель.");
            ui.weak("Через туннель идёт только TCP. UDP и QUIC приложения блокируются.");
        } else {
            ui.label("Приложения ходят через туннели типа D (SOCKS5). Таких туннелей пока нет.");
            if ui.button("Создать туннель D").clicked() {
                self.new_socks_tunnel();
            }
        }
    }
    fn app_detail(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, rule: &AppRule) {
        let state = self.app_state(rule).to_owned();
        let (label, color) = app_state_label(&state);
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
        ui.heading(&rule.name);
        ui.colored_label(tone(ui, color), label);
        ui.add_space(14.0);
        ui.label(
            RichText::new(mascot(app_mascot(&state), self.frame()))
                .monospace()
                .size(16.0)
                .color(tone(ui, color)),
        );
        ui.add_space(16.0);
        match (state.as_str(), &tunnel) {
            ("orphan", _) => {
                ui.label("Туннель этого правила удалён или больше не SOCKS5. Выберите другой туннель типа D.");
                if ui.button("Выбрать туннель").clicked() {
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
                    if ui.button("Разобраться с туннелем").clicked() {
                        self.resolve(tunnel);
                    }
                } else if !active(&tunnel_state)
                    && ui
                        .add_enabled(
                            !self.busy_tunnels.contains(&tunnel.id),
                            egui::Button::new("Запустить туннель"),
                        )
                        .clicked()
                {
                    self.toggle(ctx, tunnel);
                }
            }
            _ => {}
        }
        ui.colored_label(tone(ui, CYAN), &rule.path);
        ui.separator();
        match &tunnel {
            Some(tunnel) => {
                let (tunnel_label, _) = state_label(self.state(tunnel));
                ui.label(format!(
                    "Туннель: {} · {} · {}:{} · {}",
                    tunnel.name, tunnel.kind, tunnel.bind, tunnel.port, tunnel_label
                ));
            }
            None => {
                ui.colored_label(tone(ui, RED), "Туннель: удалён");
            }
        }
        ui.weak("Способ: перехват по пути файла, включая уже запущенные процессы");
        ui.weak(if rule.on_tunnel_down == "direct" {
            "Без туннеля: пускать напрямую"
        } else {
            "Без туннеля: блокировать сеть приложения"
        });
        ui.weak(if rule.children {
            "Дочерние процессы: включены"
        } else {
            "Дочерние процессы: не включены"
        });
        ui.weak("Трафик: только TCP, имена разрешает этот компьютер; UDP и QUIC блокируются");
        ui.label(format!(
            "Соединений {} · всего {} · ↑ {} · ↓ {}",
            runtime.connections,
            runtime.total,
            bytes(runtime.sent),
            bytes(runtime.received)
        ));
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
                    egui::Button::new(RichText::new(action).color(tone(ui, CYAN))),
                )
                .clicked()
            {
                self.toggle_app(ctx, rule);
            }
            if ui.button("E Изменить").clicked() {
                self.dialog = Some(Dialog::AppForm(Box::new(AppForm::new(Some(rule.clone())))));
            }
            if ui
                .button(RichText::new("Удалить").color(tone(ui, RED)))
                .clicked()
            {
                self.confirm = Some(Confirm::DeleteApp {
                    id: rule.id.clone(),
                    name: rule.name.clone(),
                });
            }
        });
        ui.add_space(8.0);
        ui.weak("Журнал");
        if runtime.logs.is_empty() {
            ui.weak("Записей пока нет.");
        }
        for line in &runtime.logs {
            ui.label(line);
        }
    }
}

pub(super) fn app_form_view(
    ui: &mut egui::Ui,
    form: &mut AppForm,
    tunnels: &[Tunnel],
    max_height: f32,
) -> DialogAction {
    let mut action = DialogAction::None;
    ui.heading(if form.editing {
        "Изменить правило"
    } else {
        "Новое правило"
    });
    if !form.error.is_empty() {
        ui.colored_label(tone(ui, RED), &form.error);
    }
    let content_height = max_height - if form.error.is_empty() { 0.0 } else { 45.0 };
    ui.add_enabled_ui(!form.busy, |ui| {
        egui::ScrollArea::vertical()
            .id_salt("app_form_scroll")
            .max_height(content_height)
            .show(ui, |ui| {
                ui.label("Источник");
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .selectable_label(!form.from_process, "Исполняемый файл")
                        .clicked()
                    {
                        form.from_process = false;
                    }
                    if ui
                        .selectable_label(form.from_process, "Запущенный процесс")
                        .clicked()
                    {
                        form.from_process = true;
                        form.processes = crate::apps::processes();
                    }
                });
                if form.from_process {
                    ui.horizontal(|ui| {
                        if ui.button("Обновить").clicked() {
                            form.processes = crate::apps::processes();
                        }
                        ui.add(
                            egui::TextEdit::singleline(&mut form.filter)
                                .hint_text("имя, PID или путь")
                                .desired_width(f32::INFINITY),
                        );
                    });
                    let filter = form.filter.trim().to_lowercase();
                    let mut picked = None;
                    egui::ScrollArea::vertical()
                        .id_salt("process_scroll")
                        .max_height(130.0)
                        .show(ui, |ui| {
                            let mut shown = 0;
                            for process in &form.processes {
                                let line =
                                    format!("{:>6}  {}  {}", process.pid, process.name, process.path);
                                if !filter.is_empty() && !line.to_lowercase().contains(&filter) {
                                    continue;
                                }
                                shown += 1;
                                if ui
                                    .selectable_label(form.draft.path == process.path, line)
                                    .clicked()
                                {
                                    picked = Some(process.clone());
                                }
                            }
                            if shown == 0 {
                                ui.weak("Ничего не найдено.");
                            }
                        });
                    if let Some(process) = picked {
                        form.select_path(process.path, &process.name);
                    }
                }
                ui.label("Путь к исполняемому файлу");
                ui.horizontal(|ui| {
                    let browse = cfg!(not(target_os = "linux"));
                    let reserved = if browse { 100.0 } else { 0.0 };
                    ui.add(
                        egui::TextEdit::singleline(&mut form.draft.path)
                            .desired_width((ui.available_width() - reserved).max(80.0)),
                    );
                    if browse && ui.button("Обзор…").clicked() {
                        action = DialogAction::BrowseApp;
                    }
                });
                field(ui, "Название правила", &mut form.draft.name);
                ui.label("Туннель");
                let socks: Vec<&Tunnel> = tunnels.iter().filter(|t| t.kind == "D").collect();
                if socks.is_empty() {
                    ui.colored_label(
                        tone(ui, AMBER),
                        "Нет туннелей типа D. Сначала создайте SOCKS5-туннель.",
                    );
                } else {
                    let selected = socks
                        .iter()
                        .find(|tunnel| tunnel.id == form.draft.tunnel_id)
                        .map(|tunnel| format!("{} · {}:{}", tunnel.name, tunnel.bind, tunnel.port))
                        .unwrap_or_else(|| "выберите туннель D".into());
                    egui::ComboBox::from_id_salt("app_tunnel")
                        .selected_text(selected)
                        .show_ui(ui, |ui| {
                            for tunnel in socks {
                                ui.selectable_value(
                                    &mut form.draft.tunnel_id,
                                    tunnel.id.clone(),
                                    format!("{} · {}:{}", tunnel.name, tunnel.bind, tunnel.port),
                                );
                            }
                        });
                }
                ui.label("Если туннель не работает");
                ui.horizontal_wrapped(|ui| {
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
                });
                ui.checkbox(&mut form.draft.children, "Включая дочерние процессы");
                ui.weak("Через туннель идёт только TCP. UDP и QUIC приложения блокируются, имена разрешает этот компьютер.");
            });
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            if ui.button("Отмена").clicked() {
                action = DialogAction::Close;
            }
            if ui.button("Сохранить").clicked() {
                action = DialogAction::SaveApp;
            }
        });
    });
    if form.busy {
        ui.weak("Сохраняем…");
    }
    action
}
