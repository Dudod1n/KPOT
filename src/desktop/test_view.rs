//! The speed and stability test in a tunnel's card: what it will cost, its progress and its result.
use super::*;
use crate::quality::{DEFAULT_LIMIT_MB, Kind, TestStatus, report};

/// The stability test's durations offered in the card, in minutes.
const STABILITY_MINUTES: [u64; 3] = [10, 30, 60];

fn state_text(status: &TestStatus) -> &'static str {
    match status.state.as_str() {
        "running" => "идёт",
        "done" => "завершён",
        "cancelled" => "отменён",
        _ => "прерван",
    }
}

impl Desktop {
    pub(super) fn tunnel_test(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        tunnel: &Tunnel,
        running: bool,
        pal: &Pal,
    ) {
        let status = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.tests.get(&tunnel.id))
            .cloned();
        if !running && status.is_none() {
            return;
        }
        let testing = status.as_ref().is_some_and(|status| !status.finished());
        let (title, color) = match &status {
            Some(status) => (
                format!("Тест связи: {}", state_text(status)),
                match status.state.as_str() {
                    "running" => pal.warn,
                    "done" => pal.ok,
                    _ => pal.dim,
                },
            ),
            None => ("Тест связи".to_owned(), pal.dim),
        };
        let busy = self.pending_operations > 0;
        let choice = style::group(ui, &title, color, pal, |ui| {
            let mut choice = None;
            if let Some(status) = &status {
                if testing {
                    let kind = match status.report.kind {
                        Kind::Speed => "Тест скорости".to_owned(),
                        Kind::Stability => format!(
                            "Тест стабильности на {}",
                            crate::link::duration_text(status.report.planned_s.unwrap_or(0))
                        ),
                    };
                    ui.label(
                        RichText::new(format!(
                            "{kind} · {} · прошло {}",
                            status.phase,
                            crate::link::duration_text(status.elapsed_s)
                        ))
                        .monospace()
                        .color(pal.dim),
                    );
                } else {
                    for line in report::render(&status.report) {
                        ui.label(RichText::new(line).monospace().color(pal.dim));
                    }
                    if !status.error.is_empty() {
                        ui.colored_label(pal.error, &status.error);
                    }
                }
            }
            if testing {
                if ui
                    .add_enabled(!busy, style::secondary("Отменить тест", pal))
                    .clicked()
                {
                    choice = status.as_ref().map(|status| json!({"id": status.id}));
                }
                return choice.map(|payload| ("test_cancel", payload));
            }
            if !running {
                return None;
            }
            ui.label(
                RichText::new(format!(
                    "Тест скорости передаст до {} ({} МБ в каждую сторону), тест стабильности — около 0,5 МБ в минуту. Тест делит канал с трафиком приложений; на мобильном интернете он расходует трафик.",
                    crate::link::bytes_text(report::planned_bytes(Kind::Speed, 0, DEFAULT_LIMIT_MB * 1024 * 1024)),
                    DEFAULT_LIMIT_MB
                ))
                .color(pal.dim),
            );
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(!busy, style::secondary("Тест скорости", pal))
                    .clicked()
                {
                    choice = Some(json!({"id": tunnel.id, "kind": "speed"}));
                }
                for minutes in STABILITY_MINUTES {
                    if ui
                        .add_enabled(
                            !busy,
                            style::secondary(&format!("Стабильность {minutes} мин"), pal),
                        )
                        .clicked()
                    {
                        choice = Some(
                            json!({"id": tunnel.id, "kind": "stability", "duration": minutes * 60}),
                        );
                    }
                }
            });
            choice.map(|payload| ("test_start", payload))
        });
        if let Some((command, payload)) = choice {
            self.request(ctx, Operation::Test, command, payload);
        }
    }
}
