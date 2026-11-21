//! `krot-cli test`: runs a test in the background process and prints its report.
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

use super::{
    DEFAULT_LIMIT_MB, Kind, MAX_LIMIT_MB, MAX_STABILITY, MIN_STABILITY, TestStatus, report,
};
use crate::background::Client;
use crate::config::Store;
use crate::link::bytes_text;

const POLL: Duration = Duration::from_millis(500);

/// A duration such as `30m`, `1h`, `90s` or `30` (minutes).
pub fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    let (number, unit) = match value.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((index, _)) => value.split_at(index),
        None => (value, "m"),
    };
    let number: u64 = number
        .parse()
        .ok()
        .context("Длительность — число с единицей: 10m, 1h, 90s.")?;
    let seconds = match unit.trim() {
        "s" | "с" => number,
        "m" | "min" | "м" | "мин" => number.saturating_mul(60),
        "h" | "ч" => number.saturating_mul(3600),
        _ => bail!("Длительность — число с единицей: 10m, 1h, 90s."),
    };
    let duration = Duration::from_secs(seconds);
    ensure!(
        (MIN_STABILITY..=MAX_STABILITY).contains(&duration),
        "Длительность теста стабильности — от 10 секунд до 24 часов."
    );
    Ok(duration)
}

/// What the user sees before the test starts: how much it transfers, and that it shares the
/// tunnel with the applications.
pub fn warning(kind: Kind, duration_s: u64, limit_mb: u64) -> String {
    let planned = report::planned_bytes(kind, duration_s, limit_mb * 1024 * 1024);
    format!(
        "Тест передаст до {} (в обе стороны вместе) по SSH-сессии туннеля и делит канал с трафиком приложений. На мобильном интернете это расходует трафик.",
        bytes_text(planned)
    )
}

fn title(kind: Kind, name: &str) -> String {
    match kind {
        Kind::Speed => format!("Тест скорости туннеля «{name}»"),
        Kind::Stability => format!("Тест стабильности туннеля «{name}»"),
    }
}

/// The finished test in plain words.
pub fn render(status: &TestStatus, name: &str) -> String {
    let mut text = format!("{}\n", title(status.report.kind, name));
    for line in report::render(&status.report) {
        text += &format!("  {line}\n");
    }
    let table = report::minutes_table(&status.report);
    if !table.is_empty() {
        text += "\n";
        for line in table {
            text += &format!("  {line}\n");
        }
    }
    text
}

pub async fn run(
    store: &Store,
    tunnel: &str,
    stability: Option<String>,
    limit: Option<u64>,
    json_output: bool,
) -> Result<()> {
    let duration = stability.as_deref().map(parse_duration).transpose()?;
    let kind = if duration.is_some() {
        Kind::Stability
    } else {
        Kind::Speed
    };
    let limit_mb = limit.unwrap_or(DEFAULT_LIMIT_MB);
    ensure!(
        (1..=MAX_LIMIT_MB).contains(&limit_mb),
        "Лимит объёма теста — от 1 до {MAX_LIMIT_MB} МБ."
    );
    ensure!(
        store.sidecar(".background.json").exists(),
        "Фоновый КРОТ не запущен."
    );
    let client = Client::new(store);
    let snapshot = client.snapshot().await?;
    let saved = snapshot
        .config
        .tunnels
        .iter()
        .find(|saved| saved.id == tunnel)
        .or_else(|| {
            snapshot
                .config
                .tunnels
                .iter()
                .find(|saved| saved.name == tunnel)
        })
        .context("Сохранённый туннель не найден.")?;
    let (id, name) = (saved.id.clone(), saved.name.clone());
    ensure!(
        snapshot
            .runtimes
            .get(&id)
            .is_some_and(|runtime| runtime.state == "running"),
        "Туннель «{name}» не работает. Запустите его и повторите тест."
    );
    let duration_s = duration.map(|duration| duration.as_secs());
    eprintln!("{}", warning(kind, duration_s.unwrap_or(0), limit_mb));
    let started = client
        .request(
            "test_start",
            json!({"id": id, "kind": kind, "duration": duration_s, "limit_mb": limit_mb}),
        )
        .await?;
    let test = started
        .get("id")
        .and_then(Value::as_str)
        .context("Фоновый КРОТ не сообщил ID теста.")?
        .to_owned();
    let interrupted = tokio::signal::ctrl_c();
    tokio::pin!(interrupted);
    let mut cancelled = false;
    let mut shown = String::new();
    let status = loop {
        tokio::select! {
            _ = &mut interrupted, if !cancelled => {
                cancelled = true;
                eprintln!("Отмена теста…");
                client.request("test_cancel", json!({"id": test})).await?;
            }
            () = tokio::time::sleep(POLL) => {}
        }
        let status: TestStatus =
            serde_json::from_value(client.request("test_status", json!({"id": test})).await?)
                .context("Некорректный ответ о ходе теста.")?;
        if status.finished() {
            break status;
        }
        if !status.phase.is_empty() && status.phase != shown {
            let phase = status.phase.split(':').next().unwrap_or_default();
            if !shown.starts_with(phase) {
                eprintln!("{phase}…");
            }
            shown = status.phase.clone();
        }
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&status.report)?);
    } else {
        print!("{}", render(&status, &name));
    }
    match status.state.as_str() {
        "done" => Ok(()),
        "cancelled" => bail!("Тест отменён; выше — то, что он успел измерить."),
        _ => bail!("{}", status.error),
    }
}
