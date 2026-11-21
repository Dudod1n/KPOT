//! What a test found, for the snapshot, `krot-cli test --json` and the history file, and the
//! same in plain words. Every field is optional on the wire, so older and newer clients read
//! each other's reports.
use serde::{Deserialize, Serialize};

use crate::link::{bytes_text, duration_text, rate_text};
use crate::metrics::Summary;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Speed,
    Stability,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TestReport {
    /// ID of the tunnel.
    pub tunnel: String,
    pub kind: Kind,
    /// Unix time.
    pub started_at: f64,
    pub duration_s: u64,
    /// The stability test's planned length.
    pub planned_s: Option<u64>,
    /// The transfer limit in each direction, in bytes.
    pub limit_bytes: u64,
    /// Pings without a transfer of the test going on, and during one.
    pub idle_rtt: Summary,
    pub loaded_rtt: Summary,
    pub ping_sent: u64,
    pub ping_lost: u64,
    /// Bits per second; for the stability test, the mean of its short transfers.
    pub down_bps: Option<u64>,
    pub up_bps: Option<u64>,
    pub down_bytes: u64,
    pub up_bytes: u64,
    pub stalls: Vec<Stall>,
    /// The stability test's minutes.
    pub samples: Vec<Sample>,
    pub reconnects: u64,
    /// Connects and disconnects of the session during the test.
    pub events: Vec<Event>,
    /// Steps not taken, with the reason.
    pub skipped: Vec<String>,
    /// Facts worth a look: a transfer cut short, a step that failed.
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    #[default]
    Down,
    Up,
    /// Pings in a row without an answer.
    Ping,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Stall {
    /// Seconds since the start of the test.
    pub at_s: f64,
    pub direction: Direction,
    /// Bytes of the transfer before it stood still.
    pub at_byte: Option<u64>,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Sample {
    pub minute: u64,
    pub rtt_p50_us: Option<u64>,
    pub rtt_p95_us: Option<u64>,
    pub sent: u64,
    pub lost: u64,
    pub down_bps: Option<u64>,
    pub up_bps: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Event {
    pub at_s: f64,
    /// `disconnected` or `reconnected`.
    pub kind: String,
}

/// A test as the background process reports it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TestStatus {
    pub id: String,
    /// `running`, `done`, `failed` or `cancelled`.
    pub state: String,
    /// What the test is doing now.
    pub phase: String,
    pub elapsed_s: u64,
    /// Why the test failed.
    pub error: String,
    pub report: TestReport,
}

impl TestStatus {
    pub fn finished(&self) -> bool {
        self.state != "running"
    }
}

fn milliseconds(us: u64) -> String {
    if us < 10_000 {
        format!("{:.1}", us as f64 / 1000.0).replace('.', ",")
    } else {
        (us / 1000).to_string()
    }
}

fn delay_text(summary: &Summary) -> Option<String> {
    let (p50, p95) = (summary.p50_us?, summary.p95_us?);
    Some(format!(
        "{} мс (p95 {} мс)",
        milliseconds(p50),
        milliseconds(p95)
    ))
}

fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "0 %".into();
    }
    let value = part as f64 * 100.0 / whole as f64;
    format!("{value:.1} %").replace('.', ",")
}

fn plural(count: u64, one: &str, few: &str, many: &str) -> String {
    let word = match (count % 10, count % 100) {
        (1, 11) => many,
        (1, _) => one,
        (2..=4, 12..=14) => many,
        (2..=4, _) => few,
        _ => many,
    };
    format!("{count} {word}")
}

fn seconds(ms: u64) -> String {
    format!("{:.1}", ms as f64 / 1000.0).replace('.', ",")
}

fn stall_text(stall: &Stall) -> String {
    let what = match stall.direction {
        Direction::Down => "скачивание",
        Direction::Up => "отдача",
        Direction::Ping => "ping без ответа",
    };
    let at = stall
        .at_byte
        .map(|byte| format!(" на {}", bytes_text(byte)))
        .unwrap_or_default();
    format!(
        "{what}{at}, на {} с теста — {} с",
        stall.at_s as u64,
        seconds(stall.duration_ms)
    )
}

/// The stalls in one line: `2 замирания по 6,1–9,0 с`.
fn stalls_summary(stalls: &[Stall]) -> String {
    if stalls.is_empty() {
        return "замираний нет".into();
    }
    let shortest = stalls.iter().map(|s| s.duration_ms).min().unwrap_or(0);
    let longest = stalls.iter().map(|s| s.duration_ms).max().unwrap_or(0);
    let count = stalls.len() as u64;
    let lengths = if shortest == longest {
        format!("{} с", seconds(longest))
    } else {
        format!("{}–{} с", seconds(shortest), seconds(longest))
    };
    format!(
        "{} по {lengths}",
        plural(count, "замирание", "замирания", "замираний")
    )
}

/// The report in plain words: facts only, one per line.
pub fn render(report: &TestReport) -> Vec<String> {
    let mut lines = Vec::new();
    match report.kind {
        Kind::Speed => {
            let idle = delay_text(&report.idle_rtt);
            let loaded = delay_text(&report.loaded_rtt);
            lines.push(match (idle, loaded) {
                (Some(idle), Some(loaded)) => {
                    format!("Задержка {idle}, под нагрузкой — {loaded}.")
                }
                (Some(idle), None) => format!("Задержка {idle}."),
                (None, Some(loaded)) => format!("Задержка под нагрузкой {loaded}."),
                (None, None) => "Сервер не ответил ни на один ping.".into(),
            });
            if report.ping_lost > 0 {
                lines.push(format!(
                    "Потеряно ping: {} из {}.",
                    report.ping_lost, report.ping_sent
                ));
            }
            if let Some(down) = report.down_bps {
                lines.push(format!(
                    "Скачивание {} ({}).",
                    rate_text(down),
                    bytes_text(report.down_bytes)
                ));
            }
            if let Some(up) = report.up_bps {
                lines.push(format!(
                    "Отдача {} ({}).",
                    rate_text(up),
                    bytes_text(report.up_bytes)
                ));
            }
            if report.down_bps.is_some() || report.up_bps.is_some() {
                lines.push(format!(
                    "Во время передачи: {}.",
                    stalls_summary(&report.stalls)
                ));
            }
        }
        Kind::Stability => {
            let mut line = format!(
                "За {}: {}, {}, потерь ping {} ({} из {}).",
                duration_text(report.duration_s),
                stalls_summary(&report.stalls),
                plural(
                    report.reconnects,
                    "переподключение",
                    "переподключения",
                    "переподключений"
                ),
                percent(report.ping_lost, report.ping_sent),
                report.ping_lost,
                report.ping_sent
            );
            if let Some(rtt) = delay_text(&report.idle_rtt) {
                line += &format!(" Задержка {rtt}.");
            }
            lines.push(line);
            if let (Some(down), Some(up)) = (report.down_bps, report.up_bps) {
                lines.push(format!(
                    "Короткие передачи: скачивание в среднем {}, отдача {}.",
                    rate_text(down),
                    rate_text(up)
                ));
            }
        }
    }
    for stall in &report.stalls {
        lines.push(format!("Замирание: {}.", stall_text(stall)));
    }
    for event in &report.events {
        let what = match event.kind.as_str() {
            "disconnected" => "сессия оборвалась",
            "reconnected" => "туннель переподключился",
            other => other,
        };
        lines.push(format!("На {} с теста {what}.", event.at_s as u64));
    }
    for reason in &report.skipped {
        lines.push(format!("Пропущено: {reason}"));
    }
    for note in &report.notes {
        lines.push(note.clone());
    }
    if let Some(advice) = advice(report) {
        lines.push(advice);
    }
    lines
}

/// A transfer that stood still until the end of its step and never reached its limit.
fn advice(report: &TestReport) -> Option<String> {
    let cut = report
        .notes
        .iter()
        .any(|note| note.starts_with("Скачивание остановилось"));
    cut.then(|| {
        "Если скачивание каждый раз останавливается на одном объёме, запустите `krot-cli diagnose` для этого туннеля.".into()
    })
}

/// The stability test's minutes as a table.
pub fn minutes_table(report: &TestReport) -> Vec<String> {
    if report.samples.is_empty() {
        return Vec::new();
    }
    let mut lines = vec!["Мин  p50 мс  p95 мс  потери     ↓            ↑".to_owned()];
    let cell = |value: Option<u64>| value.map_or("—".to_owned(), milliseconds);
    let rate = |value: Option<u64>| value.map_or("—".to_owned(), rate_text);
    for sample in &report.samples {
        lines.push(format!(
            "{:>3}  {:>6}  {:>6}  {:>6}  {:>12} {:>12}",
            sample.minute + 1,
            cell(sample.rtt_p50_us),
            cell(sample.rtt_p95_us),
            format!("{}/{}", sample.lost, sample.sent),
            rate(sample.down_bps),
            rate(sample.up_bps)
        ));
    }
    lines
}

/// What the test sends and receives at most, in bytes, for the warning shown before it.
pub fn planned_bytes(kind: Kind, duration_s: u64, limit_bytes: u64) -> u64 {
    match kind {
        Kind::Speed => 2 * limit_bytes,
        Kind::Stability => duration_s.div_ceil(60) * 2 * super::STABILITY_TRANSFER,
    }
}
