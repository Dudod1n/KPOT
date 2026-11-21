//! Results of finished tests in a file beside the configuration, the latest last.
use std::io::Read;
use std::path::Path;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::TestStatus;

/// Tests the file keeps; older ones are dropped.
pub const KEEP: usize = 50;
const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Default, Serialize, Deserialize)]
pub struct History {
    pub version: u32,
    #[serde(default)]
    pub tests: Vec<TestStatus>,
}

pub fn load(path: &Path) -> Result<History> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(History {
                version: 1,
                tests: Vec::new(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let mut raw = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() <= MAX_BYTES, "История тестов слишком большая.");
    Ok(serde_json::from_slice(&raw)?)
}

/// Adds a finished test. A file that cannot be read is left as it is, so that nothing the user
/// may still need is overwritten.
/// Tests finish on their own tasks; one at a time reads and rewrites the file.
pub fn append(path: &Path, test: TestStatus) -> Result<()> {
    static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _writing = WRITING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut history = load(path)?;
    history.version = 1;
    history.tests.push(test);
    if history.tests.len() > KEEP {
        history.tests.drain(..history.tests.len() - KEEP);
    }
    // Long stability tests are large: the oldest ones give way until the file fits.
    while history.tests.len() > 1 && serde_json::to_vec_pretty(&history)?.len() >= MAX_BYTES {
        history.tests.remove(0);
    }
    crate::config::atomic_json(path, &history, Some(MAX_BYTES))
}
