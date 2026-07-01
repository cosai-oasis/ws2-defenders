//! Wazuh exporter — writes events to a JSONL file the wazuh-agent's
//! `localfile` collector tails.
//!
//! Wazuh's preferred ingest path for arbitrary structured logs is a file
//! configured in `ossec.conf`:
//!
//! ```xml
//! <localfile>
//!   <log_format>json</log_format>
//!   <location>/var/ossec/logs/agentdr.json</location>
//! </localfile>
//! ```
//!
//! Files are rotated by size (operator-tunable; default 50 MiB).

use super::Exporter;
use crate::config::WazuhConfig;
use crate::models::EventRecord;
use async_trait::async_trait;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct Wazuh {
    path: PathBuf,
    rotate_bytes: u64,
    lock: Mutex<()>,
}

impl Wazuh {
    pub fn new(cfg: &WazuhConfig) -> Result<Self, String> {
        if cfg.output_path.is_empty() {
            return Err("wazuh.output_path is empty".into());
        }
        let path = PathBuf::from(&cfg.output_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("wazuh: mkdir {}: {e}", parent.display()))?;
        }
        Ok(Self { path, rotate_bytes: cfg.rotate_bytes, lock: Mutex::new(()) })
    }

    fn rotate_if_needed(&self) {
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() >= self.rotate_bytes {
                let rotated = self.path.with_extension("json.1");
                let _ = std::fs::rename(&self.path, rotated);
            }
        }
    }
}

#[async_trait]
impl Exporter for Wazuh {
    fn name(&self) -> &'static str { "wazuh" }

    async fn send(&self, events: &[EventRecord]) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap();
        self.rotate_if_needed();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("wazuh: open {}: {e}", self.path.display()))?;
        for ev in events {
            let line = serde_json::to_string(ev).map_err(|e| e.to_string())?;
            writeln!(f, "{}", line).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
