//! Event storage (JSONL) and HTTP event pusher.

use crate::models::EventRecord;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};

// ── JSONL file store with rotation ──

pub struct JsonlStore {
    path: PathBuf,
    max_bytes: u64,
    backup_count: u32,
    lock: Mutex<()>,
}

impl JsonlStore {
    pub fn new(path: PathBuf, max_bytes: u64, backup_count: u32) -> Self {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        // Ensure file exists
        let _ = OpenOptions::new().create(true).append(true).open(&path);
        Self { path, max_bytes, backup_count, lock: Mutex::new(()) }
    }

    pub fn write_event(&self, event: &EventRecord) {
        let json = match serde_json::to_string(event) {
            Ok(j) => j,
            Err(e) => { error!("Failed to serialize event: {}", e); return; }
        };
        let bytes = json.len() as u64 + 1;

        let _guard = self.lock.lock().unwrap();
        self.rotate_if_needed(bytes);

        if let Ok(file) = OpenOptions::new().create(true).append(true).open(&self.path) {
            let mut writer = BufWriter::new(file);
            let _ = writeln!(writer, "{}", json);
        }
    }

    fn rotate_if_needed(&self, incoming: u64) {
        let current = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if current + incoming <= self.max_bytes {
            return;
        }

        // Shift backups
        for idx in (1..self.backup_count).rev() {
            let src = self.backup_path(idx);
            let dst = self.backup_path(idx + 1);
            if src.exists() {
                let _ = fs::rename(&src, &dst);
            }
        }

        let first_backup = self.backup_path(1);
        let _ = fs::rename(&self.path, &first_backup);
        let _ = File::create(&self.path);
    }

    fn backup_path(&self, idx: u32) -> PathBuf {
        let name = format!("{}.{}", self.path.to_string_lossy(), idx);
        PathBuf::from(name)
    }
}

// ── HTTP event pusher ──

pub struct EventPusher {
    enabled: bool,
    endpoint: String,
    api_key: String,
    timeout: Duration,
    batch_size: usize,
    flush_interval: Duration,
}

impl EventPusher {
    pub fn new(cfg: &crate::config::ServerPushConfig) -> Self {
        Self {
            enabled: cfg.enabled && !cfg.endpoint.is_empty(),
            endpoint: cfg.endpoint.clone(),
            api_key: cfg.api_key.clone(),
            timeout: Duration::from_secs(cfg.timeout_seconds),
            batch_size: cfg.batch_size,
            flush_interval: Duration::from_secs(cfg.flush_interval_seconds),
        }
    }

    pub async fn run(self, mut rx: mpsc::UnboundedReceiver<EventRecord>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        if !self.enabled {
            // Drain the channel silently
            loop {
                tokio::select! {
                    _ = rx.recv() => {},
                    _ = shutdown.changed() => { break; }
                }
            }
            return;
        }

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .unwrap_or_default();

        let mut batch: Vec<serde_json::Value> = Vec::new();
        let mut ticker = interval(self.flush_interval);

        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    if let Ok(val) = serde_json::to_value(&event) {
                        batch.push(val);
                    }
                    if batch.len() >= self.batch_size {
                        self.send_batch(&client, &mut batch).await;
                    }
                }
                _ = ticker.tick() => {
                    if !batch.is_empty() {
                        self.send_batch(&client, &mut batch).await;
                    }
                }
                _ = shutdown.changed() => {
                    // Flush remaining
                    if !batch.is_empty() {
                        self.send_batch(&client, &mut batch).await;
                    }
                    break;
                }
            }
        }
        debug!("Event pusher shut down");
    }

    async fn send_batch(&self, client: &reqwest::Client, batch: &mut Vec<serde_json::Value>) {
        let payload = serde_json::json!({ "events": batch });
        let mut req = client.post(&self.endpoint)
            .header("Content-Type", "application/json")
            .json(&payload);

        if !self.api_key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Pushed {} events to server", batch.len());
                batch.clear();
            }
            Ok(resp) => {
                error!("Push failed with status: {}", resp.status());
                // Keep batch for retry
            }
            Err(e) => {
                error!("Push error: {}", e);
                // Keep batch for retry
            }
        }
    }
}
