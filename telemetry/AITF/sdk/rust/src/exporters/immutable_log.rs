//! Immutable, hash-chained audit-log exporter.
//!
//! Writes [`AIBaseEvent`] values to an append-only JSONL log where each entry
//! embeds a SHA-256 hash of the previous entry, forming an unbroken chain. Any
//! modification to a historical entry invalidates all subsequent hashes, making
//! tampering detectable. Ported from the Go `exporters/immutable_log.go`
//! (genesis hash, `seq | timestamp | prev_hash | event_json` payload, entry
//! `{seq, timestamp, prev_hash, hash, event}`, and chain verification).
//!
//! Satisfies audit requirements for EU AI Act Article 12 (record-keeping),
//! NIST AI RMF GOVERN-1.5 (audit trail), SOC 2 CC8.1 (integrity), and ISO/IEC
//! 42001 (AI management records).

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use serde_json::Value;

use crate::ocsf::AIBaseEvent;

/// The genesis hash that seeds the chain (64 zeros).
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Computes the SHA-256 hash for a log entry.
fn compute_entry_hash(seq: u64, timestamp: &str, prev_hash: &str, event_json: &str) -> String {
    let payload = format!("{seq}|{timestamp}|{prev_hash}|{event_json}");
    let digest = Sha256::digest(payload.as_bytes());
    hex(&digest)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A single entry in the hash-chained log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableLogEntry {
    pub seq: u64,
    pub timestamp: String,
    pub prev_hash: String,
    pub hash: String,
    pub event: Value,
}

/// Result of an integrity check over an immutable log file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerificationResult {
    pub valid: bool,
    pub entries_checked: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_invalid_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Writes hash-chained, tamper-evident JSONL log entries for AI events.
#[derive(Debug, Clone)]
pub struct ImmutableLogExporter {
    log_file: PathBuf,
    prev_hash: String,
    seq: u64,
    event_count: u64,
}

impl ImmutableLogExporter {
    /// Creates an exporter for `log_file`, resuming the chain from an existing
    /// file when present.
    pub fn new(log_file: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = log_file.as_ref().to_path_buf();
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let mut exporter = ImmutableLogExporter {
            log_file: path,
            prev_hash: GENESIS_HASH.to_string(),
            seq: 0,
            event_count: 0,
        };
        exporter.resume_chain();
        Ok(exporter)
    }

    fn resume_chain(&mut self) {
        let file = match std::fs::File::open(&self.log_file) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut last_line = String::new();
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                last_line = trimmed.to_string();
            }
        }
        if !last_line.is_empty() {
            if let Ok(entry) = serde_json::from_str::<ImmutableLogEntry>(&last_line) {
                self.prev_hash = entry.hash;
                self.seq = entry.seq + 1;
            }
        }
    }

    /// Appends a batch of events to the log, extending the hash chain.
    pub fn export(&mut self, events: &[AIBaseEvent]) -> std::io::Result<()> {
        let mut lines: Vec<String> = Vec::new();
        for event in events {
            let event_value: Value = serde_json::to_value(event)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let event_json = serde_json::to_string(&event_value)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            let timestamp = now_rfc3339_nanos();
            let entry_hash = compute_entry_hash(self.seq, &timestamp, &self.prev_hash, &event_json);
            let entry = ImmutableLogEntry {
                seq: self.seq,
                timestamp,
                prev_hash: self.prev_hash.clone(),
                hash: entry_hash.clone(),
                event: event_value,
            };
            let entry_line = serde_json::to_string(&entry)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            lines.push(entry_line);
            self.prev_hash = entry_hash;
            self.seq += 1;
            self.event_count += 1;
        }

        if lines.is_empty() {
            return Ok(());
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)?;
        for line in lines {
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
        Ok(())
    }

    /// Total number of events written by this exporter.
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// The next sequence number that will be assigned.
    pub fn current_seq(&self) -> u64 {
        self.seq
    }

    /// The hash of the most recently written entry (or the genesis hash).
    pub fn current_hash(&self) -> &str {
        &self.prev_hash
    }
}

/// Verifies the integrity of an immutable log file by replaying the hash chain
/// from genesis. Returns a [`VerificationResult`] describing any break.
pub fn verify_immutable_log(log_file: impl AsRef<Path>) -> VerificationResult {
    let file = match std::fs::File::open(log_file.as_ref()) {
        Ok(f) => f,
        Err(e) => {
            return VerificationResult {
                valid: false,
                error: Some(format!("cannot open file: {e}")),
                ..Default::default()
            }
        }
    };

    let mut prev_hash = GENESIS_HASH.to_string();
    let mut entries_checked: u64 = 0;

    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: ImmutableLogEntry = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(e) => {
                return VerificationResult {
                    valid: false,
                    entries_checked,
                    first_invalid_seq: Some(entries_checked),
                    error: Some(format!("invalid JSON at seq {entries_checked}: {e}")),
                    ..Default::default()
                }
            }
        };

        if entry.prev_hash != prev_hash {
            return VerificationResult {
                valid: false,
                entries_checked,
                first_invalid_seq: Some(entry.seq),
                expected_hash: Some(prev_hash),
                found_hash: Some(entry.prev_hash),
                error: Some(format!("chain break at seq {}: prev_hash mismatch", entry.seq)),
                ..Default::default()
            };
        }

        let event_json = serde_json::to_string(&entry.event).unwrap_or_default();
        let computed = compute_entry_hash(entry.seq, &entry.timestamp, &entry.prev_hash, &event_json);
        if computed != entry.hash {
            return VerificationResult {
                valid: false,
                entries_checked,
                first_invalid_seq: Some(entry.seq),
                expected_hash: Some(computed),
                found_hash: Some(entry.hash),
                error: Some(format!("hash mismatch at seq {}: entry tampered", entry.seq)),
                ..Default::default()
            };
        }

        prev_hash = entry.hash;
        entries_checked += 1;
    }

    VerificationResult {
        valid: true,
        entries_checked,
        final_hash: Some(prev_hash),
        ..Default::default()
    }
}

fn now_rfc3339_nanos() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Dependency-free RFC3339-style marker with nanosecond precision (mirrors
    // the crate's existing timestamp convention).
    format!("1970-01-01T00:00:00Z+{}.{:09}", d.as_secs(), d.subsec_nanos())
}
