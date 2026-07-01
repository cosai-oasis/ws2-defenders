//! Splunk HTTP Event Collector (HEC).
//!
//! Sends one HEC event per AgentDR EventRecord. The HEC wire format is a
//! newline-delimited stream of `{"event": ..., "time": ..., ...}` objects,
//! posted to `<endpoint>/services/collector/event` with
//! `Authorization: Splunk <token>`.

use super::{http_client, Exporter};
use crate::config::SplunkConfig;
use crate::models::EventRecord;
use async_trait::async_trait;
use chrono::DateTime;
use serde_json::json;

pub struct Splunk {
    client: reqwest::Client,
    endpoint: String,
    token: String,
    index: String,
    sourcetype: String,
}

impl Splunk {
    pub fn new(cfg: &SplunkConfig) -> Result<Self, String> {
        if cfg.endpoint.is_empty() {
            return Err("splunk.endpoint is empty".into());
        }
        if cfg.token.is_empty() {
            return Err("splunk.token is empty".into());
        }
        Ok(Self {
            client: http_client(cfg.batch.timeout_seconds, cfg.verify_tls),
            endpoint: format!("{}/services/collector/event", cfg.endpoint.trim_end_matches('/')),
            token: cfg.token.clone(),
            index: cfg.index.clone(),
            sourcetype: cfg.sourcetype.clone(),
        })
    }
}

#[async_trait]
impl Exporter for Splunk {
    fn name(&self) -> &'static str { "splunk" }

    async fn send(&self, events: &[EventRecord]) -> Result<(), String> {
        let mut body = String::new();
        for ev in events {
            let epoch = DateTime::parse_from_rfc3339(&ev.timestamp)
                .map(|d| d.timestamp_millis() as f64 / 1000.0)
                .unwrap_or(0.0);
            let mut hec = json!({
                "event": ev,
                "sourcetype": self.sourcetype,
                "source": "agentdr",
                "time": epoch,
            });
            if !self.index.is_empty() {
                hec["index"] = json!(self.index);
            }
            body.push_str(&hec.to_string());
            body.push('\n');
        }
        let resp = self.client
            .post(&self.endpoint)
            .header("Authorization", format!("Splunk {}", self.token))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("splunk: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("splunk: HTTP {}", resp.status()));
        }
        Ok(())
    }
}
