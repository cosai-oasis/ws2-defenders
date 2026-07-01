//! Microsoft Sentinel — Azure Log Analytics HTTP Data Collector.
//!
//! Sentinel ingest is signed: SHA-256 HMAC of a canonicalised request
//! line, keyed with the workspace's base64-decoded shared key.
//! Endpoint: `https://<workspace>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01`
//! Header: `Authorization: SharedKey <workspaceId>:<base64(hmac-sha256(...))>`.
//! Custom log type ends up as `<log_type>_CL` in Sentinel.

use super::{http_client, Exporter};
use crate::config::SentinelConfig;
use crate::models::EventRecord;
use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct Sentinel {
    client: reqwest::Client,
    endpoint: String,
    workspace_id: String,
    shared_key: Vec<u8>,
    log_type: String,
}

impl Sentinel {
    pub fn new(cfg: &SentinelConfig) -> Result<Self, String> {
        if cfg.workspace_id.is_empty() {
            return Err("sentinel.workspace_id is empty".into());
        }
        if cfg.shared_key.is_empty() {
            return Err("sentinel.shared_key is empty".into());
        }
        let shared_key = base64::engine::general_purpose::STANDARD
            .decode(&cfg.shared_key)
            .map_err(|e| format!("sentinel.shared_key not base64: {e}"))?;
        let endpoint = format!(
            "https://{}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
            cfg.workspace_id
        );
        Ok(Self {
            client: http_client(cfg.batch.timeout_seconds, true),
            endpoint,
            workspace_id: cfg.workspace_id.clone(),
            shared_key,
            log_type: cfg.log_type.clone(),
        })
    }
}

#[async_trait]
impl Exporter for Sentinel {
    fn name(&self) -> &'static str { "sentinel" }

    async fn send(&self, events: &[EventRecord]) -> Result<(), String> {
        let body = serde_json::to_vec(events).map_err(|e| e.to_string())?;
        let content_length = body.len();

        // RFC 1123 date in UTC, as the Sentinel collector requires.
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let str_to_sign = format!(
            "POST\n{}\napplication/json\nx-ms-date:{}\n/api/logs",
            content_length, date
        );

        let mut mac = HmacSha256::new_from_slice(&self.shared_key)
            .map_err(|e| format!("sentinel: bad key: {e}"))?;
        mac.update(str_to_sign.as_bytes());
        let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        let auth = format!("SharedKey {}:{}", self.workspace_id, signature);

        let resp = self.client
            .post(&self.endpoint)
            .header("Authorization", auth)
            .header("Log-Type", &self.log_type)
            .header("Content-Type", "application/json")
            .header("x-ms-date", date)
            .header("time-generated-field", "timestamp")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("sentinel: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("sentinel: HTTP {}", resp.status()));
        }
        Ok(())
    }
}
