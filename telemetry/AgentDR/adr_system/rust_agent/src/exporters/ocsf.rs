//! Generic OCSF webhook exporter (AITF Class-Reuse Model).
//!
//! POSTs `{"events": [...]}` to a configured HTTP endpoint with optional
//! `Authorization: Bearer <token>`. Each AgentDR event is already shaped
//! against the AITF `ai_operation` profile over reused OCSF classes —
//! class_uid, type_uid, activity_id, severity_id, ai_operation,
//! provider/model/agent fields — so this is the "canonical" exporter for
//! downstream pipelines that want raw OCSF AI events.

use super::{http_client, Exporter};
use crate::config::OcsfConfig;
use crate::models::EventRecord;
use async_trait::async_trait;
use serde_json::json;

pub struct Ocsf {
    client: reqwest::Client,
    endpoint: String,
    bearer_token: String,
}

impl Ocsf {
    pub fn new(cfg: &OcsfConfig) -> Result<Self, String> {
        if cfg.endpoint.is_empty() {
            return Err("ocsf.endpoint is empty".into());
        }
        Ok(Self {
            client: http_client(cfg.batch.timeout_seconds, true),
            endpoint: cfg.endpoint.clone(),
            bearer_token: cfg.bearer_token.clone(),
        })
    }
}

#[async_trait]
impl Exporter for Ocsf {
    fn name(&self) -> &'static str { "ocsf" }

    async fn send(&self, events: &[EventRecord]) -> Result<(), String> {
        let body = json!({
            "spec": "ocsf",
            "profile": "ai_operation",
            "events": events,
        });
        let mut req = self.client
            .post(&self.endpoint)
            .header("Content-Type", "application/x-ocsf+json");
        if !self.bearer_token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.bearer_token));
        }
        let resp = req.json(&body).send().await.map_err(|e| format!("ocsf: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("ocsf: HTTP {}", resp.status()));
        }
        Ok(())
    }
}
