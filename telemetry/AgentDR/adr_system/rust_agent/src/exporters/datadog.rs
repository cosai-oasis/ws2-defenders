//! Datadog Logs Intake.
//!
//! POSTs to `https://http-intake.logs.<site>/api/v2/logs` with
//! `DD-API-KEY: <key>`. Body is a JSON array; each element follows
//! Datadog's log schema (`ddsource`, `ddtags`, `service`, `hostname`,
//! `message`, then arbitrary structured fields).

use super::{http_client, Exporter};
use crate::config::DatadogConfig;
use crate::models::EventRecord;
use async_trait::async_trait;
use serde_json::{json, Value};

pub struct Datadog {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
    service: String,
    tags: String,
}

impl Datadog {
    pub fn new(cfg: &DatadogConfig) -> Result<Self, String> {
        if cfg.api_key.is_empty() {
            return Err("datadog.api_key is empty".into());
        }
        let endpoint = format!("https://http-intake.logs.{}/api/v2/logs", cfg.site);
        let tags = if cfg.tags.is_empty() {
            "source:agentdr,framework:cosai-aitf".to_string()
        } else {
            format!("source:agentdr,framework:cosai-aitf,{}", cfg.tags.join(","))
        };
        Ok(Self {
            client: http_client(cfg.batch.timeout_seconds, true),
            endpoint,
            api_key: cfg.api_key.clone(),
            service: cfg.service.clone(),
            tags,
        })
    }
}

#[async_trait]
impl Exporter for Datadog {
    fn name(&self) -> &'static str { "datadog" }

    async fn send(&self, events: &[EventRecord]) -> Result<(), String> {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_default();
        let body: Vec<Value> = events.iter().map(|ev| {
            let mut o = serde_json::to_value(ev).unwrap_or(json!({}));
            // Spread our flat schema into Datadog's expected envelope.
            if let Value::Object(ref mut m) = o {
                m.insert("ddsource".into(), json!("agentdr"));
                m.insert("ddtags".into(), json!(self.tags));
                m.insert("service".into(), json!(self.service));
                m.insert("hostname".into(), json!(hostname));
                // Datadog uses `status` for severity emoji; map from risk_level.
                let dd_status = match ev.risk_level.as_str() {
                    "critical" => "critical",
                    "high"     => "error",
                    "medium"   => "warn",
                    _          => "info",
                };
                m.insert("status".into(), json!(dd_status));
                if let Some(msg) = &ev.message {
                    m.insert("message".into(), json!(msg));
                } else {
                    m.insert("message".into(), json!(ev.event_type));
                }
            }
            o
        }).collect();

        let resp = self.client
            .post(&self.endpoint)
            .header("DD-API-KEY", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("datadog: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("datadog: HTTP {}", resp.status()));
        }
        Ok(())
    }
}
