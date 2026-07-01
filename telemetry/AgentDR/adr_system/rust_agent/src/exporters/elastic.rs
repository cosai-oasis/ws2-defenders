//! Elasticsearch _bulk API exporter with light ECS field mapping.
//!
//! Targets a daily index (`<base>-yyyy.MM.dd`). Each AgentDR event is
//! merged with an ECS-compatible envelope so SOC dashboards built against
//! ECS can pivot immediately (`@timestamp`, `event.kind`, `event.category`,
//! `agent.type`, `agent.version`, `host.hostname`, `user.name`,
//! `labels.aitf.*`).

use super::{http_client, Exporter};
use crate::config::ElasticConfig;
use crate::models::EventRecord;
use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

pub struct Elastic {
    client: reqwest::Client,
    endpoint: String,
    index_base: String,
    auth_header: Option<(String, String)>,
}

impl Elastic {
    pub fn new(cfg: &ElasticConfig) -> Result<Self, String> {
        if cfg.endpoint.is_empty() {
            return Err("elastic.endpoint is empty".into());
        }
        let endpoint = format!("{}/_bulk", cfg.endpoint.trim_end_matches('/'));
        let auth_header = if !cfg.api_key.is_empty() {
            Some(("Authorization".into(), format!("ApiKey {}", cfg.api_key)))
        } else if !cfg.basic_auth.is_empty() {
            let b = base64::engine::general_purpose::STANDARD.encode(cfg.basic_auth.as_bytes());
            Some(("Authorization".into(), format!("Basic {}", b)))
        } else {
            None
        };
        Ok(Self {
            client: http_client(cfg.batch.timeout_seconds, cfg.verify_tls),
            endpoint,
            index_base: cfg.index.clone(),
            auth_header,
        })
    }
}

#[async_trait]
impl Exporter for Elastic {
    fn name(&self) -> &'static str { "elastic" }

    async fn send(&self, events: &[EventRecord]) -> Result<(), String> {
        let day = Utc::now().format("%Y.%m.%d").to_string();
        let index = format!("{}-{}", self.index_base, day);
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_default();

        let mut body = String::new();
        for ev in events {
            // Bulk action line
            body.push_str(&json!({
                "index": { "_index": index }
            }).to_string());
            body.push('\n');

            // ECS-shaped document
            let ts_iso = DateTime::parse_from_rfc3339(&ev.timestamp)
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|_| ev.timestamp.clone());
            // Map the AITF ai_operation profile onto ECS event.category.
            let category = match ev.ai_operation.as_deref() {
                Some("inference") | Some("agent_action") | Some("tool_execution") => "process",
                Some("mcp_operation") | Some("asset_inventory") => "configuration",
                Some("data_exfiltration") | Some("permission_escalation")
                | Some("prompt_injection") | Some("guardrail") | Some("cost_anomaly")
                | Some("compliance_violation") | Some("supply_chain") => "intrusion_detection",
                Some("identity") => "authentication",
                _ => "other",
            };
            let kind = if ev.event_type.starts_with("alert_") { "alert" } else { "event" };
            let doc = json!({
                "@timestamp": ts_iso,
                "event": {
                    "kind": kind,
                    "category": [category],
                    "dataset": "agentdr.aitf",
                    "module": "agentdr",
                    "type": [ev.event_type.clone()],
                    "severity": ev.severity_id.unwrap_or(1),
                },
                "agent": {
                    "type": "agentdr",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "host": { "hostname": hostname },
                "labels": {
                    "aitf.class_uid": ev.class_uid,
                    "aitf.ai_operation": ev.ai_operation,
                    "aitf.activity_id": ev.activity_id,
                    "aitf.risk_level": ev.risk_level,
                    "aitf.provider": ev.provider,
                    "aitf.model": ev.model,
                    "aitf.agent_name": ev.agent_name,
                    "aitf.tool_name": ev.tool_name,
                    "aitf.mcp_server": ev.mcp_server,
                    "aitf.trace_id": ev.trace_id,
                    "aitf.span_id": ev.span_id,
                },
                "aitf": ev,
                "message": ev.message,
            });
            body.push_str(&doc.to_string());
            body.push('\n');
        }

        let mut req = self.client
            .post(&self.endpoint)
            .header("Content-Type", "application/x-ndjson");
        if let Some((k, v)) = &self.auth_header {
            req = req.header(k, v);
        }
        let resp = req.body(body).send().await.map_err(|e| format!("elastic: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("elastic: HTTP {}", resp.status()));
        }
        // Optional: inspect bulk response for partial failures
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if body.get("errors").and_then(|v| v.as_bool()) == Some(true) {
            return Err("elastic: bulk response contained errors".into());
        }
        Ok(())
    }
}
