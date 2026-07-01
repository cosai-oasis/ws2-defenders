//! Google Chronicle (Backstory) UDM Events ingest.
//!
//! POST `{endpoint}/v2/udmevents:batchCreate` with an OAuth2 Bearer token
//! that the operator supplies (we don't sign service-account JWTs inside
//! the agent — operators provision a token via `gcloud auth print-access-token`
//! or a sidecar refresher). Each AgentDR event is wrapped in a minimal UDM
//! envelope so it's queryable by Chronicle search.

use super::{http_client, Exporter};
use crate::config::ChronicleConfig;
use crate::models::EventRecord;
use async_trait::async_trait;
use chrono::DateTime;
use serde_json::{json, Value};

pub struct Chronicle {
    client: reqwest::Client,
    endpoint: String,
    access_token: String,
    customer_id: String,
    namespace: String,
    log_type: String,
}

impl Chronicle {
    pub fn new(cfg: &ChronicleConfig) -> Result<Self, String> {
        if cfg.customer_id.is_empty() {
            return Err("chronicle.customer_id is empty".into());
        }
        if cfg.access_token.is_empty() {
            return Err("chronicle.access_token is empty".into());
        }
        Ok(Self {
            client: http_client(cfg.batch.timeout_seconds, true),
            endpoint: format!("{}/v2/udmevents:batchCreate", cfg.endpoint.trim_end_matches('/')),
            access_token: cfg.access_token.clone(),
            customer_id: cfg.customer_id.clone(),
            namespace: cfg.namespace.clone(),
            log_type: cfg.log_type.clone(),
        })
    }
}

#[async_trait]
impl Exporter for Chronicle {
    fn name(&self) -> &'static str { "chronicle" }

    async fn send(&self, events: &[EventRecord]) -> Result<(), String> {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_default();

        let udm_events: Vec<Value> = events.iter().map(|ev| {
            let event_micros = DateTime::parse_from_rfc3339(&ev.timestamp)
                .map(|d| d.timestamp_micros())
                .unwrap_or(0);
            // Map the AITF ai_operation profile onto Chronicle UDM event types.
            let event_type = match ev.ai_operation.as_deref() {
                Some("inference") | Some("prompt_injection") | Some("data_exfiltration") => "USER_RESOURCE_ACCESS",
                Some("agent_action") | Some("tool_execution") => "PROCESS_LAUNCH",
                Some("mcp_operation") => "USER_COMMUNICATION",
                Some("permission_escalation") => "USER_RESOURCE_PERMISSIONS_CHANGE",
                _ => "GENERIC_EVENT",
            };
            // Pull user / pid out of the actor blob, if present.
            let (user, pid) = ev.actor.as_ref().map(|a| (
                a.get("user").and_then(|v| v.as_str()).map(String::from),
                a.get("pid").and_then(|v| v.as_i64()),
            )).unwrap_or((None, None));

            json!({
                "metadata": {
                    "event_timestamp": {
                        "seconds": event_micros / 1_000_000,
                        "nanos":  (event_micros % 1_000_000) * 1000,
                    },
                    "event_type": event_type,
                    "vendor_name": "CoSAI",
                    "product_name": "AgentDR",
                    "product_version": env!("CARGO_PKG_VERSION"),
                    "log_type": self.log_type,
                    "description": ev.message,
                },
                "principal": {
                    "hostname": hostname,
                    "user": user.map(|u| json!({ "userid": u })).unwrap_or(Value::Null),
                    "process": pid.map(|p| json!({ "pid": p })).unwrap_or(Value::Null),
                },
                "security_result": ev.security_finding.clone().map(|f| json!([{
                    "rule_id":   f.get("rule_id"),
                    "rule_name": f.get("title"),
                    "severity":  ev.risk_level.to_uppercase(),
                    "summary":   ev.message,
                    "category_details": [f.get("owasp_llm")],
                }])).unwrap_or(json!([])),
                // Embed the full AgentDR record as an additional field for
                // Chronicle UDM "extension" lookups.
                "additional": { "fields": ev }
            })
        }).collect();

        let body = json!({
            "customer_id": self.customer_id,
            "events": udm_events,
        });

        let resp = self.client
            .post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Content-Type", "application/json")
            .header("X-Chronicle-Namespace", &self.namespace)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("chronicle: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("chronicle: HTTP {}", resp.status()));
        }
        Ok(())
    }
}
