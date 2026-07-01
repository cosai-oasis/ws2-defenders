//! Cortex XSIAM HTTP Log Collector exporter.
//!
//! XSIAM exposes a "Generic HTTPs Collector" endpoint per tenant that
//! accepts a JSON array of events under `Authorization: <token>`. The
//! collector parses each entry as a single log line and runs it through
//! the tenant's parsing rules. We forward AgentDR JSON wrapped with
//! vendor/product metadata.

use super::{http_client, Exporter};
use crate::config::XsiamConfig;
use crate::models::EventRecord;
use async_trait::async_trait;
use serde_json::{json, Value};

pub struct Xsiam {
    client: reqwest::Client,
    endpoint: String,
    auth_token: String,
    vendor: String,
    product: String,
}

impl Xsiam {
    pub fn new(cfg: &XsiamConfig) -> Result<Self, String> {
        if cfg.endpoint.is_empty() {
            return Err("xsiam.endpoint is empty".into());
        }
        if cfg.auth_token.is_empty() {
            return Err("xsiam.auth_token is empty".into());
        }
        Ok(Self {
            client: http_client(cfg.batch.timeout_seconds, true),
            endpoint: cfg.endpoint.clone(),
            auth_token: cfg.auth_token.clone(),
            vendor: cfg.vendor.clone(),
            product: cfg.product.clone(),
        })
    }
}

#[async_trait]
impl Exporter for Xsiam {
    fn name(&self) -> &'static str { "xsiam" }

    async fn send(&self, events: &[EventRecord]) -> Result<(), String> {
        let body: Vec<Value> = events.iter().map(|ev| json!({
            "vendor": self.vendor,
            "product": self.product,
            "ts": ev.timestamp,
            "event": ev,
        })).collect();

        let resp = self.client
            .post(&self.endpoint)
            .header("Authorization", &self.auth_token)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("xsiam: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("xsiam: HTTP {}", resp.status()));
        }
        Ok(())
    }
}
