//! Snowflake REST ingest exporter.
//!
//! Two viable modes:
//!   * **Snowpipe Streaming**: POST to a regional insert endpoint with a
//!     bearer JWT — body is `{"rowSequencer": ..., "rows": [...]}`.
//!   * **Snowpipe classic**: POST to `/v1/data/pipes/<pipe>/insertReport`
//!     after PUT-ing a file to a stage. The agent supports the streaming
//!     mode (much simpler from an endpoint agent) and degrades to a
//!     generic bearer POST otherwise.
//!
//! AgentDR does NOT generate the Snowflake JWT itself (that requires the
//! `rsa`/`jsonwebtoken` crates plus a private key on disk, which is
//! best handled out-of-process). Operators supply a current `bearer_jwt`
//! and rotate it via their preferred token-refresh tooling.

use super::{http_client, Exporter};
use crate::config::SnowflakeConfig;
use crate::models::EventRecord;
use async_trait::async_trait;
use serde_json::{json, Value};

pub struct Snowflake {
    client: reqwest::Client,
    endpoint: String,
    bearer_jwt: String,
    pipe: Option<String>,
}

impl Snowflake {
    pub fn new(cfg: &SnowflakeConfig) -> Result<Self, String> {
        if cfg.endpoint.is_empty() {
            return Err("snowflake.endpoint is empty".into());
        }
        if cfg.bearer_jwt.is_empty() {
            return Err("snowflake.bearer_jwt is empty".into());
        }
        Ok(Self {
            client: http_client(cfg.batch.timeout_seconds, true),
            endpoint: cfg.endpoint.clone(),
            bearer_jwt: cfg.bearer_jwt.clone(),
            pipe: if cfg.pipe.is_empty() { None } else { Some(cfg.pipe.clone()) },
        })
    }
}

#[async_trait]
impl Exporter for Snowflake {
    fn name(&self) -> &'static str { "snowflake" }

    async fn send(&self, events: &[EventRecord]) -> Result<(), String> {
        let rows: Vec<Value> = events.iter()
            .map(|ev| serde_json::to_value(ev).unwrap_or(Value::Null))
            .collect();
        let body = match &self.pipe {
            Some(pipe) => json!({ "pipe": pipe, "rows": rows }),
            None       => json!({ "rows": rows }),
        };

        let resp = self.client
            .post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", self.bearer_jwt))
            .header("X-Snowflake-Authorization-Token-Type", "KEYPAIR_JWT")
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("snowflake: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("snowflake: HTTP {}", resp.status()));
        }
        Ok(())
    }
}
