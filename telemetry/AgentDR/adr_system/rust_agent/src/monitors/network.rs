//! Network monitor — polls active TCP connections for AI API and messaging traffic.

use crate::models::*;
use serde_json::json;
use std::collections::HashSet;
use std::process::Command;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::debug;

pub struct NetworkMonitor {
    poll_interval: Duration,
    ai_endpoints: Vec<String>,
    tx: mpsc::UnboundedSender<EventRecord>,
}

impl NetworkMonitor {
    pub fn new(
        poll_seconds: u64,
        ai_endpoints: Vec<String>,
        tx: mpsc::UnboundedSender<EventRecord>,
    ) -> Self {
        Self {
            poll_interval: Duration::from_secs(poll_seconds.max(1)),
            ai_endpoints: ai_endpoints.into_iter().map(|e| e.to_lowercase()).collect(),
            tx,
        }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut seen: HashSet<String> = HashSet::new();
        let mut ticker = interval(self.poll_interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {},
                _ = shutdown.changed() => { break; }
            }

            let connections = Self::get_active_connections();
            for (host, port) in connections {
                let key = format!("{}:{}", host, port);
                if seen.contains(&key) {
                    continue;
                }
                seen.insert(key);

                let ai_info = classify_ai_endpoint(&host);
                let messaging = classify_messaging_endpoint(&host);
                let matches_endpoint = self.matches_ai_endpoint(&host);

                let is_ai_api = ai_info.is_some() || matches_endpoint;
                let is_messaging = messaging.is_some();

                if !is_ai_api && !is_messaging {
                    continue; // Only emit events for interesting traffic
                }

                let (risk, op, activity_id, event_type, msg) = if let Some(ref ai) = ai_info {
                    ("medium", AiOperation::Inference, ACTIVITY_EXECUTE, "network_request",
                     format!("AI API request to {} ({})", host, ai.provider))
                } else if let Some(ref platform) = messaging {
                    ("high", AiOperation::PermissionEscalation, ACTIVITY_EXECUTE, "messaging_channel_access",
                     format!("Agent accessing {} via {}", platform, host))
                } else {
                    ("low", AiOperation::AgentAction, ACTIVITY_CREATE, "network_request",
                     format!("Network request to {}", host))
                };

                let mut ev = EventRecord::new(event_type, json!({
                    "host": host,
                    "port": port,
                    "is_ai_api": is_ai_api,
                    "is_messaging": is_messaging,
                    "messaging_platform": messaging,
                    "ai_provider": ai_info.as_ref().map(|a| &a.provider),
                }), risk);
                ev.source = Some("network_monitor".into());
                ev.set_op(op, activity_id);
                ev.activity_id = Some(activity_id);
                ev.status_id = Some(STATUS_SUCCESS);
                ev.message = Some(msg);

                if let Some(ref ai) = ai_info {
                    ev.provider = Some(ai.provider.clone());
                    ev.model = Some(ai.model.clone());
                    ev.agent_detected = Some("ai_api_call".into());
                    ev.token_usage = Some(json!({ "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0 }));
                } else if is_messaging {
                    ev.agent_detected = Some("messaging_access".into());
                }

                let _ = self.tx.send(ev);
            }
        }
        debug!("Network monitor shut down");
    }

    fn matches_ai_endpoint(&self, host: &str) -> bool {
        let h = host.to_lowercase();
        self.ai_endpoints.iter().any(|ep| h.contains(ep.as_str()))
    }

    /// Parse active TCP connections from `ss -tnp` output.
    fn get_active_connections() -> Vec<(String, String)> {
        let output = match Command::new("ss").args([&"-tnp"]).output() {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut results = Vec::new();
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let peer = parts[4];
                if let Some(idx) = peer.rfind(':') {
                    let host = &peer[..idx];
                    let port = &peer[idx + 1..];
                    results.push((host.to_string(), port.to_string()));
                }
            }
        }
        results
    }
}
