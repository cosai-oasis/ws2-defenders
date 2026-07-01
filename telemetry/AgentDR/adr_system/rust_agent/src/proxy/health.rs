//! Upstream health checking for the LLM Guard.
//!
//! Each configured backend exposes a cheap liveness path (Ollama
//! `/api/tags`, OpenAI-compatible `/v1/models`, llama.cpp `/health`). The
//! guard pings them on an interval and caches the latest status so the
//! `GET /healthz` endpoint can answer instantly without fanning out a
//! request per call.

use crate::config::BackendConfig;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

/// Latest known status for a single backend.
#[derive(Debug, Clone, Serialize)]
pub struct BackendHealth {
    pub name: String,
    pub url: String,
    pub healthy: bool,
    /// Last observed HTTP status code, if the request completed.
    pub status_code: Option<u16>,
    /// Round-trip latency of the last successful probe, in milliseconds.
    pub latency_ms: Option<u64>,
    /// Error description when the last probe failed.
    pub error: Option<String>,
    /// ISO-8601 timestamp of the last probe.
    pub checked_at: String,
}

/// Thread-safe cache of per-backend health, shared with the HTTP handler.
#[derive(Default)]
pub struct HealthRegistry {
    inner: RwLock<HashMap<String, BackendHealth>>,
}

impl HealthRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&self, health: BackendHealth) {
        if let Ok(mut map) = self.inner.write() {
            map.insert(health.name.clone(), health);
        }
    }

    /// Snapshot of all backend statuses (stable order by name).
    pub fn snapshot(&self) -> Vec<BackendHealth> {
        let mut out: Vec<BackendHealth> = self
            .inner
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// True when every known backend is healthy (and at least one exists).
    pub fn all_healthy(&self) -> bool {
        self.inner
            .read()
            .map(|m| !m.is_empty() && m.values().all(|h| h.healthy))
            .unwrap_or(false)
    }
}

/// Probe one backend's health path and return a fresh [`BackendHealth`].
pub async fn probe(client: &reqwest::Client, backend: &BackendConfig) -> BackendHealth {
    let url = format!(
        "{}{}",
        backend.url.trim_end_matches('/'),
        if backend.health_path.starts_with('/') {
            backend.health_path.clone()
        } else {
            format!("/{}", backend.health_path)
        }
    );
    let started = Instant::now();
    let now = crate::models::utc_now_iso();

    match client.get(&url).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let ok = resp.status().is_success();
            BackendHealth {
                name: backend.name.clone(),
                url: backend.url.clone(),
                healthy: ok,
                status_code: Some(code),
                latency_ms: Some(started.elapsed().as_millis() as u64),
                error: if ok { None } else { Some(format!("HTTP {code}")) },
                checked_at: now,
            }
        }
        Err(e) => BackendHealth {
            name: backend.name.clone(),
            url: backend.url.clone(),
            healthy: false,
            status_code: None,
            latency_ms: None,
            error: Some(e.to_string()),
            checked_at: now,
        },
    }
}
