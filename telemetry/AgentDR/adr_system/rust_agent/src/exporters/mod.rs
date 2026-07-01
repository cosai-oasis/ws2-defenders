//! Tier 3 — Vendor exporters.
//!
//! Each submodule implements the `Exporter` trait for one destination
//! (Splunk HEC, Datadog Logs Intake, Elasticsearch _bulk, Google Chronicle
//! UDM, Cortex XSIAM HTTP collector, Snowflake REST, Microsoft Sentinel
//! Log Analytics, Wazuh JSON output, RFC 5424 syslog, generic OCSF JSON).
//!
//! The `run_all` orchestrator spawns one `ExporterRunner` per enabled
//! backend, fans events from a single broadcast channel out to each
//! runner, batches per-backend, retries with exponential backoff, and
//! drops queued batches only on terminal failure (after `max_retries`).
//!
//! The fan-out lives in `engine.rs` so this module stays I/O-only and is
//! drop-in replaceable.

use crate::config;
use crate::models::EventRecord;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{broadcast, watch};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

pub mod chronicle;
pub mod datadog;
pub mod elastic;
pub mod ocsf;
pub mod sentinel;
pub mod snowflake;
pub mod splunk;
pub mod syslog;
pub mod wazuh;
pub mod xsiam;

/// One destination. Implementations are stateless beyond client setup.
#[async_trait]
pub trait Exporter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn send(&self, events: &[EventRecord]) -> Result<(), String>;
}

pub struct ExporterRunner {
    exporter: Arc<dyn Exporter>,
    batch:    config::BatchConfig,
}

impl ExporterRunner {
    pub fn new(exporter: Arc<dyn Exporter>, batch: config::BatchConfig) -> Self {
        Self { exporter, batch }
    }

    pub async fn run(
        self,
        mut rx: broadcast::Receiver<EventRecord>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut buf: Vec<EventRecord> = Vec::with_capacity(self.batch.batch_size);
        let mut ticker = tokio::time::interval(Duration::from_secs(self.batch.flush_interval_seconds));

        loop {
            tokio::select! {
                recv = rx.recv() => match recv {
                    Ok(ev) => {
                        buf.push(ev);
                        if buf.len() >= self.batch.batch_size {
                            self.flush(&mut buf).await;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("{}: dropped {} events (slow consumer)", self.exporter.name(), n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = ticker.tick() => {
                    if !buf.is_empty() {
                        self.flush(&mut buf).await;
                    }
                }
                _ = shutdown.changed() => {
                    if !buf.is_empty() {
                        self.flush(&mut buf).await;
                    }
                    break;
                }
            }
        }
        debug!("exporter {} shut down", self.exporter.name());
    }

    async fn flush(&self, buf: &mut Vec<EventRecord>) {
        let payload: Vec<EventRecord> = std::mem::take(buf);
        let name = self.exporter.name();
        let max = self.batch.max_retries.max(1);
        for attempt in 1..=max {
            match self.exporter.send(&payload).await {
                Ok(()) => {
                    info!("exporter {}: shipped {} events", name, payload.len());
                    return;
                }
                Err(e) if attempt < max => {
                    let backoff = Duration::from_millis(200 * (1u64 << (attempt - 1)).min(64));
                    warn!("exporter {} attempt {}/{} failed: {} (retrying in {:?})",
                        name, attempt, max, e, backoff);
                    sleep(backoff).await;
                }
                Err(e) => {
                    error!("exporter {} giving up after {} attempts: {}", name, max, e);
                    return;
                }
            }
        }
    }
}

/// Spawn one task per enabled exporter. Caller owns the broadcast::Sender
/// (in `engine.rs`) and `shutdown` channel.
pub fn spawn_all(
    cfg: &config::ExportersConfig,
    bus: &broadcast::Sender<EventRecord>,
    shutdown: &watch::Receiver<bool>,
) -> Vec<&'static str> {
    let mut active: Vec<&'static str> = Vec::new();
    macro_rules! spawn_one {
        ($name:expr, $on:expr, $build:expr, $batch:expr) => {
            if $on {
                match $build {
                    Ok(exp) => {
                        let exporter: Arc<dyn Exporter> = Arc::new(exp);
                        let runner = ExporterRunner::new(exporter.clone(), $batch);
                        let rx = bus.subscribe();
                        let sd = shutdown.clone();
                        tokio::spawn(async move { runner.run(rx, sd).await });
                        active.push($name);
                    }
                    Err(e) => warn!("exporter {} disabled: {}", $name, e),
                }
            }
        }
    }

    spawn_one!("splunk",    cfg.splunk.enabled,    splunk::Splunk::new(&cfg.splunk),         cfg.splunk.batch.clone());
    spawn_one!("datadog",   cfg.datadog.enabled,   datadog::Datadog::new(&cfg.datadog),      cfg.datadog.batch.clone());
    spawn_one!("elastic",   cfg.elastic.enabled,   elastic::Elastic::new(&cfg.elastic),      cfg.elastic.batch.clone());
    spawn_one!("chronicle", cfg.chronicle.enabled, chronicle::Chronicle::new(&cfg.chronicle),cfg.chronicle.batch.clone());
    spawn_one!("xsiam",     cfg.xsiam.enabled,     xsiam::Xsiam::new(&cfg.xsiam),            cfg.xsiam.batch.clone());
    spawn_one!("snowflake", cfg.snowflake.enabled, snowflake::Snowflake::new(&cfg.snowflake),cfg.snowflake.batch.clone());
    spawn_one!("sentinel",  cfg.sentinel.enabled,  sentinel::Sentinel::new(&cfg.sentinel),   cfg.sentinel.batch.clone());
    spawn_one!("wazuh",     cfg.wazuh.enabled,     wazuh::Wazuh::new(&cfg.wazuh),            cfg.wazuh.batch.clone());
    spawn_one!("syslog",    cfg.syslog.enabled,    syslog::Syslog::new(&cfg.syslog),         cfg.syslog.batch.clone());
    spawn_one!("ocsf",      cfg.ocsf.enabled,      ocsf::Ocsf::new(&cfg.ocsf),               cfg.ocsf.batch.clone());

    active
}

// ── Shared helpers used by multiple HTTP exporters ────────────────────────

pub(crate) fn http_client(timeout_secs: u64, verify_tls: bool) -> reqwest::Client {
    let mut b = reqwest::Client::builder().timeout(Duration::from_secs(timeout_secs));
    if !verify_tls {
        b = b.danger_accept_invalid_certs(true);
    }
    b.build().unwrap_or_default()
}
