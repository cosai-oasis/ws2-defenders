//! Agent Engine — orchestrates monitors, detectors, and storage.

use crate::config::Config;
use crate::detectors::PatternDetector;
use crate::exporters;
use crate::ingest::openshell::OpenShellIngest;
use crate::ingest::otlp::{self, OtlpSink};
use crate::mcp;
use crate::models::*;
use crate::monitors::{
    browser::BrowserMonitor, file::FileMonitor, kernel::KernelMonitor,
    network::NetworkMonitor, process::ProcessMonitor,
};
use crate::discovery;
use crate::policy::PolicyEngine;
use crate::proxy::InlineProxy;
use crate::storage::{EventPusher, JsonlStore};
use crate::watchdog::WatchdogMonitor;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::{interval, Duration};
use tracing::info;

pub struct AgentEngine {
    config: Config,
    root_path: PathBuf,
    stream_output: bool,
}

impl AgentEngine {
    pub fn new(root_path: PathBuf, config: Config, stream_output: bool) -> Self {
        Self { config, root_path, stream_output }
    }

    pub async fn run(self) {
        info!("Starting CoSAI ADR Agent Engine (Rust)");

        // Shutdown signal
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Event channel — all monitors write here
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<EventRecord>();

        // Pusher channel (separate so we can clone events to it)
        let (push_tx, push_rx) = mpsc::unbounded_channel::<EventRecord>();

        // Storage
        let store_path = self.root_path.join(&self.config.storage.events_path);
        let store = Arc::new(JsonlStore::new(
            store_path,
            self.config.storage.max_bytes,
            self.config.storage.backup_count,
        ));

        // Status file
        self.write_status("running");

        // Spawn legacy server_push pusher (kept for back-compat with the
        // existing /api/sync dashboard endpoint).
        let pusher = EventPusher::new(&self.config.server_push);
        let pusher_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            pusher.run(push_rx, pusher_shutdown).await;
        });

        // ── Tier 3: vendor exporter bus ──
        let (bus_tx, _bus_rx) = broadcast::channel::<EventRecord>(4096);
        let active = exporters::spawn_all(&self.config.exporters, &bus_tx, &shutdown_rx);
        if !active.is_empty() {
            info!("vendor exporters active: {:?}", active);
        }

        // ── Tier 5: load the policy pack ──
        let policy_engine = Arc::new(if self.config.policy.enabled {
            if !self.config.policy.path.is_empty() {
                match PolicyEngine::load_from(std::path::Path::new(&self.config.policy.path)) {
                    Ok(e) => { info!("policy: loaded {} rule(s) from {}", e.len(), e.source().display()); e }
                    Err(err) => { tracing::warn!("policy: {err}"); PolicyEngine::empty() }
                }
            } else {
                let e = PolicyEngine::load_default();
                if e.is_empty() {
                    tracing::warn!("policy: no policy pack found (looked under cosai-community/policies/)");
                } else {
                    info!("policy: loaded {} rule(s) from {}", e.len(), e.source().display());
                }
                e
            }
        } else {
            PolicyEngine::empty()
        });

        // Spawn process monitor
        let proc_tx = event_tx.clone();
        let proc_shutdown = shutdown_rx.clone();
        let proc_poll = self.config.process_monitor.poll_interval_seconds;
        tokio::spawn(async move {
            ProcessMonitor::new(proc_poll, proc_tx).run(proc_shutdown).await;
        });

        // Spawn file monitor
        let file_tx = event_tx.clone();
        let file_shutdown = shutdown_rx.clone();
        let watch_dirs = self.config.watch_directories.clone();
        let recursive = self.config.file_monitor.recursive;
        let ignore = self.config.file_monitor.ignore_patterns.clone();
        tokio::spawn(async move {
            FileMonitor::new(watch_dirs, recursive, ignore, file_tx)
                .run(file_shutdown).await;
        });

        // Spawn network monitor
        let net_tx = event_tx.clone();
        let net_shutdown = shutdown_rx.clone();
        let net_poll = self.config.network_monitor.poll_seconds;
        let ai_eps = self.config.network_monitor.ai_api_endpoints.clone();
        tokio::spawn(async move {
            NetworkMonitor::new(net_poll, ai_eps, net_tx).run(net_shutdown).await;
        });

        // ── Tier 1: OTLP ingest server ──
        if self.config.otlp.enabled {
            let otlp_tx = event_tx.clone();
            let otlp_shutdown = shutdown_rx.clone();
            let bind = self.config.otlp.bind.clone();
            let max = self.config.otlp.max_body_bytes;
            let redact = self.config.otlp.redact_content;
            tokio::spawn(async move {
                let sink = OtlpSink::new(otlp_tx, redact);
                otlp::serve(&bind, max, sink, otlp_shutdown).await;
            });
        }

        // ── Tier 1: NVIDIA OpenShell audit-log ingest ──
        if self.config.openshell.enabled {
            let os_tx = event_tx.clone();
            let os_shutdown = shutdown_rx.clone();
            let os_cfg = self.config.openshell.clone();
            tokio::spawn(async move {
                OpenShellIngest::new(&os_cfg, os_tx).run(os_shutdown).await;
            });
        }

        // ── Tier 5: inline blocking forward proxy ──
        // Now enriched with caller provenance, optional auth + per-caller
        // rate limiting (see `proxy::InlineProxy::from_config`).
        if self.config.proxy.enabled {
            let proxy_tx = event_tx.clone();
            let proxy_shutdown = shutdown_rx.clone();
            let proxy_cfg = self.config.proxy.clone();
            let engine = policy_engine.clone();
            tokio::spawn(async move {
                InlineProxy::from_config(&proxy_cfg, engine, proxy_tx)
                    .run(proxy_shutdown)
                    .await;
            });
        }

        // ── Tier 9: LLM Guard reverse proxy ──
        // Reverse proxy in front of local model backends (Ollama, LM Studio,
        // llama.cpp). Authenticates + rate-limits callers, records process
        // provenance, scans prompts for injection / PII, tracks token usage,
        // and probes upstream health.
        if self.config.llm_guard.enabled {
            let lg_tx = event_tx.clone();
            let lg_shutdown = shutdown_rx.clone();
            let lg_cfg = self.config.llm_guard.clone();
            tokio::spawn(async move {
                crate::proxy::reverse::serve(&lg_cfg, lg_tx, lg_shutdown).await;
            });
        }

        // ── Tier 6: kernel-level telemetry ──
        if self.config.kernel.enabled {
            let kern_tx = event_tx.clone();
            let kern_shutdown = shutdown_rx.clone();
            let group = self.config.kernel.audit_multicast_group;
            tokio::spawn(async move {
                KernelMonitor::new(group, kern_tx).run(kern_shutdown).await;
            });
        }

        // ── Tier 8: auto-discovery ──
        if self.config.discovery.enabled {
            let endpoint = format!("http://{}", self.config.otlp.bind);
            // (a) on-start scan
            if self.config.discovery.scan_on_start {
                let disc_cfg = self.config.discovery.clone();
                let root = self.root_path.clone();
                let ep = endpoint.clone();
                let disc_tx = event_tx.clone();
                tokio::spawn(async move {
                    let rep = discovery::scan_and_apply(&disc_cfg, &root, &ep);
                    let mut ev = EventRecord::new("discovery_scan_completed", json!({
                        "mode":    rep.mode,
                        "found":   rep.scanned.agents.len(),
                        "actions": rep.actions,
                    }), "low");
                    ev.set_op(AiOperation::AgentAction, ACTIVITY_DETECT);
                    ev.activity_id = Some(ACTIVITY_DETECT);
                    ev.source      = Some("discovery".into());
                    ev.message     = Some(format!(
                        "discovery scan: {} agent(s) found",
                        rep.scanned.agents.len()
                    ));
                    let _ = disc_tx.send(ev);
                });
            }
            // (b) periodic re-scan
            if self.config.discovery.scan_interval_hours > 0 {
                let period = self.config.discovery.scan_interval_hours;
                let disc_cfg = self.config.discovery.clone();
                let root = self.root_path.clone();
                let ep = endpoint.clone();
                let disc_tx = event_tx.clone();
                let mut disc_shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    let mut ticker = interval(Duration::from_secs(period * 3600));
                    ticker.tick().await; // skip immediate fire (covered above)
                    loop {
                        tokio::select! {
                            _ = ticker.tick() => {
                                let rep = discovery::scan_and_apply(&disc_cfg, &root, &ep);
                                let mut ev = EventRecord::new("discovery_scan_completed", json!({
                                    "mode": rep.mode,
                                    "found": rep.scanned.agents.len(),
                                    "actions": rep.actions,
                                    "trigger": "scheduled",
                                }), "low");
                                ev.set_op(AiOperation::AgentAction, ACTIVITY_DETECT);
                                ev.activity_id = Some(ACTIVITY_DETECT);
                                ev.source      = Some("discovery".into());
                                ev.message     = Some(format!("scheduled discovery scan: {} agent(s)", rep.scanned.agents.len()));
                                let _ = disc_tx.send(ev);
                            }
                            _ = disc_shutdown.changed() => break,
                        }
                    }
                });
            }
        }

        // ── Tier 7: self-protection / watchdog ──
        if self.config.watchdog.enabled {
            let wd_tx = event_tx.clone();
            let wd_shutdown = shutdown_rx.clone();
            let wd_cfg = self.config.watchdog.clone();
            let root = self.root_path.clone();
            let endpoint = format!("http://{}", self.config.otlp.bind);
            tokio::spawn(async move {
                WatchdogMonitor::new(wd_cfg, root, endpoint, wd_tx)
                    .run(wd_shutdown)
                    .await;
            });
        }

        // ── Tier 6: browser CDP monitor ──
        if self.config.browser.enabled {
            let br_tx = event_tx.clone();
            let br_shutdown = shutdown_rx.clone();
            let ep = self.config.browser.cdp_endpoint.clone();
            let poll = self.config.browser.poll_seconds;
            tokio::spawn(async move {
                BrowserMonitor::new(ep, poll, br_tx).run(br_shutdown).await;
            });
        }

        // ── Tier 1: MCP inventory (one-shot + optional periodic re-scan) ──
        if self.config.mcp.inventory_on_start {
            let mcp_tx = event_tx.clone();
            tokio::spawn(async move {
                let report = mcp::inventory::scan();
                for ev in report.events {
                    let _ = mcp_tx.send(ev);
                }
            });
        }
        if self.config.mcp.rescan_seconds > 0 {
            let mcp_tx = event_tx.clone();
            let mut mcp_shutdown = shutdown_rx.clone();
            let period = self.config.mcp.rescan_seconds;
            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(period));
                ticker.tick().await; // skip immediate tick (covered by inventory_on_start)
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let report = mcp::inventory::scan();
                            for ev in report.events { let _ = mcp_tx.send(ev); }
                        }
                        _ = mcp_shutdown.changed() => { break; }
                    }
                }
            });
        }

        // Emit start event
        let start_event = {
            let mut ev = EventRecord::new("agent_started", json!({
                "watch_directories": self.config.watch_directories,
                "runtime": "rust",
                "version": env!("CARGO_PKG_VERSION"),
            }), "low");
            ev.source = Some("engine".into());
            ev.set_op(AiOperation::AgentAction, ACTIVITY_CREATE);
            ev.activity_id = Some(ACTIVITY_CREATE);
            ev.status_id = Some(STATUS_SUCCESS);
            ev.message = Some("CoSAI ADR Agent Engine started (Rust)".into());
            ev.agent_name = Some("ADR Monitor".into());
            ev.agent_framework = Some("CoSAI".into());
            ev
        };
        let _ = event_tx.send(start_event);

        // Detector
        let mut detector = PatternDetector::new(self.config.detection.clone());

        // Ctrl+C handler
        let ctrl_c_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("Received Ctrl+C, shutting down...");
            let _ = ctrl_c_tx.send(true);
        });

        // Main event loop
        let stream = self.stream_output;
        let mut main_shutdown = shutdown_rx.clone();
        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    // Persist
                    store.write_event(&event);
                    let _ = push_tx.send(event.clone());
                    let _ = bus_tx.send(event.clone());

                    if stream {
                        Self::print_event(&event);
                    }

                    // Run detections
                    let alerts = detector.analyze(&event);
                    for alert in alerts {
                        store.write_event(&alert);
                        let _ = push_tx.send(alert.clone());
                        let _ = bus_tx.send(alert.clone());
                        if stream {
                            Self::print_event(&alert);
                        }
                    }

                    // ── Tier 5: policy evaluation ──
                    if !policy_engine.is_empty() {
                        let decision = policy_engine.evaluate(&event);
                        for pol_ev in decision.events {
                            store.write_event(&pol_ev);
                            let _ = push_tx.send(pol_ev.clone());
                            let _ = bus_tx.send(pol_ev.clone());
                            if stream { Self::print_event(&pol_ev); }
                        }
                    }
                }
                _ = main_shutdown.changed() => {
                    break;
                }
            }
        }

        // Emit stop event
        let stop_event = {
            let mut ev = EventRecord::new("agent_stopped", json!({}), "low");
            ev.source = Some("engine".into());
            ev.set_op(AiOperation::AgentAction, ACTIVITY_DELETE);
            ev.activity_id = Some(ACTIVITY_DELETE);
            ev.status_id = Some(STATUS_SUCCESS);
            ev.message = Some("CoSAI ADR Agent Engine stopped".into());
            ev
        };
        store.write_event(&stop_event);

        self.write_status("stopped");
        info!("CoSAI ADR Agent Engine shut down cleanly");
    }

    fn print_event(event: &EventRecord) {
        println!(
            "[{}] {:8} {:32} | {}",
            event.timestamp,
            event.risk_level.to_uppercase(),
            event.event_type,
            serde_json::to_string(&event.details).unwrap_or_default(),
        );
    }

    fn write_status(&self, status: &str) {
        let path = self.root_path.join(&self.config.runtime.status_file);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let payload = json!({
            "status": status,
            "timestamp": utc_now_iso(),
            "pid": std::process::id(),
            "runtime": "rust",
        });
        let _ = std::fs::write(path, serde_json::to_string_pretty(&payload).unwrap_or_default());
    }
}
