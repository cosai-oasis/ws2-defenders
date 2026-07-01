//! Tier 6 — browser-use telemetry via Chrome DevTools Protocol.
//!
//! When a user runs Chrome / Edge / Chromium with `--remote-debugging-port=9222`
//! (the standard for browser-use agents like Browser Use, Stagehand, Operator,
//! Claude Computer Use) the browser exposes a JSON discovery endpoint at
//! `/json`. We poll that endpoint, diff the page list across ticks, and
//! emit:
//!
//!   - `browser_page_opened`  (ai_operation=agent_action) when a new page appears
//!   - `browser_page_closed`  (ai_operation=agent_action) when an existing page disappears
//!   - `browser_page_navigated` (ai_operation=agent_action) when the URL changed
//!
//! Each event carries the destination URL, the page title and the
//! WebSocket debugger URL so analysts can pivot into a deeper trace.
//!
//! The monitor is opt-in (config.browser.enabled = true) because not
//! every endpoint has Chrome running with DevTools open, and we do not
//! want to log a periodic "endpoint not reachable" error in the common
//! case.

use crate::models::*;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct PageInfo {
    pub id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub title: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default, rename = "webSocketDebuggerUrl")]
    pub ws_url: String,
}

pub struct BrowserMonitor {
    endpoint: String,
    poll: Duration,
    tx: mpsc::UnboundedSender<EventRecord>,
}

impl BrowserMonitor {
    pub fn new(endpoint: String, poll_seconds: u64, tx: mpsc::UnboundedSender<EventRecord>) -> Self {
        Self { endpoint, poll: Duration::from_secs(poll_seconds.max(1)), tx }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap_or_default();
        let url = format!("{}/json", self.endpoint.trim_end_matches('/'));

        let mut known: HashMap<String, PageInfo> = HashMap::new();
        let mut ticker = interval(self.poll);
        let mut reachable = false;

        loop {
            tokio::select! {
                _ = ticker.tick() => {},
                _ = shutdown.changed() => break,
            }

            let pages: Vec<PageInfo> = match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.json().await {
                    Ok(v) => v,
                    Err(e) => { debug!("browser cdp parse: {e}"); continue; }
                },
                Ok(resp) => { debug!("browser cdp HTTP {}", resp.status()); continue; }
                Err(_) if !reachable => continue,
                Err(e) => { debug!("browser cdp unreachable: {e}"); continue; }
            };
            if !reachable {
                reachable = true;
                let mut ev = EventRecord::new("browser_attached", json!({ "endpoint": self.endpoint }), "low");
                ev.set_op(AiOperation::AgentAction, ACTIVITY_CREATE);
                ev.activity_id = Some(ACTIVITY_CREATE);
                ev.source = Some("browser_monitor".into());
                ev.message = Some(format!("browser CDP attached at {}", self.endpoint));
                let _ = self.tx.send(ev);
            }

            // Diff
            let mut new_known: HashMap<String, PageInfo> = HashMap::new();
            for p in pages.iter().filter(|p| p.kind == "page") {
                new_known.insert(p.id.clone(), p.clone());
            }

            for (id, p) in &new_known {
                match known.get(id) {
                    None => {
                        let _ = self.tx.send(page_event("browser_page_opened", p, ACTIVITY_CREATE, "medium"));
                    }
                    Some(prev) if prev.url != p.url => {
                        let mut ev = page_event("browser_page_navigated", p, ACTIVITY_UPDATE, "medium");
                        if let Some(d) = ev.details.as_object_mut() {
                            d.insert("previous_url".into(), json!(prev.url));
                        }
                        let _ = self.tx.send(ev);
                    }
                    _ => {}
                }
            }
            for (id, p) in &known {
                if !new_known.contains_key(id) {
                    let _ = self.tx.send(page_event("browser_page_closed", p, ACTIVITY_DELETE, "low"));
                }
            }
            known = new_known;
        }
        warn!("browser monitor shutting down");
    }
}

fn page_event(event_type: &str, p: &PageInfo, activity: u32, risk: &str) -> EventRecord {
    let mut ev = EventRecord::new(event_type, json!({
        "page_id": p.id,
        "url": p.url,
        "title": p.title,
        "ws_url": p.ws_url,
    }), risk);
    ev.set_op(AiOperation::AgentAction, activity);
    ev.activity_id = Some(activity);
    ev.status_id = Some(STATUS_SUCCESS);
    ev.source = Some("browser_monitor".into());
    ev.message = Some(format!("browser {}: {}", event_type, p.url));
    ev
}
