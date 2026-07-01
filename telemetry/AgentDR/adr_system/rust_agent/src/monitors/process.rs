//! Process monitor — watches for new/terminated processes, identifies AI agents.

use crate::models::*;
use serde_json::json;
use std::collections::HashSet;
use sysinfo::System;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::debug;

pub struct ProcessMonitor {
    poll_interval: Duration,
    tx: mpsc::UnboundedSender<EventRecord>,
}

impl ProcessMonitor {
    pub fn new(poll_seconds: u64, tx: mpsc::UnboundedSender<EventRecord>) -> Self {
        Self {
            poll_interval: Duration::from_secs(poll_seconds.max(1)),
            tx,
        }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut sys = System::new_all();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let mut known_pids: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();

        let mut ticker = interval(self.poll_interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {},
                _ = shutdown.changed() => { break; }
            }

            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            let current_pids: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();

            // New processes
            for &pid in current_pids.difference(&known_pids) {
                let pid_obj = sysinfo::Pid::from_u32(pid);
                if let Some(proc) = sys.process(pid_obj) {
                    let name = proc.name().to_string_lossy().to_string();
                    let exe = proc.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
                    let cmd: Vec<String> = proc.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect();
                    let haystack = format!("{} {} {}", name, exe, cmd.join(" "));
                    let agent_info = identify_agent(&haystack);
                    let is_agent = agent_info.is_some();
                    let risk = if is_agent { "medium" } else { "low" };

                    let mut event = EventRecord::new(
                        "process_started",
                        json!({
                            "pid": pid,
                            "name": name,
                            "exe": exe,
                            "cmdline": cmd,
                        }),
                        risk,
                    );
                    event.source = Some("process_monitor".into());
                    event.set_op(AiOperation::AgentAction, ACTIVITY_CREATE);
                    event.activity_id = Some(ACTIVITY_CREATE);
                    event.status_id = Some(STATUS_SUCCESS);
                    event.message = Some(format!("Process started: {}", name));
                    event.actor = Some(json!({ "pid": pid }));

                    if let Some(ref agent) = agent_info {
                        event.agent_detected = Some(agent.name.to_string());
                        event.agent_name = Some(agent.name.to_string());
                        event.agent_framework = Some(agent.framework.to_string());
                    }

                    let _ = self.tx.send(event);
                }
            }

            // Terminated processes
            for &pid in known_pids.difference(&current_pids) {
                let mut event = EventRecord::new(
                    "process_ended",
                    json!({ "pid": pid }),
                    "low",
                );
                event.source = Some("process_monitor".into());
                event.set_op(AiOperation::AgentAction, ACTIVITY_DELETE);
                event.activity_id = Some(ACTIVITY_DELETE);
                event.message = Some(format!("Process ended: PID {}", pid));
                let _ = self.tx.send(event);
            }

            known_pids = current_pids;
        }
        debug!("Process monitor shut down");
    }
}
