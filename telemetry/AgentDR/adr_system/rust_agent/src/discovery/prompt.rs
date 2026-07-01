//! Interactive stdin prompt for discovery decisions.
//!
//! Drives the user through every newly-discovered agent that does not
//! already have a recorded decision. Each prompt persists immediately
//! so even partial sessions are useful.

use super::{scan, state};
use crate::hooks;
use std::io::{BufRead, Write};
use std::path::Path;
use tracing::warn;

pub fn run(
    rep: &scan::ScanReport,
    endpoint: &str,
    state_path: &Path,
) -> Result<usize, String> {
    let mut st = state::DiscoveryState::load(state_path).unwrap_or_default();
    let mut installed = 0;

    for a in &rep.agents {
        if a.already_monitored {
            continue;
        }
        if st.decision_for(&a.id).is_some() {
            continue;
        }

        println!("─── AgentDR — discovered local AI agent ─────────────────");
        println!("  Name      : {}", a.name);
        println!("  Id        : {}", a.id);
        println!("  Category  : {}", a.category);
        println!("  Confidence: {:.0}%", a.confidence * 100.0);
        println!("  Evidence  :");
        for e in &a.evidence {
            println!("    - {}", evidence_human(e));
        }
        print!("  Monitor with AgentDR? [Y/n/skip-always] ");
        let _ = std::io::stdout().flush();

        let stdin = std::io::stdin();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            warn!("discovery prompt: stdin closed; falling back to skip");
            break;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" | "y" | "yes" => {
                match hooks::install(&a.id, endpoint) {
                    Ok(()) => {
                        println!("  ✓ installed hook for {}", a.id);
                        st.record(&a.id, "monitor", "tty");
                        installed += 1;
                    }
                    Err(e) => warn!("  ✗ install failed: {e}"),
                }
            }
            "n" | "no" | "skip" => {
                println!("  – skipped (will re-ask next scan)");
                // Don't record — re-ask later
            }
            "skip-always" | "never" => {
                println!("  – skipped permanently");
                st.record(&a.id, "skip", "tty");
            }
            other => {
                println!("  ? unrecognised input '{}', skipping", other);
            }
        }
        println!();
    }
    let _ = st.save(state_path);
    Ok(installed)
}

fn evidence_human(e: &scan::Evidence) -> String {
    match e {
        scan::Evidence::BinaryOnPath { path }                  => format!("binary on $PATH: {path}"),
        scan::Evidence::KnownInstallLocation { path, hint }    => format!("install location ({hint}): {path}"),
        scan::Evidence::HookConfigPresent { path, marker_present: true } => format!("hook config present (already managed): {path}"),
        scan::Evidence::HookConfigPresent { path, .. }         => format!("hook config present (unmanaged): {path}"),
        scan::Evidence::McpEntries { path, server_count }      => format!("{server_count} MCP server entr{}: {path}",
                                                                          if *server_count == 1 { "y" } else { "ies" }),
        scan::Evidence::ProcessRunning { pid }                 => format!("process running (pid={pid})"),
    }
}
