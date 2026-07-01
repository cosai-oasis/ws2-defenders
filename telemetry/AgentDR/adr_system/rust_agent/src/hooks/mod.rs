//! Runtime hooks for local AI agents (Tier 1).
//!
//! Each submodule knows how to install / uninstall / report the hook
//! configuration for a single AI runtime. Hooks point the runtime at the
//! AgentDR local OTLP collector (default `http://127.0.0.1:4318`) so that
//! prompt, tool-call, and approval events are captured with semantic
//! certainty rather than inferred from process / network signals.

pub mod aider;
pub mod claude_code;
pub mod codex;
pub mod common;
pub mod cursor;
pub mod opencode;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HookStatus {
    pub claude_code: common::HookState,
    pub cursor: common::HookState,
    pub codex: common::HookState,
    pub aider: common::HookState,
    pub opencode: common::HookState,
}

pub fn install(target: &str, endpoint: &str) -> Result<(), String> {
    match target.to_ascii_lowercase().as_str() {
        "claude-code" => claude_code::install(endpoint),
        "cursor"      => cursor::install(endpoint),
        "codex"       => codex::install(endpoint),
        "aider"       => aider::install(endpoint),
        "opencode"    => opencode::install(endpoint),
        "all"         => {
            let mut errs: Vec<String> = Vec::new();
            if let Err(e) = claude_code::install(endpoint) { errs.push(format!("claude-code: {e}")); }
            if let Err(e) = cursor::install(endpoint)      { errs.push(format!("cursor: {e}")); }
            if let Err(e) = codex::install(endpoint)       { errs.push(format!("codex: {e}")); }
            if let Err(e) = aider::install(endpoint)       { errs.push(format!("aider: {e}")); }
            if let Err(e) = opencode::install(endpoint)    { errs.push(format!("opencode: {e}")); }
            if errs.is_empty() { Ok(()) } else { Err(errs.join("; ")) }
        }
        other => Err(format!("unknown target '{other}' — expected claude-code|cursor|codex|aider|opencode|all")),
    }
}

pub fn uninstall(target: &str) -> Result<(), String> {
    match target.to_ascii_lowercase().as_str() {
        "claude-code" => claude_code::uninstall(),
        "cursor"      => cursor::uninstall(),
        "codex"       => codex::uninstall(),
        "aider"       => aider::uninstall(),
        "opencode"    => opencode::uninstall(),
        "all"         => {
            let mut errs: Vec<String> = Vec::new();
            if let Err(e) = claude_code::uninstall() { errs.push(format!("claude-code: {e}")); }
            if let Err(e) = cursor::uninstall()      { errs.push(format!("cursor: {e}")); }
            if let Err(e) = codex::uninstall()       { errs.push(format!("codex: {e}")); }
            if let Err(e) = aider::uninstall()       { errs.push(format!("aider: {e}")); }
            if let Err(e) = opencode::uninstall()    { errs.push(format!("opencode: {e}")); }
            if errs.is_empty() { Ok(()) } else { Err(errs.join("; ")) }
        }
        other => Err(format!("unknown target '{other}'")),
    }
}

pub fn status() -> HookStatus {
    HookStatus {
        claude_code: claude_code::status(),
        cursor: cursor::status(),
        codex: codex::status(),
        aider: aider::status(),
        opencode: opencode::status(),
    }
}
