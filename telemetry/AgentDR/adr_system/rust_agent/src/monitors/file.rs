//! File system monitor — watches directories for file changes, detects skill paths.

use crate::models::*;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::json;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

pub struct FileMonitor {
    watch_dirs: Vec<PathBuf>,
    recursive: bool,
    ignore_patterns: Vec<String>,
    tx: mpsc::UnboundedSender<EventRecord>,
}

impl FileMonitor {
    pub fn new(
        watch_dirs: Vec<String>,
        recursive: bool,
        ignore_patterns: Vec<String>,
        tx: mpsc::UnboundedSender<EventRecord>,
    ) -> Self {
        Self {
            watch_dirs: watch_dirs.into_iter().map(PathBuf::from).collect(),
            recursive,
            ignore_patterns,
            tx,
        }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::unbounded_channel();

        // Create watcher in a blocking thread since notify uses sync API
        let watch_dirs = self.watch_dirs.clone();
        let recursive = self.recursive;
        let _watcher_handle = std::thread::spawn(move || {
            let rt_tx = notify_tx;
            let mut watcher = match RecommendedWatcher::new(
                move |res: Result<Event, notify::Error>| {
                    if let Ok(ev) = res {
                        let _ = rt_tx.send(ev);
                    }
                },
                Config::default(),
            ) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create file watcher: {}", e);
                    return;
                }
            };

            let mode = if recursive { RecursiveMode::Recursive } else { RecursiveMode::NonRecursive };
            for dir in &watch_dirs {
                if dir.exists() && dir.is_dir() {
                    if let Err(e) = watcher.watch(dir, mode) {
                        error!("Failed to watch {:?}: {}", dir, e);
                    } else {
                        info!("Watching directory: {:?}", dir);
                    }
                }
            }

            // Keep watcher alive
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        });

        loop {
            tokio::select! {
                Some(event) = notify_rx.recv() => {
                    self.handle_event(event);
                }
                _ = shutdown.changed() => { break; }
            }
        }
        debug!("File monitor shut down");
    }

    fn handle_event(&self, event: Event) {
        for path in &event.paths {
            let path_str = path.to_string_lossy().to_string();
            let filename = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();

            // Check ignore patterns
            if self.is_ignored(&filename) {
                continue;
            }

            // Skip directories
            if path.is_dir() {
                continue;
            }

            let skill = is_skill_path(&path_str);
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

            let (event_type, activity) = match event.kind {
                EventKind::Create(_) => ("file_created", ACTIVITY_CREATE),
                EventKind::Modify(_) => ("file_modified", ACTIVITY_UPDATE),
                EventKind::Remove(_) => ("file_deleted", ACTIVITY_DELETE),
                _ => continue,
            };

            let risk = if event_type == "file_deleted" {
                if size >= 25 * 1024 * 1024 { "high" } else { "medium" }
            } else if skill {
                "high"
            } else {
                "low"
            };

            let op = if skill { AiOperation::McpOperation } else { AiOperation::ToolExecution };

            let mut msg = format!("File {}: {}", event_type.replace("file_", ""), filename);
            if skill {
                msg = format!("[SKILL] {} — potential plugin activity", msg);
            }

            let mut ev = EventRecord::new(
                event_type,
                json!({
                    "path": path_str,
                    "size_bytes": size,
                    "is_skill_path": skill,
                }),
                risk,
            );
            ev.source = Some("file_monitor".into());
            ev.set_op(op, activity);
            ev.activity_id = Some(activity);
            ev.status_id = Some(STATUS_SUCCESS);
            ev.message = Some(msg);
            ev.tool_name = Some("filesystem".into());

            if skill {
                ev.security_finding = Some(json!({
                    "title": format!("Skill/Plugin File {}", event_type.replace("file_", "")),
                    "severity": risk,
                    "description": format!("Agent skill directory activity: {}", path_str),
                }));
            }

            let _ = self.tx.send(ev);
        }
    }

    fn is_ignored(&self, filename: &str) -> bool {
        for pattern in &self.ignore_patterns {
            // Simple glob matching: *.ext
            if let Some(ext) = pattern.strip_prefix('*') {
                if filename.ends_with(ext) {
                    return true;
                }
            } else if filename == pattern.as_str() {
                return true;
            }
        }
        false
    }
}
