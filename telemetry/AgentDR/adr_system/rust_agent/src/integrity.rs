//! CoSAI Community Rules — SHA-256 integrity verification and update manager.
//!
//! Verifies local rule files against `checksums.sha256` manifest and can
//! download updated rules from a configurable remote URL.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const MANIFEST_FILE: &str = "checksums.sha256";
const RULE_FILES: &[&str] = &[
    "rules/agent-signatures.json",
    "rules/ai-endpoints.json",
    "rules/messaging-endpoints.json",
    "policies/detection-rules.json",
];

/// Status for a single file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FileStatus {
    pub file: String,
    pub status: String, // "ok", "mismatch", "missing"
    pub hash: String,
}

/// Overall integrity status.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IntegrityStatus {
    pub integrity: String, // "ok" or "failed"
    pub version: String,
    pub files: Vec<FileStatus>,
    pub community_dir: String,
}

/// Update result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UpdateResult {
    pub status: String, // "updated", "up_to_date", "integrity_failed", "error"
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub updated: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct RuleIntegrity {
    pub community_dir: PathBuf,
    pub remote_url: String,
}

impl RuleIntegrity {
    pub fn new(community_dir: PathBuf) -> Self {
        let remote_url = std::env::var("COSAI_RULES_URL").unwrap_or_else(|_| {
            "https://raw.githubusercontent.com/girdav01/aitf/main/cosai-community".to_string()
        });
        Self {
            community_dir,
            remote_url: remote_url.trim_end_matches('/').to_string(),
        }
    }

    /// Discover the community rules directory relative to the executable.
    pub fn discover() -> Self {
        let exe = std::env::current_exe().unwrap_or_default();
        let dev = exe
            .parent()
            .unwrap_or(Path::new("."))
            .join("../cosai-community");
        let dir = if dev.exists() {
            dev
        } else {
            PathBuf::from("cosai-community")
        };
        Self::new(dir)
    }

    /// Verify all rule files against the local checksums manifest.
    pub fn verify(&self) -> Result<IntegrityStatus, String> {
        let status = self.status();
        if status.integrity == "ok" {
            Ok(status)
        } else {
            Err(format!(
                "Integrity check FAILED: {}",
                status
                    .files
                    .iter()
                    .filter(|f| f.status != "ok")
                    .map(|f| format!("{}: {}", f.file, f.status))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
    }

    /// Get status without raising errors.
    pub fn status(&self) -> IntegrityStatus {
        let manifest = self.load_manifest();
        let mut files = Vec::new();
        let mut all_ok = true;

        for &relpath in RULE_FILES {
            let filepath = self.community_dir.join(relpath);
            let expected = manifest.get(relpath).cloned().unwrap_or_default();
            if !filepath.exists() {
                files.push(FileStatus {
                    file: relpath.to_string(),
                    status: "missing".to_string(),
                    hash: String::new(),
                });
                all_ok = false;
                continue;
            }
            let actual = sha256_file(&filepath);
            let ok = actual == expected;
            if !ok {
                all_ok = false;
            }
            files.push(FileStatus {
                file: relpath.to_string(),
                status: if ok { "ok" } else { "mismatch" }.to_string(),
                hash: actual[..16.min(actual.len())].to_string(),
            });
        }

        // Read version from agent-signatures.json
        let version = self
            .community_dir
            .join("rules/agent-signatures.json")
            .exists()
            .then(|| {
                fs::read_to_string(self.community_dir.join("rules/agent-signatures.json"))
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|v| v.get("version")?.as_str().map(String::from))
            })
            .flatten()
            .unwrap_or_else(|| "unknown".to_string());

        IntegrityStatus {
            integrity: if all_ok { "ok" } else { "failed" }.to_string(),
            version,
            files,
            community_dir: self.community_dir.display().to_string(),
        }
    }

    /// Download updated rules, verify, and replace local files.
    pub fn update(&self, force: bool) -> UpdateResult {
        tracing::info!(url = %self.remote_url, "Starting rule update");

        // 1. Download manifest
        let manifest_url = format!("{}/{}", self.remote_url, MANIFEST_FILE);
        let new_manifest_text = match download_text(&manifest_url) {
            Ok(t) => t,
            Err(e) => {
                return UpdateResult {
                    status: "error".into(),
                    updated: vec![],
                    error: Some(format!("Failed to download manifest: {}", e)),
                }
            }
        };
        let new_manifest = parse_manifest(&new_manifest_text);

        if !force {
            let old_manifest = self.load_manifest();
            if old_manifest == new_manifest {
                tracing::info!("Rules are already up to date");
                return UpdateResult {
                    status: "up_to_date".into(),
                    updated: vec![],
                    error: None,
                };
            }
        }

        // 2. Download + verify each file
        let mut downloaded: HashMap<String, Vec<u8>> = HashMap::new();
        let mut failures = Vec::new();

        for &relpath in RULE_FILES {
            let url = format!("{}/{}", self.remote_url, relpath);
            match download_bytes(&url) {
                Ok(bytes) => {
                    let actual = sha256_bytes(&bytes);
                    if let Some(expected) = new_manifest.get(relpath) {
                        if &actual != expected {
                            failures.push(format!(
                                "{}: hash mismatch (expected {}… got {}…)",
                                relpath,
                                &expected[..16.min(expected.len())],
                                &actual[..16.min(actual.len())]
                            ));
                            continue;
                        }
                    }
                    downloaded.insert(relpath.to_string(), bytes);
                }
                Err(e) => failures.push(format!("{}: download failed: {}", relpath, e)),
            }
        }

        if !failures.is_empty() {
            tracing::error!(failures = ?failures, "Downloaded rules FAILED integrity check");
            return UpdateResult {
                status: "integrity_failed".into(),
                updated: vec![],
                error: Some(failures.join("; ")),
            };
        }

        // 3. Replace local files
        let mut updated = Vec::new();
        for (relpath, bytes) in &downloaded {
            let dest = self.community_dir.join(relpath);
            if let Some(parent) = dest.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if fs::write(&dest, bytes).is_ok() {
                updated.push(relpath.clone());
            }
        }

        // Replace manifest
        let _ = fs::write(
            self.community_dir.join(MANIFEST_FILE),
            new_manifest_text.as_bytes(),
        );

        tracing::info!(count = updated.len(), "Rule update complete");
        UpdateResult {
            status: "updated".into(),
            updated,
            error: None,
        }
    }

    fn load_manifest(&self) -> HashMap<String, String> {
        let path = self.community_dir.join(MANIFEST_FILE);
        fs::read_to_string(&path)
            .ok()
            .map(|s| parse_manifest(&s))
            .unwrap_or_default()
    }
}

fn parse_manifest(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        if let (Some(hash), Some(file)) = (parts.next(), parts.next()) {
            map.insert(file.trim().to_string(), hash.trim().to_string());
        }
    }
    map
}

fn sha256_file(path: &Path) -> String {
    let mut hasher = Sha256::new();
    if let Ok(mut f) = fs::File::open(path) {
        let mut buf = [0u8; 8192];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(_) => break,
            }
        }
    }
    format!("{:x}", hasher.finalize())
}

fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn download_text(url: &str) -> Result<String, String> {
    // Use a minimal blocking HTTP GET via ureq-style approach
    // Since we already have reqwest in deps, use it in blocking mode
    let resp = std::process::Command::new("curl")
        .args(["-sSfL", "--max-time", "30", "-A", "CoSAI-ADR-Agent/1.0", url])
        .output()
        .map_err(|e| format!("curl failed: {}", e))?;
    if !resp.status.success() {
        return Err(format!(
            "HTTP error for {}: {}",
            url,
            String::from_utf8_lossy(&resp.stderr)
        ));
    }
    String::from_utf8(resp.stdout).map_err(|e| format!("UTF-8 decode error: {}", e))
}

fn download_bytes(url: &str) -> Result<Vec<u8>, String> {
    let resp = std::process::Command::new("curl")
        .args(["-sSfL", "--max-time", "30", "-A", "CoSAI-ADR-Agent/1.0", url])
        .output()
        .map_err(|e| format!("curl failed: {}", e))?;
    if !resp.status.success() {
        return Err(format!(
            "HTTP error for {}: {}",
            url,
            String::from_utf8_lossy(&resp.stderr)
        ));
    }
    Ok(resp.stdout)
}
