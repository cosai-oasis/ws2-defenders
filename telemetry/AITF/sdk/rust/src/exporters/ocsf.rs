//! OCSF JSON exporter.
//!
//! Serializes [`AIBaseEvent`] values to OCSF JSON (nulls skipped via the schema's
//! `skip_serializing_if`). Supports emitting to a JSONL string / byte buffer,
//! appending to a file, and — behind the `client` feature — POSTing to an HTTP
//! endpoint, mirroring the Go `exporters/ocsf.go` security rules (HTTP is only
//! allowed for localhost/dev hosts; HTTPS is required otherwise).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::ocsf::AIBaseEvent;

/// Localhost addresses where plain HTTP is permitted for development.
pub const DEV_HOSTS: &[&str] = &["localhost", "127.0.0.1", "::1"];

/// An OCSF exporter producing JSON Lines from mapped AI events.
#[derive(Debug, Clone, Default)]
pub struct OcsfExporter;

impl OcsfExporter {
    /// Creates a new exporter.
    pub fn new() -> Self {
        OcsfExporter
    }

    /// Serializes a single event to a compact JSON string (nulls skipped).
    pub fn to_json(&self, event: &AIBaseEvent) -> Result<String, serde_json::Error> {
        serde_json::to_string(event)
    }

    /// Serializes a batch of events to a JSON Lines string (one event per line,
    /// trailing newline included).
    pub fn to_jsonl(&self, events: &[AIBaseEvent]) -> Result<String, serde_json::Error> {
        let mut out = String::new();
        for event in events {
            out.push_str(&serde_json::to_string(event)?);
            out.push('\n');
        }
        Ok(out)
    }

    /// Serializes a batch of events to JSON Lines bytes.
    pub fn to_jsonl_bytes(&self, events: &[AIBaseEvent]) -> Result<Vec<u8>, serde_json::Error> {
        Ok(self.to_jsonl(events)?.into_bytes())
    }

    /// Appends a batch of events as JSON Lines to a file, creating it if needed.
    pub fn append_to_file(
        &self,
        path: impl AsRef<Path>,
        events: &[AIBaseEvent],
    ) -> std::io::Result<()> {
        let data = self
            .to_jsonl_bytes(events)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(&data)?;
        Ok(())
    }
}

/// Validates an OCSF endpoint URL.
///
/// Only `http`/`https` schemes are accepted. When an API key is supplied, HTTPS
/// is required unless the host is a development host. Mirrors Go
/// `validateEndpoint`.
pub fn validate_endpoint(endpoint: &str, api_key: Option<&str>) -> Result<(), String> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| format!("invalid endpoint URL: {endpoint}"))?;
    let scheme = scheme.to_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "unsupported URL scheme '{scheme}'; only http and https are allowed"
        ));
    }
    // Extract hostname (strip path, query, port, and userinfo).
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let hostname = if let Some(stripped) = host_port.strip_prefix('[') {
        // IPv6 literal: [::1]:port
        stripped.split(']').next().unwrap_or(stripped)
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    let is_dev = DEV_HOSTS.contains(&hostname);
    if api_key.is_some_and(|k| !k.is_empty()) && scheme != "https" && !is_dev {
        return Err(
            "HTTPS is required when using API key authentication; use https:// or localhost for development"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(feature = "client")]
impl OcsfExporter {
    /// POSTs a batch of events as a JSON array to an HTTP endpoint.
    ///
    /// Sets `Content-Type: application/json` and, when `api_key` is supplied,
    /// `Authorization: Bearer <key>`. Additional headers may be provided as
    /// `(name, value)` pairs. Returns an error on a non-2xx status. Requires the
    /// `client` feature.
    pub fn post_to_endpoint(
        &self,
        endpoint: &str,
        events: &[AIBaseEvent],
        api_key: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<(), String> {
        validate_endpoint(endpoint, api_key)?;
        let payload = serde_json::to_string(events).map_err(|e| e.to_string())?;

        let mut req = ureq::post(endpoint).set("Content-Type", "application/json");
        if let Some(key) = api_key {
            if !key.is_empty() {
                req = req.set("Authorization", &format!("Bearer {key}"));
            }
        }
        for (name, value) in headers {
            req = req.set(name, value);
        }

        match req.send_string(&payload) {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, _)) => {
                Err(format!("ocsf endpoint returned status {code}"))
            }
            Err(e) => Err(format!("failed to send to endpoint: {e}")),
        }
    }
}
