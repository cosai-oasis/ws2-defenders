//! AITF exporters.
//!
//! Unlike the Go/Python SDKs (whose exporters consume OTel spans), the Rust
//! crate has no OpenTelemetry dependency, so its exporters consume already-mapped
//! [`AIBaseEvent`](crate::ocsf::AIBaseEvent) values. The pipeline is:
//!
//! ```text
//! OcsfMapper::map_span(..) -> AIBaseEvent -> exporter
//! ```
//!
//! - [`ocsf::OcsfExporter`] serializes events to OCSF JSON Lines (and, with the
//!   `client` feature, POSTs them to an HTTP endpoint).
//! - [`cef_syslog::CefSyslogExporter`] renders events as CEF (Common Event
//!   Format) syslog message strings for SIEMs that do not support OCSF natively.
//! - [`immutable_log::ImmutableLogExporter`] writes an append-only, SHA-256
//!   hash-chained JSONL audit log with tamper-evident verification.

pub mod cef_syslog;
pub mod immutable_log;
pub mod ocsf;

pub use cef_syslog::CefSyslogExporter;
pub use immutable_log::{
    verify_immutable_log, ImmutableLogEntry, ImmutableLogExporter, VerificationResult,
};
pub use ocsf::OcsfExporter;
