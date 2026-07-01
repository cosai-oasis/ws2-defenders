//! Telemetry ingest paths.
//!
//! `otlp` exposes an OpenTelemetry Protocol (OTLP/HTTP) endpoint on the
//! loopback interface and maps OTel `gen_ai.*` semantic-convention attributes
//! into the CoSAI AITF OCSF Class-Reuse (ai_operation profile) event model.
//!
//! `openshell` tails NVIDIA OpenShell's OCSF JSON audit log and re-emits each
//! Gateway allow/deny decision as an AITF `EventRecord`.

pub mod openshell;
pub mod otlp;

/// Opt-in interop with the official AITF Rust SDK (`aitf` crate). Enabled with
/// `--features aitf-sdk`; off by default so the core build never depends on the
/// (beta, not-yet-published) crate.
#[cfg(feature = "aitf-sdk")]
pub mod aitf_interop;
