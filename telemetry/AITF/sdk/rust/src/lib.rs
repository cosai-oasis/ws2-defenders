//! # AITF Rust SDK
//!
//! An idiomatic Rust port of the core of the AITF Go/Python SDKs:
//!
//! - the OCSF "class-reuse" model (OCSF PR #1641 / issue #1640): AI telemetry is
//!   emitted under existing OCSF classes enriched with the `ai_operation`
//!   profile, with the proposed "ai" category (uid 9) reserved for the new
//!   agent / delegation control-plane classes;
//! - the `ai_operation` profile (`ai_agent`, `ai_model`, `delegation`,
//!   `delegation_lineage`);
//! - agent-to-agent communication unification (one generic `agent_message`
//!   object with a `protocol_id` discriminator across A2A / ACP / ANP / MCP);
//! - the Anthropic Claude Compliance mapper.
//!
//! ## Example
//!
//! ```
//! use aitf::ocsf::{OcsfMapper, SpanData};
//! use aitf::semconv;
//!
//! let span = SpanData::new("chat gpt-4o")
//!     .with_attr(semconv::gen_ai::SYSTEM, "openai")
//!     .with_attr(semconv::gen_ai::REQUEST_MODEL, "gpt-4o")
//!     .with_attr(semconv::gen_ai::OPERATION_NAME, "chat");
//!
//! let event = OcsfMapper::new().map_span(&span).unwrap();
//! assert_eq!(event.class_uid, 6003); // OCSF API Activity
//! let json = event.to_json().unwrap();
//! assert!(json.contains("\"class_uid\":6003"));
//! ```

pub mod exporters;
#[cfg(feature = "otel")]
pub mod instrumentation;
pub mod ocsf;
pub mod pipeline;
pub mod semconv;

pub use exporters::{CefSyslogExporter, ImmutableLogExporter, OcsfExporter};
pub use ocsf::{
    AIBaseEvent, AttrValue, ClaudeComplianceMapper, ComplianceMapper, ComplianceMetadata,
    OcsfMapper, SpanData,
};
pub use pipeline::{DualPipeline, DualPipelineBuilder};

#[cfg(feature = "otel")]
pub use instrumentation::{
    AgentInstrumentor, AuthenticationConfig, DelegationConfig, IdentityInstrumentor,
    InferenceConfig, LifecycleConfig, LlmInstrumentor, McpInstrumentor, RagInstrumentor,
    SessionConfig,
};
