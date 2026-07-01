//! OpenTelemetry-backed auto-instrumentation helpers (feature `otel`).
//!
//! Rust cannot monkey-patch, so these are manual-but-ergonomic instrumentation
//! helpers that mirror the Go `sdk/go/instrumentation` package: each domain has
//! an instrumentor that wraps an OpenTelemetry tracer and produces a span
//! wrapper with typed setter methods emitting AITF-semconv attributes, plus an
//! `end(result)` that sets the span status / records the error.
//!
//! Every instrumentor offers a `new()` that uses the global tracer
//! (`opentelemetry::global::tracer("instrumentation.<domain>")`) and a
//! `with_tracer(...)` constructor for an explicit tracer.
//!
//! ```no_run
//! use aitf::instrumentation::{LlmInstrumentor, InferenceConfig};
//!
//! let llm = LlmInstrumentor::new();
//! let mut span = llm.trace_inference(InferenceConfig {
//!     model: "gpt-4o".into(),
//!     provider: "openai".into(),
//!     ..Default::default()
//! });
//! span.set_usage(100, 50);
//! span.end(Ok::<_, std::io::Error>(()));
//! ```

pub mod agent;
pub mod identity;
pub mod llm;
pub mod rag;
pub mod tool;

pub use agent::{AgentInstrumentor, AgentSession, AgentStep, SessionConfig};
pub use identity::{
    AuthenticationConfig, DelegationConfig, IdentityInstrumentor, LifecycleConfig,
};
pub use llm::{InferenceConfig, InferenceSpan, LlmInstrumentor};
pub use rag::{RagInstrumentor, RagPipeline, RetrievalSpan};
pub use tool::{McpInstrumentor, McpServerConnection, McpToolInvocation};
