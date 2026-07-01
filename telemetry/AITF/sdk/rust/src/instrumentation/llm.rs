//! LLM inference instrumentation mirroring the Go `instrumentation/llm.go`.
//!
//! [`LlmInstrumentor`] wraps an OpenTelemetry [`Tracer`] and produces an
//! [`InferenceSpan`] with typed setter methods that emit AITF-semconv
//! attributes for an LLM inference operation.

use std::time::Instant;

use opentelemetry::global::{self, BoxedTracer};
use opentelemetry::trace::{Span, SpanKind, Status, Tracer};
use opentelemetry::KeyValue;

use crate::semconv::{cost, gen_ai, latency};

/// Default operation name (mirrors Go `GenAIOperationChat`).
const DEFAULT_OPERATION: &str = "chat";
/// Default provider name (mirrors Go `GenAISystemOpenAI`).
const DEFAULT_PROVIDER: &str = "openai";
/// Tracer name used by the default constructor.
const TRACER_NAME: &str = "instrumentation.llm";

/// Configuration for an inference span.
///
/// Mirrors the Go `InferenceConfig` struct.
#[derive(Debug, Clone, Default)]
pub struct InferenceConfig {
    /// The requested model (e.g. `gpt-4o`).
    pub model: String,
    /// The provider / system name (`gen_ai.provider.name`). Defaults to `openai`.
    pub provider: String,
    /// The operation name (`gen_ai.operation.name`). Defaults to `chat`.
    pub operation: String,
    /// Optional sampling temperature.
    pub temperature: Option<f64>,
    /// Optional max-tokens request.
    pub max_tokens: Option<i64>,
    /// Whether the request was streamed.
    pub stream: bool,
    /// Tool names made available to the model.
    pub tools: Vec<String>,
}

impl InferenceConfig {
    /// Convenience constructor from a model name.
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            ..Default::default()
        }
    }
}

/// Traces LLM inference operations.
pub struct LlmInstrumentor<T = BoxedTracer> {
    tracer: T,
}

impl LlmInstrumentor<BoxedTracer> {
    /// Creates an instrumentor using the global tracer provider.
    pub fn new() -> Self {
        Self {
            tracer: global::tracer(TRACER_NAME),
        }
    }
}

impl Default for LlmInstrumentor<BoxedTracer> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Tracer> LlmInstrumentor<T> {
    /// Creates an instrumentor from an explicit tracer.
    pub fn with_tracer(tracer: T) -> Self {
        Self { tracer }
    }

    /// Starts a new inference span. The caller must call [`InferenceSpan::end`]
    /// when done.
    pub fn trace_inference(&self, mut cfg: InferenceConfig) -> InferenceSpan<T::Span> {
        if cfg.operation.is_empty() {
            cfg.operation = DEFAULT_OPERATION.to_string();
        }
        if cfg.provider.is_empty() {
            cfg.provider = DEFAULT_PROVIDER.to_string();
        }

        let span_name = format!("{} {}", cfg.operation, cfg.model);
        let mut attrs = vec![
            KeyValue::new(gen_ai::PROVIDER_NAME, cfg.provider.clone()),
            KeyValue::new(gen_ai::OPERATION_NAME, cfg.operation.clone()),
            KeyValue::new(gen_ai::REQUEST_MODEL, cfg.model.clone()),
        ];
        if let Some(t) = cfg.temperature {
            attrs.push(KeyValue::new(gen_ai::REQUEST_TEMPERATURE, t));
        }
        if let Some(m) = cfg.max_tokens {
            attrs.push(KeyValue::new(gen_ai::REQUEST_MAX_TOKENS, m));
        }
        if cfg.stream {
            attrs.push(KeyValue::new(gen_ai::REQUEST_STREAM, true));
        }
        if !cfg.tools.is_empty() {
            attrs.push(KeyValue::new(
                gen_ai::REQUEST_TOOLS,
                opentelemetry::Value::Array(
                    cfg.tools
                        .iter()
                        .map(|s| opentelemetry::StringValue::from(s.clone()))
                        .collect::<Vec<_>>()
                        .into(),
                ),
            ));
        }

        let span = self
            .tracer
            .span_builder(span_name)
            .with_kind(SpanKind::Client)
            .with_attributes(attrs)
            .start(&self.tracer);

        InferenceSpan {
            span,
            start: Instant::now(),
        }
    }
}

/// Records inference attributes for an in-progress span.
pub struct InferenceSpan<S: Span> {
    span: S,
    start: Instant,
}

impl<S: Span> InferenceSpan<S> {
    /// Records the prompt content as an event.
    pub fn set_prompt(&mut self, prompt: impl Into<String>) {
        self.span.add_event(
            "gen_ai.content.prompt",
            vec![KeyValue::new(gen_ai::PROMPT, prompt.into())],
        );
    }

    /// Records the completion content as an event.
    pub fn set_completion(&mut self, completion: impl Into<String>) {
        self.span.add_event(
            "gen_ai.content.completion",
            vec![KeyValue::new(gen_ai::COMPLETION, completion.into())],
        );
    }

    /// Sets token-usage attributes.
    pub fn set_usage(&mut self, input_tokens: i64, output_tokens: i64) {
        self.span
            .set_attribute(KeyValue::new(gen_ai::USAGE_INPUT_TOKENS, input_tokens));
        self.span
            .set_attribute(KeyValue::new(gen_ai::USAGE_OUTPUT_TOKENS, output_tokens));
    }

    /// Sets response attributes.
    pub fn set_response(&mut self, id: &str, model: &str, finish_reasons: &[String]) {
        if !id.is_empty() {
            self.span
                .set_attribute(KeyValue::new(gen_ai::RESPONSE_ID, id.to_string()));
        }
        if !model.is_empty() {
            self.span
                .set_attribute(KeyValue::new(gen_ai::RESPONSE_MODEL, model.to_string()));
        }
        if !finish_reasons.is_empty() {
            self.span.set_attribute(KeyValue::new(
                gen_ai::RESPONSE_FINISH_REASONS,
                opentelemetry::Value::Array(
                    finish_reasons
                        .iter()
                        .map(|s| opentelemetry::StringValue::from(s.clone()))
                        .collect::<Vec<_>>()
                        .into(),
                ),
            ));
        }
    }

    /// Sets cost attributes.
    pub fn set_cost(&mut self, input_cost: f64, output_cost: f64, total_cost: f64) {
        self.span
            .set_attribute(KeyValue::new(cost::INPUT_COST, input_cost));
        self.span
            .set_attribute(KeyValue::new(cost::OUTPUT_COST, output_cost));
        self.span
            .set_attribute(KeyValue::new(cost::TOTAL_COST, total_cost));
    }

    /// Sets latency metrics.
    pub fn set_latency(&mut self, total_ms: f64, tokens_per_second: Option<f64>) {
        self.span
            .set_attribute(KeyValue::new(latency::TOTAL_MS, total_ms));
        if let Some(tps) = tokens_per_second {
            self.span
                .set_attribute(KeyValue::new(latency::TOKENS_PER_SECOND, tps));
        }
    }

    /// Records the time-to-first-token relative to span start.
    pub fn mark_first_token(&mut self) {
        let ttft = self.start.elapsed().as_millis() as f64;
        self.span
            .set_attribute(KeyValue::new(latency::TIME_TO_FIRST_TOKEN_MS, ttft));
    }

    /// Records a tool-call event.
    pub fn set_tool_call(&mut self, name: &str, call_id: &str, arguments: &str) {
        self.span.add_event(
            "gen_ai.tool.call",
            vec![
                KeyValue::new(gen_ai::TOOL_NAME, name.to_string()),
                KeyValue::new(gen_ai::TOOL_CALL_ID, call_id.to_string()),
                KeyValue::new(gen_ai::TOOL_ARGUMENTS, arguments.to_string()),
            ],
        );
    }

    /// Completes the inference span, recording status and total latency.
    pub fn end<E: std::fmt::Display>(mut self, result: Result<(), E>) {
        match result {
            Ok(()) => self.span.set_status(Status::Ok),
            Err(e) => {
                self.span.set_status(Status::error(e.to_string()));
            }
        }
        let total_ms = self.start.elapsed().as_millis() as f64;
        self.span
            .set_attribute(KeyValue::new(latency::TOTAL_MS, total_ms));
        self.span.end();
    }

    /// Returns a mutable reference to the underlying span.
    pub fn span_mut(&mut self) -> &mut S {
        &mut self.span
    }
}
