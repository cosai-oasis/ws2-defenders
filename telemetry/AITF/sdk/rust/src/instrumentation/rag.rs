//! RAG retrieval instrumentation mirroring the Go `instrumentation/rag.go`.

use opentelemetry::global::{self, BoxedTracer};
use opentelemetry::trace::{Span, SpanKind, Status, Tracer};
use opentelemetry::KeyValue;

use crate::semconv::rag;

const TRACER_NAME: &str = "instrumentation.rag";
const STAGE_RETRIEVE: &str = "retrieve";
/// Attribute key for the embedding model. The Rust `semconv::rag` module does
/// not define a dedicated constant, so the canonical key string is used here.
const EMBEDDING_MODEL_KEY: &str = "rag.embedding.model";

/// Traces RAG pipeline operations.
pub struct RagInstrumentor<T = BoxedTracer> {
    tracer: T,
}

impl RagInstrumentor<BoxedTracer> {
    /// Creates an instrumentor using the global tracer provider.
    pub fn new() -> Self {
        Self {
            tracer: global::tracer(TRACER_NAME),
        }
    }
}

impl Default for RagInstrumentor<BoxedTracer> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Tracer> RagInstrumentor<T> {
    /// Creates an instrumentor from an explicit tracer.
    pub fn with_tracer(tracer: T) -> Self {
        Self { tracer }
    }

    /// Starts a RAG pipeline span.
    pub fn trace_pipeline(&self, pipeline_name: &str, query: &str) -> RagPipeline<T::Span> {
        let mut attrs = vec![KeyValue::new(rag::PIPELINE_NAME, pipeline_name.to_string())];
        if !query.is_empty() {
            attrs.push(KeyValue::new(rag::QUERY, query.to_string()));
        }
        let span = self
            .tracer
            .span_builder(format!("rag.pipeline {pipeline_name}"))
            .with_kind(SpanKind::Internal)
            .with_attributes(attrs)
            .start(&self.tracer);
        RagPipeline { span }
    }

    /// Starts a standalone retrieval span.
    pub fn trace_retrieve(&self, database: &str, top_k: i64) -> RetrievalSpan<T::Span> {
        let span = self
            .tracer
            .span_builder(format!("rag.retrieve {database}"))
            .with_kind(SpanKind::Client)
            .with_attributes(vec![
                KeyValue::new(rag::PIPELINE_STAGE, STAGE_RETRIEVE),
                KeyValue::new(rag::RETRIEVE_DATABASE, database.to_string()),
                KeyValue::new(rag::RETRIEVE_TOP_K, top_k),
            ])
            .start(&self.tracer);
        RetrievalSpan { span }
    }
}

/// Manages a RAG pipeline span.
pub struct RagPipeline<S: Span> {
    span: S,
}

impl<S: Span> RagPipeline<S> {
    /// Records the embedding model used by the pipeline.
    pub fn set_embedding_model(&mut self, model: &str) {
        self.span
            .set_attribute(KeyValue::new(EMBEDDING_MODEL_KEY, model.to_string()));
    }

    /// Records the query string on the pipeline span.
    pub fn set_query(&mut self, query: &str) {
        self.span
            .set_attribute(KeyValue::new(rag::QUERY, query.to_string()));
    }

    /// Completes the pipeline span.
    pub fn end<E: std::fmt::Display>(mut self, result: Result<(), E>) {
        match result {
            Ok(()) => self.span.set_status(Status::Ok),
            Err(e) => self.span.set_status(Status::error(e.to_string())),
        }
        self.span.end();
    }

    /// Returns a mutable reference to the underlying span.
    pub fn span_mut(&mut self) -> &mut S {
        &mut self.span
    }
}

/// Manages a retrieval span.
pub struct RetrievalSpan<S: Span> {
    span: S,
}

impl<S: Span> RetrievalSpan<S> {
    /// Sets retrieval result attributes (count and score range).
    pub fn set_results(&mut self, count: i64, min_score: f64, max_score: f64) {
        self.span
            .set_attribute(KeyValue::new(rag::RETRIEVE_RESULTS_COUNT, count));
        self.span
            .set_attribute(KeyValue::new(rag::RETRIEVE_MIN_SCORE, min_score));
        self.span
            .set_attribute(KeyValue::new(rag::RETRIEVE_MAX_SCORE, max_score));
    }

    /// Records the embedding model used for the retrieval.
    pub fn set_embedding_model(&mut self, model: &str) {
        self.span
            .set_attribute(KeyValue::new(EMBEDDING_MODEL_KEY, model.to_string()));
    }

    /// Completes the retrieval span.
    pub fn end<E: std::fmt::Display>(mut self, result: Result<(), E>) {
        match result {
            Ok(()) => self.span.set_status(Status::Ok),
            Err(e) => self.span.set_status(Status::error(e.to_string())),
        }
        self.span.end();
    }

    /// Returns a mutable reference to the underlying span.
    pub fn span_mut(&mut self) -> &mut S {
        &mut self.span
    }
}
