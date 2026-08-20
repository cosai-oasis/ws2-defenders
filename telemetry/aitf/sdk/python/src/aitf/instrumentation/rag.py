"""AITF RAG (Retrieval-Augmented Generation) Instrumentation.

Provides tracing for RAG pipeline stages: retrieval, reranking, generation,
and quality evaluation.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import GenAIAttributes, RAGAttributes

_TRACER_NAME = "instrumentation.rag"


class RAGInstrumentor:
    """Instrumentor for RAG pipeline operations."""

    def __init__(self, tracer_provider: TracerProvider | None = None):
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False

    def instrument(self) -> None:
        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)
        self._instrumented = True

    def uninstrument(self) -> None:
        self._tracer = None
        self._instrumented = False

    def get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    @contextmanager
    def trace_pipeline(
        self,
        pipeline_name: str,
        query: str | None = None,
    ) -> Generator[RAGPipeline, None, None]:
        """Trace a complete RAG pipeline execution."""
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            RAGAttributes.PIPELINE_NAME: pipeline_name,
        }
        if query:
            attributes[GenAIAttributes.RETRIEVAL_QUERY_TEXT] = query

        with tracer.start_as_current_span(
            name=f"rag.pipeline {pipeline_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            pipeline = RAGPipeline(span, tracer, pipeline_name)
            try:
                yield pipeline
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_retrieve(
        self,
        database: str,
        index: str | None = None,
        top_k: int = 10,
        query: str | None = None,
        embedding_model: str | None = None,
        filter_expr: str | None = None,
    ) -> Generator[RetrievalSpan, None, None]:
        """Trace a vector retrieval operation."""
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            RAGAttributes.PIPELINE_STAGE: RAGAttributes.Stage.RETRIEVE,
            GenAIAttributes.DATA_SOURCE_ID: database,
            GenAIAttributes.REQUEST_TOP_K: top_k,
        }
        if index:
            attributes[RAGAttributes.RETRIEVE_INDEX] = index
        if query:
            attributes[GenAIAttributes.RETRIEVAL_QUERY_TEXT] = query
        if embedding_model:
            attributes[GenAIAttributes.RETRIEVAL_QUERY_TEXT_EMBEDDING_MODEL] = embedding_model
        if filter_expr:
            attributes[RAGAttributes.RETRIEVE_FILTER] = filter_expr

        with tracer.start_as_current_span(
            name=f"rag.retrieve {database}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            retrieval = RetrievalSpan(span)
            try:
                yield retrieval
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_rerank(
        self,
        model: str,
        input_count: int | None = None,
    ) -> Generator[RerankSpan, None, None]:
        """Trace a reranking operation."""
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            RAGAttributes.PIPELINE_STAGE: RAGAttributes.Stage.RERANK,
            RAGAttributes.RERANK_MODEL: model,
        }
        if input_count is not None:
            attributes[RAGAttributes.RERANK_INPUT_COUNT] = input_count

        with tracer.start_as_current_span(
            name=f"rag.rerank {model}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            rerank = RerankSpan(span)
            try:
                yield rerank
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


class RAGPipeline:
    """Helper for managing RAG pipeline child spans."""

    def __init__(self, span: trace.Span, tracer: trace.Tracer, pipeline_name: str):
        self._span = span
        self._tracer = tracer
        self._pipeline_name = pipeline_name

    @property
    def span(self) -> trace.Span:
        return self._span

    @contextmanager
    def retrieve(
        self, database: str, top_k: int = 10, **kwargs: Any
    ) -> Generator[RetrievalSpan, None, None]:
        attributes: dict[str, Any] = {
            RAGAttributes.PIPELINE_STAGE: RAGAttributes.Stage.RETRIEVE,
            RAGAttributes.PIPELINE_NAME: self._pipeline_name,
            GenAIAttributes.DATA_SOURCE_ID: database,
            GenAIAttributes.REQUEST_TOP_K: top_k,
        }
        attributes.update(kwargs)
        with self._tracer.start_as_current_span(
            name=f"rag.retrieve {database}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            retrieval = RetrievalSpan(span)
            try:
                yield retrieval
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    @contextmanager
    def rerank(self, model: str, **kwargs: Any) -> Generator[RerankSpan, None, None]:
        attributes: dict[str, Any] = {
            RAGAttributes.PIPELINE_STAGE: RAGAttributes.Stage.RERANK,
            RAGAttributes.PIPELINE_NAME: self._pipeline_name,
            RAGAttributes.RERANK_MODEL: model,
        }
        attributes.update(kwargs)
        with self._tracer.start_as_current_span(
            name=f"rag.rerank {model}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            rerank = RerankSpan(span)
            try:
                yield rerank
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    def set_quality(
        self,
        context_relevance: float | None = None,
        answer_relevance: float | None = None,
        faithfulness: float | None = None,
        groundedness: float | None = None,
    ) -> None:
        if context_relevance is not None:
            self._span.set_attribute(RAGAttributes.QUALITY_CONTEXT_RELEVANCE, context_relevance)
        if answer_relevance is not None:
            self._span.set_attribute(RAGAttributes.QUALITY_ANSWER_RELEVANCE, answer_relevance)
        if faithfulness is not None:
            self._span.set_attribute(RAGAttributes.QUALITY_FAITHFULNESS, faithfulness)
        if groundedness is not None:
            self._span.set_attribute(RAGAttributes.QUALITY_GROUNDEDNESS, groundedness)


class RetrievalSpan:
    """Helper for retrieval span attributes."""

    def __init__(self, span: trace.Span):
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_results(
        self,
        count: int,
        min_score: float | None = None,
        max_score: float | None = None,
        docs_json: str | None = None,
    ) -> None:
        self._span.set_attribute(RAGAttributes.RETRIEVE_RESULTS_COUNT, count)
        if min_score is not None:
            self._span.set_attribute(RAGAttributes.RETRIEVE_MIN_SCORE, min_score)
        if max_score is not None:
            self._span.set_attribute(RAGAttributes.RETRIEVE_MAX_SCORE, max_score)
        if docs_json is not None:
            self._span.set_attribute(RAGAttributes.RETRIEVAL_DOCS, docs_json)

    def add_document(
        self,
        doc_id: str,
        score: float | None = None,
        provenance: str | None = None,
    ) -> None:
        """Record a retrieved document as a span event (CoSAI WS2: RAG_CONTEXT)."""
        attrs: dict[str, Any] = {RAGAttributes.DOC_ID: doc_id}
        if score is not None:
            attrs[RAGAttributes.DOC_SCORE] = score
        if provenance is not None:
            attrs[RAGAttributes.DOC_PROVENANCE] = provenance
        self._span.add_event("rag.doc.retrieved", attributes=attrs)


class RerankSpan:
    """Helper for rerank span attributes."""

    def __init__(self, span: trace.Span):
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_results(self, input_count: int, output_count: int) -> None:
        self._span.set_attribute(RAGAttributes.RERANK_INPUT_COUNT, input_count)
        self._span.set_attribute(RAGAttributes.RERANK_OUTPUT_COUNT, output_count)
