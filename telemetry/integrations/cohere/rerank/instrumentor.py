"""AITF Cohere Rerank Instrumentor.

Wraps ``cohere.Client().rerank()`` with OpenTelemetry tracing using AITF RAG
semantic conventions. Tracks relevance scores, document counts, and top_n
selection to provide observability into reranking stages of RAG pipelines.

Usage::

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    from integrations.cohere.rerank import CohereRerankInstrumentor

    instrumentor = CohereRerankInstrumentor(tracer_provider=provider)
    instrumentor.instrument()

    import cohere
    client = cohere.Client(api_key="...")

    # All rerank calls are now automatically traced:
    response = client.rerank(
        model="rerank-english-v3.0",
        query="What is deep learning?",
        documents=[
            "Deep learning is a subset of machine learning.",
            "Python is a programming language.",
            "Neural networks power deep learning systems.",
        ],
        top_n=2,
    )

    for result in response.results:
        print(f"Index: {result.index}, Score: {result.relevance_score}")

    # To remove instrumentation:
    instrumentor.uninstrument()

Attributes Emitted:
    - ``gen_ai.system`` = ``"cohere"``
    - ``gen_ai.request.model``
    - ``aitf.rag.pipeline.stage`` = ``"rerank"``
    - ``aitf.rag.query`` (the rerank query)
    - ``aitf.rag.rerank.model``
    - ``aitf.rag.rerank.input_count`` (number of documents submitted)
    - ``aitf.rag.rerank.output_count`` (number of results returned / top_n)
    - ``aitf.rag.retrieve.top_k`` (top_n parameter)
    - ``aitf.rag.retrieve.min_score`` (lowest relevance score in results)
    - ``aitf.rag.retrieve.max_score`` (highest relevance score in results)
    - ``aitf.cohere.rerank.return_documents`` (whether documents are returned)
    - ``aitf.cohere.rerank.max_chunks_per_doc`` (chunking parameter)
    - ``aitf.latency.*`` timing attributes
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import (
    GenAIAttributes,
    LatencyAttributes,
    RAGAttributes,
)

logger = logging.getLogger(__name__)

_TRACER_NAME = "aitf.integrations.cohere.rerank"

# Cohere Rerank-specific attribute keys
_COHERE_RERANK_RETURN_DOCUMENTS = "aitf.cohere.rerank.return_documents"
_COHERE_RERANK_MAX_CHUNKS_PER_DOC = "aitf.cohere.rerank.max_chunks_per_doc"


class CohereRerankInstrumentor:
    """Auto-instrumentor for the Cohere Rerank API.

    Monkey-patches ``cohere.Client.rerank`` to emit OpenTelemetry spans with
    AITF RAG semantic conventions (``aitf.rag.*``) for every reranking request.

    This instrumentor is designed to integrate with RAG pipeline telemetry,
    using the rerank stage attributes defined in the AITF specification.

    Args:
        tracer_provider: Optional OpenTelemetry TracerProvider. If not
            provided, the global TracerProvider is used.

    Example::

        instrumentor = CohereRerankInstrumentor()
        instrumentor.instrument()

        import cohere
        co = cohere.Client(api_key="YOUR_KEY")

        # Traced with aitf.rag.* attributes
        results = co.rerank(
            model="rerank-english-v3.0",
            query="machine learning",
            documents=["Doc 1 content", "Doc 2 content"],
            top_n=2,
        )

        instrumentor.uninstrument()
    """

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._original_rerank: Any = None

    @property
    def is_instrumented(self) -> bool:
        """Return whether instrumentation is currently active."""
        return self._instrumented

    def instrument(self) -> None:
        """Enable instrumentation by patching ``cohere.Client.rerank``.

        Raises:
            ImportError: If the ``cohere`` package is not installed.
        """
        if self._instrumented:
            logger.warning("CohereRerankInstrumentor is already instrumented.")
            return

        try:
            import cohere  # noqa: F811
        except ImportError as exc:
            raise ImportError(
                "The 'cohere' package is required for CohereRerankInstrumentor. "
                "Install it with: pip install cohere"
            ) from exc

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        # Preserve original method
        self._original_rerank = cohere.Client.rerank

        instrumentor = self

        def _instrumented_rerank(client_self: Any, *args: Any, **kwargs: Any) -> Any:
            return instrumentor._trace_rerank(client_self, args, kwargs)

        cohere.Client.rerank = _instrumented_rerank

        self._instrumented = True
        logger.info("CohereRerankInstrumentor instrumentation enabled.")

    def uninstrument(self) -> None:
        """Remove instrumentation and restore original ``cohere.Client.rerank``."""
        if not self._instrumented:
            logger.warning("CohereRerankInstrumentor is not currently instrumented.")
            return

        try:
            import cohere  # noqa: F811
        except ImportError:
            return

        if self._original_rerank is not None:
            cohere.Client.rerank = self._original_rerank

        self._original_rerank = None
        self._tracer = None
        self._instrumented = False
        logger.info("CohereRerankInstrumentor instrumentation disabled.")

    def _get_tracer(self) -> trace.Tracer:
        """Return the active tracer, initializing if needed."""
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    def _trace_rerank(
        self,
        client: Any,
        args: tuple,
        kwargs: dict[str, Any],
    ) -> Any:
        """Wrap a ``cohere.Client.rerank`` call with tracing."""
        tracer = self._get_tracer()

        model = kwargs.get("model", "rerank-english-v3.0")
        query = kwargs.get("query", "")
        documents = kwargs.get("documents", [])
        top_n = kwargs.get("top_n")
        return_documents = kwargs.get("return_documents")
        max_chunks_per_doc = kwargs.get("max_chunks_per_doc")

        input_count = len(documents) if documents else 0

        span_name = f"rag.rerank {model}"
        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: GenAIAttributes.System.COHERE,
            GenAIAttributes.REQUEST_MODEL: model,
            RAGAttributes.PIPELINE_STAGE: RAGAttributes.Stage.RERANK,
            RAGAttributes.RERANK_MODEL: model,
            RAGAttributes.RERANK_INPUT_COUNT: input_count,
        }

        if query:
            attributes[RAGAttributes.QUERY] = query

        if top_n is not None:
            attributes[RAGAttributes.RETRIEVE_TOP_K] = int(top_n)
            attributes[RAGAttributes.RERANK_OUTPUT_COUNT] = int(top_n)

        if return_documents is not None:
            attributes[_COHERE_RERANK_RETURN_DOCUMENTS] = bool(return_documents)

        if max_chunks_per_doc is not None:
            attributes[_COHERE_RERANK_MAX_CHUNKS_PER_DOC] = int(max_chunks_per_doc)

        start_time = time.monotonic()

        with tracer.start_as_current_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            try:
                response = self._original_rerank(client, *args, **kwargs)

                elapsed_ms = (time.monotonic() - start_time) * 1000
                span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

                self._record_rerank_response(span, response, top_n)

                span.set_status(StatusCode.OK)
                return response

            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    def _record_rerank_response(
        self,
        span: trace.Span,
        response: Any,
        requested_top_n: int | None,
    ) -> None:
        """Extract and record attributes from a Cohere rerank response."""
        if response is None:
            return

        # Response ID
        response_id = getattr(response, "id", None)
        if response_id:
            span.set_attribute(GenAIAttributes.RESPONSE_ID, str(response_id))

        # Token usage from meta
        meta = getattr(response, "meta", None)
        if meta is not None:
            billed_units = getattr(meta, "billed_units", None)
            if billed_units is not None:
                search_units = getattr(billed_units, "search_units", 0) or 0
                if search_units:
                    span.set_attribute("aitf.cohere.rerank.search_units", search_units)

        # Reranked results
        results = getattr(response, "results", None)
        if results and len(results) > 0:
            actual_output_count = len(results)
            span.set_attribute(RAGAttributes.RERANK_OUTPUT_COUNT, actual_output_count)

            # Compute relevance score statistics
            scores = []
            for result in results:
                score = getattr(result, "relevance_score", None)
                if score is not None:
                    scores.append(float(score))

            if scores:
                span.set_attribute(RAGAttributes.RETRIEVE_MIN_SCORE, min(scores))
                span.set_attribute(RAGAttributes.RETRIEVE_MAX_SCORE, max(scores))

            # Record individual result details as events
            for result in results:
                index = getattr(result, "index", None)
                score = getattr(result, "relevance_score", None)
                event_attrs: dict[str, Any] = {}
                if index is not None:
                    event_attrs["aitf.cohere.rerank.result.index"] = int(index)
                if score is not None:
                    event_attrs["aitf.cohere.rerank.result.relevance_score"] = float(
                        score
                    )
                # Include document text snippet if returned
                doc = getattr(result, "document", None)
                if doc is not None:
                    doc_text = getattr(doc, "text", None)
                    if doc_text:
                        # Truncate for span events to avoid excessive size
                        event_attrs["aitf.cohere.rerank.result.document_snippet"] = (
                            str(doc_text)[:500]
                        )
                span.add_event("aitf.cohere.rerank.result", attributes=event_attrs)
