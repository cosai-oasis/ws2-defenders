"""AITF Pinecone Instrumentor.

Monkey-patches the ``pinecone`` Python SDK to automatically emit
OpenTelemetry spans with AITF RAG semantic conventions for every
vector database operation.

Instrumented methods:
    - ``Index.upsert()``  -- vector insertion / update
    - ``Index.query()``   -- similarity search
    - ``Index.delete()``  -- vector deletion
    - ``Index.fetch()``   -- vector retrieval by ID
    - ``Index.update()``  -- vector metadata update

Each span carries ``aitf.rag.retrieve.*`` attributes including vector
dimensions, namespace, top_k, filter metadata, and score distribution.

Usage::

    from integrations.vector_db.pinecone import PineconeInstrumentor

    # Instrument before creating any Pinecone clients
    instrumentor = PineconeInstrumentor()
    instrumentor.instrument()

    from pinecone import Pinecone
    pc = Pinecone(api_key="YOUR_KEY")
    index = pc.Index("my-index")

    # This query is now automatically traced with AITF spans:
    results = index.query(
        vector=[0.1, 0.2, 0.3],
        top_k=10,
        namespace="articles",
        filter={"category": "science"},
    )

    # Remove instrumentation when no longer needed:
    instrumentor.uninstrument()
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Collection

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import RAGAttributes

logger = logging.getLogger(__name__)

_TRACER_NAME = "integration.pinecone"

# ---------------------------------------------------------------------------
# Attribute keys specific to Pinecone that extend the base RAG conventions
# ---------------------------------------------------------------------------
_PINECONE_NAMESPACE = "rag.retrieve.namespace"
_PINECONE_VECTOR_DIMENSIONS = "rag.retrieve.vector_dimensions"
_PINECONE_VECTOR_COUNT = "rag.retrieve.vector_count"
_PINECONE_INCLUDE_VALUES = "rag.retrieve.include_values"
_PINECONE_INCLUDE_METADATA = "rag.retrieve.include_metadata"
_PINECONE_SCORE_MIN = "rag.retrieve.score_min"
_PINECONE_SCORE_MAX = "rag.retrieve.score_max"
_PINECONE_SCORE_MEAN = "rag.retrieve.score_mean"
_PINECONE_SPARSE_VECTOR = "rag.retrieve.sparse_vector"
_PINECONE_IDS = "rag.retrieve.ids"
_PINECONE_DELETE_ALL = "rag.retrieve.delete_all"
_PINECONE_UPSERTED_COUNT = "rag.retrieve.upserted_count"
_PINECONE_OPERATION = "rag.retrieve.operation"


class PineconeInstrumentor:
    """Instruments the ``pinecone`` Python SDK with AITF telemetry.

    Wraps ``Index.upsert()``, ``Index.query()``, ``Index.delete()``,
    ``Index.fetch()``, and ``Index.update()`` to emit OpenTelemetry spans
    enriched with RAG retrieval attributes.

    Args:
        tracer_provider: Optional ``TracerProvider`` to use. Falls back to the
            globally registered provider if not supplied.

    Example::

        from integrations.vector_db.pinecone import PineconeInstrumentor

        PineconeInstrumentor().instrument()
    """

    _PATCHED_METHODS: tuple[str, ...] = (
        "upsert",
        "query",
        "delete",
        "fetch",
        "update",
    )

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._originals: dict[str, Callable[..., Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Apply monkey-patches to the ``pinecone.Index`` class.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        if self._instrumented:
            logger.debug("PineconeInstrumentor is already active -- skipping.")
            return

        try:
            from pinecone import Index as PineconeIndex  # type: ignore[import-untyped]
        except ImportError:
            logger.warning(
                "The 'pinecone' package is not installed. "
                "Install it with: pip install pinecone"
            )
            return

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        for method_name in self._PATCHED_METHODS:
            original = getattr(PineconeIndex, method_name, None)
            if original is None:
                logger.debug("pinecone.Index.%s not found -- skipping.", method_name)
                continue
            self._originals[method_name] = original
            wrapper = self._make_wrapper(method_name, original)
            setattr(PineconeIndex, method_name, wrapper)

        self._instrumented = True
        logger.info("Pinecone instrumentation applied.")

    def uninstrument(self) -> None:
        """Remove all monkey-patches and restore original SDK behaviour."""
        if not self._instrumented:
            return

        try:
            from pinecone import Index as PineconeIndex  # type: ignore[import-untyped]
        except ImportError:
            return

        for method_name, original in self._originals.items():
            setattr(PineconeIndex, method_name, original)

        self._originals.clear()
        self._tracer = None
        self._instrumented = False
        logger.info("Pinecone instrumentation removed.")

    @property
    def is_instrumented(self) -> bool:
        """Return whether instrumentation is currently active."""
        return self._instrumented

    # ------------------------------------------------------------------
    # Internal: wrapper factory
    # ------------------------------------------------------------------

    def _make_wrapper(
        self, method_name: str, original: Callable[..., Any]
    ) -> Callable[..., Any]:
        """Return a traced wrapper for *method_name* that delegates to *original*."""
        tracer = self._tracer
        assert tracer is not None

        def wrapper(index_self: Any, *args: Any, **kwargs: Any) -> Any:
            index_name = getattr(index_self, "_name", None) or getattr(
                index_self, "name", "unknown"
            )
            span_name = f"pinecone.{method_name} {index_name}"
            attributes: dict[str, Any] = {
                _PINECONE_OPERATION: method_name,
                RAGAttributes.RETRIEVE_DATABASE: "pinecone",
                RAGAttributes.RETRIEVE_INDEX: str(index_name),
            }

            # ------- method-specific attribute extraction -------
            if method_name == "query":
                _extract_query_attrs(attributes, args, kwargs)
            elif method_name == "upsert":
                _extract_upsert_attrs(attributes, args, kwargs)
            elif method_name == "delete":
                _extract_delete_attrs(attributes, args, kwargs)
            elif method_name == "fetch":
                _extract_fetch_attrs(attributes, args, kwargs)
            elif method_name == "update":
                _extract_update_attrs(attributes, args, kwargs)

            span_kind = (
                SpanKind.CLIENT
                if method_name in ("query", "fetch")
                else SpanKind.CLIENT
            )

            start = time.monotonic()
            with tracer.start_as_current_span(
                name=span_name,
                kind=span_kind,
                attributes=attributes,
            ) as span:
                try:
                    result = original(index_self, *args, **kwargs)
                    elapsed_ms = (time.monotonic() - start) * 1000
                    span.set_attribute("latency.total_ms", elapsed_ms)

                    # Post-call enrichment
                    if method_name == "query":
                        _enrich_query_result(span, result)
                    elif method_name == "upsert":
                        _enrich_upsert_result(span, result)
                    elif method_name == "fetch":
                        _enrich_fetch_result(span, result)

                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    span.set_attribute("latency.total_ms", elapsed_ms)
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        # Preserve docstring and name for introspection
        wrapper.__name__ = original.__name__  # type: ignore[attr-defined]
        wrapper.__qualname__ = original.__qualname__  # type: ignore[attr-defined]
        wrapper.__doc__ = original.__doc__
        wrapper.__wrapped__ = original  # type: ignore[attr-defined]
        return wrapper


# ---------------------------------------------------------------------------
# Attribute extraction helpers
# ---------------------------------------------------------------------------


def _extract_query_attrs(
    attrs: dict[str, Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    """Extract query-specific attributes before the SDK call."""
    attrs[RAGAttributes.PIPELINE_STAGE] = RAGAttributes.Stage.RETRIEVE

    vector = kwargs.get("vector") or (args[0] if args else None)
    if vector is not None:
        try:
            attrs[_PINECONE_VECTOR_DIMENSIONS] = len(vector)
        except TypeError:
            pass

    top_k = kwargs.get("top_k")
    if top_k is not None:
        attrs[RAGAttributes.RETRIEVE_TOP_K] = int(top_k)

    namespace = kwargs.get("namespace")
    if namespace:
        attrs[_PINECONE_NAMESPACE] = str(namespace)

    filter_param = kwargs.get("filter")
    if filter_param is not None:
        try:
            attrs[RAGAttributes.RETRIEVE_FILTER] = json.dumps(
                filter_param, default=str
            )
        except (TypeError, ValueError):
            attrs[RAGAttributes.RETRIEVE_FILTER] = str(filter_param)

    include_values = kwargs.get("include_values")
    if include_values is not None:
        attrs[_PINECONE_INCLUDE_VALUES] = bool(include_values)

    include_metadata = kwargs.get("include_metadata")
    if include_metadata is not None:
        attrs[_PINECONE_INCLUDE_METADATA] = bool(include_metadata)

    sparse_vector = kwargs.get("sparse_vector")
    if sparse_vector is not None:
        attrs[_PINECONE_SPARSE_VECTOR] = True


def _extract_upsert_attrs(
    attrs: dict[str, Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    """Extract upsert-specific attributes."""
    vectors = kwargs.get("vectors") or (args[0] if args else None)
    if vectors is not None:
        try:
            attrs[_PINECONE_VECTOR_COUNT] = len(vectors)
            # Attempt to capture vector dimension from first vector
            first = vectors[0] if vectors else None
            if first is not None:
                if isinstance(first, dict):
                    vals = first.get("values")
                    if vals is not None:
                        attrs[_PINECONE_VECTOR_DIMENSIONS] = len(vals)
                elif isinstance(first, (list, tuple)) and len(first) >= 2:
                    # (id, values) or (id, values, metadata)
                    vals = first[1]
                    if hasattr(vals, "__len__"):
                        attrs[_PINECONE_VECTOR_DIMENSIONS] = len(vals)
        except (TypeError, IndexError, KeyError):
            pass

    namespace = kwargs.get("namespace")
    if namespace:
        attrs[_PINECONE_NAMESPACE] = str(namespace)


def _extract_delete_attrs(
    attrs: dict[str, Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    """Extract delete-specific attributes."""
    ids = kwargs.get("ids")
    if ids is not None:
        attrs[_PINECONE_VECTOR_COUNT] = len(ids)

    namespace = kwargs.get("namespace")
    if namespace:
        attrs[_PINECONE_NAMESPACE] = str(namespace)

    delete_all = kwargs.get("delete_all")
    if delete_all:
        attrs[_PINECONE_DELETE_ALL] = True

    filter_param = kwargs.get("filter")
    if filter_param is not None:
        try:
            attrs[RAGAttributes.RETRIEVE_FILTER] = json.dumps(
                filter_param, default=str
            )
        except (TypeError, ValueError):
            attrs[RAGAttributes.RETRIEVE_FILTER] = str(filter_param)


def _extract_fetch_attrs(
    attrs: dict[str, Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    """Extract fetch-specific attributes."""
    ids = kwargs.get("ids") or (args[0] if args else None)
    if ids is not None:
        try:
            attrs[_PINECONE_VECTOR_COUNT] = len(ids)
        except TypeError:
            pass

    namespace = kwargs.get("namespace")
    if namespace:
        attrs[_PINECONE_NAMESPACE] = str(namespace)


def _extract_update_attrs(
    attrs: dict[str, Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    """Extract update-specific attributes."""
    vector_id = kwargs.get("id") or (args[0] if args else None)
    if vector_id is not None:
        attrs[_PINECONE_IDS] = str(vector_id)

    namespace = kwargs.get("namespace")
    if namespace:
        attrs[_PINECONE_NAMESPACE] = str(namespace)

    values = kwargs.get("values")
    if values is not None:
        try:
            attrs[_PINECONE_VECTOR_DIMENSIONS] = len(values)
        except TypeError:
            pass


# ---------------------------------------------------------------------------
# Post-call result enrichment
# ---------------------------------------------------------------------------


def _enrich_query_result(span: trace.Span, result: Any) -> None:
    """Enrich the span with score distribution from query results."""
    if result is None:
        return

    matches = getattr(result, "matches", None)
    if matches is None:
        # Dict-style response
        if isinstance(result, dict):
            matches = result.get("matches", [])
        else:
            return

    if not matches:
        span.set_attribute(RAGAttributes.RETRIEVE_RESULTS_COUNT, 0)
        return

    span.set_attribute(RAGAttributes.RETRIEVE_RESULTS_COUNT, len(matches))

    scores: list[float] = []
    for match in matches:
        score = getattr(match, "score", None)
        if score is None and isinstance(match, dict):
            score = match.get("score")
        if score is not None:
            try:
                scores.append(float(score))
            except (TypeError, ValueError):
                pass

    if scores:
        span.set_attribute(RAGAttributes.RETRIEVE_MIN_SCORE, min(scores))
        span.set_attribute(RAGAttributes.RETRIEVE_MAX_SCORE, max(scores))
        span.set_attribute(_PINECONE_SCORE_MEAN, sum(scores) / len(scores))


def _enrich_upsert_result(span: trace.Span, result: Any) -> None:
    """Enrich the span with the upserted count from the response."""
    if result is None:
        return

    count = getattr(result, "upserted_count", None)
    if count is None and isinstance(result, dict):
        count = result.get("upserted_count")

    if count is not None:
        span.set_attribute(_PINECONE_UPSERTED_COUNT, int(count))


def _enrich_fetch_result(span: trace.Span, result: Any) -> None:
    """Enrich the span with the count of fetched vectors."""
    if result is None:
        return

    vectors = getattr(result, "vectors", None)
    if vectors is None and isinstance(result, dict):
        vectors = result.get("vectors", {})

    if vectors is not None:
        try:
            span.set_attribute(RAGAttributes.RETRIEVE_RESULTS_COUNT, len(vectors))
        except TypeError:
            pass
