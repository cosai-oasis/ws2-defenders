"""AITF Weaviate Instrumentor.

Monkey-patches the ``weaviate-client`` Python SDK (v4) to automatically emit
OpenTelemetry spans with AITF RAG semantic conventions for collection-level
operations.

Instrumented operations:
    - **Vector search**  -- ``collection.query.near_vector()``,
      ``collection.query.near_text()``, ``collection.query.near_object()``
    - **Hybrid search**  -- ``collection.query.hybrid()``
    - **Keyword search** -- ``collection.query.bm25()``
    - **Fetch by ID**    -- ``collection.query.fetch_object_by_id()``,
      ``collection.query.fetch_objects()``
    - **Batch imports**  -- ``collection.data.insert_many()``,
      ``collection.data.insert()``
    - **Data mutations**  -- ``collection.data.update()``,
      ``collection.data.delete_by_id()``, ``collection.data.delete_many()``
    - **Cross-references** -- ``collection.data.reference_add()``,
      ``collection.data.reference_delete()``
    - **Aggregations**   -- ``collection.aggregate.over_all()``,
      ``collection.aggregate.near_vector()``

Each span carries ``aitf.rag.retrieve.*`` attributes including search type,
consistency level, replication factor, collection name, and result count.

Usage::

    from integrations.vector_db.weaviate import WeaviateInstrumentor

    # Instrument before creating any Weaviate clients
    instrumentor = WeaviateInstrumentor()
    instrumentor.instrument()

    import weaviate
    client = weaviate.connect_to_local()
    collection = client.collections.get("Article")

    # This hybrid search is now automatically traced with AITF spans:
    results = collection.query.hybrid(
        query="machine learning",
        alpha=0.5,
        limit=10,
    )

    # Remove instrumentation when no longer needed:
    instrumentor.uninstrument()
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import RAGAttributes

logger = logging.getLogger(__name__)

_TRACER_NAME = "integration.weaviate"

# ---------------------------------------------------------------------------
# Extended attribute keys specific to Weaviate
# ---------------------------------------------------------------------------
_WEAVIATE_COLLECTION = "rag.retrieve.collection"
_WEAVIATE_SEARCH_TYPE = "rag.retrieve.search_type"
_WEAVIATE_CONSISTENCY_LEVEL = "rag.retrieve.consistency_level"
_WEAVIATE_REPLICATION_FACTOR = "rag.retrieve.replication_factor"
_WEAVIATE_TENANT = "rag.retrieve.tenant"
_WEAVIATE_ALPHA = "rag.retrieve.hybrid_alpha"
_WEAVIATE_FUSION_TYPE = "rag.retrieve.fusion_type"
_WEAVIATE_VECTOR_DISTANCE = "rag.retrieve.vector_distance"
_WEAVIATE_CERTAINTY = "rag.retrieve.certainty"
_WEAVIATE_AUTOCUT = "rag.retrieve.autocut"
_WEAVIATE_QUERY_TEXT = "rag.retrieve.query_text"
_WEAVIATE_OPERATION = "rag.retrieve.operation"
_WEAVIATE_OBJECT_COUNT = "rag.retrieve.object_count"
_WEAVIATE_BATCH_SIZE = "rag.retrieve.batch_size"
_WEAVIATE_BATCH_ERRORS = "rag.retrieve.batch_errors"
_WEAVIATE_GROUP_BY = "rag.retrieve.group_by"
_WEAVIATE_RETURN_PROPERTIES = "rag.retrieve.return_properties"
_WEAVIATE_RETURN_REFERENCES = "rag.retrieve.return_references"
_WEAVIATE_FILTERS = "rag.retrieve.where_filter"


class WeaviateInstrumentor:
    """Instruments the ``weaviate-client`` Python SDK with AITF telemetry.

    Wraps query, data, and aggregate methods on Weaviate v4 collection
    objects to emit OpenTelemetry spans enriched with RAG retrieval
    attributes.

    Args:
        tracer_provider: Optional ``TracerProvider`` to use. Falls back to the
            globally registered provider if not supplied.

    Example::

        from integrations.vector_db.weaviate import WeaviateInstrumentor

        WeaviateInstrumentor().instrument()
    """

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._originals: dict[str, dict[str, Callable[..., Any]]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Apply monkey-patches to Weaviate collection query/data classes.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        if self._instrumented:
            logger.debug("WeaviateInstrumentor is already active -- skipping.")
            return

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        self._patch_query_methods()
        self._patch_data_methods()
        self._patch_aggregate_methods()

        self._instrumented = True
        logger.info("Weaviate instrumentation applied.")

    def uninstrument(self) -> None:
        """Remove all monkey-patches and restore original SDK behaviour."""
        if not self._instrumented:
            return

        for class_key, methods in self._originals.items():
            cls = self._resolve_class(class_key)
            if cls is None:
                continue
            for method_name, original in methods.items():
                setattr(cls, method_name, original)

        self._originals.clear()
        self._tracer = None
        self._instrumented = False
        logger.info("Weaviate instrumentation removed.")

    @property
    def is_instrumented(self) -> bool:
        """Return whether instrumentation is currently active."""
        return self._instrumented

    # ------------------------------------------------------------------
    # Internal: class resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_class(class_key: str) -> Any | None:
        """Resolve a dotted class key to the actual class object."""
        try:
            parts = class_key.rsplit(".", 1)
            module_path, class_name = parts[0], parts[1]
            import importlib

            mod = importlib.import_module(module_path)
            return getattr(mod, class_name, None)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Internal: patching groups
    # ------------------------------------------------------------------

    def _patch_query_methods(self) -> None:
        """Patch collection query methods (vector, hybrid, keyword search)."""
        try:
            from weaviate.collections.queries.near_vector import (  # type: ignore[import-untyped]
                _NearVectorQuery,
            )
        except ImportError:
            logger.debug("Weaviate query classes not found -- skipping query patches.")
            return

        query_patches: list[tuple[str, str, str]] = [
            # (module.Class, method_name, search_type)
            (
                "weaviate.collections.queries.near_vector._NearVectorQuery",
                "near_vector",
                "vector",
            ),
        ]

        # Attempt to import each query class and patch it
        _QUERY_CLASS_MAP: dict[str, list[tuple[str, str]]] = {
            "weaviate.collections.queries.near_vector._NearVectorQuery": [
                ("near_vector", "vector"),
            ],
            "weaviate.collections.queries.near_text._NearTextQuery": [
                ("near_text", "vector_text"),
            ],
            "weaviate.collections.queries.near_object._NearObjectQuery": [
                ("near_object", "vector_object"),
            ],
            "weaviate.collections.queries.hybrid._HybridQuery": [
                ("hybrid", "hybrid"),
            ],
            "weaviate.collections.queries.bm25._BM25Query": [
                ("bm25", "keyword"),
            ],
            "weaviate.collections.queries.fetch_object_by_id._FetchObjectByIDQuery": [
                ("fetch_object_by_id", "fetch"),
            ],
            "weaviate.collections.queries.fetch_objects._FetchObjectsQuery": [
                ("fetch_objects", "fetch"),
            ],
        }

        for class_key, method_list in _QUERY_CLASS_MAP.items():
            cls = self._resolve_class(class_key)
            if cls is None:
                continue
            if class_key not in self._originals:
                self._originals[class_key] = {}
            for method_name, search_type in method_list:
                original = getattr(cls, method_name, None)
                if original is None:
                    continue
                self._originals[class_key][method_name] = original
                wrapper = self._make_query_wrapper(method_name, search_type, original)
                setattr(cls, method_name, wrapper)

    def _patch_data_methods(self) -> None:
        """Patch collection data methods (CRUD, batch, cross-references)."""
        _DATA_CLASS_MAP: dict[str, list[tuple[str, str]]] = {
            "weaviate.collections.data._DataCollection": [
                ("insert", "insert"),
                ("insert_many", "batch_insert"),
                ("update", "update"),
                ("delete_by_id", "delete"),
                ("delete_many", "batch_delete"),
                ("reference_add", "reference_add"),
                ("reference_delete", "reference_delete"),
            ],
        }

        for class_key, method_list in _DATA_CLASS_MAP.items():
            cls = self._resolve_class(class_key)
            if cls is None:
                continue
            if class_key not in self._originals:
                self._originals[class_key] = {}
            for method_name, operation in method_list:
                original = getattr(cls, method_name, None)
                if original is None:
                    continue
                self._originals[class_key][method_name] = original
                wrapper = self._make_data_wrapper(method_name, operation, original)
                setattr(cls, method_name, wrapper)

    def _patch_aggregate_methods(self) -> None:
        """Patch collection aggregate methods."""
        _AGG_CLASS_MAP: dict[str, list[tuple[str, str]]] = {
            "weaviate.collections.aggregations._Aggregate": [
                ("over_all", "aggregate"),
                ("near_vector", "aggregate_vector"),
                ("near_text", "aggregate_text"),
            ],
        }

        for class_key, method_list in _AGG_CLASS_MAP.items():
            cls = self._resolve_class(class_key)
            if cls is None:
                continue
            if class_key not in self._originals:
                self._originals[class_key] = {}
            for method_name, operation in method_list:
                original = getattr(cls, method_name, None)
                if original is None:
                    continue
                self._originals[class_key][method_name] = original
                wrapper = self._make_aggregate_wrapper(
                    method_name, operation, original
                )
                setattr(cls, method_name, wrapper)

    # ------------------------------------------------------------------
    # Internal: wrapper factories
    # ------------------------------------------------------------------

    def _make_query_wrapper(
        self,
        method_name: str,
        search_type: str,
        original: Callable[..., Any],
    ) -> Callable[..., Any]:
        """Return a traced wrapper for a query method."""
        tracer = self._tracer
        assert tracer is not None

        def wrapper(query_self: Any, *args: Any, **kwargs: Any) -> Any:
            collection_name = _get_collection_name(query_self)
            span_name = f"weaviate.query.{method_name} {collection_name}"

            attributes: dict[str, Any] = {
                _WEAVIATE_OPERATION: f"query.{method_name}",
                _WEAVIATE_SEARCH_TYPE: search_type,
                RAGAttributes.RETRIEVE_DATABASE: "weaviate",
                RAGAttributes.PIPELINE_STAGE: RAGAttributes.Stage.RETRIEVE,
            }
            if collection_name:
                attributes[_WEAVIATE_COLLECTION] = collection_name
                attributes[RAGAttributes.RETRIEVE_INDEX] = collection_name

            _extract_query_kwargs(attributes, kwargs, search_type)

            start = time.monotonic()
            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(query_self, *args, **kwargs)
                    elapsed_ms = (time.monotonic() - start) * 1000
                    span.set_attribute("latency.total_ms", elapsed_ms)
                    _enrich_query_result(span, result)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    span.set_attribute("latency.total_ms", elapsed_ms)
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        wrapper.__name__ = original.__name__  # type: ignore[attr-defined]
        wrapper.__qualname__ = original.__qualname__  # type: ignore[attr-defined]
        wrapper.__doc__ = original.__doc__
        wrapper.__wrapped__ = original  # type: ignore[attr-defined]
        return wrapper

    def _make_data_wrapper(
        self,
        method_name: str,
        operation: str,
        original: Callable[..., Any],
    ) -> Callable[..., Any]:
        """Return a traced wrapper for a data mutation method."""
        tracer = self._tracer
        assert tracer is not None

        def wrapper(data_self: Any, *args: Any, **kwargs: Any) -> Any:
            collection_name = _get_collection_name(data_self)
            span_name = f"weaviate.data.{method_name} {collection_name}"

            attributes: dict[str, Any] = {
                _WEAVIATE_OPERATION: f"data.{method_name}",
                RAGAttributes.RETRIEVE_DATABASE: "weaviate",
            }
            if collection_name:
                attributes[_WEAVIATE_COLLECTION] = collection_name
                attributes[RAGAttributes.RETRIEVE_INDEX] = collection_name

            _extract_data_kwargs(attributes, kwargs, operation)

            start = time.monotonic()
            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(data_self, *args, **kwargs)
                    elapsed_ms = (time.monotonic() - start) * 1000
                    span.set_attribute("latency.total_ms", elapsed_ms)
                    _enrich_data_result(span, result, operation)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    span.set_attribute("latency.total_ms", elapsed_ms)
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        wrapper.__name__ = original.__name__  # type: ignore[attr-defined]
        wrapper.__qualname__ = original.__qualname__  # type: ignore[attr-defined]
        wrapper.__doc__ = original.__doc__
        wrapper.__wrapped__ = original  # type: ignore[attr-defined]
        return wrapper

    def _make_aggregate_wrapper(
        self,
        method_name: str,
        operation: str,
        original: Callable[..., Any],
    ) -> Callable[..., Any]:
        """Return a traced wrapper for an aggregate method."""
        tracer = self._tracer
        assert tracer is not None

        def wrapper(agg_self: Any, *args: Any, **kwargs: Any) -> Any:
            collection_name = _get_collection_name(agg_self)
            span_name = f"weaviate.aggregate.{method_name} {collection_name}"

            attributes: dict[str, Any] = {
                _WEAVIATE_OPERATION: f"aggregate.{method_name}",
                RAGAttributes.RETRIEVE_DATABASE: "weaviate",
            }
            if collection_name:
                attributes[_WEAVIATE_COLLECTION] = collection_name
                attributes[RAGAttributes.RETRIEVE_INDEX] = collection_name

            start = time.monotonic()
            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(agg_self, *args, **kwargs)
                    elapsed_ms = (time.monotonic() - start) * 1000
                    span.set_attribute("latency.total_ms", elapsed_ms)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    span.set_attribute("latency.total_ms", elapsed_ms)
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        wrapper.__name__ = original.__name__  # type: ignore[attr-defined]
        wrapper.__qualname__ = original.__qualname__  # type: ignore[attr-defined]
        wrapper.__doc__ = original.__doc__
        wrapper.__wrapped__ = original  # type: ignore[attr-defined]
        return wrapper


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_collection_name(obj: Any) -> str:
    """Attempt to extract the collection name from a Weaviate sub-object."""
    # Weaviate v4 sub-objects (query, data, aggregate) store a back-reference
    # to the collection on ``_collection`` or ``_name``.
    for attr in ("_name", "name", "_collection_name"):
        val = getattr(obj, attr, None)
        if isinstance(val, str) and val:
            return val

    # Walk up to the parent collection object if available
    collection = getattr(obj, "_collection", None)
    if collection is not None:
        for attr in ("name", "_name"):
            val = getattr(collection, attr, None)
            if isinstance(val, str) and val:
                return val

    return "unknown"


def _extract_query_kwargs(
    attrs: dict[str, Any],
    kwargs: dict[str, Any],
    search_type: str,
) -> None:
    """Extract query-method keyword arguments into span attributes."""
    limit = kwargs.get("limit")
    if limit is not None:
        attrs[RAGAttributes.RETRIEVE_TOP_K] = int(limit)

    # Hybrid-specific
    if search_type == "hybrid":
        alpha = kwargs.get("alpha")
        if alpha is not None:
            attrs[_WEAVIATE_ALPHA] = float(alpha)
        fusion_type = kwargs.get("fusion_type")
        if fusion_type is not None:
            attrs[_WEAVIATE_FUSION_TYPE] = str(fusion_type)

    query = kwargs.get("query")
    if query is not None:
        attrs[RAGAttributes.QUERY] = str(query)

    near_vector = kwargs.get("near_vector")
    if near_vector is not None:
        try:
            attrs["rag.retrieve.vector_dimensions"] = len(near_vector)
        except TypeError:
            pass

    certainty = kwargs.get("certainty")
    if certainty is not None:
        attrs[_WEAVIATE_CERTAINTY] = float(certainty)

    distance = kwargs.get("distance")
    if distance is not None:
        attrs[_WEAVIATE_VECTOR_DISTANCE] = float(distance)

    autocut = kwargs.get("auto_limit") or kwargs.get("autocut")
    if autocut is not None:
        attrs[_WEAVIATE_AUTOCUT] = int(autocut)

    filters = kwargs.get("filters")
    if filters is not None:
        try:
            attrs[_WEAVIATE_FILTERS] = str(filters)
        except Exception:
            pass

    group_by = kwargs.get("group_by")
    if group_by is not None:
        attrs[_WEAVIATE_GROUP_BY] = str(group_by)

    return_properties = kwargs.get("return_properties")
    if return_properties is not None:
        try:
            attrs[_WEAVIATE_RETURN_PROPERTIES] = json.dumps(
                [str(p) for p in return_properties]
            )
        except (TypeError, ValueError):
            attrs[_WEAVIATE_RETURN_PROPERTIES] = str(return_properties)

    return_references = kwargs.get("return_references")
    if return_references is not None:
        attrs[_WEAVIATE_RETURN_REFERENCES] = True

    tenant = kwargs.get("tenant")
    if tenant is not None:
        attrs[_WEAVIATE_TENANT] = str(tenant)


def _extract_data_kwargs(
    attrs: dict[str, Any],
    kwargs: dict[str, Any],
    operation: str,
) -> None:
    """Extract data-method keyword arguments into span attributes."""
    tenant = kwargs.get("tenant")
    if tenant is not None:
        attrs[_WEAVIATE_TENANT] = str(tenant)

    if operation == "batch_insert":
        objects = kwargs.get("objects")
        if objects is not None:
            try:
                attrs[_WEAVIATE_BATCH_SIZE] = len(objects)
            except TypeError:
                pass

    if operation == "batch_delete":
        where = kwargs.get("where")
        if where is not None:
            attrs[_WEAVIATE_FILTERS] = str(where)


def _enrich_query_result(span: trace.Span, result: Any) -> None:
    """Enrich span with query result metadata."""
    if result is None:
        return

    objects = getattr(result, "objects", None)
    if objects is not None:
        span.set_attribute(RAGAttributes.RETRIEVE_RESULTS_COUNT, len(objects))

        # Extract distance/certainty distribution
        distances: list[float] = []
        for obj in objects:
            metadata = getattr(obj, "metadata", None)
            if metadata is not None:
                dist = getattr(metadata, "distance", None)
                if dist is not None:
                    try:
                        distances.append(float(dist))
                    except (TypeError, ValueError):
                        pass
                certainty = getattr(metadata, "certainty", None)
                if certainty is not None and not distances:
                    try:
                        distances.append(float(certainty))
                    except (TypeError, ValueError):
                        pass

        if distances:
            span.set_attribute(RAGAttributes.RETRIEVE_MIN_SCORE, min(distances))
            span.set_attribute(RAGAttributes.RETRIEVE_MAX_SCORE, max(distances))


def _enrich_data_result(span: trace.Span, result: Any, operation: str) -> None:
    """Enrich span with data mutation result metadata."""
    if result is None:
        return

    if operation == "batch_insert":
        # insert_many returns a BatchResult with uuids and errors
        uuids = getattr(result, "uuids", None)
        if uuids is not None:
            try:
                span.set_attribute(_WEAVIATE_OBJECT_COUNT, len(uuids))
            except TypeError:
                pass
        errors = getattr(result, "errors", None)
        if errors:
            try:
                span.set_attribute(_WEAVIATE_BATCH_ERRORS, len(errors))
            except TypeError:
                pass

    elif operation == "batch_delete":
        # delete_many returns a DeleteResult with counts
        successful = getattr(result, "successful", None)
        if successful is not None:
            span.set_attribute(_WEAVIATE_OBJECT_COUNT, int(successful))
