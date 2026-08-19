"""AITF Weaviate Integration.

Third-party integration module that wraps the ``weaviate-client`` Python SDK
with AITF telemetry instrumentation for RAG pipeline observability.

Instruments collection operations (vector search, hybrid search, keyword/BM25
search), batch imports, cross-references, and multi-tenancy operations to
emit OpenTelemetry spans with ``aitf.rag.*`` semantic convention attributes.

Usage::

    from integrations.vector_db.weaviate import WeaviateInstrumentor

    instrumentor = WeaviateInstrumentor()
    instrumentor.instrument()

    # All subsequent Weaviate collection operations are traced automatically.
    import weaviate
    client = weaviate.connect_to_local()
    collection = client.collections.get("Article")
    results = collection.query.near_vector(
        near_vector=[0.1, 0.2, ...],
        limit=10,
    )

    # To remove instrumentation:
    instrumentor.uninstrument()
"""

from __future__ import annotations

from integrations.vector_db.weaviate.instrumentor import WeaviateInstrumentor

__all__ = ["WeaviateInstrumentor"]
