"""AITF Pinecone Integration.

Third-party integration module that wraps the ``pinecone`` Python SDK with
AITF telemetry instrumentation for RAG pipeline observability.

Instruments ``Index.upsert()``, ``Index.query()``, ``Index.delete()``,
``Index.fetch()``, and ``Index.update()`` to emit OpenTelemetry spans with
``aitf.rag.*`` semantic convention attributes.

Usage::

    from integrations.vector_db.pinecone import PineconeInstrumentor

    instrumentor = PineconeInstrumentor()
    instrumentor.instrument()

    # All subsequent Pinecone Index operations are traced automatically.
    from pinecone import Pinecone
    pc = Pinecone(api_key="...")
    index = pc.Index("my-index")
    results = index.query(vector=[0.1, 0.2, ...], top_k=10)

    # To remove instrumentation:
    instrumentor.uninstrument()
"""

from __future__ import annotations

from integrations.vector_db.pinecone.instrumentor import PineconeInstrumentor

__all__ = ["PineconeInstrumentor"]
