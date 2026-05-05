"""AITF Cohere Rerank Integration.

Provides auto-instrumentation for Cohere's reranking endpoint,
wrapping ``cohere.Client().rerank()`` with OpenTelemetry tracing and AITF
RAG semantic conventions. Tracks relevance scores, document counts, and
top_n selection.
"""

from __future__ import annotations

from integrations.cohere.rerank.instrumentor import CohereRerankInstrumentor

__all__ = ["CohereRerankInstrumentor"]
