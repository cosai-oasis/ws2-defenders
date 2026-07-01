"""AITF Cohere Integration.

Third-party integration modules that wrap Cohere's Python SDK with AITF
telemetry instrumentation. Provides auto-instrumentation for:

- **Command** (``cohere.Client().chat()`` / ``cohere.Client().generate()``):
  Instruments chat and text generation endpoints, including streaming
  responses, tool use, RAG with connectors, citation tracking, and
  token usage.

- **Embed** (``cohere.Client().embed()``): Instruments embedding requests
  with dimension tracking, input type classification, and truncation
  handling.

- **Rerank** (``cohere.Client().rerank()``): Instruments reranking requests
  with relevance score tracking, document counts, and top_n selection
  using ``aitf.rag.*`` semantic conventions.

Quick Start::

    from integrations.cohere import (
        CohereCommandInstrumentor,
        CohereEmbedInstrumentor,
        CohereRerankInstrumentor,
    )

    # Instrument Cohere Command (chat & generate)
    CohereCommandInstrumentor().instrument()

    # Instrument Cohere Embed
    CohereEmbedInstrumentor().instrument()

    # Instrument Cohere Rerank
    CohereRerankInstrumentor().instrument()

    # Later, to remove instrumentation:
    CohereCommandInstrumentor().uninstrument()
    CohereEmbedInstrumentor().uninstrument()
    CohereRerankInstrumentor().uninstrument()

These integrations emit OpenTelemetry spans using AITF semantic conventions
(``gen_ai.*`` and ``aitf.*`` attribute namespaces) and are designed to work
with any OpenTelemetry-compatible backend (Jaeger, OTLP, etc.).
"""

from __future__ import annotations

from integrations.cohere.command.instrumentor import CohereCommandInstrumentor
from integrations.cohere.embed.instrumentor import CohereEmbedInstrumentor
from integrations.cohere.rerank.instrumentor import CohereRerankInstrumentor

__all__ = [
    "CohereCommandInstrumentor",
    "CohereEmbedInstrumentor",
    "CohereRerankInstrumentor",
]
