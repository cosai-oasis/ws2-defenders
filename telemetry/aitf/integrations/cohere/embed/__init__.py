"""AITF Cohere Embed Integration.

Provides auto-instrumentation for Cohere's embedding endpoint,
wrapping ``cohere.Client().embed()`` with OpenTelemetry tracing and AITF
semantic conventions. Tracks embedding dimensions, input types, and
truncation behavior.
"""

from __future__ import annotations

from integrations.cohere.embed.instrumentor import CohereEmbedInstrumentor

__all__ = ["CohereEmbedInstrumentor"]
