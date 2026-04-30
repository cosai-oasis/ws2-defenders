"""AITF Cohere Command Integration.

Provides auto-instrumentation for the Cohere Command family of models,
wrapping ``cohere.Client().chat()`` and ``cohere.Client().generate()`` with
OpenTelemetry tracing and AITF semantic conventions.
"""

from __future__ import annotations

from integrations.cohere.command.instrumentor import CohereCommandInstrumentor

__all__ = ["CohereCommandInstrumentor"]
