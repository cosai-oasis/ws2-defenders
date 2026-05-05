"""AITF OpenRouter Integration.

Third-party integration module that wraps the OpenRouter API client with AITF
telemetry instrumentation. Provides auto-instrumentation for OpenRouter's
OpenAI-compatible API, capturing model routing decisions, provider attribution,
cost tracking, and latency metrics.

OpenRouter routes requests to 200+ models from multiple providers (Anthropic,
OpenAI, Google, Meta, Mistral, etc.) through a unified API.  This integration
captures routing metadata so you know which underlying provider and model
actually served each request.

Usage::

    from integrations.openrouter import OpenRouterInstrumentor

    instrumentor = OpenRouterInstrumentor()
    instrumentor.instrument()

    # All OpenRouter API calls are now traced with AITF semantic conventions.
    # To remove instrumentation:
    instrumentor.uninstrument()

These spans use AITF semantic conventions (``gen_ai.*`` and ``aitf.openrouter.*``
attribute namespaces) and are designed to work with the VendorMapper pipeline
for full OCSF event normalization.
"""

from __future__ import annotations

from integrations.openrouter.api.instrumentor import OpenRouterInstrumentor

__all__ = ["OpenRouterInstrumentor"]
