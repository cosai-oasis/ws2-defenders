"""AITF integration for the OpenRouter API.

Provides :class:`OpenRouterInstrumentor`, which monkey-patches the ``openai``
client when configured with an OpenRouter base URL to emit AITF-compatible
OpenTelemetry spans for every chat completion, capturing routing metadata,
provider attribution, cost, and latency.

Usage::

    from integrations.openrouter.api import OpenRouterInstrumentor

    instrumentor = OpenRouterInstrumentor()
    instrumentor.instrument()

    from openai import OpenAI
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key="sk-or-...",
    )
    response = client.chat.completions.create(
        model="anthropic/claude-sonnet-4-5-20250929",
        messages=[{"role": "user", "content": "Hello"}],
    )
    # Spans are emitted with provider routing and cost data.

    # To remove instrumentation:
    instrumentor.uninstrument()
"""

from __future__ import annotations

from integrations.openrouter.api.instrumentor import OpenRouterInstrumentor

__all__ = ["OpenRouterInstrumentor"]
