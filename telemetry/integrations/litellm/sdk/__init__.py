"""AITF integration for the LiteLLM Python SDK.

Provides :class:`LiteLLMSDKInstrumentor`, which monkey-patches the
``litellm`` module to emit AITF-compatible OpenTelemetry spans for every
call to ``litellm.completion()``, ``litellm.acompletion()``, and
``litellm.embedding()``.

Usage::

    from integrations.litellm.sdk import LiteLLMSDKInstrumentor

    instrumentor = LiteLLMSDKInstrumentor()
    instrumentor.instrument()

    import litellm
    response = litellm.completion(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )
    # Spans are emitted with unified provider attribution.

    # To remove instrumentation:
    instrumentor.uninstrument()
"""

from __future__ import annotations

from integrations.litellm.sdk.instrumentor import LiteLLMSDKInstrumentor

__all__ = ["LiteLLMSDKInstrumentor"]
