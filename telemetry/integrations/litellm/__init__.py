"""AITF LiteLLM Integration.

Third-party integration modules that wrap the LiteLLM library with AITF
telemetry instrumentation. Provides auto-instrumentation for both the
LiteLLM Proxy Server and the LiteLLM Python SDK.

Subpackages:
    proxy -- Instruments LiteLLM Proxy Server routing decisions, model
             fallbacks, load balancing, budget tracking, rate limiting,
             and spend logging with AITF model-ops-level spans.
    sdk   -- Instruments LiteLLM SDK calls (``litellm.completion()``,
             ``litellm.acompletion()``, ``litellm.embedding()``) with
             unified LLM tracing across providers, including provider
             mapping, streaming, token counting, and cost calculation.

Usage::

    # --- LiteLLM SDK auto-instrumentation ---
    from integrations.litellm import LiteLLMSDKInstrumentor

    instrumentor = LiteLLMSDKInstrumentor()
    instrumentor.instrument()

    import litellm
    response = litellm.completion(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )
    # Spans are emitted automatically with provider attribution.

    # --- LiteLLM Proxy auto-instrumentation ---
    from integrations.litellm import LiteLLMProxyInstrumentor

    proxy_instrumentor = LiteLLMProxyInstrumentor()
    proxy_instrumentor.instrument()

    # To remove instrumentation:
    instrumentor.uninstrument()
    proxy_instrumentor.uninstrument()

These integrations emit OpenTelemetry spans using AITF semantic conventions
(``gen_ai.*`` and ``aitf.*`` attribute namespaces) and are designed to work
with any OpenTelemetry-compatible backend (Jaeger, OTLP, etc.).
"""

from __future__ import annotations

from integrations.litellm.proxy.instrumentor import LiteLLMProxyInstrumentor
from integrations.litellm.sdk.instrumentor import LiteLLMSDKInstrumentor

__all__ = [
    "LiteLLMProxyInstrumentor",
    "LiteLLMSDKInstrumentor",
]
