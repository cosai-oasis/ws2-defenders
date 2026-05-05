"""AITF integration for the LiteLLM Proxy Server.

Provides :class:`LiteLLMProxyInstrumentor`, which hooks into the LiteLLM Proxy
to emit AITF-compatible OpenTelemetry spans for routing decisions, model
fallbacks, load balancing, budget tracking, rate limiting, and spend logging.

Usage::

    from integrations.litellm.proxy import LiteLLMProxyInstrumentor

    instrumentor = LiteLLMProxyInstrumentor()
    instrumentor.instrument()

    # All LiteLLM Proxy routing and management operations are now traced.
    # To remove instrumentation:
    instrumentor.uninstrument()
"""

from __future__ import annotations

from integrations.litellm.proxy.instrumentor import LiteLLMProxyInstrumentor

__all__ = ["LiteLLMProxyInstrumentor"]
