"""AITF integration for the Anthropic ``anthropic`` Python SDK.

This sub-package provides :class:`AnthropicInstrumentor`, which monkey-patches
the ``anthropic.Anthropic`` and ``anthropic.AsyncAnthropic`` clients to emit
AITF-compatible OpenTelemetry spans for every ``messages.create()`` call.

Usage::

    from integrations.anthropic.claude_api import AnthropicInstrumentor

    AnthropicInstrumentor().instrument()
"""

from __future__ import annotations

from integrations.anthropic.claude_api.instrumentor import AnthropicInstrumentor

__all__ = ["AnthropicInstrumentor"]
