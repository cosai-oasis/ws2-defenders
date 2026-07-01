"""AITF Anthropic Integration.

Third-party integration modules that wrap Anthropic's SDKs and tools with
AITF telemetry instrumentation. Provides auto-instrumentation for:

- **Claude API** (``anthropic`` Python SDK): Instruments ``messages.create()``
  for both sync and async clients, including streaming, tool use, token
  counting, and cost tracking.

- **Claude Code** (CLI / Agent SDK): Instruments agent sessions, tool
  invocations, and MCP server connections within Claude Code workflows.

Quick Start::

    from integrations.anthropic import AnthropicInstrumentor, ClaudeCodeInstrumentor

    # Instrument the anthropic Python SDK globally
    AnthropicInstrumentor().instrument()

    # Instrument Claude Code agent sessions
    ClaudeCodeInstrumentor().instrument()

    # Later, to remove instrumentation:
    AnthropicInstrumentor().uninstrument()
    ClaudeCodeInstrumentor().uninstrument()

These integrations emit OpenTelemetry spans using AITF semantic conventions
(``gen_ai.*`` and ``aitf.*`` attribute namespaces) and are designed to work
with any OpenTelemetry-compatible backend (Jaeger, OTLP, etc.).
"""

from __future__ import annotations

# SDK instrumentors require optional vendor packages; guard so the dependency-
# light Compliance API integration remains importable without them.
try:
    from integrations.anthropic.claude_api.instrumentor import AnthropicInstrumentor
    from integrations.anthropic.claude_code.instrumentor import ClaudeCodeInstrumentor
except ImportError:  # pragma: no cover - optional vendor SDKs not installed
    AnthropicInstrumentor = None  # type: ignore[assignment]
    ClaudeCodeInstrumentor = None  # type: ignore[assignment]

__all__ = [
    "AnthropicInstrumentor",
    "ClaudeCodeInstrumentor",
    "ClaudeComplianceMapper",
    "iter_activities",
]


def __getattr__(name: str):
    # Lazily expose the Compliance API integration without importing it (and
    # its aitf dependency) unless requested.
    if name in ("ClaudeComplianceMapper", "iter_activities"):
        from integrations.anthropic import compliance
        return getattr(compliance, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
