"""AITF integration for Claude Code CLI / Agent SDK.

This sub-package provides :class:`ClaudeCodeInstrumentor`, which instruments
Claude Code agent sessions, tool invocations, and MCP server connections
with AITF-compatible OpenTelemetry spans.

Usage::

    from integrations.anthropic.claude_code import ClaudeCodeInstrumentor

    ClaudeCodeInstrumentor().instrument()
"""

from __future__ import annotations

from integrations.anthropic.claude_code.instrumentor import ClaudeCodeInstrumentor

__all__ = ["ClaudeCodeInstrumentor"]
