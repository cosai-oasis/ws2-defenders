"""AITF Gemini Integration Package.

Provides auto-instrumentation for the ``google-generativeai`` Python SDK,
capturing telemetry for content generation, token counting, streaming,
function calling, multimodal inputs, safety settings, and grounding.

Usage::

    from aitf.integrations.google_ai.gemini import GeminiInstrumentor

    instrumentor = GeminiInstrumentor()
    instrumentor.instrument()

    # All subsequent calls to genai.GenerativeModel are traced automatically.
"""

from __future__ import annotations

from aitf.integrations.google_ai.gemini.instrumentor import GeminiInstrumentor

__all__ = [
    "GeminiInstrumentor",
]
