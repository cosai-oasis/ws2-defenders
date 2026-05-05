"""AITF Google AI Integration Package.

Provides AITF telemetry instrumentation for Google AI services:

- **Gemini**: Wraps the ``google-generativeai`` Python SDK to instrument
  ``GenerativeModel.generate_content()``, ``generate_content_async()``,
  and ``count_tokens()`` with full support for streaming, function calling,
  multimodal inputs, safety settings, and grounding.

- **Vertex AI**: Wraps the ``google-cloud-aiplatform`` SDK to instrument
  ``vertexai.generative_models.GenerativeModel``, model deployment,
  batch prediction, model evaluation, and feature store operations.

Usage::

    from aitf.integrations.google_ai.gemini import GeminiInstrumentor
    from aitf.integrations.google_ai.vertex_ai import VertexAIInstrumentor

    # Instrument the Gemini SDK
    gemini_instrumentor = GeminiInstrumentor()
    gemini_instrumentor.instrument()

    # Instrument the Vertex AI SDK
    vertex_instrumentor = VertexAIInstrumentor()
    vertex_instrumentor.instrument()

    # Use the SDKs as normal -- telemetry is captured automatically
    import google.generativeai as genai
    model = genai.GenerativeModel("gemini-2.0-flash")
    response = model.generate_content("Explain quantum computing")

    # To remove instrumentation
    gemini_instrumentor.uninstrument()
    vertex_instrumentor.uninstrument()
"""

from __future__ import annotations

from aitf.integrations.google_ai.gemini.instrumentor import GeminiInstrumentor
from aitf.integrations.google_ai.vertex_ai.instrumentor import VertexAIInstrumentor

__all__ = [
    "GeminiInstrumentor",
    "VertexAIInstrumentor",
]
