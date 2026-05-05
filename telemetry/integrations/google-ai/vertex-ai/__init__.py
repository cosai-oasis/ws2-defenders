"""AITF Vertex AI Integration Package.

Provides auto-instrumentation for the ``google-cloud-aiplatform`` SDK,
capturing telemetry for generative model inference, model deployment,
batch prediction, model evaluation, and feature store operations.

Usage::

    from aitf.integrations.google_ai.vertex_ai import VertexAIInstrumentor

    instrumentor = VertexAIInstrumentor()
    instrumentor.instrument()

    # All subsequent Vertex AI SDK calls are traced automatically.
"""

from __future__ import annotations

from aitf.integrations.google_ai.vertex_ai.instrumentor import VertexAIInstrumentor

__all__ = [
    "VertexAIInstrumentor",
]
