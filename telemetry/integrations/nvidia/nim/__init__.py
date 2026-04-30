"""AITF NVIDIA NIM Integration.

Wraps the NVIDIA NIM (Inference Microservices) SDK with AITF telemetry
instrumentation. NIM exposes an OpenAI-compatible API endpoint, so this
module instruments chat completions, embeddings, model loading, GPU
utilization tracking, batch inference, and health-check operations.

Usage::

    from integrations.nvidia.nim import NIMInstrumentor

    instrumentor = NIMInstrumentor()
    instrumentor.instrument()

    # All subsequent NIM API calls are traced automatically.
    # To remove instrumentation:
    instrumentor.uninstrument()
"""

from __future__ import annotations

from integrations.nvidia.nim.instrumentor import NIMInstrumentor

__all__ = ["NIMInstrumentor"]
