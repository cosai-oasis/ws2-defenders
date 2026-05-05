"""AITF NVIDIA Triton Inference Server Integration.

Wraps the NVIDIA Triton Inference Server client SDK with AITF telemetry
instrumentation. Instruments inference requests, model loading/unloading,
dynamic batching, model ensembles, and health/readiness probes. Tracks
queue depth, batch size, and GPU utilization.

Usage::

    from integrations.nvidia.triton import TritonInstrumentor

    instrumentor = TritonInstrumentor()
    instrumentor.instrument()

    # All subsequent Triton client calls are traced automatically.
    # To remove instrumentation:
    instrumentor.uninstrument()
"""

from __future__ import annotations

from integrations.nvidia.triton.instrumentor import TritonInstrumentor

__all__ = ["TritonInstrumentor"]
