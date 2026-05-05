"""AITF NVIDIA Integration.

Third-party integration modules that wrap NVIDIA AI/ML SDKs with AITF
telemetry instrumentation. Provides auto-instrumentation for NVIDIA's
inference and training stack:

- **NIM** (NVIDIA Inference Microservices): Instruments the OpenAI-compatible
  NIM API for inference requests, model loading, GPU utilization tracking,
  batch inference, and health checks.

- **NeMo** (NVIDIA NeMo Framework): Instruments model training, fine-tuning,
  data preprocessing, model export, and evaluation workflows using the NeMo
  toolkit.

- **Triton** (NVIDIA Triton Inference Server): Instruments inference requests,
  model loading/unloading, dynamic batching, model ensembles, and
  health/readiness probes for Triton deployments.

Usage::

    from integrations.nvidia import (
        NIMInstrumentor,
        NeMoInstrumentor,
        TritonInstrumentor,
    )

    # Instrument NVIDIA NIM inference endpoints
    nim = NIMInstrumentor()
    nim.instrument()

    # Instrument NeMo training workflows
    nemo = NeMoInstrumentor()
    nemo.instrument()

    # Instrument Triton Inference Server
    triton = TritonInstrumentor()
    triton.instrument()

    # Later, to remove instrumentation:
    nim.uninstrument()
    nemo.uninstrument()
    triton.uninstrument()

These integrations emit OpenTelemetry spans using AITF semantic conventions
(``gen_ai.*`` and ``aitf.*`` attribute namespaces) and are designed to work
with any OpenTelemetry-compatible backend (Jaeger, OTLP, etc.).
"""

from __future__ import annotations

from integrations.nvidia.nemo.instrumentor import NeMoInstrumentor
from integrations.nvidia.nim.instrumentor import NIMInstrumentor
from integrations.nvidia.triton.instrumentor import TritonInstrumentor

__all__ = [
    "NIMInstrumentor",
    "NeMoInstrumentor",
    "TritonInstrumentor",
]
