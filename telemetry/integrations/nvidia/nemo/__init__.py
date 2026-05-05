"""AITF NVIDIA NeMo Integration.

Wraps the NVIDIA NeMo framework with AITF telemetry instrumentation for
model training, fine-tuning, data preprocessing, model export, and
evaluation workflows. Tracks GPU memory, distributed training configuration,
and checkpoint management.

Usage::

    from integrations.nvidia.nemo import NeMoInstrumentor

    instrumentor = NeMoInstrumentor()
    instrumentor.instrument()

    # All subsequent NeMo training and evaluation calls are traced.
    # To remove instrumentation:
    instrumentor.uninstrument()
"""

from __future__ import annotations

from integrations.nvidia.nemo.instrumentor import NeMoInstrumentor

__all__ = ["NeMoInstrumentor"]
