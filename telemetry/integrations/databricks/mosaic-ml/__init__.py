"""AITF MosaicML Integration.

Wraps Databricks MosaicML Composer SDK with AITF telemetry instrumentation
for distributed training, FSDP, checkpointing, and evaluation.
"""

from __future__ import annotations

from integrations.databricks.mosaic_ml.instrumentor import MosaicMLInstrumentor

__all__ = ["MosaicMLInstrumentor"]
