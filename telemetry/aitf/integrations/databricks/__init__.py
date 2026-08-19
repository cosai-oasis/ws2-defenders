"""AITF Databricks Integration.

Third-party integration modules that wrap Databricks AI/ML SDKs with AITF
telemetry instrumentation. Provides unified observability across MLflow
experiment tracking, MosaicML distributed training, and Unity Catalog AI
asset management.

Submodules:
    mlflow          -- MLflow experiment tracking, model registry, and serving
    mosaic_ml       -- MosaicML Composer training, FSDP, and checkpointing
    unity_catalog   -- Unity Catalog model/function registration and lineage

Usage:
    from integrations.databricks.mlflow.instrumentor import MLflowInstrumentor
    from integrations.databricks.mosaic_ml.instrumentor import MosaicMLInstrumentor
    from integrations.databricks.unity_catalog.instrumentor import UnityCatalogInstrumentor

    # Instrument all Databricks integrations
    mlflow_inst = MLflowInstrumentor()
    mlflow_inst.instrument()

    mosaic_inst = MosaicMLInstrumentor()
    mosaic_inst.instrument()

    uc_inst = UnityCatalogInstrumentor()
    uc_inst.instrument()
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from integrations.databricks.mlflow.instrumentor import MLflowInstrumentor
    from integrations.databricks.unity_catalog.instrumentor import (
        UnityCatalogInstrumentor,
    )

__all__ = [
    "MLflowInstrumentor",
    "MosaicMLInstrumentor",
    "UnityCatalogInstrumentor",
]
