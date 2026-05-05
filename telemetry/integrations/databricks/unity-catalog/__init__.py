"""AITF Unity Catalog Integration.

Wraps Databricks Unity Catalog SDK with AITF telemetry instrumentation
for AI model registration, function registration, data lineage,
access control, and AI asset discovery.
"""

from __future__ import annotations

from integrations.databricks.unity_catalog.instrumentor import (
    UnityCatalogInstrumentor,
)

__all__ = ["UnityCatalogInstrumentor"]
