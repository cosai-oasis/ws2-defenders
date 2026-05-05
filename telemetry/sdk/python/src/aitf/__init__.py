"""AITF - AI Telemetry Framework.

A comprehensive, security-first telemetry framework for AI systems
built on OpenTelemetry and OCSF.  AITF supports dual-pipeline export:
spans flow simultaneously to OTel backends (via OTLP) and SIEM/XDR
(via OCSF), giving you observability **and** security from the same
instrumentation.
"""

__version__ = "1.0.0"

from aitf.instrumentation import AITFInstrumentor
from aitf.generators import AIBOMGenerator
from aitf.pipeline import (
    DualPipelineProvider,
    create_dual_pipeline_provider,
    create_ocsf_only_provider,
    create_otel_only_provider,
)

__all__ = [
    "AITFInstrumentor",
    "AIBOMGenerator",
    "DualPipelineProvider",
    "create_dual_pipeline_provider",
    "create_ocsf_only_provider",
    "create_otel_only_provider",
    "__version__",
]
