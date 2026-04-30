"""AITF Azure Machine Learning Integration.

Instruments the ``azure-ai-ml`` Python SDK for Azure Machine Learning model
operations. Provides telemetry spans for model deployment, online endpoint
invocation, batch endpoint submission, model registration, and managed
compute provisioning.

All spans carry ``aitf.model_ops.*`` attributes aligned with AITF semantic
conventions and link to the Azure ML workspace context.

Usage:
    from integrations.azure_ai.azure_ml import AzureMLInstrumentor

    instrumentor = AzureMLInstrumentor()
    instrumentor.instrument()

    # All subsequent MLClient operations are traced.
"""

from __future__ import annotations

from integrations.azure_ai.azure_ml.instrumentor import AzureMLInstrumentor

__all__ = [
    "AzureMLInstrumentor",
]
