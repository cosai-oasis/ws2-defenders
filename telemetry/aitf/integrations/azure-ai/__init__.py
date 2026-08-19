"""AITF Azure AI Integration Package.

Third-party integration modules that wrap Azure AI vendor SDKs with AITF
telemetry instrumentation. Provides auto-instrumentation for Azure OpenAI
Service and Azure Machine Learning operations.

Subpackages:
    azure-openai: Instruments the ``openai`` Python SDK configured for
        Azure OpenAI Service endpoints (``AzureOpenAI`` client).
    azure-ml: Instruments the ``azure-ai-ml`` SDK for Azure Machine
        Learning model operations (deployment, endpoints, registry,
        managed compute).

Usage:
    # Instrument Azure OpenAI chat completions
    from integrations.azure_ai.azure_openai import AzureOpenAIInstrumentor

    instrumentor = AzureOpenAIInstrumentor()
    instrumentor.instrument()

    # Instrument Azure ML model operations
    from integrations.azure_ai.azure_ml import AzureMLInstrumentor

    instrumentor = AzureMLInstrumentor()
    instrumentor.instrument()
"""

from __future__ import annotations

from integrations.azure_ai.azure_openai.instrumentor import AzureOpenAIInstrumentor
from integrations.azure_ai.azure_ml.instrumentor import AzureMLInstrumentor

__all__ = [
    "AzureOpenAIInstrumentor",
    "AzureMLInstrumentor",
]
