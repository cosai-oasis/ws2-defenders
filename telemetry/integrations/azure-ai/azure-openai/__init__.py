"""AITF Azure OpenAI Integration.

Instruments the ``openai`` Python SDK when configured for Azure OpenAI Service
endpoints (``AzureOpenAI`` / ``AsyncAzureOpenAI`` clients). Captures chat
completion requests and responses with Azure-specific attributes such as
deployment name, API version, and content filtering results.

All spans are tagged with ``gen_ai.system = "azure"`` and include standard
GenAI semantic convention attributes alongside AITF cost and latency extensions.

Usage:
    from integrations.azure_ai.azure_openai import AzureOpenAIInstrumentor

    instrumentor = AzureOpenAIInstrumentor()
    instrumentor.instrument()

    # All subsequent AzureOpenAI().chat.completions.create() calls are traced.
"""

from __future__ import annotations

from integrations.azure_ai.azure_openai.instrumentor import AzureOpenAIInstrumentor

__all__ = [
    "AzureOpenAIInstrumentor",
]
