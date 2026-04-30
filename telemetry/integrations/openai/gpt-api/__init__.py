"""AITF OpenAI GPT API integration package.

Provides :class:`OpenAIGPTInstrumentor` which monkey-patches the ``openai``
Python SDK to automatically emit AITF/OpenTelemetry spans for every call to
``chat.completions.create`` and ``embeddings.create`` (both sync and async).

Usage::

    from integrations.openai.gpt_api import OpenAIGPTInstrumentor

    instrumentor = OpenAIGPTInstrumentor()
    instrumentor.instrument()

    # All subsequent openai SDK calls are traced automatically.
    import openai
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello!"}],
    )

    # To remove instrumentation:
    instrumentor.uninstrument()
"""

from __future__ import annotations

from integrations.openai.gpt_api.instrumentor import OpenAIGPTInstrumentor

__all__ = [
    "OpenAIGPTInstrumentor",
]
