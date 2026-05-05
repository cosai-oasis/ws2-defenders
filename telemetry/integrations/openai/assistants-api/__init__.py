"""AITF OpenAI Assistants API integration package.

Provides :class:`OpenAIAssistantsInstrumentor` which monkey-patches the
``openai`` Python SDK to automatically emit AITF/OpenTelemetry agent spans
for every Assistants API operation -- assistant creation, thread management,
run execution, tool use, file search, and code interpreter.

Usage::

    from integrations.openai.assistants_api import OpenAIAssistantsInstrumentor

    instrumentor = OpenAIAssistantsInstrumentor()
    instrumentor.instrument()

    import openai
    client = openai.OpenAI()

    # All Assistants API calls are now traced automatically.
    assistant = client.beta.assistants.create(
        name="Data Analyst",
        model="gpt-4o",
        tools=[{"type": "code_interpreter"}],
    )

    thread = client.beta.threads.create()
    client.beta.threads.messages.create(
        thread_id=thread.id,
        role="user",
        content="What is 2 + 2?",
    )
    run = client.beta.threads.runs.create_and_poll(
        thread_id=thread.id,
        assistant_id=assistant.id,
    )

    # To remove instrumentation:
    instrumentor.uninstrument()
"""

from __future__ import annotations

from integrations.openai.assistants_api.instrumentor import OpenAIAssistantsInstrumentor

__all__ = [
    "OpenAIAssistantsInstrumentor",
]
