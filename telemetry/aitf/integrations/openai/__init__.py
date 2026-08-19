"""AITF OpenAI Integration.

Third-party integration modules that wrap the OpenAI Python SDK with AITF
telemetry instrumentation. Provides auto-instrumentation for both the GPT
(Chat Completions / Embeddings) API and the Assistants API.

Subpackages:
    gpt-api       -- Instruments ``openai.OpenAI().chat.completions.create()``,
                     ``openai.OpenAI().embeddings.create()``, and their async
                     counterparts with LLM-level spans (token counting, cost
                     tracking, streaming, function calling, structured outputs).
    assistants-api -- Instruments the OpenAI Assistants API (assistant creation,
                     thread management, runs, tool use, file search, code
                     interpreter) with AITF agent-level spans.

Usage::

    # --- GPT API auto-instrumentation ---
    from integrations.openai.gpt_api import OpenAIGPTInstrumentor

    instrumentor = OpenAIGPTInstrumentor()
    instrumentor.instrument()

    import openai
    client = openai.OpenAI()
    # All calls are now automatically traced:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )

    # --- Assistants API auto-instrumentation ---
    from integrations.openai.assistants_api import OpenAIAssistantsInstrumentor

    assistants_instrumentor = OpenAIAssistantsInstrumentor()
    assistants_instrumentor.instrument()

    assistant = client.beta.assistants.create(
        name="Math Tutor",
        model="gpt-4o",
        tools=[{"type": "code_interpreter"}],
    )  # automatically traced with agent spans
"""

from __future__ import annotations

# Re-export instrumentors at the package level for convenience.
# The sub-packages use hyphens on disk (``gpt-api``, ``assistants-api``)
# which are not valid Python identifiers, so they are importable via the
# helper aliases ``gpt_api`` and ``assistants_api`` set up here.
import importlib as _importlib
import sys as _sys
from pathlib import Path as _Path

# ---------------------------------------------------------------------------
# Make hyphenated sub-packages importable under underscore-based aliases.
# ``integrations.openai.gpt_api``  ->  integrations/openai/gpt-api/
# ``integrations.openai.assistants_api`` -> integrations/openai/assistants-api/
# ---------------------------------------------------------------------------
_PACKAGE_DIR = _Path(__file__).resolve().parent

_ALIAS_MAP: dict[str, str] = {
    "gpt_api": "gpt-api",
    "assistants_api": "assistants-api",
}


def __getattr__(name: str):
    """Lazy-load hyphenated sub-packages under their underscore aliases."""
    if name in _ALIAS_MAP:
        disk_name = _ALIAS_MAP[name]
        parent_fqn = __name__  # e.g. "integrations.openai"
        child_fqn = f"{parent_fqn}.{name}"
        disk_path = _PACKAGE_DIR / disk_name

        if child_fqn not in _sys.modules:
            spec = _importlib.util.spec_from_file_location(
                child_fqn,
                disk_path / "__init__.py",
                submodule_search_locations=[str(disk_path)],
            )
            if spec is None or spec.loader is None:
                raise ImportError(
                    f"Cannot find sub-package '{disk_name}' at {disk_path}"
                )
            module = _importlib.util.module_from_spec(spec)
            _sys.modules[child_fqn] = module
            spec.loader.exec_module(module)

        return _sys.modules[child_fqn]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "gpt_api",
    "assistants_api",
]
