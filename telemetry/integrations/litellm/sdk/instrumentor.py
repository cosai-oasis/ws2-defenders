"""AITF integration for the LiteLLM Python SDK.

Instruments the ``litellm`` module's top-level functions to emit
AITF-compatible OpenTelemetry spans for every LLM call:

- ``litellm.completion()`` / ``litellm.acompletion()`` — chat completions
- ``litellm.text_completion()`` / ``litellm.atext_completion()`` — text
- ``litellm.embedding()`` / ``litellm.aembedding()`` — embeddings

Captured attributes include:
- **Provider mapping**: LiteLLM's unified ``model`` parameter is split into
  the underlying provider (``gen_ai.system``) and model name.
- **Token usage**: Input, output, and total tokens.
- **Cost**: Per-request cost via ``litellm.completion_cost()``.
- **Streaming**: Whether the request used streaming.
- **Fallback/retry**: If LiteLLM's router retried or fell back.

Architecture
------------
The instrumentor monkey-patches ``litellm.completion``,
``litellm.acompletion``, ``litellm.embedding``, etc.  Each patched
function emits a span, calls the original, enriches the span with
response data, and re-raises any exceptions after recording them.
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import contextmanager
from functools import wraps
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import (
    CostAttributes,
    GenAIAttributes,
    LatencyAttributes,
)

logger = logging.getLogger(__name__)

_TRACER_NAME = "integration.litellm.sdk"

# ---------------------------------------------------------------------------
# Attribute constants specific to LiteLLM SDK telemetry
# ---------------------------------------------------------------------------

_LITELLM_PROVIDER = "litellm.provider"
_LITELLM_CUSTOM_LLM_PROVIDER = "litellm.custom_llm_provider"
_LITELLM_API_BASE = "litellm.api_base"
_LITELLM_CACHE_HIT = "litellm.cache_hit"
_LITELLM_RESPONSE_COST = "litellm.response_cost"

# LiteLLM provider prefixes (e.g., "openai/gpt-4o" → provider="openai")
_PROVIDER_PREFIXES = {
    "openai/": "openai",
    "anthropic/": "anthropic",
    "azure/": "azure",
    "google/": "google",
    "vertex_ai/": "google",
    "bedrock/": "aws",
    "cohere/": "cohere",
    "mistral/": "mistral",
    "deepseek/": "deepseek",
    "groq/": "groq",
    "together_ai/": "together",
    "anyscale/": "anyscale",
    "ollama/": "ollama",
    "huggingface/": "huggingface",
    "replicate/": "replicate",
    "sagemaker/": "aws",
}

# Models that imply a provider without a prefix
_MODEL_PROVIDER_HINTS: dict[str, str] = {
    "gpt-": "openai",
    "o1": "openai",
    "o3": "openai",
    "claude-": "anthropic",
    "gemini-": "google",
    "mistral-": "mistral",
    "command-": "cohere",
    "llama-": "meta",
}


def _detect_provider_and_model(model: str) -> tuple[str, str]:
    """Split a LiteLLM model string into (provider, model_name)."""
    for prefix, provider in _PROVIDER_PREFIXES.items():
        if model.startswith(prefix):
            return provider, model[len(prefix):]

    for hint, provider in _MODEL_PROVIDER_HINTS.items():
        if model.startswith(hint):
            return provider, model

    return "unknown", model


class LiteLLMSDKInstrumentor:
    """Instruments LiteLLM SDK calls with AITF telemetry.

    Parameters
    ----------
    tracer_provider : TracerProvider, optional
        Custom tracer provider. Uses the global provider if not specified.
    """

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._original_methods: dict[str, Any] = {}

    @property
    def is_instrumented(self) -> bool:
        return self._instrumented

    def get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            if self._tracer_provider:
                self._tracer = self._tracer_provider.get_tracer(_TRACER_NAME)
            else:
                self._tracer = trace.get_tracer(_TRACER_NAME)
        return self._tracer

    def instrument(self) -> None:
        """Enable auto-instrumentation by monkey-patching litellm functions."""
        if self._instrumented:
            logger.warning("LiteLLMSDKInstrumentor is already instrumented")
            return

        self._patch_completion()
        self._patch_embedding()
        self._instrumented = True
        logger.info("LiteLLM SDK instrumentation enabled")

    def uninstrument(self) -> None:
        """Remove all patches and restore original functions."""
        if not self._instrumented:
            return

        self._unpatch_all()
        self._instrumented = False
        logger.info("LiteLLM SDK instrumentation disabled")

    # -----------------------------------------------------------------
    # Context managers for manual instrumentation
    # -----------------------------------------------------------------

    @contextmanager
    def trace_completion(
        self,
        model: str,
        *,
        operation: str = "chat",
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream: bool = False,
    ) -> Generator[CompletionSpan, None, None]:
        """Manually trace a LiteLLM completion call."""
        tracer = self.get_tracer()
        provider, model_name = _detect_provider_and_model(model)

        span_name = f"litellm.{operation} {model}"
        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: provider,
            GenAIAttributes.REQUEST_MODEL: model_name,
            GenAIAttributes.OPERATION_NAME: operation,
            _LITELLM_PROVIDER: provider,
        }
        if temperature is not None:
            attributes[GenAIAttributes.REQUEST_TEMPERATURE] = temperature
        if max_tokens is not None:
            attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = max_tokens
        if stream:
            attributes[GenAIAttributes.REQUEST_STREAMING] = True

        with tracer.start_as_current_span(
            span_name, kind=SpanKind.CLIENT, attributes=attributes,
        ) as span:
            completion_span = CompletionSpan(span)
            try:
                yield completion_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_embedding(
        self,
        model: str,
    ) -> Generator[EmbeddingSpan, None, None]:
        """Manually trace a LiteLLM embedding call."""
        tracer = self.get_tracer()
        provider, model_name = _detect_provider_and_model(model)

        span_name = f"litellm.embedding {model}"
        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: provider,
            GenAIAttributes.REQUEST_MODEL: model_name,
            GenAIAttributes.OPERATION_NAME: "embeddings",
            _LITELLM_PROVIDER: provider,
        }

        with tracer.start_as_current_span(
            span_name, kind=SpanKind.CLIENT, attributes=attributes,
        ) as span:
            embedding_span = EmbeddingSpan(span)
            try:
                yield embedding_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # -----------------------------------------------------------------
    # Monkey-patching
    # -----------------------------------------------------------------

    def _patch_completion(self) -> None:
        """Patch ``litellm.completion`` and ``litellm.acompletion``."""
        try:
            import litellm
        except ImportError:
            logger.debug(
                "litellm package not installed; skipping patching. "
                "Install with: pip install litellm"
            )
            return

        # Sync completion
        if hasattr(litellm, "completion"):
            original = litellm.completion
            self._original_methods["litellm.completion"] = (litellm, "completion", original)
            litellm.completion = self._wrap_sync_call(original, "chat")

        # Async completion
        if hasattr(litellm, "acompletion"):
            original = litellm.acompletion
            self._original_methods["litellm.acompletion"] = (litellm, "acompletion", original)
            litellm.acompletion = self._wrap_async_call(original, "chat")

        # Text completion
        if hasattr(litellm, "text_completion"):
            original = litellm.text_completion
            self._original_methods["litellm.text_completion"] = (
                litellm, "text_completion", original,
            )
            litellm.text_completion = self._wrap_sync_call(original, "text_completion")

        # Async text completion
        if hasattr(litellm, "atext_completion"):
            original = litellm.atext_completion
            self._original_methods["litellm.atext_completion"] = (
                litellm, "atext_completion", original,
            )
            litellm.atext_completion = self._wrap_async_call(original, "text_completion")

    def _patch_embedding(self) -> None:
        """Patch ``litellm.embedding`` and ``litellm.aembedding``."""
        try:
            import litellm
        except ImportError:
            return

        if hasattr(litellm, "embedding"):
            original = litellm.embedding
            self._original_methods["litellm.embedding"] = (litellm, "embedding", original)
            litellm.embedding = self._wrap_sync_call(original, "embeddings")

        if hasattr(litellm, "aembedding"):
            original = litellm.aembedding
            self._original_methods["litellm.aembedding"] = (litellm, "aembedding", original)
            litellm.aembedding = self._wrap_async_call(original, "embeddings")

    def _wrap_sync_call(self, original: Any, operation: str) -> Any:
        """Create a synchronous wrapper that emits a span."""
        instrumentor = self

        @wraps(original)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            model = kwargs.get("model", args[0] if args else "unknown")
            provider, model_name = _detect_provider_and_model(model)
            stream = kwargs.get("stream", False)

            tracer = instrumentor.get_tracer()
            span_name = f"litellm.{operation} {model}"

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: provider,
                GenAIAttributes.REQUEST_MODEL: model_name,
                GenAIAttributes.OPERATION_NAME: operation,
                _LITELLM_PROVIDER: provider,
            }
            if kwargs.get("temperature") is not None:
                attributes[GenAIAttributes.REQUEST_TEMPERATURE] = kwargs["temperature"]
            if kwargs.get("max_tokens") is not None:
                attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = kwargs["max_tokens"]
            if stream:
                attributes[GenAIAttributes.REQUEST_STREAMING] = True
            if kwargs.get("api_base"):
                attributes[_LITELLM_API_BASE] = kwargs["api_base"]

            with tracer.start_as_current_span(
                span_name, kind=SpanKind.CLIENT, attributes=attributes,
            ) as span:
                start_time = time.monotonic()
                try:
                    response = original(*args, **kwargs)
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)
                    _enrich_span_from_response(span, response, operation)
                    span.set_status(StatusCode.OK)
                    return response
                except Exception as exc:
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_async_call(self, original: Any, operation: str) -> Any:
        """Create an async wrapper that emits a span."""
        instrumentor = self

        @wraps(original)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            model = kwargs.get("model", args[0] if args else "unknown")
            provider, model_name = _detect_provider_and_model(model)
            stream = kwargs.get("stream", False)

            tracer = instrumentor.get_tracer()
            span_name = f"litellm.{operation} {model}"

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: provider,
                GenAIAttributes.REQUEST_MODEL: model_name,
                GenAIAttributes.OPERATION_NAME: operation,
                _LITELLM_PROVIDER: provider,
            }
            if kwargs.get("temperature") is not None:
                attributes[GenAIAttributes.REQUEST_TEMPERATURE] = kwargs["temperature"]
            if kwargs.get("max_tokens") is not None:
                attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = kwargs["max_tokens"]
            if stream:
                attributes[GenAIAttributes.REQUEST_STREAMING] = True

            with tracer.start_as_current_span(
                span_name, kind=SpanKind.CLIENT, attributes=attributes,
            ) as span:
                start_time = time.monotonic()
                try:
                    response = await original(*args, **kwargs)
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)
                    _enrich_span_from_response(span, response, operation)
                    span.set_status(StatusCode.OK)
                    return response
                except Exception as exc:
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _unpatch_all(self) -> None:
        """Restore all monkey-patched functions to their originals."""
        for key, (module, attr_name, original) in self._original_methods.items():
            try:
                setattr(module, attr_name, original)
            except Exception:
                logger.warning("Failed to restore %s", key)
        self._original_methods.clear()


# ---------------------------------------------------------------------------
# Response enrichment helper
# ---------------------------------------------------------------------------

def _enrich_span_from_response(span: trace.Span, response: Any, operation: str) -> None:
    """Extract metadata from a LiteLLM response and set span attributes."""
    if response is None:
        return

    # Model used (may differ from requested due to fallback)
    if hasattr(response, "model"):
        span.set_attribute(GenAIAttributes.RESPONSE_MODEL, response.model)
    if hasattr(response, "id"):
        span.set_attribute(GenAIAttributes.RESPONSE_ID, response.id)

    # Token usage
    usage = getattr(response, "usage", None)
    if usage:
        if hasattr(usage, "prompt_tokens") and usage.prompt_tokens is not None:
            span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, usage.prompt_tokens)
        if hasattr(usage, "completion_tokens") and usage.completion_tokens is not None:
            span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, usage.completion_tokens)
        if hasattr(usage, "total_tokens") and usage.total_tokens is not None:
            span.set_attribute(GenAIAttributes.USAGE_TOTAL_TOKENS, usage.total_tokens)

    # Finish reasons (for completion operations)
    if operation in ("chat", "text_completion"):
        choices = getattr(response, "choices", None)
        if choices:
            reasons = [c.finish_reason for c in choices if getattr(c, "finish_reason", None)]
            if reasons:
                span.set_attribute(
                    GenAIAttributes.RESPONSE_FINISH_REASONS, json.dumps(reasons),
                )

    # LiteLLM-specific: cost from _hidden_params
    hidden = getattr(response, "_hidden_params", {})
    if isinstance(hidden, dict):
        if "response_cost" in hidden:
            span.set_attribute(_LITELLM_RESPONSE_COST, hidden["response_cost"])
        if "cache_hit" in hidden:
            span.set_attribute(_LITELLM_CACHE_HIT, hidden["cache_hit"])
        if "custom_llm_provider" in hidden:
            span.set_attribute(_LITELLM_CUSTOM_LLM_PROVIDER, hidden["custom_llm_provider"])


# ---------------------------------------------------------------------------
# Helper span classes for manual instrumentation
# ---------------------------------------------------------------------------

class CompletionSpan:
    """Wrapper around a span for LiteLLM completion calls."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    def set_usage(
        self,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        total_tokens: int | None = None,
    ) -> None:
        if input_tokens is not None:
            self._span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
        if output_tokens is not None:
            self._span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens)
        if total_tokens is not None:
            self._span.set_attribute(GenAIAttributes.USAGE_TOTAL_TOKENS, total_tokens)

    def set_cost(self, cost: float) -> None:
        self._span.set_attribute(_LITELLM_RESPONSE_COST, cost)

    def set_response(
        self,
        response_id: str | None = None,
        model: str | None = None,
        finish_reasons: list[str] | None = None,
    ) -> None:
        if response_id:
            self._span.set_attribute(GenAIAttributes.RESPONSE_ID, response_id)
        if model:
            self._span.set_attribute(GenAIAttributes.RESPONSE_MODEL, model)
        if finish_reasons:
            self._span.set_attribute(
                GenAIAttributes.RESPONSE_FINISH_REASONS, json.dumps(finish_reasons),
            )

    def set_cache_hit(self, hit: bool) -> None:
        self._span.set_attribute(_LITELLM_CACHE_HIT, hit)


class EmbeddingSpan:
    """Wrapper around a span for LiteLLM embedding calls."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    def set_usage(self, input_tokens: int | None = None) -> None:
        if input_tokens is not None:
            self._span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)

    def set_dimensions(self, dimensions: int) -> None:
        self._span.set_attribute("gen_ai.embedding.dimensions", dimensions)
