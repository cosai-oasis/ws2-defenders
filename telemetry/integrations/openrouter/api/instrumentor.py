"""AITF integration for the OpenRouter API.

Instruments OpenRouter API calls made via the ``openai`` Python client
(configured with ``base_url="https://openrouter.ai/api/v1"``).

Captures:
- **Model routing**: Which provider/model prefix was requested and which
  provider actually served the response.
- **Token usage**: Input, output, and total tokens.
- **Cost**: Per-request cost from OpenRouter's ``usage`` metadata.
- **Latency**: Total request time and time-to-first-token for streaming.
- **Streaming**: Whether the request used streaming or not.

All spans use ``gen_ai.*`` attributes for OTel compatibility and
``aitf.openrouter.*`` attributes for routing metadata that can be
normalized by the ``openrouter.json`` vendor mapping.

Architecture
------------
The instrumentor monkey-patches the ``openai`` client's chat completions
``create`` method to intercept calls when the base URL points to
OpenRouter.  Each patched call emits an OpenTelemetry span with AITF
semantic convention attributes before delegating to the original method.
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

_TRACER_NAME = "integration.openrouter"

# ---------------------------------------------------------------------------
# Attribute constants specific to OpenRouter telemetry
# ---------------------------------------------------------------------------

_OPENROUTER_ROUTE_PROVIDER = "openrouter.route_provider"
_OPENROUTER_ROUTE_MODEL = "openrouter.route_model"
_OPENROUTER_ROUTE_PREFERENCE = "openrouter.route_preference"
_OPENROUTER_TRANSFORMS = "openrouter.transforms"
_OPENROUTER_COST_INPUT = "cost.input_cost"
_OPENROUTER_COST_OUTPUT = "cost.output_cost"
_OPENROUTER_COST_TOTAL = "cost.total_cost"

# Provider prefix mapping (mirrors openrouter.json)
_MODEL_PREFIX_TO_PROVIDER: dict[str, str] = {
    "anthropic/": "anthropic",
    "openai/": "openai",
    "google/": "google",
    "meta-llama/": "meta",
    "mistralai/": "mistral",
    "cohere/": "cohere",
    "deepseek/": "deepseek",
    "qwen/": "qwen",
    "microsoft/": "microsoft",
    "nvidia/": "nvidia",
    "perplexity/": "perplexity",
    "x-ai/": "xai",
    "amazon/": "amazon",
}

_OPENROUTER_BASE_URLS = (
    "https://openrouter.ai/api/v1",
    "http://openrouter.ai/api/v1",
)


def _detect_provider(model: str) -> str | None:
    """Detect the underlying LLM provider from an OpenRouter model ID."""
    for prefix, provider in _MODEL_PREFIX_TO_PROVIDER.items():
        if model.startswith(prefix):
            return provider
    return None


def _extract_route_model(model: str) -> str | None:
    """Extract the base model name from a provider-prefixed model ID."""
    for prefix in _MODEL_PREFIX_TO_PROVIDER:
        if model.startswith(prefix):
            return model[len(prefix):]
    return None


class OpenRouterInstrumentor:
    """Instruments OpenRouter API calls via the ``openai`` Python client.

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
        """Enable auto-instrumentation by monkey-patching the openai client."""
        if self._instrumented:
            logger.warning("OpenRouterInstrumentor is already instrumented")
            return

        self._patch_openai_chat()
        self._instrumented = True
        logger.info("OpenRouter instrumentation enabled")

    def uninstrument(self) -> None:
        """Remove all patches and restore original methods."""
        if not self._instrumented:
            return

        self._unpatch_all()
        self._instrumented = False
        logger.info("OpenRouter instrumentation disabled")

    # -----------------------------------------------------------------
    # Context managers for manual instrumentation
    # -----------------------------------------------------------------

    @contextmanager
    def trace_completion(
        self,
        model: str,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        top_p: float | None = None,
        stream: bool = False,
        route: str | None = None,
        transforms: list[str] | None = None,
    ) -> Generator[CompletionSpan, None, None]:
        """Manually trace an OpenRouter chat completion.

        Use this when you want explicit control over span lifecycle
        rather than relying on auto-instrumentation.
        """
        tracer = self.get_tracer()
        span_name = f"chat {model}"

        provider = _detect_provider(model) or "openrouter"
        route_model = _extract_route_model(model)

        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: provider,
            GenAIAttributes.REQUEST_MODEL: model,
            GenAIAttributes.OPERATION_NAME: "chat",
        }
        if temperature is not None:
            attributes[GenAIAttributes.REQUEST_TEMPERATURE] = temperature
        if max_tokens is not None:
            attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = max_tokens
        if top_p is not None:
            attributes[GenAIAttributes.REQUEST_TOP_P] = top_p
        if stream:
            attributes[GenAIAttributes.REQUEST_STREAMING] = True
        if route:
            attributes[_OPENROUTER_ROUTE_PREFERENCE] = route
        if transforms:
            attributes[_OPENROUTER_TRANSFORMS] = json.dumps(transforms)
        if route_model:
            attributes[_OPENROUTER_ROUTE_MODEL] = route_model
            attributes[_OPENROUTER_ROUTE_PROVIDER] = provider

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

    # -----------------------------------------------------------------
    # Monkey-patching
    # -----------------------------------------------------------------

    def _patch_openai_chat(self) -> None:
        """Patch ``openai.resources.chat.completions.Completions.create``."""
        try:
            from openai.resources.chat.completions import Completions
        except ImportError:
            logger.debug(
                "openai package not installed; skipping OpenRouter patching. "
                "Install with: pip install openai"
            )
            return

        original_create = Completions.create
        original_key = (id(Completions), "create")
        self._original_methods[str(original_key)] = (
            Completions, "create", original_create,
        )

        instrumentor = self

        @wraps(original_create)
        def wrapped_create(self_client: Any, *args: Any, **kwargs: Any) -> Any:
            # Only intercept calls going to OpenRouter
            base_url = getattr(getattr(self_client, "_client", None), "base_url", None)
            base_url_str = str(base_url).rstrip("/") if base_url else ""

            if not any(base_url_str.startswith(u) for u in _OPENROUTER_BASE_URLS):
                return original_create(self_client, *args, **kwargs)

            model = kwargs.get("model", args[0] if args else "unknown")
            provider = _detect_provider(model) or "openrouter"
            route_model = _extract_route_model(model)
            stream = kwargs.get("stream", False)

            tracer = instrumentor.get_tracer()
            span_name = f"chat {model}"

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: provider,
                GenAIAttributes.REQUEST_MODEL: model,
                GenAIAttributes.OPERATION_NAME: "chat",
                "gen_ai.server.address": "openrouter.ai",
            }

            if kwargs.get("temperature") is not None:
                attributes[GenAIAttributes.REQUEST_TEMPERATURE] = kwargs["temperature"]
            if kwargs.get("max_tokens") is not None:
                attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = kwargs["max_tokens"]
            if kwargs.get("top_p") is not None:
                attributes[GenAIAttributes.REQUEST_TOP_P] = kwargs["top_p"]
            if stream:
                attributes[GenAIAttributes.REQUEST_STREAMING] = True
            if route_model:
                attributes[_OPENROUTER_ROUTE_MODEL] = route_model
                attributes[_OPENROUTER_ROUTE_PROVIDER] = provider

            # OpenRouter-specific extras
            extra = kwargs.get("extra_body", {}) or {}
            if extra.get("route"):
                attributes[_OPENROUTER_ROUTE_PREFERENCE] = extra["route"]
            if extra.get("transforms"):
                attributes[_OPENROUTER_TRANSFORMS] = json.dumps(extra["transforms"])

            with tracer.start_as_current_span(
                span_name, kind=SpanKind.CLIENT, attributes=attributes,
            ) as span:
                start_time = time.monotonic()
                try:
                    response = original_create(self_client, *args, **kwargs)
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

                    # Extract response metadata
                    if hasattr(response, "model"):
                        span.set_attribute(GenAIAttributes.RESPONSE_MODEL, response.model)
                    if hasattr(response, "id"):
                        span.set_attribute(GenAIAttributes.RESPONSE_ID, response.id)

                    # Usage
                    usage = getattr(response, "usage", None)
                    if usage:
                        if hasattr(usage, "prompt_tokens"):
                            span.set_attribute(
                                GenAIAttributes.USAGE_INPUT_TOKENS, usage.prompt_tokens,
                            )
                        if hasattr(usage, "completion_tokens"):
                            span.set_attribute(
                                GenAIAttributes.USAGE_OUTPUT_TOKENS, usage.completion_tokens,
                            )
                        if hasattr(usage, "total_tokens"):
                            span.set_attribute(
                                GenAIAttributes.USAGE_TOTAL_TOKENS, usage.total_tokens,
                            )

                    # Finish reasons
                    if hasattr(response, "choices") and response.choices:
                        reasons = [
                            c.finish_reason
                            for c in response.choices
                            if c.finish_reason
                        ]
                        if reasons:
                            span.set_attribute(
                                GenAIAttributes.RESPONSE_FINISH_REASONS,
                                json.dumps(reasons),
                            )

                    span.set_status(StatusCode.OK)
                    return response

                except Exception as exc:
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        Completions.create = wrapped_create  # type: ignore[assignment]

        # Also patch async variant if available
        try:
            from openai.resources.chat.completions import AsyncCompletions

            original_acreate = AsyncCompletions.create
            async_key = (id(AsyncCompletions), "create")
            self._original_methods[str(async_key)] = (
                AsyncCompletions, "create", original_acreate,
            )

            @wraps(original_acreate)
            async def wrapped_acreate(self_client: Any, *args: Any, **kwargs: Any) -> Any:
                base_url = getattr(getattr(self_client, "_client", None), "base_url", None)
                base_url_str = str(base_url).rstrip("/") if base_url else ""

                if not any(base_url_str.startswith(u) for u in _OPENROUTER_BASE_URLS):
                    return await original_acreate(self_client, *args, **kwargs)

                model = kwargs.get("model", args[0] if args else "unknown")
                provider = _detect_provider(model) or "openrouter"
                route_model = _extract_route_model(model)
                stream = kwargs.get("stream", False)

                tracer = instrumentor.get_tracer()
                span_name = f"chat {model}"

                attributes: dict[str, Any] = {
                    GenAIAttributes.SYSTEM: provider,
                    GenAIAttributes.REQUEST_MODEL: model,
                    GenAIAttributes.OPERATION_NAME: "chat",
                    "gen_ai.server.address": "openrouter.ai",
                }
                if kwargs.get("temperature") is not None:
                    attributes[GenAIAttributes.REQUEST_TEMPERATURE] = kwargs["temperature"]
                if kwargs.get("max_tokens") is not None:
                    attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = kwargs["max_tokens"]
                if route_model:
                    attributes[_OPENROUTER_ROUTE_MODEL] = route_model
                    attributes[_OPENROUTER_ROUTE_PROVIDER] = provider
                if stream:
                    attributes[GenAIAttributes.REQUEST_STREAMING] = True

                with tracer.start_as_current_span(
                    span_name, kind=SpanKind.CLIENT, attributes=attributes,
                ) as span:
                    start_time = time.monotonic()
                    try:
                        response = await original_acreate(self_client, *args, **kwargs)
                        elapsed_ms = (time.monotonic() - start_time) * 1000
                        span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

                        if hasattr(response, "model"):
                            span.set_attribute(GenAIAttributes.RESPONSE_MODEL, response.model)
                        if hasattr(response, "id"):
                            span.set_attribute(GenAIAttributes.RESPONSE_ID, response.id)

                        usage = getattr(response, "usage", None)
                        if usage:
                            if hasattr(usage, "prompt_tokens"):
                                span.set_attribute(
                                    GenAIAttributes.USAGE_INPUT_TOKENS, usage.prompt_tokens,
                                )
                            if hasattr(usage, "completion_tokens"):
                                span.set_attribute(
                                    GenAIAttributes.USAGE_OUTPUT_TOKENS, usage.completion_tokens,
                                )

                        span.set_status(StatusCode.OK)
                        return response

                    except Exception as exc:
                        elapsed_ms = (time.monotonic() - start_time) * 1000
                        span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)
                        span.set_status(StatusCode.ERROR, str(exc))
                        span.record_exception(exc)
                        raise

            AsyncCompletions.create = wrapped_acreate  # type: ignore[assignment]

        except ImportError:
            pass  # No async support

    def _unpatch_all(self) -> None:
        """Restore all monkey-patched methods to their originals."""
        for key, (cls, method_name, original) in self._original_methods.items():
            try:
                setattr(cls, method_name, original)
            except Exception:
                logger.warning("Failed to restore %s.%s", cls.__name__, method_name)
        self._original_methods.clear()


class CompletionSpan:
    """Wrapper around an OpenTelemetry span for OpenRouter completions.

    Provides typed setter methods for enriching spans with response data.
    """

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

    def set_cost(
        self,
        input_cost: float | None = None,
        output_cost: float | None = None,
        total_cost: float | None = None,
    ) -> None:
        if input_cost is not None:
            self._span.set_attribute(_OPENROUTER_COST_INPUT, input_cost)
        if output_cost is not None:
            self._span.set_attribute(_OPENROUTER_COST_OUTPUT, output_cost)
        if total_cost is not None:
            self._span.set_attribute(_OPENROUTER_COST_TOTAL, total_cost)

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

    def set_latency(
        self,
        total_ms: float | None = None,
        tokens_per_second: float | None = None,
        time_to_first_token_ms: float | None = None,
    ) -> None:
        if total_ms is not None:
            self._span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)
        if tokens_per_second is not None:
            self._span.set_attribute(LatencyAttributes.TOKENS_PER_SECOND, tokens_per_second)
        if time_to_first_token_ms is not None:
            self._span.set_attribute(
                LatencyAttributes.TIME_TO_FIRST_TOKEN_MS, time_to_first_token_ms,
            )

    def set_route_provider(self, provider: str) -> None:
        """Set the actual provider that served the request (from response)."""
        self._span.set_attribute(_OPENROUTER_ROUTE_PROVIDER, provider)

    def set_route_model(self, model: str) -> None:
        """Set the actual model that served the request (from response)."""
        self._span.set_attribute(_OPENROUTER_ROUTE_MODEL, model)
