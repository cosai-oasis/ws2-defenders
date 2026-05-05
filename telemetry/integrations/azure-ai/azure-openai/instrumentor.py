"""AITF Azure OpenAI Instrumentor.

Wraps the ``openai`` Python SDK's ``AzureOpenAI`` and ``AsyncAzureOpenAI``
clients with AITF telemetry. Monkey-patches
``chat.completions.create()`` (sync and async) to emit OpenTelemetry spans
enriched with Azure-specific attributes such as deployment name, API version,
and content filtering results.

All spans set ``gen_ai.system = "azure"`` and carry the standard GenAI
semantic convention attributes (model, tokens, finish reasons) as well as
AITF extensions for cost, latency, and content safety.

Usage:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

    from integrations.azure_ai.azure_openai.instrumentor import AzureOpenAIInstrumentor

    # Set up tracing
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    # Instrument Azure OpenAI
    instrumentor = AzureOpenAIInstrumentor(tracer_provider=provider)
    instrumentor.instrument()

    # Use the SDK as normal -- all calls are now traced
    from openai import AzureOpenAI

    client = AzureOpenAI(
        azure_endpoint="https://my-resource.openai.azure.com",
        api_version="2024-06-01",
        api_key="...",
    )
    response = client.chat.completions.create(
        model="gpt-4o",  # deployment name
        messages=[{"role": "user", "content": "Hello!"}],
    )

    # To remove instrumentation
    instrumentor.uninstrument()
"""

from __future__ import annotations

import json
import logging
import time
from functools import wraps
from typing import Any, Callable, Sequence

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.instrumentation import LLMInstrumentor
from aitf.semantic_conventions.attributes import (
    CostAttributes,
    GenAIAttributes,
    LatencyAttributes,
)

logger = logging.getLogger(__name__)

_TRACER_NAME = "aitf.integrations.azure_openai"

# Azure-specific attribute keys (aitf.azure.* namespace)
_AZURE_DEPLOYMENT_NAME = "aitf.azure.deployment_name"
_AZURE_API_VERSION = "aitf.azure.api_version"
_AZURE_ENDPOINT = "aitf.azure.endpoint"
_AZURE_CONTENT_FILTER_PROMPT = "aitf.azure.content_filter.prompt"
_AZURE_CONTENT_FILTER_COMPLETION = "aitf.azure.content_filter.completion"
_AZURE_CONTENT_FILTER_SEVERITY = "aitf.azure.content_filter.severity"
_AZURE_CONTENT_FILTER_FILTERED = "aitf.azure.content_filter.filtered"


class AzureOpenAIInstrumentor:
    """Instruments ``AzureOpenAI`` and ``AsyncAzureOpenAI`` chat completion calls.

    Wraps ``chat.completions.create`` on both the synchronous and asynchronous
    Azure OpenAI clients, emitting OpenTelemetry spans with:

    * Standard GenAI attributes (``gen_ai.system``, ``gen_ai.request.model``,
      ``gen_ai.usage.input_tokens``, ``gen_ai.usage.output_tokens``, etc.)
    * Azure-specific attributes (deployment name, API version, content
      filtering results)
    * AITF cost attributes (``aitf.cost.total_cost``)

    Args:
        tracer_provider: Optional ``TracerProvider``. When ``None``, the
            globally registered provider is used.

    Example:
        >>> instrumentor = AzureOpenAIInstrumentor()
        >>> instrumentor.instrument()
        >>> # AzureOpenAI().chat.completions.create() now emits spans
        >>> instrumentor.uninstrument()
    """

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._original_sync_create: Callable | None = None
        self._original_async_create: Callable | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Apply monkey-patches to Azure OpenAI SDK classes.

        After calling this method every invocation of
        ``AzureOpenAI().chat.completions.create()`` and
        ``AsyncAzureOpenAI().chat.completions.create()`` will be wrapped
        with an OpenTelemetry span.

        This method is idempotent -- calling it multiple times has no
        additional effect.
        """
        if self._instrumented:
            logger.debug("AzureOpenAIInstrumentor is already instrumented.")
            return

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        try:
            import openai  # noqa: F401 -- ensure the package is available
            from openai.resources.chat.completions import (
                AsyncCompletions,
                Completions,
            )
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for AzureOpenAIInstrumentor. "
                "Install it with: pip install openai"
            ) from exc

        # Patch synchronous create
        self._original_sync_create = Completions.create
        Completions.create = self._wrap_sync_create(Completions.create)

        # Patch asynchronous create
        self._original_async_create = AsyncCompletions.create
        AsyncCompletions.create = self._wrap_async_create(AsyncCompletions.create)

        self._instrumented = True
        logger.info("AzureOpenAIInstrumentor: instrumentation enabled.")

    def uninstrument(self) -> None:
        """Remove monkey-patches and restore original SDK behaviour.

        This method is idempotent -- calling it when not instrumented is
        a no-op.
        """
        if not self._instrumented:
            return

        try:
            from openai.resources.chat.completions import (
                AsyncCompletions,
                Completions,
            )

            if self._original_sync_create is not None:
                Completions.create = self._original_sync_create
            if self._original_async_create is not None:
                AsyncCompletions.create = self._original_async_create
        except ImportError:
            pass

        self._original_sync_create = None
        self._original_async_create = None
        self._tracer = None
        self._instrumented = False
        logger.info("AzureOpenAIInstrumentor: instrumentation removed.")

    @property
    def is_instrumented(self) -> bool:
        """Return ``True`` if the instrumentor is currently active."""
        return self._instrumented

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    @staticmethod
    def _is_azure_client(completions_instance: Any) -> bool:
        """Determine whether the ``Completions`` instance belongs to an Azure client."""
        try:
            client = completions_instance._client  # noqa: SLF001
            module = type(client).__module__ or ""
            class_name = type(client).__name__
            return "AzureOpenAI" in class_name or "azure" in module.lower()
        except AttributeError:
            return False

    @staticmethod
    def _extract_azure_config(completions_instance: Any) -> dict[str, str]:
        """Extract Azure-specific configuration from the underlying client."""
        config: dict[str, str] = {}
        try:
            client = completions_instance._client  # noqa: SLF001

            # Azure endpoint
            base_url = getattr(client, "base_url", None) or getattr(client, "_base_url", None)
            if base_url is not None:
                config["endpoint"] = str(base_url)

            # API version
            api_version = getattr(client, "_api_version", None)
            if api_version is not None:
                config["api_version"] = str(api_version)
        except AttributeError:
            pass
        return config

    @staticmethod
    def _extract_content_filter_results(response: Any) -> dict[str, Any] | None:
        """Extract Azure content filtering results from the response.

        Azure OpenAI responses may contain ``prompt_filter_results`` at the
        top level and ``content_filter_results`` in each choice. This method
        normalises them into a flat dictionary suitable for span attributes.
        """
        filter_data: dict[str, Any] = {}

        try:
            # Prompt-level content filter results
            prompt_results = getattr(response, "prompt_filter_results", None)
            if prompt_results:
                filter_data["prompt_filter"] = _serialize_content_filter(prompt_results)

            # Choice-level content filter results
            choices = getattr(response, "choices", None) or []
            for idx, choice in enumerate(choices):
                cfr = getattr(choice, "content_filter_results", None)
                if cfr:
                    filter_data[f"choice_{idx}_filter"] = _serialize_content_filter(cfr)
        except (AttributeError, TypeError):
            return None

        return filter_data if filter_data else None

    def _build_span_attributes(
        self,
        kwargs: dict[str, Any],
        azure_config: dict[str, str],
    ) -> dict[str, Any]:
        """Build the initial set of span attributes from request kwargs."""
        model = kwargs.get("model", "unknown")

        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: GenAIAttributes.System.AZURE,
            GenAIAttributes.OPERATION_NAME: GenAIAttributes.Operation.CHAT,
            GenAIAttributes.REQUEST_MODEL: model,
            _AZURE_DEPLOYMENT_NAME: model,  # Azure uses model as deployment name
        }

        # Azure configuration
        if "api_version" in azure_config:
            attributes[_AZURE_API_VERSION] = azure_config["api_version"]
        if "endpoint" in azure_config:
            attributes[_AZURE_ENDPOINT] = azure_config["endpoint"]

        # Standard request attributes
        if "temperature" in kwargs:
            attributes[GenAIAttributes.REQUEST_TEMPERATURE] = kwargs["temperature"]
        if "max_tokens" in kwargs:
            attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = kwargs["max_tokens"]
        if "max_completion_tokens" in kwargs:
            attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = kwargs["max_completion_tokens"]
        if "top_p" in kwargs:
            attributes[GenAIAttributes.REQUEST_TOP_P] = kwargs["top_p"]
        if "frequency_penalty" in kwargs:
            attributes[GenAIAttributes.REQUEST_FREQUENCY_PENALTY] = kwargs["frequency_penalty"]
        if "presence_penalty" in kwargs:
            attributes[GenAIAttributes.REQUEST_PRESENCE_PENALTY] = kwargs["presence_penalty"]
        if "seed" in kwargs:
            attributes[GenAIAttributes.REQUEST_SEED] = kwargs["seed"]
        if "stream" in kwargs:
            attributes[GenAIAttributes.REQUEST_STREAM] = bool(kwargs["stream"])
        if "stop" in kwargs:
            stop = kwargs["stop"]
            if isinstance(stop, str):
                stop = [stop]
            attributes[GenAIAttributes.REQUEST_STOP_SEQUENCES] = stop
        if "tools" in kwargs and kwargs["tools"]:
            tool_names = json.dumps(
                [{"name": t.get("function", {}).get("name", "")} for t in kwargs["tools"]]
            )
            attributes[GenAIAttributes.REQUEST_TOOLS] = tool_names
        if "tool_choice" in kwargs:
            tc = kwargs["tool_choice"]
            attributes[GenAIAttributes.REQUEST_TOOL_CHOICE] = (
                tc if isinstance(tc, str) else json.dumps(tc)
            )
        if "response_format" in kwargs:
            rf = kwargs["response_format"]
            attributes[GenAIAttributes.REQUEST_RESPONSE_FORMAT] = (
                rf if isinstance(rf, str) else json.dumps(rf, default=str)
            )

        return attributes

    def _enrich_span_from_response(
        self,
        span: trace.Span,
        response: Any,
        elapsed_ms: float,
    ) -> None:
        """Set response, usage, content filter, and latency attributes on the span."""
        # Response metadata
        response_id = getattr(response, "id", None)
        if response_id:
            span.set_attribute(GenAIAttributes.RESPONSE_ID, response_id)

        response_model = getattr(response, "model", None)
        if response_model:
            span.set_attribute(GenAIAttributes.RESPONSE_MODEL, response_model)

        # Finish reasons
        choices = getattr(response, "choices", None) or []
        if choices:
            finish_reasons = [
                getattr(c, "finish_reason", "unknown") or "unknown" for c in choices
            ]
            span.set_attribute(GenAIAttributes.RESPONSE_FINISH_REASONS, finish_reasons)

        # Token usage
        usage = getattr(response, "usage", None)
        if usage is not None:
            input_tokens = getattr(usage, "prompt_tokens", 0) or 0
            output_tokens = getattr(usage, "completion_tokens", 0) or 0
            span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
            span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens)

            # Cached tokens (Azure returns these under completion_tokens_details)
            cached = getattr(usage, "prompt_tokens_details", None)
            if cached is not None:
                cached_count = getattr(cached, "cached_tokens", 0) or 0
                if cached_count:
                    span.set_attribute(GenAIAttributes.USAGE_CACHED_TOKENS, cached_count)

            # Reasoning tokens
            completion_details = getattr(usage, "completion_tokens_details", None)
            if completion_details is not None:
                reasoning = getattr(completion_details, "reasoning_tokens", 0) or 0
                if reasoning:
                    span.set_attribute(GenAIAttributes.USAGE_REASONING_TOKENS, reasoning)

            # Cost estimation (placeholder -- production systems should use
            # a pricing lookup based on deployment/model)
            span.set_attribute(CostAttributes.TOTAL_COST, 0.0)
            span.set_attribute(CostAttributes.CURRENCY, "USD")

        # Content filtering (Azure-specific)
        filter_results = self._extract_content_filter_results(response)
        if filter_results:
            prompt_filter = filter_results.get("prompt_filter")
            if prompt_filter is not None:
                span.set_attribute(_AZURE_CONTENT_FILTER_PROMPT, json.dumps(prompt_filter))

            # Collect completion-level filters
            completion_filters: list[Any] = []
            any_filtered = False
            max_severity = "safe"
            for key, value in filter_results.items():
                if key.startswith("choice_"):
                    completion_filters.append(value)
                    if isinstance(value, dict):
                        for _category, detail in value.items():
                            if isinstance(detail, dict):
                                if detail.get("filtered", False):
                                    any_filtered = True
                                sev = detail.get("severity", "safe")
                                if _severity_rank(sev) > _severity_rank(max_severity):
                                    max_severity = sev

            if completion_filters:
                span.set_attribute(
                    _AZURE_CONTENT_FILTER_COMPLETION,
                    json.dumps(completion_filters),
                )
            span.set_attribute(_AZURE_CONTENT_FILTER_FILTERED, any_filtered)
            span.set_attribute(_AZURE_CONTENT_FILTER_SEVERITY, max_severity)

        # Latency
        span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

        # Tool calls emitted as events
        for choice in choices:
            message = getattr(choice, "message", None)
            if message is None:
                continue
            tool_calls = getattr(message, "tool_calls", None) or []
            for tc in tool_calls:
                func = getattr(tc, "function", None)
                if func is None:
                    continue
                span.add_event(
                    "gen_ai.tool.call",
                    attributes={
                        GenAIAttributes.TOOL_NAME: getattr(func, "name", ""),
                        GenAIAttributes.TOOL_CALL_ID: getattr(tc, "id", ""),
                        GenAIAttributes.TOOL_ARGUMENTS: getattr(func, "arguments", ""),
                    },
                )

    # ------------------------------------------------------------------
    # Wrappers
    # ------------------------------------------------------------------

    def _wrap_sync_create(self, original: Callable) -> Callable:
        """Return a synchronous wrapper around ``Completions.create``."""
        instrumentor = self

        @wraps(original)
        def wrapped(completions_self: Any, *args: Any, **kwargs: Any) -> Any:
            # Only instrument Azure clients; pass through vanilla OpenAI
            if not instrumentor._is_azure_client(completions_self):
                return original(completions_self, *args, **kwargs)

            tracer = instrumentor._get_tracer()
            azure_config = instrumentor._extract_azure_config(completions_self)
            attributes = instrumentor._build_span_attributes(kwargs, azure_config)
            model = kwargs.get("model", "unknown")
            span_name = f"chat {model}"

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                start = time.monotonic()
                try:
                    response = original(completions_self, *args, **kwargs)
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

                elapsed_ms = (time.monotonic() - start) * 1000.0
                instrumentor._enrich_span_from_response(span, response, elapsed_ms)
                span.set_status(StatusCode.OK)
                return response

        return wrapped

    def _wrap_async_create(self, original: Callable) -> Callable:
        """Return an asynchronous wrapper around ``AsyncCompletions.create``."""
        instrumentor = self

        @wraps(original)
        async def wrapped(completions_self: Any, *args: Any, **kwargs: Any) -> Any:
            if not instrumentor._is_azure_client(completions_self):
                return await original(completions_self, *args, **kwargs)

            tracer = instrumentor._get_tracer()
            azure_config = instrumentor._extract_azure_config(completions_self)
            attributes = instrumentor._build_span_attributes(kwargs, azure_config)
            model = kwargs.get("model", "unknown")
            span_name = f"chat {model}"

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                start = time.monotonic()
                try:
                    response = await original(completions_self, *args, **kwargs)
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

                elapsed_ms = (time.monotonic() - start) * 1000.0
                instrumentor._enrich_span_from_response(span, response, elapsed_ms)
                span.set_status(StatusCode.OK)
                return response

        return wrapped


# ----------------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------------

_SEVERITY_RANKING = {
    "safe": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}


def _severity_rank(severity: str) -> int:
    """Return a numeric rank for an Azure content filter severity level."""
    return _SEVERITY_RANKING.get(severity.lower(), -1)


def _serialize_content_filter(obj: Any) -> Any:
    """Recursively serialise Azure content filter result objects to dicts.

    The Azure SDK returns Pydantic-like model instances; this helper
    normalises them into plain dicts for JSON serialisation.
    """
    if isinstance(obj, dict):
        return {k: _serialize_content_filter(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize_content_filter(item) for item in obj]
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "__dict__"):
        return {k: _serialize_content_filter(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
    return obj
