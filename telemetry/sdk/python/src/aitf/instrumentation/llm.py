"""AITF LLM Instrumentation.

Provides tracing for LLM inference operations (chat completion, text completion,
embeddings) with extended attributes for cost, latency, and security.
"""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import (
    CostAttributes,
    GenAIAttributes,
    LatencyAttributes,
    SecurityAttributes,
)

_TRACER_NAME = "instrumentation.llm"


class LLMInstrumentor:
    """Instrumentor for LLM inference operations.

    Traces chat completions, text completions, and embedding operations
    with OTel GenAI-compatible attributes plus AITF extensions.
    """

    def __init__(self, tracer_provider: TracerProvider | None = None):
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False

    def instrument(self, provider: str | None = None) -> None:
        """Enable LLM instrumentation."""
        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)
        self._instrumented = True

    def uninstrument(self) -> None:
        """Disable LLM instrumentation."""
        self._tracer = None
        self._instrumented = False

    def get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    @contextmanager
    def trace_inference(
        self,
        model: str,
        operation: str = "chat",
        system: str = "openai",
        temperature: float | None = None,
        max_tokens: int | None = None,
        stream: bool = False,
        tools: list[dict] | None = None,
        **kwargs: Any,
    ) -> Generator[InferenceSpan, None, None]:
        """Context manager for tracing an LLM inference operation.

        Usage:
            with llm.trace_inference(model="gpt-4o", system="openai") as span:
                span.set_prompt("Hello, world!")
                response = openai_client.chat.completions.create(...)
                span.set_completion(response.choices[0].message.content)
                span.set_usage(input_tokens=10, output_tokens=50)
        """
        tracer = self.get_tracer()
        span_name = f"{operation} {model}"
        attributes: dict[str, Any] = {
            GenAIAttributes.PROVIDER_NAME: system,
            GenAIAttributes.OPERATION_NAME: operation,
            GenAIAttributes.REQUEST_MODEL: model,
        }
        if temperature is not None:
            attributes[GenAIAttributes.REQUEST_TEMPERATURE] = temperature
        if max_tokens is not None:
            attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = max_tokens
        if stream:
            attributes[GenAIAttributes.REQUEST_STREAM] = True
        if tools:
            attributes[GenAIAttributes.REQUEST_TOOLS] = json.dumps(
                [{"name": t.get("name", "")} for t in tools]
            )
        # Validate extra attributes to prevent namespace pollution
        _ALLOWED_VALUE_TYPES = (str, int, float, bool)
        _MAX_ATTR_KEY_LEN = 128
        for key, value in kwargs.items():
            if len(key) > _MAX_ATTR_KEY_LEN:
                continue
            if not isinstance(value, _ALLOWED_VALUE_TYPES):
                continue
            attr_key = f"gen_ai.request.{key}"
            attributes[attr_key] = value

        start_time = time.monotonic()

        with tracer.start_as_current_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            inference_span = InferenceSpan(span, start_time)
            try:
                yield inference_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


class InferenceSpan:
    """Helper for setting attributes on an LLM inference span."""

    def __init__(self, span: trace.Span, start_time: float):
        self._span = span
        self._start_time = start_time
        self._first_token_time: float | None = None

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_system_prompt_hash(self, hash_value: str) -> None:
        """Set the system prompt hash (CoSAI WS2: AI_INTERACTION)."""
        self._span.set_attribute(GenAIAttributes.SYSTEM_PROMPT_HASH, hash_value)

    def set_prompt(self, prompt: str) -> None:
        """Record the prompt content as an event."""
        self._span.add_event(
            "gen_ai.content.prompt",
            attributes={GenAIAttributes.PROMPT: prompt},
        )

    def set_completion(self, completion: str) -> None:
        """Record the completion content as an event."""
        self._span.add_event(
            "gen_ai.content.completion",
            attributes={GenAIAttributes.COMPLETION: completion},
        )

    def set_response(
        self,
        response_id: str | None = None,
        model: str | None = None,
        finish_reasons: list[str] | None = None,
    ) -> None:
        """Set response attributes."""
        if response_id:
            self._span.set_attribute(GenAIAttributes.RESPONSE_ID, response_id)
        if model:
            self._span.set_attribute(GenAIAttributes.RESPONSE_MODEL, model)
        if finish_reasons:
            self._span.set_attribute(GenAIAttributes.RESPONSE_FINISH_REASONS, finish_reasons)

    def set_usage(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cached_tokens: int = 0,
        reasoning_tokens: int = 0,
    ) -> None:
        """Set token usage attributes."""
        self._span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
        self._span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens)
        if cached_tokens:
            self._span.set_attribute(GenAIAttributes.USAGE_CACHED_TOKENS, cached_tokens)
        if reasoning_tokens:
            self._span.set_attribute(GenAIAttributes.USAGE_REASONING_TOKENS, reasoning_tokens)

    def set_cost(
        self,
        input_cost: float = 0.0,
        output_cost: float = 0.0,
        total_cost: float | None = None,
        currency: str = "USD",
    ) -> None:
        """Set cost attributes."""
        self._span.set_attribute(CostAttributes.INPUT_COST, input_cost)
        self._span.set_attribute(CostAttributes.OUTPUT_COST, output_cost)
        self._span.set_attribute(
            CostAttributes.TOTAL_COST,
            total_cost if total_cost is not None else input_cost + output_cost,
        )
        self._span.set_attribute(CostAttributes.CURRENCY, currency)

    def set_tool_call(self, name: str, call_id: str, arguments: str) -> None:
        """Record a tool/function call event."""
        self._span.add_event(
            "gen_ai.tool.call",
            attributes={
                GenAIAttributes.TOOL_NAME: name,
                GenAIAttributes.TOOL_CALL_ID: call_id,
                GenAIAttributes.TOOL_CALL_ARGUMENTS: arguments,
            },
        )

    def set_tool_result(self, name: str, call_id: str, result: str) -> None:
        """Record a tool/function result event."""
        self._span.add_event(
            "gen_ai.tool.result",
            attributes={
                GenAIAttributes.TOOL_NAME: name,
                GenAIAttributes.TOOL_CALL_ID: call_id,
                GenAIAttributes.TOOL_CALL_RESULT: result,
            },
        )

    def mark_first_token(self) -> None:
        """Mark when the first token is received (for streaming)."""
        self._first_token_time = time.monotonic()
        ttft = (self._first_token_time - self._start_time) * 1000
        self._span.set_attribute(LatencyAttributes.TIME_TO_FIRST_TOKEN_MS, ttft)

    def set_latency(
        self,
        total_ms: float | None = None,
        tokens_per_second: float | None = None,
        queue_time_ms: float | None = None,
        inference_time_ms: float | None = None,
    ) -> None:
        """Set latency metrics."""
        if total_ms is None:
            total_ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)
        if tokens_per_second is not None:
            self._span.set_attribute(LatencyAttributes.TOKENS_PER_SECOND, tokens_per_second)
        if queue_time_ms is not None:
            self._span.set_attribute(LatencyAttributes.QUEUE_TIME_MS, queue_time_ms)
        if inference_time_ms is not None:
            self._span.set_attribute(LatencyAttributes.INFERENCE_TIME_MS, inference_time_ms)

    def set_security(self, risk_score: float = 0.0, risk_level: str = "info") -> None:
        """Set security assessment attributes."""
        self._span.set_attribute(SecurityAttributes.RISK_SCORE, risk_score)
        self._span.set_attribute(SecurityAttributes.RISK_LEVEL, risk_level)


def inference_span(
    model: str,
    system: str = "openai",
    operation: str = "chat",
    capture_prompt: bool = False,
    capture_completion: bool = False,
) -> Callable:
    """Decorator for tracing LLM inference functions.

    Usage:
        @inference_span(model="gpt-4o", system="openai")
        def call_llm(prompt: str) -> str:
            return openai_client.chat.completions.create(...)
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            instrumentor = LLMInstrumentor()
            with instrumentor.trace_inference(
                model=model,
                system=system,
                operation=operation,
            ) as span:
                result = func(*args, **kwargs)
                return result

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            instrumentor = LLMInstrumentor()
            with instrumentor.trace_inference(
                model=model,
                system=system,
                operation=operation,
            ) as span:
                result = await func(*args, **kwargs)
                return result

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator
