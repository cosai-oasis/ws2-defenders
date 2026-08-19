"""AITF OpenAI GPT API Instrumentor.

Auto-instruments the ``openai`` Python SDK so that every call to
``chat.completions.create``, ``embeddings.create``, and their async
counterparts automatically emits rich OpenTelemetry / AITF spans with
token-level usage, cost tracking, function-calling events, structured-output
metadata, and first-class streaming support.

The instrumentation uses **monkey-patching**: the original SDK methods are
replaced with thin wrappers that start a span, delegate to the real method,
and record telemetry attributes before the span closes.

Usage::

    from integrations.openai.gpt_api.instrumentor import OpenAIGPTInstrumentor

    # Instrument once at application startup.
    instrumentor = OpenAIGPTInstrumentor()
    instrumentor.instrument()

    import openai
    client = openai.OpenAI()

    # --- Chat completion (sync, non-streaming) ---
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Explain quantum computing."}],
    )

    # --- Chat completion (sync, streaming) ---
    stream = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Write a haiku."}],
        stream=True,
    )
    for chunk in stream:
        print(chunk.choices[0].delta.content or "", end="")

    # --- Embeddings ---
    emb = client.embeddings.create(
        model="text-embedding-3-small",
        input="Hello world",
    )

    # --- Async variants ---
    aclient = openai.AsyncOpenAI()
    response = await aclient.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hi!"}],
    )

    # Remove instrumentation when no longer needed.
    instrumentor.uninstrument()
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, AsyncIterator, Dict, Iterator, Optional, Tuple

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.instrumentation.llm import LLMInstrumentor
from aitf.semantic_conventions.attributes import (
    CostAttributes,
    GenAIAttributes,
    LatencyAttributes,
)

logger = logging.getLogger(__name__)

_TRACER_NAME = "integration.openai.gpt_api"

# ---------------------------------------------------------------------------
# Approximate pricing per 1 M tokens (USD).  Updated periodically; the
# instrumentor also exposes ``set_pricing`` so callers can override.
# ---------------------------------------------------------------------------
_DEFAULT_PRICING: Dict[str, Tuple[float, float]] = {
    # model-prefix: (input_per_1M, output_per_1M)
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-4": (30.00, 60.00),
    "gpt-3.5-turbo": (0.50, 1.50),
    "o1-mini": (3.00, 12.00),
    "o1": (15.00, 60.00),
    "o3-mini": (1.10, 4.40),
    "text-embedding-3-small": (0.02, 0.00),
    "text-embedding-3-large": (0.13, 0.00),
    "text-embedding-ada-002": (0.10, 0.00),
}


def _resolve_pricing(model: str) -> Tuple[float, float]:
    """Return ``(input_per_1M, output_per_1M)`` for *model*.

    Falls back to ``(0.0, 0.0)`` when the model is unknown.
    """
    for prefix, pricing in _DEFAULT_PRICING.items():
        if model.startswith(prefix):
            return pricing
    return (0.0, 0.0)


def _compute_cost(
    model: str,
    input_tokens: int,
    output_tokens: int,
) -> Tuple[float, float, float]:
    """Return ``(input_cost, output_cost, total_cost)`` in USD."""
    inp_per_1m, out_per_1m = _resolve_pricing(model)
    input_cost = (input_tokens / 1_000_000) * inp_per_1m
    output_cost = (output_tokens / 1_000_000) * out_per_1m
    return input_cost, output_cost, input_cost + output_cost


# ---- helpers for extracting data from openai response objects -------------

def _safe_getattr(obj: Any, path: str, default: Any = None) -> Any:
    """Traverse dotted *path* on *obj*, returning *default* on failure."""
    current = obj
    for part in path.split("."):
        try:
            current = getattr(current, part)
        except AttributeError:
            return default
    return current


def _extract_chat_request_attrs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Build span attributes from the ``create`` keyword arguments."""
    attrs: Dict[str, Any] = {
        GenAIAttributes.SYSTEM: GenAIAttributes.System.OPENAI,
        GenAIAttributes.OPERATION_NAME: GenAIAttributes.Operation.CHAT,
    }
    if "model" in kwargs:
        attrs[GenAIAttributes.REQUEST_MODEL] = kwargs["model"]
    if "temperature" in kwargs:
        attrs[GenAIAttributes.REQUEST_TEMPERATURE] = kwargs["temperature"]
    if "max_tokens" in kwargs:
        attrs[GenAIAttributes.REQUEST_MAX_TOKENS] = kwargs["max_tokens"]
    if "max_completion_tokens" in kwargs:
        attrs[GenAIAttributes.REQUEST_MAX_TOKENS] = kwargs["max_completion_tokens"]
    if "top_p" in kwargs:
        attrs[GenAIAttributes.REQUEST_TOP_P] = kwargs["top_p"]
    if "frequency_penalty" in kwargs:
        attrs[GenAIAttributes.REQUEST_FREQUENCY_PENALTY] = kwargs["frequency_penalty"]
    if "presence_penalty" in kwargs:
        attrs[GenAIAttributes.REQUEST_PRESENCE_PENALTY] = kwargs["presence_penalty"]
    if "seed" in kwargs:
        attrs[GenAIAttributes.REQUEST_SEED] = kwargs["seed"]
    if "stop" in kwargs:
        stop = kwargs["stop"]
        if isinstance(stop, str):
            stop = [stop]
        attrs[GenAIAttributes.REQUEST_STOP_SEQUENCES] = json.dumps(stop)

    # Stream flag
    is_stream = kwargs.get("stream", False)
    if is_stream:
        attrs[GenAIAttributes.REQUEST_STREAM] = True

    # Tools / function calling
    tools = kwargs.get("tools")
    if tools:
        tool_summaries = []
        for t in tools:
            fn = t.get("function", {}) if isinstance(t, dict) else {}
            tool_summaries.append({"name": fn.get("name", "unknown")})
        attrs[GenAIAttributes.REQUEST_TOOLS] = json.dumps(tool_summaries)
    tool_choice = kwargs.get("tool_choice")
    if tool_choice is not None:
        if isinstance(tool_choice, str):
            attrs[GenAIAttributes.REQUEST_TOOL_CHOICE] = tool_choice
        elif isinstance(tool_choice, dict):
            attrs[GenAIAttributes.REQUEST_TOOL_CHOICE] = json.dumps(tool_choice)

    # Structured outputs (response_format)
    response_format = kwargs.get("response_format")
    if response_format is not None:
        if isinstance(response_format, dict):
            attrs[GenAIAttributes.REQUEST_RESPONSE_FORMAT] = json.dumps(response_format)
        elif hasattr(response_format, "model_json_schema"):
            # Pydantic model passed as response_format for structured outputs.
            attrs[GenAIAttributes.REQUEST_RESPONSE_FORMAT] = json.dumps({
                "type": "json_schema",
                "json_schema": {
                    "name": getattr(response_format, "__name__", "schema"),
                },
            })
        else:
            attrs[GenAIAttributes.REQUEST_RESPONSE_FORMAT] = str(response_format)

    return attrs


def _extract_embedding_request_attrs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Build span attributes from ``embeddings.create`` keyword arguments."""
    attrs: Dict[str, Any] = {
        GenAIAttributes.SYSTEM: GenAIAttributes.System.OPENAI,
        GenAIAttributes.OPERATION_NAME: GenAIAttributes.Operation.EMBEDDINGS,
    }
    if "model" in kwargs:
        attrs[GenAIAttributes.REQUEST_MODEL] = kwargs["model"]
    # Record the count of input items.
    inp = kwargs.get("input")
    if inp is not None:
        if isinstance(inp, str):
            attrs["gen_ai.request.embedding_input_count"] = 1
        elif isinstance(inp, list):
            attrs["gen_ai.request.embedding_input_count"] = len(inp)
    if "dimensions" in kwargs:
        attrs["gen_ai.request.embedding_dimensions"] = kwargs["dimensions"]
    if "encoding_format" in kwargs:
        attrs["gen_ai.request.encoding_format"] = kwargs["encoding_format"]
    return attrs


def _record_chat_response(span: trace.Span, response: Any, model: str) -> None:
    """Set span attributes from a chat completion response object."""
    response_id = _safe_getattr(response, "id")
    if response_id:
        span.set_attribute(GenAIAttributes.RESPONSE_ID, response_id)
    response_model = _safe_getattr(response, "model")
    if response_model:
        span.set_attribute(GenAIAttributes.RESPONSE_MODEL, response_model)
        model = response_model  # prefer the model returned by the API

    # Finish reasons
    choices = _safe_getattr(response, "choices", [])
    if choices:
        finish_reasons = [
            getattr(c, "finish_reason", None) or "unknown" for c in choices
        ]
        span.set_attribute(GenAIAttributes.RESPONSE_FINISH_REASONS, finish_reasons)

    # Token usage
    usage = _safe_getattr(response, "usage")
    if usage is not None:
        input_tokens = getattr(usage, "prompt_tokens", 0) or 0
        output_tokens = getattr(usage, "completion_tokens", 0) or 0
        span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
        span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens)

        # Cached tokens (prompt caching)
        prompt_details = _safe_getattr(usage, "prompt_tokens_details")
        if prompt_details is not None:
            cached = getattr(prompt_details, "cached_tokens", 0) or 0
            if cached:
                span.set_attribute(GenAIAttributes.USAGE_CACHED_TOKENS, cached)

        # Reasoning tokens
        completion_details = _safe_getattr(usage, "completion_tokens_details")
        if completion_details is not None:
            reasoning = getattr(completion_details, "reasoning_tokens", 0) or 0
            if reasoning:
                span.set_attribute(GenAIAttributes.USAGE_REASONING_TOKENS, reasoning)

        # Cost
        input_cost, output_cost, total_cost = _compute_cost(
            model, input_tokens, output_tokens,
        )
        span.set_attribute(CostAttributes.INPUT_COST, input_cost)
        span.set_attribute(CostAttributes.OUTPUT_COST, output_cost)
        span.set_attribute(CostAttributes.TOTAL_COST, total_cost)
        span.set_attribute(CostAttributes.CURRENCY, "USD")

    # Function / tool calls
    if choices:
        message = _safe_getattr(choices[0], "message")
        if message is not None:
            tool_calls = getattr(message, "tool_calls", None)
            if tool_calls:
                for tc in tool_calls:
                    fn = getattr(tc, "function", None)
                    if fn:
                        span.add_event(
                            "gen_ai.tool.call",
                            attributes={
                                GenAIAttributes.TOOL_NAME: getattr(fn, "name", ""),
                                GenAIAttributes.TOOL_CALL_ID: getattr(tc, "id", ""),
                                GenAIAttributes.TOOL_ARGUMENTS: getattr(fn, "arguments", ""),
                            },
                        )

    # Structured outputs -- if the response was parsed via the beta parse API
    # the SDK attaches a ``.parsed`` attribute.
    if choices:
        parsed = _safe_getattr(choices[0], "message.parsed")
        if parsed is not None:
            span.add_event(
                "gen_ai.structured_output",
                attributes={
                    "gen_ai.structured_output.type": type(parsed).__name__,
                },
            )


def _record_embedding_response(span: trace.Span, response: Any, model: str) -> None:
    """Set span attributes from an embeddings response object."""
    response_model = _safe_getattr(response, "model")
    if response_model:
        span.set_attribute(GenAIAttributes.RESPONSE_MODEL, response_model)
        model = response_model

    usage = _safe_getattr(response, "usage")
    if usage is not None:
        input_tokens = getattr(usage, "prompt_tokens", 0) or getattr(usage, "total_tokens", 0) or 0
        span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
        span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, 0)

        input_cost, _, total_cost = _compute_cost(model, input_tokens, 0)
        span.set_attribute(CostAttributes.INPUT_COST, input_cost)
        span.set_attribute(CostAttributes.OUTPUT_COST, 0.0)
        span.set_attribute(CostAttributes.TOTAL_COST, total_cost)
        span.set_attribute(CostAttributes.CURRENCY, "USD")

    data = _safe_getattr(response, "data")
    if data is not None:
        span.set_attribute("gen_ai.response.embedding_count", len(data))
        if data:
            embedding = getattr(data[0], "embedding", None)
            if embedding is not None:
                span.set_attribute(
                    "gen_ai.response.embedding_dimensions",
                    len(embedding) if isinstance(embedding, (list, tuple)) else 0,
                )


# ---------------------------------------------------------------------------
# Streaming wrappers
# ---------------------------------------------------------------------------

class _TracedStream:
    """Wraps an OpenAI sync streaming response to record telemetry.

    Iterates over the original stream, accumulates token chunks and usage,
    and finalises the span when the stream is exhausted or an error occurs.
    """

    def __init__(
        self,
        original_stream: Any,
        span: trace.Span,
        otel_token: Any,
        model: str,
        start_time: float,
    ) -> None:
        self._stream = original_stream
        self._span = span
        self._token = otel_token
        self._model = model
        self._start_time = start_time
        self._first_token_recorded = False
        self._accumulated_content: list[str] = []
        self._finish_reason: Optional[str] = None
        self._response_id: Optional[str] = None
        self._response_model: Optional[str] = None
        self._usage_input: int = 0
        self._usage_output: int = 0
        self._tool_calls: Dict[int, Dict[str, str]] = {}

    def __iter__(self) -> Iterator:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._stream)
        except StopIteration:
            self._finalise()
            raise
        except Exception as exc:
            self._span.set_status(StatusCode.ERROR, str(exc))
            self._span.record_exception(exc)
            self._end_span()
            raise

        self._process_chunk(chunk)
        return chunk

    def __enter__(self) -> "_TracedStream":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None:
            self._span.set_status(StatusCode.ERROR, str(exc_val))
            self._span.record_exception(exc_val)
        else:
            self._finalise_attributes()
            self._span.set_status(StatusCode.OK)
        self._end_span()
        # Delegate to the original stream's __exit__ if it has one.
        if hasattr(self._stream, "__exit__"):
            self._stream.__exit__(exc_type, exc_val, exc_tb)

    def close(self) -> None:
        self._finalise()
        if hasattr(self._stream, "close"):
            self._stream.close()

    # -- internals ----------------------------------------------------------

    def _process_chunk(self, chunk: Any) -> None:
        if not self._first_token_recorded:
            self._first_token_recorded = True
            ttft = (time.monotonic() - self._start_time) * 1000
            self._span.set_attribute(LatencyAttributes.TIME_TO_FIRST_TOKEN_MS, ttft)

        self._response_id = self._response_id or _safe_getattr(chunk, "id")
        self._response_model = self._response_model or _safe_getattr(chunk, "model")

        choices = _safe_getattr(chunk, "choices", [])
        if choices:
            delta = _safe_getattr(choices[0], "delta")
            if delta is not None:
                content = getattr(delta, "content", None)
                if content:
                    self._accumulated_content.append(content)

                # Accumulate streamed tool calls
                tool_calls = getattr(delta, "tool_calls", None)
                if tool_calls:
                    for tc in tool_calls:
                        idx = getattr(tc, "index", 0)
                        if idx not in self._tool_calls:
                            self._tool_calls[idx] = {
                                "id": "",
                                "name": "",
                                "arguments": "",
                            }
                        tc_id = getattr(tc, "id", None)
                        if tc_id:
                            self._tool_calls[idx]["id"] = tc_id
                        fn = getattr(tc, "function", None)
                        if fn:
                            fn_name = getattr(fn, "name", None)
                            if fn_name:
                                self._tool_calls[idx]["name"] = fn_name
                            fn_args = getattr(fn, "arguments", None)
                            if fn_args:
                                self._tool_calls[idx]["arguments"] += fn_args

            fr = _safe_getattr(choices[0], "finish_reason")
            if fr:
                self._finish_reason = fr

        # Some stream events include usage when ``stream_options`` is set.
        usage = _safe_getattr(chunk, "usage")
        if usage is not None:
            self._usage_input = getattr(usage, "prompt_tokens", 0) or 0
            self._usage_output = getattr(usage, "completion_tokens", 0) or 0

    def _finalise(self) -> None:
        self._finalise_attributes()
        self._span.set_status(StatusCode.OK)
        self._end_span()

    def _finalise_attributes(self) -> None:
        if self._response_id:
            self._span.set_attribute(GenAIAttributes.RESPONSE_ID, self._response_id)
        model = self._response_model or self._model
        if self._response_model:
            self._span.set_attribute(GenAIAttributes.RESPONSE_MODEL, self._response_model)
        if self._finish_reason:
            self._span.set_attribute(
                GenAIAttributes.RESPONSE_FINISH_REASONS, [self._finish_reason],
            )
        if self._usage_input or self._usage_output:
            self._span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, self._usage_input)
            self._span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, self._usage_output)
            input_cost, output_cost, total_cost = _compute_cost(
                model, self._usage_input, self._usage_output,
            )
            self._span.set_attribute(CostAttributes.INPUT_COST, input_cost)
            self._span.set_attribute(CostAttributes.OUTPUT_COST, output_cost)
            self._span.set_attribute(CostAttributes.TOTAL_COST, total_cost)
            self._span.set_attribute(CostAttributes.CURRENCY, "USD")

        # Record accumulated tool calls
        for tc_info in self._tool_calls.values():
            self._span.add_event(
                "gen_ai.tool.call",
                attributes={
                    GenAIAttributes.TOOL_NAME: tc_info["name"],
                    GenAIAttributes.TOOL_CALL_ID: tc_info["id"],
                    GenAIAttributes.TOOL_ARGUMENTS: tc_info["arguments"],
                },
            )

        # Latency
        total_ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)

    def _end_span(self) -> None:
        self._span.end()
        otel_context.detach(self._token)


class _TracedAsyncStream:
    """Async counterpart of :class:`_TracedStream`."""

    def __init__(
        self,
        original_stream: Any,
        span: trace.Span,
        otel_token: Any,
        model: str,
        start_time: float,
    ) -> None:
        self._stream = original_stream
        self._span = span
        self._token = otel_token
        self._model = model
        self._start_time = start_time
        self._first_token_recorded = False
        self._accumulated_content: list[str] = []
        self._finish_reason: Optional[str] = None
        self._response_id: Optional[str] = None
        self._response_model: Optional[str] = None
        self._usage_input: int = 0
        self._usage_output: int = 0
        self._tool_calls: Dict[int, Dict[str, str]] = {}

    def __aiter__(self) -> AsyncIterator:
        return self

    async def __anext__(self) -> Any:
        try:
            chunk = await self._stream.__anext__()
        except StopAsyncIteration:
            self._finalise()
            raise
        except Exception as exc:
            self._span.set_status(StatusCode.ERROR, str(exc))
            self._span.record_exception(exc)
            self._end_span()
            raise

        self._process_chunk(chunk)
        return chunk

    async def __aenter__(self) -> "_TracedAsyncStream":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None:
            self._span.set_status(StatusCode.ERROR, str(exc_val))
            self._span.record_exception(exc_val)
        else:
            self._finalise_attributes()
            self._span.set_status(StatusCode.OK)
        self._end_span()
        if hasattr(self._stream, "__aexit__"):
            await self._stream.__aexit__(exc_type, exc_val, exc_tb)

    async def close(self) -> None:
        self._finalise()
        if hasattr(self._stream, "close"):
            result = self._stream.close()
            if hasattr(result, "__await__"):
                await result

    # The internals reuse the same logic as the sync variant.

    def _process_chunk(self, chunk: Any) -> None:
        if not self._first_token_recorded:
            self._first_token_recorded = True
            ttft = (time.monotonic() - self._start_time) * 1000
            self._span.set_attribute(LatencyAttributes.TIME_TO_FIRST_TOKEN_MS, ttft)

        self._response_id = self._response_id or _safe_getattr(chunk, "id")
        self._response_model = self._response_model or _safe_getattr(chunk, "model")

        choices = _safe_getattr(chunk, "choices", [])
        if choices:
            delta = _safe_getattr(choices[0], "delta")
            if delta is not None:
                content = getattr(delta, "content", None)
                if content:
                    self._accumulated_content.append(content)

                tool_calls = getattr(delta, "tool_calls", None)
                if tool_calls:
                    for tc in tool_calls:
                        idx = getattr(tc, "index", 0)
                        if idx not in self._tool_calls:
                            self._tool_calls[idx] = {
                                "id": "",
                                "name": "",
                                "arguments": "",
                            }
                        tc_id = getattr(tc, "id", None)
                        if tc_id:
                            self._tool_calls[idx]["id"] = tc_id
                        fn = getattr(tc, "function", None)
                        if fn:
                            fn_name = getattr(fn, "name", None)
                            if fn_name:
                                self._tool_calls[idx]["name"] = fn_name
                            fn_args = getattr(fn, "arguments", None)
                            if fn_args:
                                self._tool_calls[idx]["arguments"] += fn_args

            fr = _safe_getattr(choices[0], "finish_reason")
            if fr:
                self._finish_reason = fr

        usage = _safe_getattr(chunk, "usage")
        if usage is not None:
            self._usage_input = getattr(usage, "prompt_tokens", 0) or 0
            self._usage_output = getattr(usage, "completion_tokens", 0) or 0

    def _finalise(self) -> None:
        self._finalise_attributes()
        self._span.set_status(StatusCode.OK)
        self._end_span()

    def _finalise_attributes(self) -> None:
        if self._response_id:
            self._span.set_attribute(GenAIAttributes.RESPONSE_ID, self._response_id)
        model = self._response_model or self._model
        if self._response_model:
            self._span.set_attribute(GenAIAttributes.RESPONSE_MODEL, self._response_model)
        if self._finish_reason:
            self._span.set_attribute(
                GenAIAttributes.RESPONSE_FINISH_REASONS, [self._finish_reason],
            )
        if self._usage_input or self._usage_output:
            self._span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, self._usage_input)
            self._span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, self._usage_output)
            input_cost, output_cost, total_cost = _compute_cost(
                model, self._usage_input, self._usage_output,
            )
            self._span.set_attribute(CostAttributes.INPUT_COST, input_cost)
            self._span.set_attribute(CostAttributes.OUTPUT_COST, output_cost)
            self._span.set_attribute(CostAttributes.TOTAL_COST, total_cost)
            self._span.set_attribute(CostAttributes.CURRENCY, "USD")

        for tc_info in self._tool_calls.values():
            self._span.add_event(
                "gen_ai.tool.call",
                attributes={
                    GenAIAttributes.TOOL_NAME: tc_info["name"],
                    GenAIAttributes.TOOL_CALL_ID: tc_info["id"],
                    GenAIAttributes.TOOL_ARGUMENTS: tc_info["arguments"],
                },
            )

        total_ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)

    def _end_span(self) -> None:
        self._span.end()
        otel_context.detach(self._token)


# ---------------------------------------------------------------------------
# The instrumentor
# ---------------------------------------------------------------------------

class OpenAIGPTInstrumentor:
    """Auto-instruments the ``openai`` Python SDK for AITF telemetry.

    Monkey-patches ``chat.completions.create`` and ``embeddings.create``
    (sync and async) to emit OpenTelemetry spans enriched with AITF
    semantic-convention attributes.

    Usage::

        instrumentor = OpenAIGPTInstrumentor()
        instrumentor.instrument()

        # All openai SDK calls now produce spans automatically.

        instrumentor.uninstrument()  # restore original methods
    """

    def __init__(
        self,
        tracer_provider: Optional[TracerProvider] = None,
    ) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: Optional[trace.Tracer] = None
        self._instrumented = False

        # Stash for the original (un-patched) methods so we can restore them.
        self._originals: Dict[str, Any] = {}

    # -- public API ---------------------------------------------------------

    def instrument(self) -> None:
        """Apply monkey-patches to the ``openai`` SDK.

        Idempotent -- calling ``instrument()`` a second time without an
        intervening ``uninstrument()`` is a no-op.
        """
        if self._instrumented:
            logger.debug("OpenAIGPTInstrumentor: already instrumented, skipping.")
            return

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        try:
            import openai  # noqa: F811
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for OpenAIGPTInstrumentor. "
                "Install it with: pip install openai"
            ) from exc

        # ---- Sync patches -------------------------------------------------
        self._patch_sync_chat(openai)
        self._patch_sync_embeddings(openai)

        # ---- Async patches ------------------------------------------------
        self._patch_async_chat(openai)
        self._patch_async_embeddings(openai)

        self._instrumented = True
        logger.info("OpenAIGPTInstrumentor: instrumentation applied.")

    def uninstrument(self) -> None:
        """Remove all monkey-patches and restore original SDK methods."""
        if not self._instrumented:
            return

        try:
            import openai  # noqa: F811
        except ImportError:
            return

        for key, original in self._originals.items():
            parts = key.split(".")
            target = openai
            for part in parts[:-1]:
                target = getattr(target, part, None)
                if target is None:
                    break
            else:
                setattr(target, parts[-1], original)

        self._originals.clear()
        self._tracer = None
        self._instrumented = False
        logger.info("OpenAIGPTInstrumentor: instrumentation removed.")

    @property
    def is_instrumented(self) -> bool:
        """Return ``True`` if the SDK is currently patched."""
        return self._instrumented

    @staticmethod
    def set_pricing(model: str, input_per_1m: float, output_per_1m: float) -> None:
        """Override the pricing used for cost calculation.

        Args:
            model: Model name prefix (e.g. ``"gpt-4o"``).
            input_per_1m: Cost in USD per 1 million input tokens.
            output_per_1m: Cost in USD per 1 million output tokens.
        """
        _DEFAULT_PRICING[model] = (input_per_1m, output_per_1m)

    # -- sync patch helpers -------------------------------------------------

    def _patch_sync_chat(self, openai_module: Any) -> None:
        """Patch ``openai.resources.chat.completions.Completions.create``."""
        cls = _safe_getattr(
            openai_module, "resources.chat.completions.Completions",
        )
        if cls is None:
            logger.warning(
                "OpenAIGPTInstrumentor: could not locate "
                "openai.resources.chat.completions.Completions; sync chat "
                "completions will not be instrumented.",
            )
            return

        original = cls.create
        self._originals["resources.chat.completions.Completions.create"] = original
        tracer = self._tracer

        def patched_create(self_inner: Any, *args: Any, **kwargs: Any) -> Any:
            return _instrumented_chat_create(
                tracer, original, self_inner, args, kwargs, is_async=False,
            )

        cls.create = patched_create

    def _patch_sync_embeddings(self, openai_module: Any) -> None:
        """Patch ``openai.resources.embeddings.Embeddings.create``."""
        cls = _safe_getattr(
            openai_module, "resources.embeddings.Embeddings",
        )
        if cls is None:
            logger.warning(
                "OpenAIGPTInstrumentor: could not locate "
                "openai.resources.embeddings.Embeddings; sync embeddings "
                "will not be instrumented.",
            )
            return

        original = cls.create
        self._originals["resources.embeddings.Embeddings.create"] = original
        tracer = self._tracer

        def patched_create(self_inner: Any, *args: Any, **kwargs: Any) -> Any:
            return _instrumented_embedding_create(
                tracer, original, self_inner, args, kwargs,
            )

        cls.create = patched_create

    # -- async patch helpers ------------------------------------------------

    def _patch_async_chat(self, openai_module: Any) -> None:
        """Patch ``openai.resources.chat.completions.AsyncCompletions.create``."""
        cls = _safe_getattr(
            openai_module, "resources.chat.completions.AsyncCompletions",
        )
        if cls is None:
            logger.warning(
                "OpenAIGPTInstrumentor: could not locate "
                "openai.resources.chat.completions.AsyncCompletions; async "
                "chat completions will not be instrumented.",
            )
            return

        original = cls.create
        self._originals["resources.chat.completions.AsyncCompletions.create"] = original
        tracer = self._tracer

        async def patched_create(self_inner: Any, *args: Any, **kwargs: Any) -> Any:
            return await _instrumented_async_chat_create(
                tracer, original, self_inner, args, kwargs,
            )

        cls.create = patched_create

    def _patch_async_embeddings(self, openai_module: Any) -> None:
        """Patch ``openai.resources.embeddings.AsyncEmbeddings.create``."""
        cls = _safe_getattr(
            openai_module, "resources.embeddings.AsyncEmbeddings",
        )
        if cls is None:
            logger.warning(
                "OpenAIGPTInstrumentor: could not locate "
                "openai.resources.embeddings.AsyncEmbeddings; async "
                "embeddings will not be instrumented.",
            )
            return

        original = cls.create
        self._originals["resources.embeddings.AsyncEmbeddings.create"] = original
        tracer = self._tracer

        async def patched_create(self_inner: Any, *args: Any, **kwargs: Any) -> Any:
            return await _instrumented_async_embedding_create(
                tracer, original, self_inner, args, kwargs,
            )

        cls.create = patched_create


# ---------------------------------------------------------------------------
# Instrumented call implementations
# ---------------------------------------------------------------------------

def _instrumented_chat_create(
    tracer: trace.Tracer,
    original_fn: Any,
    self_inner: Any,
    args: tuple,
    kwargs: Dict[str, Any],
    *,
    is_async: bool = False,
) -> Any:
    """Wrap a sync ``chat.completions.create`` call with a span."""
    model = kwargs.get("model", "unknown")
    is_stream = kwargs.get("stream", False)
    attrs = _extract_chat_request_attrs(kwargs)
    span_name = f"chat {model}"

    start_time = time.monotonic()

    if is_stream:
        # For streaming we start the span manually and hand ownership to the
        # stream wrapper which will close it when iteration completes.
        span = tracer.start_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attrs,
        )
        token = otel_context.attach(trace.set_span_in_context(span))
        try:
            raw_stream = original_fn(self_inner, *args, **kwargs)
            return _TracedStream(raw_stream, span, token, model, start_time)
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            span.end()
            otel_context.detach(token)
            raise
    else:
        with tracer.start_as_current_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attrs,
        ) as span:
            try:
                response = original_fn(self_inner, *args, **kwargs)
                _record_chat_response(span, response, model)
                total_ms = (time.monotonic() - start_time) * 1000
                span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)
                span.set_status(StatusCode.OK)
                return response
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


async def _instrumented_async_chat_create(
    tracer: trace.Tracer,
    original_fn: Any,
    self_inner: Any,
    args: tuple,
    kwargs: Dict[str, Any],
) -> Any:
    """Wrap an async ``chat.completions.create`` call with a span."""
    model = kwargs.get("model", "unknown")
    is_stream = kwargs.get("stream", False)
    attrs = _extract_chat_request_attrs(kwargs)
    span_name = f"chat {model}"

    start_time = time.monotonic()

    if is_stream:
        span = tracer.start_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attrs,
        )
        token = otel_context.attach(trace.set_span_in_context(span))
        try:
            raw_stream = await original_fn(self_inner, *args, **kwargs)
            return _TracedAsyncStream(raw_stream, span, token, model, start_time)
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            span.end()
            otel_context.detach(token)
            raise
    else:
        with tracer.start_as_current_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attrs,
        ) as span:
            try:
                response = await original_fn(self_inner, *args, **kwargs)
                _record_chat_response(span, response, model)
                total_ms = (time.monotonic() - start_time) * 1000
                span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)
                span.set_status(StatusCode.OK)
                return response
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


def _instrumented_embedding_create(
    tracer: trace.Tracer,
    original_fn: Any,
    self_inner: Any,
    args: tuple,
    kwargs: Dict[str, Any],
) -> Any:
    """Wrap a sync ``embeddings.create`` call with a span."""
    model = kwargs.get("model", "unknown")
    attrs = _extract_embedding_request_attrs(kwargs)
    span_name = f"embeddings {model}"

    start_time = time.monotonic()

    with tracer.start_as_current_span(
        name=span_name,
        kind=SpanKind.CLIENT,
        attributes=attrs,
    ) as span:
        try:
            response = original_fn(self_inner, *args, **kwargs)
            _record_embedding_response(span, response, model)
            total_ms = (time.monotonic() - start_time) * 1000
            span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)
            span.set_status(StatusCode.OK)
            return response
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            raise


async def _instrumented_async_embedding_create(
    tracer: trace.Tracer,
    original_fn: Any,
    self_inner: Any,
    args: tuple,
    kwargs: Dict[str, Any],
) -> Any:
    """Wrap an async ``embeddings.create`` call with a span."""
    model = kwargs.get("model", "unknown")
    attrs = _extract_embedding_request_attrs(kwargs)
    span_name = f"embeddings {model}"

    start_time = time.monotonic()

    with tracer.start_as_current_span(
        name=span_name,
        kind=SpanKind.CLIENT,
        attributes=attrs,
    ) as span:
        try:
            response = await original_fn(self_inner, *args, **kwargs)
            _record_embedding_response(span, response, model)
            total_ms = (time.monotonic() - start_time) * 1000
            span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)
            span.set_status(StatusCode.OK)
            return response
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            raise
