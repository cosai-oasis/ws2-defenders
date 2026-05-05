"""AITF Instrumentor for the Anthropic Python SDK (``anthropic``).

Monkey-patches ``anthropic.Anthropic().messages.create()`` and
``anthropic.AsyncAnthropic().messages.create()`` to automatically emit
OpenTelemetry spans with AITF semantic convention attributes for every
Messages API call.

Features:
    - Automatic span creation for sync and async ``messages.create``
    - Streaming support (``stream=True`` and ``messages.stream()`` context
      manager) with time-to-first-token tracking
    - Tool-use / function-calling event recording
    - Token usage extraction from response ``usage`` objects
    - Cost tracking based on configurable per-model pricing tables
    - Error handling with proper span status and exception recording
    - Prompt and completion content capture (opt-in for privacy)

Usage::

    from integrations.anthropic.claude_api import AnthropicInstrumentor

    # Basic instrumentation -- patches all Anthropic clients globally
    AnthropicInstrumentor().instrument()

    # With custom tracer provider and content capture
    from opentelemetry.sdk.trace import TracerProvider
    provider = TracerProvider()
    AnthropicInstrumentor(
        tracer_provider=provider,
        capture_content=True,
    ).instrument()

    # Now all calls are traced automatically:
    import anthropic
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello!"}],
    )

    # To remove instrumentation:
    AnthropicInstrumentor().uninstrument()

Architecture:
    The instrumentor stores references to the original unpatched methods and
    replaces them with thin wrappers that create OTel spans, forward the call,
    and enrich the span with response data.  ``uninstrument()`` restores the
    original methods.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import (
    AgentAttributes,
    CostAttributes,
    GenAIAttributes,
    LatencyAttributes,
)

logger = logging.getLogger(__name__)

_TRACER_NAME = "integration.anthropic.claude_api"

# ---------------------------------------------------------------------------
# Default per-model pricing (USD per 1 million tokens).
# Users can override via AnthropicInstrumentor(pricing=...).
# ---------------------------------------------------------------------------
_DEFAULT_PRICING: Dict[str, Dict[str, float]] = {
    # Claude 4 Opus
    "claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
    # Claude Sonnet 4
    "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    # Claude 3.7 Sonnet
    "claude-3-7-sonnet-latest": {"input": 3.00, "output": 15.00},
    "claude-3-7-sonnet-20250219": {"input": 3.00, "output": 15.00},
    # Claude 3.5 family
    "claude-3-5-sonnet-latest": {"input": 3.00, "output": 15.00},
    "claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
    "claude-3-5-sonnet-20240620": {"input": 3.00, "output": 15.00},
    "claude-3-5-haiku-latest": {"input": 0.80, "output": 4.00},
    "claude-3-5-haiku-20241022": {"input": 0.80, "output": 4.00},
    # Claude 3.0 family
    "claude-3-opus-latest": {"input": 15.00, "output": 75.00},
    "claude-3-opus-20240229": {"input": 15.00, "output": 75.00},
    "claude-3-sonnet-20240229": {"input": 3.00, "output": 15.00},
    "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
}

# Cache-read tokens are typically charged at a discounted rate (10% of input).
_CACHE_READ_DISCOUNT = 0.1
# Cache-write tokens are typically charged at a premium (25% above input).
_CACHE_WRITE_PREMIUM = 1.25


def _compute_cost(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_creation_input_tokens: int = 0,
    cache_read_input_tokens: int = 0,
    pricing: Optional[Dict[str, Dict[str, float]]] = None,
) -> Tuple[float, float, float]:
    """Compute (input_cost, output_cost, total_cost) in USD.

    Args:
        model: The Anthropic model identifier.
        input_tokens: Non-cached input tokens.
        output_tokens: Output tokens.
        cache_creation_input_tokens: Tokens written into the prompt cache.
        cache_read_input_tokens: Tokens read from the prompt cache.
        pricing: Optional override pricing table.

    Returns:
        Tuple of (input_cost_usd, output_cost_usd, total_cost_usd).
    """
    table = pricing or _DEFAULT_PRICING
    model_prices = table.get(model)
    if model_prices is None:
        # Try prefix matching for model aliases / dated variants.
        for key, val in table.items():
            if model.startswith(key.rsplit("-", 1)[0]):
                model_prices = val
                break
    if model_prices is None:
        return (0.0, 0.0, 0.0)

    input_rate = model_prices["input"] / 1_000_000
    output_rate = model_prices["output"] / 1_000_000

    # Standard input tokens (excluding cached tokens that are already counted separately)
    base_input_cost = input_tokens * input_rate
    cache_read_cost = cache_read_input_tokens * input_rate * _CACHE_READ_DISCOUNT
    cache_write_cost = cache_creation_input_tokens * input_rate * _CACHE_WRITE_PREMIUM
    input_cost = base_input_cost + cache_read_cost + cache_write_cost

    output_cost = output_tokens * output_rate
    total_cost = input_cost + output_cost
    return (input_cost, output_cost, total_cost)


# ---------------------------------------------------------------------------
# Span attribute helpers
# ---------------------------------------------------------------------------

def _extract_request_attributes(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Build span attributes from ``messages.create()`` keyword arguments."""
    attrs: Dict[str, Any] = {
        GenAIAttributes.SYSTEM: GenAIAttributes.System.ANTHROPIC,
        GenAIAttributes.OPERATION_NAME: GenAIAttributes.Operation.CHAT,
    }

    model = kwargs.get("model")
    if model:
        attrs[GenAIAttributes.REQUEST_MODEL] = str(model)

    max_tokens = kwargs.get("max_tokens")
    if max_tokens is not None:
        attrs[GenAIAttributes.REQUEST_MAX_TOKENS] = int(max_tokens)

    temperature = kwargs.get("temperature")
    if temperature is not None:
        attrs[GenAIAttributes.REQUEST_TEMPERATURE] = float(temperature)

    top_p = kwargs.get("top_p")
    if top_p is not None:
        attrs[GenAIAttributes.REQUEST_TOP_P] = float(top_p)

    top_k = kwargs.get("top_k")
    if top_k is not None:
        attrs[GenAIAttributes.REQUEST_TOP_K] = int(top_k)

    stop_sequences = kwargs.get("stop_sequences")
    if stop_sequences:
        attrs[GenAIAttributes.REQUEST_STOP_SEQUENCES] = stop_sequences

    stream = kwargs.get("stream", False)
    if stream:
        attrs[GenAIAttributes.REQUEST_STREAM] = True

    tools = kwargs.get("tools")
    if tools:
        tool_summaries = []
        for tool in tools:
            if isinstance(tool, dict):
                tool_summaries.append({"name": tool.get("name", "")})
            else:
                # Support Pydantic tool objects from the SDK
                tool_summaries.append({"name": getattr(tool, "name", "")})
        attrs[GenAIAttributes.REQUEST_TOOLS] = json.dumps(tool_summaries)

    tool_choice = kwargs.get("tool_choice")
    if tool_choice is not None:
        if isinstance(tool_choice, dict):
            attrs[GenAIAttributes.REQUEST_TOOL_CHOICE] = json.dumps(tool_choice)
        else:
            attrs[GenAIAttributes.REQUEST_TOOL_CHOICE] = str(tool_choice)

    return attrs


def _extract_message_content_text(messages: List[Dict[str, Any]]) -> str:
    """Extract a textual summary from the messages list for prompt capture."""
    parts: List[str] = []
    for msg in messages:
        role = msg.get("role", "unknown")
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(f"[{role}]: {content}")
        elif isinstance(content, list):
            # Content blocks
            text_parts = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        text_parts.append(block.get("text", ""))
                    elif block.get("type") == "tool_result":
                        text_parts.append(f"[tool_result:{block.get('tool_use_id', '')}]")
                    elif block.get("type") == "image":
                        text_parts.append("[image]")
                else:
                    text_parts.append(str(block))
            parts.append(f"[{role}]: {' '.join(text_parts)}")
    return "\n".join(parts)


def _set_response_attributes(
    span: trace.Span,
    response: Any,
    start_time: float,
    capture_content: bool,
    pricing: Optional[Dict[str, Dict[str, float]]],
) -> None:
    """Enrich a span with data extracted from an Anthropic ``Message`` response."""
    # Response identification
    response_id = getattr(response, "id", None)
    if response_id:
        span.set_attribute(GenAIAttributes.RESPONSE_ID, response_id)

    response_model = getattr(response, "model", None)
    if response_model:
        span.set_attribute(GenAIAttributes.RESPONSE_MODEL, str(response_model))

    stop_reason = getattr(response, "stop_reason", None)
    if stop_reason:
        span.set_attribute(GenAIAttributes.RESPONSE_FINISH_REASONS, [str(stop_reason)])

    # Token usage
    usage = getattr(response, "usage", None)
    input_tokens = 0
    output_tokens = 0
    cache_creation_input_tokens = 0
    cache_read_input_tokens = 0

    if usage is not None:
        input_tokens = getattr(usage, "input_tokens", 0) or 0
        output_tokens = getattr(usage, "output_tokens", 0) or 0
        cache_creation_input_tokens = getattr(usage, "cache_creation_input_tokens", 0) or 0
        cache_read_input_tokens = getattr(usage, "cache_read_input_tokens", 0) or 0

        span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
        span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens)

        if cache_read_input_tokens:
            span.set_attribute(GenAIAttributes.USAGE_CACHED_TOKENS, cache_read_input_tokens)

    # Cost tracking
    model_name = str(response_model) if response_model else ""
    input_cost, output_cost, total_cost = _compute_cost(
        model=model_name,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_creation_input_tokens=cache_creation_input_tokens,
        cache_read_input_tokens=cache_read_input_tokens,
        pricing=pricing,
    )
    if total_cost > 0:
        span.set_attribute(CostAttributes.INPUT_COST, input_cost)
        span.set_attribute(CostAttributes.OUTPUT_COST, output_cost)
        span.set_attribute(CostAttributes.TOTAL_COST, total_cost)
        span.set_attribute(CostAttributes.CURRENCY, "USD")

    # Pricing metadata
    model_prices = (pricing or _DEFAULT_PRICING).get(model_name)
    if model_prices:
        span.set_attribute(CostAttributes.PRICING_INPUT_PER_1M, model_prices["input"])
        span.set_attribute(CostAttributes.PRICING_OUTPUT_PER_1M, model_prices["output"])

    # Latency
    elapsed_ms = (time.monotonic() - start_time) * 1000
    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)
    if output_tokens > 0 and elapsed_ms > 0:
        tokens_per_sec = output_tokens / (elapsed_ms / 1000)
        span.set_attribute(LatencyAttributes.TOKENS_PER_SECOND, tokens_per_sec)

    # Tool use events
    content_blocks = getattr(response, "content", []) or []
    completion_parts: List[str] = []

    for block in content_blocks:
        block_type = getattr(block, "type", None)
        if block_type == "tool_use":
            tool_name = getattr(block, "name", "")
            tool_id = getattr(block, "id", "")
            tool_input = getattr(block, "input", {})
            span.add_event(
                "gen_ai.tool.call",
                attributes={
                    GenAIAttributes.TOOL_NAME: tool_name,
                    GenAIAttributes.TOOL_CALL_ID: tool_id,
                    GenAIAttributes.TOOL_ARGUMENTS: json.dumps(tool_input)
                    if not isinstance(tool_input, str)
                    else tool_input,
                },
            )
        elif block_type == "text":
            text = getattr(block, "text", "")
            completion_parts.append(text)

    # Completion content capture (opt-in)
    if capture_content and completion_parts:
        span.add_event(
            "gen_ai.content.completion",
            attributes={GenAIAttributes.COMPLETION: "\n".join(completion_parts)},
        )


# ---------------------------------------------------------------------------
# Streaming wrapper
# ---------------------------------------------------------------------------

class _InstrumentedStream:
    """Wrapper around an Anthropic streaming response that records AITF spans.

    Tracks time-to-first-token, accumulates content blocks, and sets final
    usage/cost attributes when the stream completes.
    """

    def __init__(
        self,
        stream: Any,
        span: trace.Span,
        start_time: float,
        otel_token: Any,
        capture_content: bool,
        pricing: Optional[Dict[str, Dict[str, float]]],
    ) -> None:
        self._stream = stream
        self._span = span
        self._start_time = start_time
        self._otel_token = otel_token
        self._capture_content = capture_content
        self._pricing = pricing
        self._first_token_seen = False
        self._accumulated_text: List[str] = []
        self._tool_uses: List[Dict[str, Any]] = []
        self._current_tool: Optional[Dict[str, Any]] = None
        self._current_tool_input_parts: List[str] = []
        self._final_message: Any = None

    def __iter__(self) -> _InstrumentedStream:
        return self

    def __next__(self) -> Any:
        try:
            event = next(self._stream)
            self._process_event(event)
            return event
        except StopIteration:
            self._finalize()
            raise
        except Exception as exc:
            self._span.set_status(StatusCode.ERROR, str(exc))
            self._span.record_exception(exc)
            self._detach_context()
            raise

    def __enter__(self) -> _InstrumentedStream:
        if hasattr(self._stream, "__enter__"):
            self._stream.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if hasattr(self._stream, "__exit__"):
            self._stream.__exit__(exc_type, exc_val, exc_tb)
        if exc_val is not None:
            self._span.set_status(StatusCode.ERROR, str(exc_val))
            self._span.record_exception(exc_val)
        else:
            self._finalize_from_message()
            self._span.set_status(StatusCode.OK)
        self._detach_context()

    def _process_event(self, event: Any) -> None:
        """Process a single streaming event and update span data."""
        event_type = getattr(event, "type", "")

        if event_type == "content_block_delta":
            delta = getattr(event, "delta", None)
            if delta is not None:
                delta_type = getattr(delta, "type", "")
                if delta_type == "text_delta":
                    if not self._first_token_seen:
                        self._first_token_seen = True
                        ttft = (time.monotonic() - self._start_time) * 1000
                        self._span.set_attribute(
                            LatencyAttributes.TIME_TO_FIRST_TOKEN_MS, ttft
                        )
                    self._accumulated_text.append(getattr(delta, "text", ""))
                elif delta_type == "input_json_delta":
                    self._current_tool_input_parts.append(
                        getattr(delta, "partial_json", "")
                    )

        elif event_type == "content_block_start":
            content_block = getattr(event, "content_block", None)
            if content_block is not None:
                block_type = getattr(content_block, "type", "")
                if block_type == "tool_use":
                    self._current_tool = {
                        "name": getattr(content_block, "name", ""),
                        "id": getattr(content_block, "id", ""),
                    }
                    self._current_tool_input_parts = []

        elif event_type == "content_block_stop":
            if self._current_tool is not None:
                input_json = "".join(self._current_tool_input_parts)
                self._span.add_event(
                    "gen_ai.tool.call",
                    attributes={
                        GenAIAttributes.TOOL_NAME: self._current_tool["name"],
                        GenAIAttributes.TOOL_CALL_ID: self._current_tool["id"],
                        GenAIAttributes.TOOL_ARGUMENTS: input_json,
                    },
                )
                self._tool_uses.append({**self._current_tool, "input": input_json})
                self._current_tool = None
                self._current_tool_input_parts = []

        elif event_type == "message_start":
            message = getattr(event, "message", None)
            if message is not None:
                msg_id = getattr(message, "id", None)
                if msg_id:
                    self._span.set_attribute(GenAIAttributes.RESPONSE_ID, msg_id)
                msg_model = getattr(message, "model", None)
                if msg_model:
                    self._span.set_attribute(
                        GenAIAttributes.RESPONSE_MODEL, str(msg_model)
                    )
                # Initial usage (input tokens are usually here)
                usage = getattr(message, "usage", None)
                if usage is not None:
                    input_tokens = getattr(usage, "input_tokens", 0) or 0
                    if input_tokens:
                        self._span.set_attribute(
                            GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens
                        )

        elif event_type == "message_delta":
            delta = getattr(event, "delta", None)
            if delta is not None:
                stop_reason = getattr(delta, "stop_reason", None)
                if stop_reason:
                    self._span.set_attribute(
                        GenAIAttributes.RESPONSE_FINISH_REASONS, [str(stop_reason)]
                    )
            # message_delta often includes final usage
            usage = getattr(event, "usage", None)
            if usage is not None:
                output_tokens = getattr(usage, "output_tokens", 0) or 0
                if output_tokens:
                    self._span.set_attribute(
                        GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens
                    )

        elif event_type == "message_stop":
            self._final_message = getattr(event, "message", None)

    def _finalize(self) -> None:
        """Finalize span when the iterator is exhausted."""
        self._finalize_from_message()
        self._span.set_status(StatusCode.OK)
        self._detach_context()

    def _finalize_from_message(self) -> None:
        """Set final cost and latency from accumulated data."""
        elapsed_ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

        # Capture completion content if enabled
        if self._capture_content and self._accumulated_text:
            self._span.add_event(
                "gen_ai.content.completion",
                attributes={
                    GenAIAttributes.COMPLETION: "".join(self._accumulated_text)
                },
            )

        # Compute cost from whatever usage attributes we have on the span
        span_ctx = self._span
        # Read back the token counts we set earlier
        input_tokens = 0
        output_tokens = 0
        if self._final_message:
            usage = getattr(self._final_message, "usage", None)
            if usage:
                input_tokens = getattr(usage, "input_tokens", 0) or 0
                output_tokens = getattr(usage, "output_tokens", 0) or 0
                cache_creation = getattr(usage, "cache_creation_input_tokens", 0) or 0
                cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
                # Update the span with final values
                self._span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
                self._span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens)
                if cache_read:
                    self._span.set_attribute(GenAIAttributes.USAGE_CACHED_TOKENS, cache_read)

                model = ""
                model_attr = getattr(self._final_message, "model", None)
                if model_attr:
                    model = str(model_attr)

                input_cost, output_cost, total_cost = _compute_cost(
                    model=model,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cache_creation_input_tokens=cache_creation,
                    cache_read_input_tokens=cache_read,
                    pricing=self._pricing,
                )
                if total_cost > 0:
                    self._span.set_attribute(CostAttributes.INPUT_COST, input_cost)
                    self._span.set_attribute(CostAttributes.OUTPUT_COST, output_cost)
                    self._span.set_attribute(CostAttributes.TOTAL_COST, total_cost)
                    self._span.set_attribute(CostAttributes.CURRENCY, "USD")

        if output_tokens > 0 and elapsed_ms > 0:
            tokens_per_sec = output_tokens / (elapsed_ms / 1000)
            self._span.set_attribute(LatencyAttributes.TOKENS_PER_SECOND, tokens_per_sec)

    def _detach_context(self) -> None:
        """Detach the OTel context token and end the span."""
        try:
            self._span.end()
        except Exception:
            pass
        if self._otel_token is not None:
            try:
                otel_context.detach(self._otel_token)
            except Exception:
                pass
            self._otel_token = None

    # Proxy attribute access to the underlying stream so callers can use
    # stream helper methods (e.g. ``get_final_message()``, ``text_stream``).
    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


# ---------------------------------------------------------------------------
# Async streaming wrapper
# ---------------------------------------------------------------------------

class _InstrumentedAsyncStream:
    """Async counterpart of :class:`_InstrumentedStream`."""

    def __init__(
        self,
        stream: Any,
        span: trace.Span,
        start_time: float,
        otel_token: Any,
        capture_content: bool,
        pricing: Optional[Dict[str, Dict[str, float]]],
    ) -> None:
        self._stream = stream
        self._span = span
        self._start_time = start_time
        self._otel_token = otel_token
        self._capture_content = capture_content
        self._pricing = pricing
        self._first_token_seen = False
        self._accumulated_text: List[str] = []
        self._tool_uses: List[Dict[str, Any]] = []
        self._current_tool: Optional[Dict[str, Any]] = None
        self._current_tool_input_parts: List[str] = []
        self._final_message: Any = None

    def __aiter__(self) -> _InstrumentedAsyncStream:
        return self

    async def __anext__(self) -> Any:
        try:
            event = await self._stream.__anext__()
            self._process_event(event)
            return event
        except StopAsyncIteration:
            self._finalize()
            raise
        except Exception as exc:
            self._span.set_status(StatusCode.ERROR, str(exc))
            self._span.record_exception(exc)
            self._detach_context()
            raise

    async def __aenter__(self) -> _InstrumentedAsyncStream:
        if hasattr(self._stream, "__aenter__"):
            await self._stream.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if hasattr(self._stream, "__aexit__"):
            await self._stream.__aexit__(exc_type, exc_val, exc_tb)
        if exc_val is not None:
            self._span.set_status(StatusCode.ERROR, str(exc_val))
            self._span.record_exception(exc_val)
        else:
            self._finalize_from_message()
            self._span.set_status(StatusCode.OK)
        self._detach_context()

    # Reuse the exact same event-processing logic from the sync wrapper.
    _process_event = _InstrumentedStream._process_event
    _finalize = _InstrumentedStream._finalize
    _finalize_from_message = _InstrumentedStream._finalize_from_message
    _detach_context = _InstrumentedStream._detach_context

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


# ---------------------------------------------------------------------------
# Main instrumentor class
# ---------------------------------------------------------------------------

class AnthropicInstrumentor:
    """Auto-instruments the ``anthropic`` Python SDK with AITF telemetry.

    Patches ``anthropic.resources.messages.Messages.create`` and
    ``anthropic.resources.messages.AsyncMessages.create`` to emit
    OpenTelemetry spans with ``gen_ai.*`` and ``aitf.*`` attributes.

    Args:
        tracer_provider: Optional OTel ``TracerProvider``. Falls back to the
            global provider if not supplied.
        capture_content: When ``True``, prompt and completion text is recorded
            as span events.  Defaults to ``False`` to protect user privacy.
        pricing: Optional per-model pricing table that overrides the built-in
            defaults.  Keys are model identifier strings; values are dicts
            with ``"input"`` and ``"output"`` prices per 1M tokens in USD.

    Example::

        instrumentor = AnthropicInstrumentor(capture_content=True)
        instrumentor.instrument()

        # All subsequent messages.create() calls are now traced.
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=256,
            messages=[{"role": "user", "content": "Explain AITF"}],
        )

        instrumentor.uninstrument()
    """

    def __init__(
        self,
        tracer_provider: Optional[TracerProvider] = None,
        capture_content: bool = False,
        pricing: Optional[Dict[str, Dict[str, float]]] = None,
    ) -> None:
        self._tracer_provider = tracer_provider
        self._capture_content = capture_content
        self._pricing = pricing
        self._tracer: Optional[trace.Tracer] = None
        self._instrumented = False

        # Saved references to original methods for uninstrumentation.
        self._original_sync_create: Any = None
        self._original_async_create: Any = None
        self._original_sync_stream: Any = None
        self._original_async_stream: Any = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Patch the ``anthropic`` SDK to emit AITF spans.

        This method is idempotent -- calling it multiple times has no
        additional effect.

        Raises:
            ImportError: If the ``anthropic`` package is not installed.
        """
        if self._instrumented:
            logger.debug("AnthropicInstrumentor is already instrumented.")
            return

        try:
            import anthropic  # noqa: F401
            from anthropic.resources.messages import AsyncMessages, Messages
        except ImportError as exc:
            raise ImportError(
                "The 'anthropic' package is required for AnthropicInstrumentor. "
                "Install it with: pip install anthropic"
            ) from exc

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        # ---- Patch sync Messages.create ----
        self._original_sync_create = Messages.create

        instrumentor_ref = self  # prevent closure over 'self' name collision

        def _patched_sync_create(messages_self: Any, **kwargs: Any) -> Any:
            return instrumentor_ref._wrapped_sync_create(
                messages_self, kwargs
            )

        Messages.create = _patched_sync_create  # type: ignore[assignment]

        # ---- Patch async AsyncMessages.create ----
        self._original_async_create = AsyncMessages.create

        async def _patched_async_create(messages_self: Any, **kwargs: Any) -> Any:
            return await instrumentor_ref._wrapped_async_create(
                messages_self, kwargs
            )

        AsyncMessages.create = _patched_async_create  # type: ignore[assignment]

        # ---- Patch sync Messages.stream (context-manager helper) ----
        if hasattr(Messages, "stream"):
            self._original_sync_stream = Messages.stream

            def _patched_sync_stream(messages_self: Any, **kwargs: Any) -> Any:
                return instrumentor_ref._wrapped_sync_stream(
                    messages_self, kwargs
                )

            Messages.stream = _patched_sync_stream  # type: ignore[assignment]

        # ---- Patch async AsyncMessages.stream ----
        if hasattr(AsyncMessages, "stream"):
            self._original_async_stream = AsyncMessages.stream

            def _patched_async_stream(messages_self: Any, **kwargs: Any) -> Any:
                return instrumentor_ref._wrapped_async_stream(
                    messages_self, kwargs
                )

            AsyncMessages.stream = _patched_async_stream  # type: ignore[assignment]

        self._instrumented = True
        logger.info("AnthropicInstrumentor: anthropic SDK instrumented.")

    def uninstrument(self) -> None:
        """Remove AITF patches and restore original SDK methods.

        This method is idempotent.
        """
        if not self._instrumented:
            return

        try:
            from anthropic.resources.messages import AsyncMessages, Messages
        except ImportError:
            self._instrumented = False
            return

        if self._original_sync_create is not None:
            Messages.create = self._original_sync_create  # type: ignore[assignment]
            self._original_sync_create = None

        if self._original_async_create is not None:
            AsyncMessages.create = self._original_async_create  # type: ignore[assignment]
            self._original_async_create = None

        if self._original_sync_stream is not None:
            Messages.stream = self._original_sync_stream  # type: ignore[assignment]
            self._original_sync_stream = None

        if self._original_async_stream is not None:
            AsyncMessages.stream = self._original_async_stream  # type: ignore[assignment]
            self._original_async_stream = None

        self._tracer = None
        self._instrumented = False
        logger.info("AnthropicInstrumentor: anthropic SDK uninstrumented.")

    @property
    def is_instrumented(self) -> bool:
        """Return ``True`` if the SDK is currently patched."""
        return self._instrumented

    # ------------------------------------------------------------------
    # Internal wrapper implementations
    # ------------------------------------------------------------------

    def _get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    def _make_span_name(self, kwargs: Dict[str, Any]) -> str:
        model = kwargs.get("model", "unknown")
        return f"chat {model}"

    def _wrapped_sync_create(
        self, messages_self: Any, kwargs: Dict[str, Any]
    ) -> Any:
        """Sync wrapper for ``Messages.create``."""
        tracer = self._get_tracer()
        span_name = self._make_span_name(kwargs)
        attributes = _extract_request_attributes(kwargs)
        start_time = time.monotonic()

        # Capture prompt content if enabled
        if self._capture_content:
            messages = kwargs.get("messages", [])
            if messages:
                prompt_text = _extract_message_content_text(messages)
                # Will be added as an event after span starts

        span = tracer.start_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        )
        token = trace.set_span_in_context(span)
        ctx_token = otel_context.attach(token)

        if self._capture_content:
            messages = kwargs.get("messages", [])
            if messages:
                prompt_text = _extract_message_content_text(messages)
                span.add_event(
                    "gen_ai.content.prompt",
                    attributes={GenAIAttributes.PROMPT: prompt_text},
                )

        is_streaming = kwargs.get("stream", False)

        try:
            assert self._original_sync_create is not None
            response = self._original_sync_create(messages_self, **kwargs)

            if is_streaming:
                # Return an instrumented stream wrapper instead of finalizing
                return _InstrumentedStream(
                    stream=response,
                    span=span,
                    start_time=start_time,
                    otel_token=ctx_token,
                    capture_content=self._capture_content,
                    pricing=self._pricing,
                )

            # Non-streaming: enrich span and finish immediately.
            _set_response_attributes(
                span, response, start_time, self._capture_content, self._pricing
            )
            span.set_status(StatusCode.OK)
            span.end()
            otel_context.detach(ctx_token)
            return response

        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            span.end()
            otel_context.detach(ctx_token)
            raise

    async def _wrapped_async_create(
        self, messages_self: Any, kwargs: Dict[str, Any]
    ) -> Any:
        """Async wrapper for ``AsyncMessages.create``."""
        tracer = self._get_tracer()
        span_name = self._make_span_name(kwargs)
        attributes = _extract_request_attributes(kwargs)
        start_time = time.monotonic()

        span = tracer.start_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        )
        token = trace.set_span_in_context(span)
        ctx_token = otel_context.attach(token)

        if self._capture_content:
            messages = kwargs.get("messages", [])
            if messages:
                prompt_text = _extract_message_content_text(messages)
                span.add_event(
                    "gen_ai.content.prompt",
                    attributes={GenAIAttributes.PROMPT: prompt_text},
                )

        is_streaming = kwargs.get("stream", False)

        try:
            assert self._original_async_create is not None
            response = await self._original_async_create(messages_self, **kwargs)

            if is_streaming:
                return _InstrumentedAsyncStream(
                    stream=response,
                    span=span,
                    start_time=start_time,
                    otel_token=ctx_token,
                    capture_content=self._capture_content,
                    pricing=self._pricing,
                )

            _set_response_attributes(
                span, response, start_time, self._capture_content, self._pricing
            )
            span.set_status(StatusCode.OK)
            span.end()
            otel_context.detach(ctx_token)
            return response

        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            span.end()
            otel_context.detach(ctx_token)
            raise

    def _wrapped_sync_stream(
        self, messages_self: Any, kwargs: Dict[str, Any]
    ) -> Any:
        """Sync wrapper for ``Messages.stream()`` context-manager helper."""
        tracer = self._get_tracer()
        # The stream() helper implicitly sets stream=True.
        kwargs["stream"] = True
        span_name = self._make_span_name(kwargs)
        attributes = _extract_request_attributes(kwargs)
        start_time = time.monotonic()

        span = tracer.start_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        )
        token = trace.set_span_in_context(span)
        ctx_token = otel_context.attach(token)

        if self._capture_content:
            messages = kwargs.get("messages", [])
            if messages:
                prompt_text = _extract_message_content_text(messages)
                span.add_event(
                    "gen_ai.content.prompt",
                    attributes={GenAIAttributes.PROMPT: prompt_text},
                )

        try:
            assert self._original_sync_stream is not None
            stream = self._original_sync_stream(messages_self, **kwargs)
            return _InstrumentedStream(
                stream=stream,
                span=span,
                start_time=start_time,
                otel_token=ctx_token,
                capture_content=self._capture_content,
                pricing=self._pricing,
            )
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            span.end()
            otel_context.detach(ctx_token)
            raise

    def _wrapped_async_stream(
        self, messages_self: Any, kwargs: Dict[str, Any]
    ) -> Any:
        """Async wrapper for ``AsyncMessages.stream()`` context-manager helper."""
        tracer = self._get_tracer()
        kwargs["stream"] = True
        span_name = self._make_span_name(kwargs)
        attributes = _extract_request_attributes(kwargs)
        start_time = time.monotonic()

        span = tracer.start_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        )
        token = trace.set_span_in_context(span)
        ctx_token = otel_context.attach(token)

        if self._capture_content:
            messages = kwargs.get("messages", [])
            if messages:
                prompt_text = _extract_message_content_text(messages)
                span.add_event(
                    "gen_ai.content.prompt",
                    attributes={GenAIAttributes.PROMPT: prompt_text},
                )

        try:
            assert self._original_async_stream is not None
            stream = self._original_async_stream(messages_self, **kwargs)
            return _InstrumentedAsyncStream(
                stream=stream,
                span=span,
                start_time=start_time,
                otel_token=ctx_token,
                capture_content=self._capture_content,
                pricing=self._pricing,
            )
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            span.record_exception(exc)
            span.end()
            otel_context.detach(ctx_token)
            raise
