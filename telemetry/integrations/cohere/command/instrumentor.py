"""AITF Cohere Command Instrumentor.

Wraps Cohere SDK chat and generation methods with OpenTelemetry tracing
using AITF semantic conventions. Supports both the v2 SDK
(``cohere.ClientV2``, recommended) and the v1 SDK (``cohere.Client``).

Supports streaming, tool use, RAG with connectors, and citation tracking.

Usage (v2 SDK -- recommended)::

    from integrations.cohere.command import CohereCommandInstrumentor

    instrumentor = CohereCommandInstrumentor()
    instrumentor.instrument()

    import cohere
    client = cohere.ClientV2(api_key="...")

    response = client.chat(
        model="command-r-plus-08-2024",
        messages=[{"role": "user", "content": "Explain quantum computing"}],
    )

Usage (v1 SDK -- legacy)::

    from integrations.cohere.command import CohereCommandInstrumentor

    instrumentor = CohereCommandInstrumentor()
    instrumentor.instrument()

    import cohere
    client = cohere.Client(api_key="...")

    # All calls are now automatically traced:
    response = client.chat(
        model="command-r-plus",
        message="Explain quantum computing",
    )

    # Streaming is also traced:
    stream = client.chat_stream(
        model="command-r-plus",
        message="Tell me a story",
    )
    for event in stream:
        print(event)

    # To remove instrumentation:
    instrumentor.uninstrument()

Attributes Emitted:
    - ``gen_ai.system`` = ``"cohere"``
    - ``gen_ai.operation.name`` = ``"chat"`` or ``"text_completion"``
    - ``gen_ai.request.model``, ``gen_ai.request.temperature``, etc.
    - ``gen_ai.response.id``, ``gen_ai.response.model``, ``gen_ai.response.finish_reasons``
    - ``gen_ai.usage.input_tokens``, ``gen_ai.usage.output_tokens``
    - ``gen_ai.request.tools``, ``gen_ai.tool.name``, ``gen_ai.tool.call_id``
    - ``aitf.cohere.connectors`` (RAG connector IDs)
    - ``aitf.cohere.citations.count`` (number of citations returned)
    - ``aitf.cohere.search_queries.count`` (number of search queries generated)
    - ``aitf.cohere.documents.count`` (number of documents provided or retrieved)
    - ``aitf.latency.*`` timing attributes
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Collection

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

_TRACER_NAME = "aitf.integrations.cohere.command"

# Cohere-specific attribute keys
_COHERE_CONNECTORS = "aitf.cohere.connectors"
_COHERE_CITATIONS_COUNT = "aitf.cohere.citations.count"
_COHERE_SEARCH_QUERIES_COUNT = "aitf.cohere.search_queries.count"
_COHERE_DOCUMENTS_COUNT = "aitf.cohere.documents.count"
_COHERE_PREAMBLE = "aitf.cohere.preamble"
_COHERE_CONVERSATION_ID = "aitf.cohere.conversation_id"
_COHERE_IS_SEARCH_REQUIRED = "aitf.cohere.is_search_required"


class CohereCommandInstrumentor:
    """Auto-instrumentor for the Cohere Command API.

    Supports both the Cohere v2 SDK (``cohere.ClientV2``, recommended)
    and the v1 SDK (``cohere.Client``). The instrumentor patches whichever
    classes are available.

    v2 SDK methods patched:
      - ``cohere.ClientV2.chat``
      - ``cohere.ClientV2.chat_stream``

    v1 SDK methods patched (legacy):
      - ``cohere.Client.chat``
      - ``cohere.Client.chat_stream``
      - ``cohere.Client.generate``

    Args:
        tracer_provider: Optional OpenTelemetry TracerProvider. If not
            provided, the global TracerProvider is used.

    Example (v2 SDK -- recommended)::

        instrumentor = CohereCommandInstrumentor()
        instrumentor.instrument()

        import cohere
        co = cohere.ClientV2(api_key="YOUR_KEY")

        # This call is now traced automatically
        response = co.chat(
            model="command-r-plus-08-2024",
            messages=[{"role": "user", "content": "Hello"}],
        )

        instrumentor.uninstrument()

    Example (v1 SDK -- legacy)::

        instrumentor = CohereCommandInstrumentor()
        instrumentor.instrument()

        import cohere
        co = cohere.Client(api_key="YOUR_KEY")
        response = co.chat(model="command-r-plus", message="Hello")

        instrumentor.uninstrument()
    """

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._original_chat: Any = None
        self._original_chat_stream: Any = None
        self._original_generate: Any = None
        # v2 SDK originals
        self._original_v2_chat: Any = None
        self._original_v2_chat_stream: Any = None

    @property
    def is_instrumented(self) -> bool:
        """Return whether instrumentation is currently active."""
        return self._instrumented

    def instrument(self) -> None:
        """Enable instrumentation by patching Cohere client methods.

        Patches ``cohere.ClientV2`` (v2 SDK) if available, and always
        patches ``cohere.Client`` (v1 SDK) for backward compatibility.

        Raises:
            ImportError: If the ``cohere`` package is not installed.
        """
        if self._instrumented:
            logger.warning("CohereCommandInstrumentor is already instrumented.")
            return

        try:
            import cohere  # noqa: F811
        except ImportError as exc:
            raise ImportError(
                "The 'cohere' package is required for CohereCommandInstrumentor. "
                "Install it with: pip install cohere"
            ) from exc

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        instrumentor = self

        def _instrumented_chat(client_self: Any, *args: Any, **kwargs: Any) -> Any:
            return instrumentor._trace_chat(client_self, args, kwargs, stream=False)

        def _instrumented_chat_stream(client_self: Any, *args: Any, **kwargs: Any) -> Any:
            return instrumentor._trace_chat(client_self, args, kwargs, stream=True)

        def _instrumented_generate(client_self: Any, *args: Any, **kwargs: Any) -> Any:
            return instrumentor._trace_generate(client_self, args, kwargs)

        # Patch v2 SDK (ClientV2) if available -- this is the recommended SDK
        if hasattr(cohere, "ClientV2"):
            self._original_v2_chat = cohere.ClientV2.chat
            self._original_v2_chat_stream = getattr(
                cohere.ClientV2, "chat_stream", None
            )
            cohere.ClientV2.chat = _instrumented_chat
            if self._original_v2_chat_stream is not None:
                cohere.ClientV2.chat_stream = _instrumented_chat_stream
            logger.info("Patched cohere.ClientV2 (v2 SDK).")

        # Patch v1 SDK (Client) for backward compatibility
        self._original_chat = cohere.Client.chat
        self._original_chat_stream = getattr(cohere.Client, "chat_stream", None)
        self._original_generate = cohere.Client.generate

        cohere.Client.chat = _instrumented_chat
        if self._original_chat_stream is not None:
            cohere.Client.chat_stream = _instrumented_chat_stream
        cohere.Client.generate = _instrumented_generate

        self._instrumented = True
        logger.info("CohereCommandInstrumentor instrumentation enabled.")

    def uninstrument(self) -> None:
        """Remove instrumentation and restore original Cohere client methods."""
        if not self._instrumented:
            logger.warning("CohereCommandInstrumentor is not currently instrumented.")
            return

        try:
            import cohere  # noqa: F811
        except ImportError:
            return

        # Restore v2 SDK
        if hasattr(cohere, "ClientV2"):
            if self._original_v2_chat is not None:
                cohere.ClientV2.chat = self._original_v2_chat
            if self._original_v2_chat_stream is not None:
                cohere.ClientV2.chat_stream = self._original_v2_chat_stream

        # Restore v1 SDK
        if self._original_chat is not None:
            cohere.Client.chat = self._original_chat
        if self._original_chat_stream is not None:
            cohere.Client.chat_stream = self._original_chat_stream
        if self._original_generate is not None:
            cohere.Client.generate = self._original_generate

        self._original_v2_chat = None
        self._original_v2_chat_stream = None
        self._original_chat = None
        self._original_chat_stream = None
        self._original_generate = None
        self._tracer = None
        self._instrumented = False
        logger.info("CohereCommandInstrumentor instrumentation disabled.")

    def _get_tracer(self) -> trace.Tracer:
        """Return the active tracer, initializing if needed."""
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    def _trace_chat(
        self,
        client: Any,
        args: tuple,
        kwargs: dict[str, Any],
        stream: bool,
    ) -> Any:
        """Wrap a ``cohere.Client.chat`` or ``chat_stream`` call with tracing."""
        tracer = self._get_tracer()

        model = kwargs.get("model", "command-r")
        message = kwargs.get("message", "")
        temperature = kwargs.get("temperature")
        max_tokens = kwargs.get("max_tokens")
        tools = kwargs.get("tools")
        connectors = kwargs.get("connectors")
        documents = kwargs.get("documents")
        preamble = kwargs.get("preamble")
        conversation_id = kwargs.get("conversation_id")
        tool_results = kwargs.get("tool_results")

        span_name = f"chat {model}"
        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: GenAIAttributes.System.COHERE,
            GenAIAttributes.OPERATION_NAME: GenAIAttributes.Operation.CHAT,
            GenAIAttributes.REQUEST_MODEL: model,
            GenAIAttributes.REQUEST_STREAM: stream,
        }

        if temperature is not None:
            attributes[GenAIAttributes.REQUEST_TEMPERATURE] = float(temperature)
        if max_tokens is not None:
            attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = int(max_tokens)

        # Tool definitions
        if tools:
            tool_names = []
            for tool in tools:
                name = tool.get("name", "") if isinstance(tool, dict) else getattr(tool, "name", "")
                tool_names.append(name)
            attributes[GenAIAttributes.REQUEST_TOOLS] = json.dumps(
                [{"name": n} for n in tool_names]
            )

        # RAG connectors
        if connectors:
            connector_ids = []
            for conn in connectors:
                cid = conn.get("id", "") if isinstance(conn, dict) else getattr(conn, "id", "")
                connector_ids.append(cid)
            attributes[_COHERE_CONNECTORS] = json.dumps(connector_ids)

        # Documents for RAG
        if documents:
            attributes[_COHERE_DOCUMENTS_COUNT] = len(documents)

        # Preamble / system prompt
        if preamble:
            attributes[_COHERE_PREAMBLE] = preamble

        # Conversation ID for multi-turn
        if conversation_id:
            attributes[_COHERE_CONVERSATION_ID] = conversation_id

        start_time = time.monotonic()

        with tracer.start_as_current_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            try:
                if stream:
                    return self._handle_stream_response(
                        span, start_time, client, args, kwargs
                    )
                else:
                    response = self._original_chat(client, *args, **kwargs)
                    self._record_chat_response(span, response, start_time)
                    span.set_status(StatusCode.OK)
                    return response
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    def _handle_stream_response(
        self,
        span: trace.Span,
        start_time: float,
        client: Any,
        args: tuple,
        kwargs: dict[str, Any],
    ) -> Any:
        """Wrap a streaming response to capture telemetry from events.

        Yields events from the underlying stream while accumulating token
        usage and recording time-to-first-token.
        """
        original = self._original_chat_stream or self._original_chat
        stream_response = original(client, *args, **kwargs)

        first_token_recorded = False
        accumulated_text = ""
        final_response = None

        class InstrumentedStream:
            """Proxy iterator that instruments the Cohere streaming response."""

            def __init__(self, inner: Any, parent_span: trace.Span) -> None:
                self._inner = inner
                self._span = parent_span

            def __iter__(self) -> "InstrumentedStream":
                return self

            def __next__(self) -> Any:
                nonlocal first_token_recorded, accumulated_text, final_response
                try:
                    event = next(self._inner)
                except StopIteration:
                    # Stream exhausted; finalize span
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    self._span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)
                    if final_response is not None:
                        _record_chat_response_attrs(self._span, final_response)
                    self._span.set_status(StatusCode.OK)
                    raise

                # Record time-to-first-token on the first text event
                event_type = getattr(event, "event_type", None)
                if event_type == "text-generation" and not first_token_recorded:
                    ttft = (time.monotonic() - start_time) * 1000
                    self._span.set_attribute(
                        LatencyAttributes.TIME_TO_FIRST_TOKEN_MS, ttft
                    )
                    first_token_recorded = True

                if event_type == "text-generation":
                    text = getattr(event, "text", "")
                    accumulated_text += text

                # Capture the final stream-end event for metadata
                if event_type == "stream-end":
                    final_response = getattr(event, "response", None)

                return event

            def __enter__(self) -> "InstrumentedStream":
                if hasattr(self._inner, "__enter__"):
                    self._inner.__enter__()
                return self

            def __exit__(self, *exc_info: Any) -> None:
                if hasattr(self._inner, "__exit__"):
                    self._inner.__exit__(*exc_info)

        return InstrumentedStream(stream_response, span)

    def _record_chat_response(
        self,
        span: trace.Span,
        response: Any,
        start_time: float,
    ) -> None:
        """Extract and record attributes from a non-streaming chat response."""
        elapsed_ms = (time.monotonic() - start_time) * 1000
        span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)
        _record_chat_response_attrs(span, response)

    def _trace_generate(
        self,
        client: Any,
        args: tuple,
        kwargs: dict[str, Any],
    ) -> Any:
        """Wrap a ``cohere.Client.generate`` call with tracing."""
        tracer = self._get_tracer()

        model = kwargs.get("model", "command-r")
        prompt = kwargs.get("prompt", "")
        temperature = kwargs.get("temperature")
        max_tokens = kwargs.get("max_tokens")
        num_generations = kwargs.get("num_generations", 1)
        stop_sequences = kwargs.get("stop_sequences")
        frequency_penalty = kwargs.get("frequency_penalty")
        presence_penalty = kwargs.get("presence_penalty")
        seed = kwargs.get("seed")

        span_name = f"text_completion {model}"
        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: GenAIAttributes.System.COHERE,
            GenAIAttributes.OPERATION_NAME: GenAIAttributes.Operation.TEXT_COMPLETION,
            GenAIAttributes.REQUEST_MODEL: model,
        }

        if temperature is not None:
            attributes[GenAIAttributes.REQUEST_TEMPERATURE] = float(temperature)
        if max_tokens is not None:
            attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = int(max_tokens)
        if stop_sequences:
            attributes[GenAIAttributes.REQUEST_STOP_SEQUENCES] = json.dumps(stop_sequences)
        if frequency_penalty is not None:
            attributes[GenAIAttributes.REQUEST_FREQUENCY_PENALTY] = float(frequency_penalty)
        if presence_penalty is not None:
            attributes[GenAIAttributes.REQUEST_PRESENCE_PENALTY] = float(presence_penalty)
        if seed is not None:
            attributes[GenAIAttributes.REQUEST_SEED] = int(seed)

        start_time = time.monotonic()

        with tracer.start_as_current_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            try:
                response = self._original_generate(client, *args, **kwargs)

                elapsed_ms = (time.monotonic() - start_time) * 1000
                span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

                # Extract response metadata
                response_id = getattr(response, "id", None)
                if response_id:
                    span.set_attribute(GenAIAttributes.RESPONSE_ID, response_id)

                # Token usage from meta
                meta = getattr(response, "meta", None)
                if meta is not None:
                    billed_units = getattr(meta, "billed_units", None)
                    if billed_units is not None:
                        input_tokens = getattr(billed_units, "input_tokens", 0) or 0
                        output_tokens = getattr(billed_units, "output_tokens", 0) or 0
                        span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
                        span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens)

                # Extract generations
                generations = getattr(response, "generations", [])
                if generations:
                    finish_reasons = [
                        getattr(gen, "finish_reason", "COMPLETE") for gen in generations
                    ]
                    span.set_attribute(
                        GenAIAttributes.RESPONSE_FINISH_REASONS,
                        json.dumps(finish_reasons),
                    )

                    # Record completion text as event
                    for i, gen in enumerate(generations):
                        text = getattr(gen, "text", "")
                        span.add_event(
                            "gen_ai.content.completion",
                            attributes={
                                GenAIAttributes.COMPLETION: text,
                                "gen_ai.generation.index": i,
                            },
                        )

                span.set_status(StatusCode.OK)
                return response

            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


def _record_chat_response_attrs(span: trace.Span, response: Any) -> None:
    """Record standard attributes from a Cohere chat response object.

    Works for both the final non-streaming response and the ``stream-end``
    event's embedded response.
    """
    if response is None:
        return

    # Response ID
    response_id = getattr(response, "id", None) or getattr(response, "response_id", None)
    if response_id:
        span.set_attribute(GenAIAttributes.RESPONSE_ID, str(response_id))

    # Finish reason
    finish_reason = getattr(response, "finish_reason", None)
    if finish_reason:
        span.set_attribute(
            GenAIAttributes.RESPONSE_FINISH_REASONS,
            json.dumps([str(finish_reason)]),
        )

    # Token usage
    meta = getattr(response, "meta", None)
    if meta is not None:
        billed_units = getattr(meta, "billed_units", None)
        if billed_units is not None:
            input_tokens = getattr(billed_units, "input_tokens", 0) or 0
            output_tokens = getattr(billed_units, "output_tokens", 0) or 0
            span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
            span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens)

        tokens = getattr(meta, "tokens", None)
        if tokens is not None:
            input_tokens = getattr(tokens, "input_tokens", 0) or 0
            output_tokens = getattr(tokens, "output_tokens", 0) or 0
            span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
            span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens)

    # Tool calls
    tool_calls = getattr(response, "tool_calls", None)
    if tool_calls:
        for tc in tool_calls:
            tc_name = getattr(tc, "name", "unknown")
            tc_id = getattr(tc, "id", "") or getattr(tc, "name", "")
            tc_params = getattr(tc, "parameters", {})
            span.add_event(
                "gen_ai.tool.call",
                attributes={
                    GenAIAttributes.TOOL_NAME: str(tc_name),
                    GenAIAttributes.TOOL_CALL_ID: str(tc_id),
                    GenAIAttributes.TOOL_ARGUMENTS: json.dumps(
                        tc_params if isinstance(tc_params, dict) else str(tc_params)
                    ),
                },
            )

    # Citations (Cohere RAG feature)
    citations = getattr(response, "citations", None)
    if citations:
        span.set_attribute(_COHERE_CITATIONS_COUNT, len(citations))
        for i, citation in enumerate(citations):
            cite_text = getattr(citation, "text", "")
            doc_ids = getattr(citation, "document_ids", []) or []
            span.add_event(
                "aitf.cohere.citation",
                attributes={
                    "aitf.cohere.citation.index": i,
                    "aitf.cohere.citation.text": str(cite_text),
                    "aitf.cohere.citation.document_ids": json.dumps(
                        [str(d) for d in doc_ids]
                    ),
                },
            )

    # Search queries generated for RAG
    search_queries = getattr(response, "search_queries", None)
    if search_queries:
        span.set_attribute(_COHERE_SEARCH_QUERIES_COUNT, len(search_queries))
        for i, sq in enumerate(search_queries):
            query_text = getattr(sq, "text", "") or getattr(sq, "query", "")
            span.add_event(
                "aitf.cohere.search_query",
                attributes={
                    "aitf.cohere.search_query.index": i,
                    "aitf.cohere.search_query.text": str(query_text),
                },
            )

    # Documents retrieved or provided
    documents = getattr(response, "documents", None)
    if documents:
        span.set_attribute(_COHERE_DOCUMENTS_COUNT, len(documents))

    # is_search_required flag
    is_search_required = getattr(response, "is_search_required", None)
    if is_search_required is not None:
        span.set_attribute(_COHERE_IS_SEARCH_REQUIRED, bool(is_search_required))

    # Completion text
    text = getattr(response, "text", None)
    if text:
        span.add_event(
            "gen_ai.content.completion",
            attributes={GenAIAttributes.COMPLETION: str(text)},
        )
