"""AITF Cohere Embed Instrumentor.

Wraps ``cohere.Client().embed()`` with OpenTelemetry tracing using AITF
semantic conventions. Tracks embedding dimensions, input types, truncation
options, and token usage.

Usage::

    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    from integrations.cohere.embed import CohereEmbedInstrumentor

    instrumentor = CohereEmbedInstrumentor(tracer_provider=provider)
    instrumentor.instrument()

    import cohere
    client = cohere.Client(api_key="...")

    # All embed calls are now automatically traced:
    response = client.embed(
        model="embed-english-v3.0",
        texts=["Hello world", "Goodbye world"],
        input_type="search_document",
        embedding_types=["float"],
    )

    # To remove instrumentation:
    instrumentor.uninstrument()

Attributes Emitted:
    - ``gen_ai.system`` = ``"cohere"``
    - ``gen_ai.operation.name`` = ``"embeddings"``
    - ``gen_ai.request.model``
    - ``gen_ai.usage.input_tokens``
    - ``aitf.cohere.embed.input_type`` (``search_document``, ``search_query``,
      ``classification``, ``clustering``)
    - ``aitf.cohere.embed.truncate`` (``NONE``, ``START``, ``END``)
    - ``aitf.cohere.embed.dimensions`` (output embedding dimensions)
    - ``aitf.cohere.embed.texts_count`` (number of input texts)
    - ``aitf.cohere.embed.embedding_types`` (requested embedding types)
    - ``aitf.latency.*`` timing attributes
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.instrumentation import LLMInstrumentor
from aitf.semantic_conventions.attributes import (
    GenAIAttributes,
    LatencyAttributes,
)

logger = logging.getLogger(__name__)

_TRACER_NAME = "aitf.integrations.cohere.embed"

# Cohere Embed-specific attribute keys
_COHERE_EMBED_INPUT_TYPE = "aitf.cohere.embed.input_type"
_COHERE_EMBED_TRUNCATE = "aitf.cohere.embed.truncate"
_COHERE_EMBED_DIMENSIONS = "aitf.cohere.embed.dimensions"
_COHERE_EMBED_TEXTS_COUNT = "aitf.cohere.embed.texts_count"
_COHERE_EMBED_EMBEDDING_TYPES = "aitf.cohere.embed.embedding_types"


class CohereEmbedInstrumentor:
    """Auto-instrumentor for the Cohere Embed API.

    Monkey-patches ``cohere.Client.embed`` to emit OpenTelemetry spans with
    AITF semantic conventions for every embedding request.

    Args:
        tracer_provider: Optional OpenTelemetry TracerProvider. If not
            provided, the global TracerProvider is used.

    Example::

        instrumentor = CohereEmbedInstrumentor()
        instrumentor.instrument()

        import cohere
        co = cohere.Client(api_key="YOUR_KEY")

        # Traced automatically
        result = co.embed(
            model="embed-english-v3.0",
            texts=["search query here"],
            input_type="search_query",
        )

        print(f"Embedding dimensions: {len(result.embeddings[0])}")

        instrumentor.uninstrument()
    """

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._original_embed: Any = None

    @property
    def is_instrumented(self) -> bool:
        """Return whether instrumentation is currently active."""
        return self._instrumented

    def instrument(self) -> None:
        """Enable instrumentation by patching ``cohere.Client.embed``.

        Raises:
            ImportError: If the ``cohere`` package is not installed.
        """
        if self._instrumented:
            logger.warning("CohereEmbedInstrumentor is already instrumented.")
            return

        try:
            import cohere  # noqa: F811
        except ImportError as exc:
            raise ImportError(
                "The 'cohere' package is required for CohereEmbedInstrumentor. "
                "Install it with: pip install cohere"
            ) from exc

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        # Preserve original method
        self._original_embed = cohere.Client.embed

        instrumentor = self

        def _instrumented_embed(client_self: Any, *args: Any, **kwargs: Any) -> Any:
            return instrumentor._trace_embed(client_self, args, kwargs)

        cohere.Client.embed = _instrumented_embed

        self._instrumented = True
        logger.info("CohereEmbedInstrumentor instrumentation enabled.")

    def uninstrument(self) -> None:
        """Remove instrumentation and restore original ``cohere.Client.embed``."""
        if not self._instrumented:
            logger.warning("CohereEmbedInstrumentor is not currently instrumented.")
            return

        try:
            import cohere  # noqa: F811
        except ImportError:
            return

        if self._original_embed is not None:
            cohere.Client.embed = self._original_embed

        self._original_embed = None
        self._tracer = None
        self._instrumented = False
        logger.info("CohereEmbedInstrumentor instrumentation disabled.")

    def _get_tracer(self) -> trace.Tracer:
        """Return the active tracer, initializing if needed."""
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    def _trace_embed(
        self,
        client: Any,
        args: tuple,
        kwargs: dict[str, Any],
    ) -> Any:
        """Wrap a ``cohere.Client.embed`` call with tracing."""
        tracer = self._get_tracer()

        model = kwargs.get("model", "embed-english-v3.0")
        texts = kwargs.get("texts", [])
        input_type = kwargs.get("input_type")
        truncate = kwargs.get("truncate")
        embedding_types = kwargs.get("embedding_types")

        span_name = f"embeddings {model}"
        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: GenAIAttributes.System.COHERE,
            GenAIAttributes.OPERATION_NAME: GenAIAttributes.Operation.EMBEDDINGS,
            GenAIAttributes.REQUEST_MODEL: model,
        }

        # Number of input texts
        if texts:
            attributes[_COHERE_EMBED_TEXTS_COUNT] = len(texts)

        # Input type classification
        if input_type:
            attributes[_COHERE_EMBED_INPUT_TYPE] = str(input_type)

        # Truncation strategy
        if truncate:
            attributes[_COHERE_EMBED_TRUNCATE] = str(truncate)

        # Requested embedding types (float, int8, uint8, binary, ubinary)
        if embedding_types:
            attributes[_COHERE_EMBED_EMBEDDING_TYPES] = json.dumps(
                [str(et) for et in embedding_types]
            )

        start_time = time.monotonic()

        with tracer.start_as_current_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            try:
                response = self._original_embed(client, *args, **kwargs)

                elapsed_ms = (time.monotonic() - start_time) * 1000
                span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

                self._record_embed_response(span, response)

                span.set_status(StatusCode.OK)
                return response

            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    def _record_embed_response(self, span: trace.Span, response: Any) -> None:
        """Extract and record attributes from a Cohere embed response."""
        if response is None:
            return

        # Response ID
        response_id = getattr(response, "id", None)
        if response_id:
            span.set_attribute(GenAIAttributes.RESPONSE_ID, str(response_id))

        # Token usage from meta
        meta = getattr(response, "meta", None)
        if meta is not None:
            billed_units = getattr(meta, "billed_units", None)
            if billed_units is not None:
                input_tokens = getattr(billed_units, "input_tokens", 0) or 0
                span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)

            tokens = getattr(meta, "tokens", None)
            if tokens is not None:
                input_tokens = getattr(tokens, "input_tokens", 0) or 0
                span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)

        # Embedding dimensions from the response data
        embeddings = getattr(response, "embeddings", None)
        if embeddings is not None:
            # Cohere v2 returns embeddings as a dict keyed by type
            if isinstance(embeddings, dict):
                for emb_type, vectors in embeddings.items():
                    if vectors and len(vectors) > 0:
                        first_vector = vectors[0]
                        if hasattr(first_vector, "__len__"):
                            span.set_attribute(
                                _COHERE_EMBED_DIMENSIONS, len(first_vector)
                            )
                        break
            # Cohere v1 returns embeddings as a list of vectors
            elif isinstance(embeddings, list) and len(embeddings) > 0:
                first_vector = embeddings[0]
                if hasattr(first_vector, "__len__"):
                    span.set_attribute(
                        _COHERE_EMBED_DIMENSIONS, len(first_vector)
                    )

        # Embeddings by type (for v2 API with EmbedByTypeResponse)
        embeddings_by_type = getattr(response, "embeddings_by_type", None)
        if embeddings_by_type is not None and isinstance(embeddings_by_type, dict):
            for emb_type, vectors in embeddings_by_type.items():
                if vectors and len(vectors) > 0:
                    first_vector = vectors[0]
                    if hasattr(first_vector, "__len__"):
                        span.set_attribute(
                            _COHERE_EMBED_DIMENSIONS, len(first_vector)
                        )
                    break
