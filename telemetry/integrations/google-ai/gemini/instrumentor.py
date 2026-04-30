"""AITF Gemini SDK Instrumentor.

Wraps the Google Gemini Python SDKs with AITF telemetry instrumentation.
Supports both the new ``google-genai`` SDK (recommended) and the legacy
``google-generativeai`` SDK. Monkey-patches content generation and token
counting methods to emit OpenTelemetry spans enriched with ``gen_ai.*``
and ``aitf.*`` attributes.

Supported features:
    - Synchronous and asynchronous content generation
    - Streaming responses (``stream=True``)
    - Function calling / tool use
    - Multimodal inputs (text, images, audio, video, files)
    - Safety settings capture
    - Google Search grounding metadata
    - Token usage and cost attribution

SDK compatibility:
    - **google-genai** (>=1.0, recommended): ``google.genai.Client``
      with ``client.models.generate_content()`` and
      ``client.aio.models.generate_content()``.
    - **google-generativeai** (legacy): ``genai.GenerativeModel``
      with ``model.generate_content()`` and
      ``model.generate_content_async()``.

Usage (new google-genai SDK)::

    from aitf.integrations.google_ai.gemini import GeminiInstrumentor

    instrumentor = GeminiInstrumentor()
    instrumentor.instrument()

    from google import genai
    client = genai.Client(api_key="YOUR_API_KEY")

    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents="Explain quantum computing",
    )

    instrumentor.uninstrument()

Usage (legacy google-generativeai SDK)::

    from aitf.integrations.google_ai.gemini import GeminiInstrumentor

    instrumentor = GeminiInstrumentor()
    instrumentor.instrument()

    import google.generativeai as genai
    genai.configure(api_key="YOUR_API_KEY")
    model = genai.GenerativeModel("gemini-2.0-flash")
    response = model.generate_content("Explain quantum computing")

    instrumentor.uninstrument()
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import time
from typing import Any, Callable, Collection, Iterator, Sequence

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

_TRACER_NAME = "integrations.google_ai.gemini"

# ---------------------------------------------------------------------------
# Attribute keys specific to the Gemini integration (under aitf.* namespace)
# ---------------------------------------------------------------------------
_GEMINI_SAFETY_SETTINGS = "google.gemini.safety_settings"
_GEMINI_GROUNDING_ENABLED = "google.gemini.grounding.enabled"
_GEMINI_GROUNDING_SOURCES = "google.gemini.grounding.sources"
_GEMINI_GROUNDING_PASSAGES = "google.gemini.grounding.passages_count"
_GEMINI_CANDIDATE_COUNT = "google.gemini.candidate_count"
_GEMINI_INPUT_MODALITIES = "google.gemini.input_modalities"
_GEMINI_FUNCTION_CALLS = "google.gemini.function_calls"


class GeminiInstrumentor:
    """Instrumentor for Google Gemini Python SDKs.

    Supports both the new ``google-genai`` SDK (recommended, uses
    ``google.genai.Client``) and the legacy ``google-generativeai`` SDK
    (uses ``genai.GenerativeModel``).  The instrumentor tries the new SDK
    first and falls back to the legacy one.

    Args:
        tracer_provider: Optional custom ``TracerProvider``. When *None*,
            the global provider is used.

    Usage::

        instrumentor = GeminiInstrumentor()
        instrumentor.instrument()

        # ... application code using google.genai or google.generativeai ...

        instrumentor.uninstrument()
    """

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._sdk_variant: str | None = None  # "google-genai" or "legacy"

        # Original methods to restore on uninstrument()
        self._original_generate_content: Callable | None = None
        self._original_generate_content_async: Callable | None = None
        self._original_count_tokens: Callable | None = None
        # New SDK originals
        self._original_genai_generate: Callable | None = None
        self._original_genai_aio_generate: Callable | None = None
        self._original_genai_count_tokens: Callable | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Monkey-patch a Gemini SDK to emit AITF telemetry.

        Tries ``google-genai`` (new SDK) first. If not installed, falls
        back to ``google-generativeai`` (legacy SDK).

        This method is idempotent -- calling it multiple times has no
        additional effect.

        Raises:
            ImportError: If neither Gemini SDK is installed.
        """
        if self._instrumented:
            logger.debug("GeminiInstrumentor is already active; skipping.")
            return

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        # Try new google-genai SDK first (recommended)
        try:
            self._instrument_new_sdk()
            self._sdk_variant = "google-genai"
            self._instrumented = True
            logger.info(
                "GeminiInstrumentor activated (google-genai SDK)."
            )
            return
        except ImportError:
            pass

        # Fall back to legacy google-generativeai SDK
        try:
            self._instrument_legacy_sdk()
            self._sdk_variant = "legacy"
            self._instrumented = True
            logger.info(
                "GeminiInstrumentor activated (legacy google-generativeai SDK)."
            )
            return
        except ImportError:
            pass

        raise ImportError(
            "A Google Gemini SDK is required. Install one of:\n"
            "  pip install google-genai          # recommended\n"
            "  pip install google-generativeai   # legacy"
        )

    def _instrument_new_sdk(self) -> None:
        """Patch the new ``google-genai`` SDK (``google.genai.Client``)."""
        from google.genai import models as genai_models

        # Patch Models.generate_content (sync)
        self._original_genai_generate = genai_models.Models.generate_content
        genai_models.Models.generate_content = self._wrap_generate_content(
            self._original_genai_generate,
        )

        # Patch AsyncModels.generate_content (async)
        from google.genai import models as _m
        if hasattr(_m, "AsyncModels"):
            self._original_genai_aio_generate = (
                _m.AsyncModels.generate_content
            )
            _m.AsyncModels.generate_content = (
                self._wrap_generate_content_async(
                    self._original_genai_aio_generate,
                )
            )

        # Patch count_tokens
        if hasattr(genai_models.Models, "count_tokens"):
            self._original_genai_count_tokens = (
                genai_models.Models.count_tokens
            )
            genai_models.Models.count_tokens = self._wrap_count_tokens(
                self._original_genai_count_tokens,
            )

    def _instrument_legacy_sdk(self) -> None:
        """Patch the legacy ``google-generativeai`` SDK."""
        import google.generativeai as genai

        model_cls = genai.GenerativeModel

        self._original_generate_content = model_cls.generate_content
        self._original_generate_content_async = (
            model_cls.generate_content_async
        )
        self._original_count_tokens = model_cls.count_tokens

        model_cls.generate_content = self._wrap_generate_content(
            self._original_generate_content,
        )
        model_cls.generate_content_async = (
            self._wrap_generate_content_async(
                self._original_generate_content_async,
            )
        )
        model_cls.count_tokens = self._wrap_count_tokens(
            self._original_count_tokens,
        )

    def uninstrument(self) -> None:
        """Remove all monkey-patches and restore original SDK behaviour.

        This method is idempotent.
        """
        if not self._instrumented:
            return

        if self._sdk_variant == "google-genai":
            self._uninstrument_new_sdk()
        elif self._sdk_variant == "legacy":
            self._uninstrument_legacy_sdk()

        self._tracer = None
        self._instrumented = False
        self._sdk_variant = None
        logger.info("GeminiInstrumentor deactivated.")

    def _uninstrument_new_sdk(self) -> None:
        """Restore the new google-genai SDK."""
        try:
            from google.genai import models as genai_models
        except ImportError:
            return

        if self._original_genai_generate is not None:
            genai_models.Models.generate_content = (
                self._original_genai_generate
            )
        if self._original_genai_aio_generate is not None:
            if hasattr(genai_models, "AsyncModels"):
                genai_models.AsyncModels.generate_content = (
                    self._original_genai_aio_generate
                )
        if self._original_genai_count_tokens is not None:
            genai_models.Models.count_tokens = (
                self._original_genai_count_tokens
            )

        self._original_genai_generate = None
        self._original_genai_aio_generate = None
        self._original_genai_count_tokens = None

    def _uninstrument_legacy_sdk(self) -> None:
        """Restore the legacy google-generativeai SDK."""
        try:
            import google.generativeai as genai
        except ImportError:
            return

        model_cls = genai.GenerativeModel

        if self._original_generate_content is not None:
            model_cls.generate_content = self._original_generate_content
        if self._original_generate_content_async is not None:
            model_cls.generate_content_async = (
                self._original_generate_content_async
            )
        if self._original_count_tokens is not None:
            model_cls.count_tokens = self._original_count_tokens

        self._original_generate_content = None
        self._original_generate_content_async = None
        self._original_count_tokens = None

    @property
    def is_instrumented(self) -> bool:
        """Return ``True`` if instrumentation is currently active."""
        return self._instrumented

    # ------------------------------------------------------------------
    # Wrapper factories
    # ------------------------------------------------------------------

    def _wrap_generate_content(
        self,
        original: Callable,
    ) -> Callable:
        """Return a patched ``generate_content`` that creates spans."""
        instrumentor = self

        @functools.wraps(original)
        def wrapper(model_self: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._tracer
            if tracer is None:
                return original(model_self, *args, **kwargs)

            model_name = _extract_model_name(model_self)
            is_stream = kwargs.get("stream", False)
            operation = "chat"
            span_name = f"{operation} {model_name}"

            attributes = _build_request_attributes(
                model_self, model_name, operation, is_stream, args, kwargs,
            )

            start_time = time.monotonic()

            span = tracer.start_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            )
            ctx = trace.set_span_in_context(span)
            token = trace.context_api.attach(ctx)

            try:
                response = original(model_self, *args, **kwargs)

                if is_stream:
                    return _StreamingResponseProxy(
                        response, span, start_time, token,
                    )

                _record_response_attributes(span, response, start_time)
                span.set_status(StatusCode.OK)
                span.end()
                trace.context_api.detach(token)
                return response

            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                span.end()
                trace.context_api.detach(token)
                raise

        return wrapper

    def _wrap_generate_content_async(
        self,
        original: Callable,
    ) -> Callable:
        """Return a patched ``generate_content_async`` that creates spans."""
        instrumentor = self

        @functools.wraps(original)
        async def wrapper(model_self: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._tracer
            if tracer is None:
                return await original(model_self, *args, **kwargs)

            model_name = _extract_model_name(model_self)
            is_stream = kwargs.get("stream", False)
            operation = "chat"
            span_name = f"{operation} {model_name}"

            attributes = _build_request_attributes(
                model_self, model_name, operation, is_stream, args, kwargs,
            )

            start_time = time.monotonic()

            span = tracer.start_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            )
            ctx = trace.set_span_in_context(span)
            token = trace.context_api.attach(ctx)

            try:
                response = await original(model_self, *args, **kwargs)

                if is_stream:
                    return _AsyncStreamingResponseProxy(
                        response, span, start_time, token,
                    )

                _record_response_attributes(span, response, start_time)
                span.set_status(StatusCode.OK)
                span.end()
                trace.context_api.detach(token)
                return response

            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                span.end()
                trace.context_api.detach(token)
                raise

        return wrapper

    def _wrap_count_tokens(
        self,
        original: Callable,
    ) -> Callable:
        """Return a patched ``count_tokens`` that creates spans."""
        instrumentor = self

        @functools.wraps(original)
        def wrapper(model_self: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._tracer
            if tracer is None:
                return original(model_self, *args, **kwargs)

            model_name = _extract_model_name(model_self)
            span_name = f"count_tokens {model_name}"

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: GenAIAttributes.System.GOOGLE,
                GenAIAttributes.OPERATION_NAME: "count_tokens",
                GenAIAttributes.REQUEST_MODEL: model_name,
            }

            start_time = time.monotonic()

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(model_self, *args, **kwargs)

                    # Record token count from the response
                    if hasattr(result, "total_tokens"):
                        span.set_attribute(
                            GenAIAttributes.USAGE_INPUT_TOKENS,
                            result.total_tokens,
                        )

                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)
                    span.set_status(StatusCode.OK)
                    return result

                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper


# ---------------------------------------------------------------------------
# Streaming response proxies
# ---------------------------------------------------------------------------

class _StreamingResponseProxy:
    """Wraps a synchronous streaming response iterator to capture telemetry.

    Iterates through all chunks, records the first-token latency, accumulates
    token usage, captures function calls and finish reasons, and finalises
    the span when iteration completes or an error occurs.
    """

    def __init__(
        self,
        response_iter: Any,
        span: trace.Span,
        start_time: float,
        context_token: object,
    ) -> None:
        self._response_iter = response_iter
        self._span = span
        self._start_time = start_time
        self._context_token = context_token
        self._first_token_recorded = False
        self._chunks: list[Any] = []
        self._finished = False

    def __iter__(self) -> _StreamingResponseProxy:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._response_iter)
        except StopIteration:
            self._finalise()
            raise
        except Exception as exc:
            self._span.set_status(StatusCode.ERROR, str(exc))
            self._span.record_exception(exc)
            self._span.end()
            trace.context_api.detach(self._context_token)
            self._finished = True
            raise

        if not self._first_token_recorded:
            ttft_ms = (time.monotonic() - self._start_time) * 1000
            self._span.set_attribute(
                LatencyAttributes.TIME_TO_FIRST_TOKEN_MS, ttft_ms,
            )
            self._first_token_recorded = True

        self._chunks.append(chunk)
        return chunk

    # Allow attribute passthrough so callers can access .text, .candidates, etc.
    def __getattr__(self, name: str) -> Any:
        return getattr(self._response_iter, name)

    def _finalise(self) -> None:
        """Record accumulated telemetry and close the span."""
        if self._finished:
            return
        self._finished = True

        try:
            _record_streaming_attributes(
                self._span, self._chunks, self._start_time,
            )
            self._span.set_status(StatusCode.OK)
        except Exception:
            logger.debug(
                "Failed to record streaming attributes.", exc_info=True,
            )
        finally:
            self._span.end()
            trace.context_api.detach(self._context_token)


class _AsyncStreamingResponseProxy:
    """Wraps an asynchronous streaming response iterator to capture telemetry.

    Mirrors ``_StreamingResponseProxy`` for ``async for`` usage.
    """

    def __init__(
        self,
        response_iter: Any,
        span: trace.Span,
        start_time: float,
        context_token: object,
    ) -> None:
        self._response_iter = response_iter
        self._span = span
        self._start_time = start_time
        self._context_token = context_token
        self._first_token_recorded = False
        self._chunks: list[Any] = []
        self._finished = False

    def __aiter__(self) -> _AsyncStreamingResponseProxy:
        return self

    async def __anext__(self) -> Any:
        try:
            chunk = await self._response_iter.__anext__()
        except StopAsyncIteration:
            self._finalise()
            raise
        except Exception as exc:
            self._span.set_status(StatusCode.ERROR, str(exc))
            self._span.record_exception(exc)
            self._span.end()
            trace.context_api.detach(self._context_token)
            self._finished = True
            raise

        if not self._first_token_recorded:
            ttft_ms = (time.monotonic() - self._start_time) * 1000
            self._span.set_attribute(
                LatencyAttributes.TIME_TO_FIRST_TOKEN_MS, ttft_ms,
            )
            self._first_token_recorded = True

        self._chunks.append(chunk)
        return chunk

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response_iter, name)

    def _finalise(self) -> None:
        """Record accumulated telemetry and close the span."""
        if self._finished:
            return
        self._finished = True

        try:
            _record_streaming_attributes(
                self._span, self._chunks, self._start_time,
            )
            self._span.set_status(StatusCode.OK)
        except Exception:
            logger.debug(
                "Failed to record async streaming attributes.", exc_info=True,
            )
        finally:
            self._span.end()
            trace.context_api.detach(self._context_token)


# ---------------------------------------------------------------------------
# Attribute extraction helpers
# ---------------------------------------------------------------------------

def _extract_model_name(model_instance: Any) -> str:
    """Extract the model identifier from a ``GenerativeModel`` instance.

    The SDK stores the model name as ``model_name`` (e.g.
    ``"models/gemini-2.0-flash"``).  We strip the ``models/`` prefix for
    cleaner attribute values.
    """
    name = getattr(model_instance, "model_name", None) or "unknown"
    if isinstance(name, str) and name.startswith("models/"):
        name = name[len("models/"):]
    return name


def _build_request_attributes(
    model_instance: Any,
    model_name: str,
    operation: str,
    is_stream: bool,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Build the initial span attributes from the request parameters."""
    attributes: dict[str, Any] = {
        GenAIAttributes.SYSTEM: GenAIAttributes.System.GOOGLE,
        GenAIAttributes.OPERATION_NAME: operation,
        GenAIAttributes.REQUEST_MODEL: model_name,
    }

    if is_stream:
        attributes[GenAIAttributes.REQUEST_STREAM] = True

    # Generation config -------------------------------------------------
    generation_config = kwargs.get("generation_config") or getattr(
        model_instance, "_generation_config", None,
    )
    if generation_config is not None:
        _apply_generation_config(attributes, generation_config)

    # Tools / function declarations -------------------------------------
    tools = kwargs.get("tools") or getattr(model_instance, "_tools", None)
    if tools:
        tool_names = _extract_tool_names(tools)
        if tool_names:
            attributes[GenAIAttributes.REQUEST_TOOLS] = json.dumps(tool_names)

    # Tool config (auto / any / none) -----------------------------------
    tool_config = kwargs.get("tool_config") or getattr(
        model_instance, "_tool_config", None,
    )
    if tool_config is not None:
        attributes[GenAIAttributes.REQUEST_TOOL_CHOICE] = str(tool_config)

    # Safety settings ---------------------------------------------------
    safety_settings = kwargs.get("safety_settings") or getattr(
        model_instance, "_safety_settings", None,
    )
    if safety_settings:
        attributes[_GEMINI_SAFETY_SETTINGS] = _serialise_safety_settings(
            safety_settings,
        )

    # Multimodal input detection ----------------------------------------
    contents = args[0] if args else kwargs.get("contents")
    if contents is not None:
        modalities = _detect_modalities(contents)
        if modalities:
            attributes[_GEMINI_INPUT_MODALITIES] = json.dumps(
                sorted(modalities),
            )

    return attributes


def _apply_generation_config(
    attributes: dict[str, Any],
    config: Any,
) -> None:
    """Extract fields from a GenerationConfig (dict or proto) into span attributes."""
    if isinstance(config, dict):
        mapping = config
    else:
        # Proto-like object -- use attribute access
        mapping = {
            "temperature": getattr(config, "temperature", None),
            "top_p": getattr(config, "top_p", None),
            "top_k": getattr(config, "top_k", None),
            "max_output_tokens": getattr(config, "max_output_tokens", None),
            "candidate_count": getattr(config, "candidate_count", None),
            "stop_sequences": getattr(config, "stop_sequences", None),
            "response_mime_type": getattr(config, "response_mime_type", None),
            "seed": getattr(config, "seed", None),
        }

    if mapping.get("temperature") is not None:
        attributes[GenAIAttributes.REQUEST_TEMPERATURE] = float(
            mapping["temperature"],
        )
    if mapping.get("top_p") is not None:
        attributes[GenAIAttributes.REQUEST_TOP_P] = float(mapping["top_p"])
    if mapping.get("top_k") is not None:
        attributes[GenAIAttributes.REQUEST_TOP_K] = int(mapping["top_k"])
    if mapping.get("max_output_tokens") is not None:
        attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = int(
            mapping["max_output_tokens"],
        )
    if mapping.get("candidate_count") is not None:
        attributes[_GEMINI_CANDIDATE_COUNT] = int(mapping["candidate_count"])
    if mapping.get("stop_sequences"):
        attributes[GenAIAttributes.REQUEST_STOP_SEQUENCES] = json.dumps(
            list(mapping["stop_sequences"]),
        )
    if mapping.get("response_mime_type"):
        attributes[GenAIAttributes.REQUEST_RESPONSE_FORMAT] = str(
            mapping["response_mime_type"],
        )
    if mapping.get("seed") is not None:
        attributes[GenAIAttributes.REQUEST_SEED] = int(mapping["seed"])


def _extract_tool_names(tools: Any) -> list[str]:
    """Extract function/tool names from the Gemini tools configuration.

    ``tools`` can be a list of ``Tool`` protos, a list of callables,
    or a list of dicts.
    """
    names: list[str] = []
    if not isinstance(tools, (list, tuple)):
        tools = [tools]

    for tool in tools:
        # Proto-based Tool with function_declarations
        if hasattr(tool, "function_declarations"):
            for fn in tool.function_declarations:
                name = getattr(fn, "name", None) or str(fn)
                names.append(name)
        # Callable (automatic function calling)
        elif callable(tool) and hasattr(tool, "__name__"):
            names.append(tool.__name__)
        # Dict representation
        elif isinstance(tool, dict):
            for fn in tool.get("function_declarations", []):
                if isinstance(fn, dict):
                    names.append(fn.get("name", "unknown"))
    return names


def _serialise_safety_settings(settings: Any) -> str:
    """Serialise safety settings to a JSON string for span attributes.

    ``settings`` can be a list of ``SafetySetting`` protos or a dict
    mapping ``HarmCategory`` to ``HarmBlockThreshold``.
    """
    try:
        if isinstance(settings, dict):
            return json.dumps(
                {str(k): str(v) for k, v in settings.items()},
            )
        if isinstance(settings, (list, tuple)):
            result: list[dict[str, str]] = []
            for s in settings:
                if isinstance(s, dict):
                    result.append(
                        {str(k): str(v) for k, v in s.items()},
                    )
                else:
                    result.append(
                        {
                            "category": str(getattr(s, "category", "")),
                            "threshold": str(getattr(s, "threshold", "")),
                        },
                    )
            return json.dumps(result)
    except Exception:
        logger.debug("Could not serialise safety settings.", exc_info=True)
    return "[]"


def _detect_modalities(contents: Any) -> set[str]:
    """Detect input modalities from the request contents.

    The Gemini SDK accepts strings, ``Part`` objects, ``Content`` protos,
    and ``PIL.Image.Image`` instances.
    """
    modalities: set[str] = set()

    if isinstance(contents, str):
        modalities.add("text")
        return modalities

    # Flatten to a list of items
    items: list[Any]
    if isinstance(contents, (list, tuple)):
        items = list(contents)
    else:
        items = [contents]

    for item in items:
        if isinstance(item, str):
            modalities.add("text")
        elif hasattr(item, "text") and getattr(item, "text", None):
            modalities.add("text")
        elif hasattr(item, "inline_data"):
            mime = getattr(
                getattr(item, "inline_data", None), "mime_type", "",
            )
            if "image" in mime:
                modalities.add("image")
            elif "audio" in mime:
                modalities.add("audio")
            elif "video" in mime:
                modalities.add("video")
            else:
                modalities.add("binary")
        elif hasattr(item, "file_data"):
            mime = getattr(
                getattr(item, "file_data", None), "mime_type", "",
            )
            if "image" in mime:
                modalities.add("image")
            elif "audio" in mime:
                modalities.add("audio")
            elif "video" in mime:
                modalities.add("video")
            elif "pdf" in mime:
                modalities.add("document")
            else:
                modalities.add("file")
        # PIL Image detection
        elif _is_pil_image(item):
            modalities.add("image")
        # Content proto with parts
        elif hasattr(item, "parts"):
            for part in item.parts:
                modalities.update(_detect_modalities(part))

    return modalities


def _is_pil_image(obj: Any) -> bool:
    """Check if *obj* is a PIL/Pillow Image without importing PIL."""
    cls_name = type(obj).__module__ + "." + type(obj).__qualname__
    return "PIL" in cls_name or "Image.Image" in cls_name


# ---------------------------------------------------------------------------
# Response attribute recording
# ---------------------------------------------------------------------------

def _record_response_attributes(
    span: trace.Span,
    response: Any,
    start_time: float,
) -> None:
    """Record response-level attributes on the span for a non-streaming response."""
    elapsed_ms = (time.monotonic() - start_time) * 1000
    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

    # Response ID -----------------------------------------------------------
    # The Gemini SDK does not always expose a response ID, but some response
    # objects carry one via the underlying proto.
    response_id = _safe_getattr_chain(response, ("response_id",))
    if response_id:
        span.set_attribute(GenAIAttributes.RESPONSE_ID, str(response_id))

    # Token usage -----------------------------------------------------------
    usage = getattr(response, "usage_metadata", None)
    if usage is not None:
        prompt_tokens = getattr(usage, "prompt_token_count", 0) or 0
        completion_tokens = getattr(usage, "candidates_token_count", 0) or 0
        cached_tokens = getattr(usage, "cached_content_token_count", 0) or 0
        span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, prompt_tokens)
        span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, completion_tokens)
        if cached_tokens:
            span.set_attribute(GenAIAttributes.USAGE_CACHED_TOKENS, cached_tokens)

        total_tokens = prompt_tokens + completion_tokens
        if elapsed_ms > 0 and total_tokens > 0:
            tps = (total_tokens / elapsed_ms) * 1000
            span.set_attribute(LatencyAttributes.TOKENS_PER_SECOND, tps)

    # Finish reasons --------------------------------------------------------
    candidates = getattr(response, "candidates", None) or []
    finish_reasons: list[str] = []
    for candidate in candidates:
        reason = getattr(candidate, "finish_reason", None)
        if reason is not None:
            finish_reasons.append(str(reason))
    if finish_reasons:
        span.set_attribute(GenAIAttributes.RESPONSE_FINISH_REASONS, json.dumps(finish_reasons))

    # Function calls --------------------------------------------------------
    _record_function_calls(span, candidates)

    # Grounding metadata ----------------------------------------------------
    _record_grounding_metadata(span, candidates)


def _record_streaming_attributes(
    span: trace.Span,
    chunks: list[Any],
    start_time: float,
) -> None:
    """Aggregate telemetry from accumulated streaming chunks."""
    elapsed_ms = (time.monotonic() - start_time) * 1000
    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

    # Aggregate token usage from the last chunk (Gemini reports cumulative
    # usage in the final chunk).
    if chunks:
        last = chunks[-1]
        usage = getattr(last, "usage_metadata", None)
        if usage is not None:
            prompt_tokens = getattr(usage, "prompt_token_count", 0) or 0
            completion_tokens = (
                getattr(usage, "candidates_token_count", 0) or 0
            )
            cached_tokens = (
                getattr(usage, "cached_content_token_count", 0) or 0
            )
            span.set_attribute(
                GenAIAttributes.USAGE_INPUT_TOKENS, prompt_tokens,
            )
            span.set_attribute(
                GenAIAttributes.USAGE_OUTPUT_TOKENS, completion_tokens,
            )
            if cached_tokens:
                span.set_attribute(
                    GenAIAttributes.USAGE_CACHED_TOKENS, cached_tokens,
                )

            total_tokens = prompt_tokens + completion_tokens
            if elapsed_ms > 0 and total_tokens > 0:
                tps = (total_tokens / elapsed_ms) * 1000
                span.set_attribute(LatencyAttributes.TOKENS_PER_SECOND, tps)

        # Finish reasons from the last chunk
        candidates = getattr(last, "candidates", None) or []
        finish_reasons: list[str] = []
        for candidate in candidates:
            reason = getattr(candidate, "finish_reason", None)
            if reason is not None:
                finish_reasons.append(str(reason))
        if finish_reasons:
            span.set_attribute(
                GenAIAttributes.RESPONSE_FINISH_REASONS,
                json.dumps(finish_reasons),
            )

        # Function calls across all chunks
        all_candidates: list[Any] = []
        for chunk in chunks:
            all_candidates.extend(getattr(chunk, "candidates", None) or [])
        _record_function_calls(span, all_candidates)
        _record_grounding_metadata(span, all_candidates)


def _record_function_calls(
    span: trace.Span,
    candidates: Sequence[Any],
) -> None:
    """Extract and record function call events from candidates."""
    call_names: list[str] = []

    for candidate in candidates:
        content = getattr(candidate, "content", None)
        if content is None:
            continue
        parts = getattr(content, "parts", None) or []
        for part in parts:
            fn_call = getattr(part, "function_call", None)
            if fn_call is None:
                continue

            name = getattr(fn_call, "name", "unknown")
            call_names.append(name)

            # Serialise arguments
            fn_args: str
            raw_args = getattr(fn_call, "args", None)
            if raw_args is not None:
                try:
                    fn_args = json.dumps(dict(raw_args))
                except Exception:
                    fn_args = str(raw_args)
            else:
                fn_args = "{}"

            span.add_event(
                "gen_ai.tool.call",
                attributes={
                    GenAIAttributes.TOOL_NAME: name,
                    GenAIAttributes.TOOL_ARGUMENTS: fn_args,
                },
            )

    if call_names:
        span.set_attribute(_GEMINI_FUNCTION_CALLS, json.dumps(call_names))


def _record_grounding_metadata(
    span: trace.Span,
    candidates: Sequence[Any],
) -> None:
    """Record Google Search grounding metadata when present."""
    for candidate in candidates:
        grounding = getattr(candidate, "grounding_metadata", None)
        if grounding is None:
            continue

        span.set_attribute(_GEMINI_GROUNDING_ENABLED, True)

        # Grounding sources (Google Search, custom data, etc.)
        sources = getattr(grounding, "grounding_attributions", None)
        if sources:
            source_labels: list[str] = []
            for src in sources:
                source_id = getattr(
                    getattr(src, "source_id", None), "grounding_passage", None,
                )
                if source_id:
                    source_labels.append(str(source_id))
            if source_labels:
                span.set_attribute(
                    _GEMINI_GROUNDING_SOURCES, json.dumps(source_labels),
                )

        # Search entry point / web search queries
        search_queries = getattr(grounding, "web_search_queries", None)
        if search_queries:
            span.add_event(
                "google.gemini.grounding.search",
                attributes={
                    "queries": json.dumps(list(search_queries)),
                },
            )

        # Grounding passages count
        passages = getattr(grounding, "grounding_chunks", None)
        if passages:
            span.set_attribute(
                _GEMINI_GROUNDING_PASSAGES, len(passages),
            )

        # Only process the first candidate's grounding
        break


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _safe_getattr_chain(
    obj: Any,
    attr_names: tuple[str, ...],
) -> Any:
    """Safely traverse a chain of attribute lookups, returning *None* on failure."""
    current = obj
    for attr in attr_names:
        current = getattr(current, attr, None)
        if current is None:
            return None
    return current
