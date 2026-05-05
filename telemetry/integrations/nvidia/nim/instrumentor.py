"""AITF Instrumentor for NVIDIA NIM (Inference Microservices).

NVIDIA NIM provides GPU-optimized inference containers that expose an
OpenAI-compatible API endpoint.  This module wraps the NIM client SDK
(or any OpenAI-compatible client pointed at a NIM endpoint) with AITF
telemetry, producing OpenTelemetry spans for:

- **Inference requests** -- chat completions, text completions, embeddings
  via the OpenAI-compatible ``/v1/chat/completions`` endpoint.
- **Model loading** -- pulling and starting NIM containers / model profiles.
- **GPU utilization tracking** -- recording GPU memory, utilization
  percentage, and TensorRT-LLM optimization flags.
- **Batch inference** -- multi-request batches with per-batch metrics.
- **Health checks** -- ``/v1/health/ready`` and ``/v1/health/live`` probes.

All spans carry ``gen_ai.system = "nvidia_nim"`` and use AITF semantic
convention attributes from ``aitf.semantic_conventions.attributes``.

Usage::

    from integrations.nvidia.nim.instrumentor import NIMInstrumentor

    instrumentor = NIMInstrumentor(nim_base_url="http://localhost:8000")
    instrumentor.instrument()

    # Using the OpenAI-compatible client against a NIM endpoint:
    import openai
    client = openai.OpenAI(base_url="http://localhost:8000/v1", api_key="none")
    response = client.chat.completions.create(
        model="meta/llama-3.1-70b-instruct",
        messages=[{"role": "user", "content": "Hello!"}],
    )
    # ^^ This call is automatically traced with AITF spans.

    # Manual tracing for model loading:
    with instrumentor.trace_model_load(
        model_name="meta/llama-3.1-70b-instruct",
        gpu_type="A100",
        gpu_count=2,
        optimization="tensorrt_llm",
    ) as load_op:
        # ... trigger NIM model load ...
        load_op.set_load_time_ms(4500.0)
        load_op.set_gpu_memory_used_mb(38_000)

    # Batch inference:
    with instrumentor.trace_batch_inference(
        model="meta/llama-3.1-70b-instruct",
        batch_size=32,
    ) as batch_op:
        # ... run batch ...
        batch_op.set_throughput(tokens_per_second=1200.0)

    # Health check:
    with instrumentor.trace_health_check(check_type="readiness") as health:
        # ... call /v1/health/ready ...
        health.set_status("healthy", latency_ms=12.0)

    instrumentor.uninstrument()
"""

from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import (
    CostAttributes,
    GenAIAttributes,
    LatencyAttributes,
    ModelOpsAttributes,
)

_TRACER_NAME = "integrations.nvidia.nim"
_GEN_AI_SYSTEM = "nvidia_nim"


class NIMInstrumentor:
    """Instrumentor for NVIDIA NIM inference microservices.

    Wraps NIM's OpenAI-compatible API with AITF telemetry spans.
    Supports both automatic monkey-patching of ``openai.OpenAI`` clients
    configured for NIM endpoints and manual context-manager-based tracing.

    Args:
        tracer_provider: Optional custom ``TracerProvider``. Falls back to
            the globally registered provider.
        nim_base_url: Base URL of the NIM endpoint (e.g.
            ``http://localhost:8000``). Used to identify NIM-bound calls
            when auto-instrumenting shared ``openai`` clients.
    """

    def __init__(
        self,
        tracer_provider: TracerProvider | None = None,
        nim_base_url: str | None = None,
    ) -> None:
        self._tracer_provider = tracer_provider
        self._nim_base_url = nim_base_url
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._original_chat_create: Any | None = None
        self._original_embeddings_create: Any | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Enable NIM instrumentation.

        Obtains a tracer from the configured (or global) ``TracerProvider``
        and optionally monkey-patches the ``openai`` SDK if the
        ``nim_base_url`` was provided.
        """
        if self._instrumented:
            return

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)
        self._instrumented = True
        self._patch_openai_sdk()

    def uninstrument(self) -> None:
        """Remove NIM instrumentation and restore original SDK methods."""
        self._unpatch_openai_sdk()
        self._tracer = None
        self._instrumented = False

    @property
    def is_instrumented(self) -> bool:
        """Return ``True`` if this instrumentor is currently active."""
        return self._instrumented

    def get_tracer(self) -> trace.Tracer:
        """Return the active tracer, creating one lazily if needed."""
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    # ------------------------------------------------------------------
    # Inference tracing (OpenAI-compatible endpoint)
    # ------------------------------------------------------------------

    @contextmanager
    def trace_inference(
        self,
        model: str,
        operation: str = "chat",
        temperature: float | None = None,
        max_tokens: int | None = None,
        top_p: float | None = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> Generator[NIMInferenceSpan, None, None]:
        """Trace a single NIM inference call (chat completion or embedding).

        Usage::

            with instrumentor.trace_inference(
                model="meta/llama-3.1-70b-instruct",
                operation="chat",
                temperature=0.7,
                max_tokens=1024,
            ) as span:
                response = nim_client.chat.completions.create(...)
                span.set_response(
                    response_id=response.id,
                    model=response.model,
                    finish_reasons=[c.finish_reason for c in response.choices],
                )
                span.set_usage(
                    input_tokens=response.usage.prompt_tokens,
                    output_tokens=response.usage.completion_tokens,
                )
        """
        tracer = self.get_tracer()
        span_name = f"{operation} {model}"

        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: _GEN_AI_SYSTEM,
            GenAIAttributes.OPERATION_NAME: operation,
            GenAIAttributes.REQUEST_MODEL: model,
        }
        if temperature is not None:
            attributes[GenAIAttributes.REQUEST_TEMPERATURE] = temperature
        if max_tokens is not None:
            attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = max_tokens
        if top_p is not None:
            attributes[GenAIAttributes.REQUEST_TOP_P] = top_p
        if stream:
            attributes[GenAIAttributes.REQUEST_STREAM] = True

        # Forward any NIM-specific request parameters.
        for key, value in kwargs.items():
            attributes[f"gen_ai.request.{key}"] = value

        start = time.monotonic()

        with tracer.start_as_current_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            inference_span = NIMInferenceSpan(span, start)
            try:
                yield inference_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    @contextmanager
    def trace_model_load(
        self,
        model_name: str,
        gpu_type: str | None = None,
        gpu_count: int | None = None,
        optimization: str | None = None,
        model_profile: str | None = None,
    ) -> Generator[NIMModelLoadSpan, None, None]:
        """Trace a NIM model load / container startup operation.

        Args:
            model_name: NIM model identifier (e.g. ``meta/llama-3.1-70b-instruct``).
            gpu_type: GPU hardware (e.g. ``A100``, ``H100``, ``L40S``).
            gpu_count: Number of GPUs allocated.
            optimization: Optimization backend (e.g. ``tensorrt_llm``, ``vllm``).
            model_profile: NIM model profile (e.g. ``throughput``, ``latency``).

        Usage::

            with instrumentor.trace_model_load(
                model_name="meta/llama-3.1-70b-instruct",
                gpu_type="H100",
                gpu_count=4,
                optimization="tensorrt_llm",
            ) as load_op:
                # ... trigger model pull and load ...
                load_op.set_load_time_ms(5200.0)
                load_op.set_gpu_memory_used_mb(72_000)
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: _GEN_AI_SYSTEM,
            GenAIAttributes.OPERATION_NAME: "model_load",
            GenAIAttributes.REQUEST_MODEL: model_name,
            "nvidia.nim.operation": "model_load",
        }
        if gpu_type:
            attributes[ModelOpsAttributes.DEPLOYMENT_INFRA_GPU_TYPE] = gpu_type
        if gpu_count is not None:
            attributes[ModelOpsAttributes.TRAINING_COMPUTE_GPU_COUNT] = gpu_count
        if optimization:
            attributes["nvidia.nim.optimization"] = optimization
        if model_profile:
            attributes["nvidia.nim.model_profile"] = model_profile

        start = time.monotonic()

        with tracer.start_as_current_span(
            name=f"nim.model_load {model_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            load_span = NIMModelLoadSpan(span, start)
            try:
                yield load_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # GPU utilization tracking
    # ------------------------------------------------------------------

    @contextmanager
    def trace_gpu_utilization(
        self,
        model: str,
        gpu_type: str | None = None,
        gpu_count: int | None = None,
    ) -> Generator[NIMGPUUtilizationSpan, None, None]:
        """Trace a GPU utilization sample for a running NIM model.

        Usage::

            with instrumentor.trace_gpu_utilization(
                model="meta/llama-3.1-70b-instruct",
                gpu_type="A100",
                gpu_count=2,
            ) as gpu:
                gpu.set_utilization(
                    gpu_utilization_percent=87.5,
                    gpu_memory_used_mb=35_000,
                    gpu_memory_total_mb=40_960,
                )
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: _GEN_AI_SYSTEM,
            GenAIAttributes.REQUEST_MODEL: model,
            "nvidia.nim.operation": "gpu_utilization",
        }
        if gpu_type:
            attributes[ModelOpsAttributes.DEPLOYMENT_INFRA_GPU_TYPE] = gpu_type
        if gpu_count is not None:
            attributes[ModelOpsAttributes.TRAINING_COMPUTE_GPU_COUNT] = gpu_count

        with tracer.start_as_current_span(
            name=f"nim.gpu_utilization {model}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            util_span = NIMGPUUtilizationSpan(span)
            try:
                yield util_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # Batch inference
    # ------------------------------------------------------------------

    @contextmanager
    def trace_batch_inference(
        self,
        model: str,
        batch_size: int,
        max_tokens: int | None = None,
    ) -> Generator[NIMBatchInferenceSpan, None, None]:
        """Trace a batch inference operation on a NIM endpoint.

        Args:
            model: Model identifier.
            batch_size: Number of requests in the batch.
            max_tokens: Optional per-request token limit.

        Usage::

            with instrumentor.trace_batch_inference(
                model="meta/llama-3.1-70b-instruct",
                batch_size=64,
            ) as batch:
                # ... submit batch ...
                batch.set_throughput(tokens_per_second=2400.0)
                batch.set_usage(total_input_tokens=12800, total_output_tokens=6400)
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: _GEN_AI_SYSTEM,
            GenAIAttributes.OPERATION_NAME: "batch_inference",
            GenAIAttributes.REQUEST_MODEL: model,
            "nvidia.nim.operation": "batch_inference",
            "nvidia.nim.batch.size": batch_size,
        }
        if max_tokens is not None:
            attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = max_tokens

        start = time.monotonic()

        with tracer.start_as_current_span(
            name=f"nim.batch_inference {model}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            batch_span = NIMBatchInferenceSpan(span, start, batch_size)
            try:
                yield batch_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # Health checks
    # ------------------------------------------------------------------

    @contextmanager
    def trace_health_check(
        self,
        check_type: str = "readiness",
        endpoint: str | None = None,
    ) -> Generator[NIMHealthCheckSpan, None, None]:
        """Trace a NIM health or readiness check.

        Args:
            check_type: One of ``"readiness"``, ``"liveness"``, or ``"startup"``.
            endpoint: Optional explicit endpoint URL.

        Usage::

            with instrumentor.trace_health_check(check_type="readiness") as hc:
                resp = requests.get("http://localhost:8000/v1/health/ready")
                hc.set_status(
                    "healthy" if resp.status_code == 200 else "unhealthy",
                    latency_ms=resp.elapsed.total_seconds() * 1000,
                )
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            GenAIAttributes.SYSTEM: _GEN_AI_SYSTEM,
            "nvidia.nim.operation": "health_check",
            "nvidia.nim.health.check_type": check_type,
        }
        if endpoint:
            attributes[ModelOpsAttributes.DEPLOYMENT_ENDPOINT] = endpoint

        start = time.monotonic()

        with tracer.start_as_current_span(
            name=f"nim.health_check.{check_type}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            hc_span = NIMHealthCheckSpan(span, start)
            try:
                yield hc_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # Auto-patching helpers (OpenAI-compatible SDK)
    # ------------------------------------------------------------------

    def _patch_openai_sdk(self) -> None:
        """Monkey-patch ``openai`` SDK chat completions and embeddings."""
        try:
            import openai  # noqa: F811
        except ImportError:
            return  # openai SDK not installed; skip auto-patching.

        if self._nim_base_url is None:
            return  # No base URL; cannot distinguish NIM calls.

        instrumentor = self

        # -- Chat completions --
        original_chat_create = openai.resources.chat.completions.Completions.create
        self._original_chat_create = original_chat_create

        def _patched_chat_create(client_self: Any, *args: Any, **kwargs: Any) -> Any:
            base_url = str(getattr(client_self._client, "base_url", ""))
            if instrumentor._nim_base_url and instrumentor._nim_base_url in base_url:
                model = kwargs.get("model", args[0] if args else "unknown")
                with instrumentor.trace_inference(
                    model=str(model),
                    operation="chat",
                    temperature=kwargs.get("temperature"),
                    max_tokens=kwargs.get("max_tokens"),
                    top_p=kwargs.get("top_p"),
                    stream=kwargs.get("stream", False),
                ) as span:
                    response = original_chat_create(client_self, *args, **kwargs)
                    if hasattr(response, "id"):
                        span.set_response(
                            response_id=response.id,
                            model=getattr(response, "model", None),
                            finish_reasons=[
                                c.finish_reason
                                for c in getattr(response, "choices", [])
                                if hasattr(c, "finish_reason")
                            ],
                        )
                    if hasattr(response, "usage") and response.usage:
                        span.set_usage(
                            input_tokens=getattr(response.usage, "prompt_tokens", 0),
                            output_tokens=getattr(
                                response.usage, "completion_tokens", 0
                            ),
                        )
                    return response
            return original_chat_create(client_self, *args, **kwargs)

        openai.resources.chat.completions.Completions.create = _patched_chat_create  # type: ignore[assignment]

        # -- Embeddings --
        original_embeddings_create = openai.resources.embeddings.Embeddings.create
        self._original_embeddings_create = original_embeddings_create

        def _patched_embeddings_create(
            client_self: Any, *args: Any, **kwargs: Any
        ) -> Any:
            base_url = str(getattr(client_self._client, "base_url", ""))
            if instrumentor._nim_base_url and instrumentor._nim_base_url in base_url:
                model = kwargs.get("model", args[0] if args else "unknown")
                with instrumentor.trace_inference(
                    model=str(model),
                    operation="embeddings",
                ) as span:
                    response = original_embeddings_create(
                        client_self, *args, **kwargs
                    )
                    if hasattr(response, "usage") and response.usage:
                        span.set_usage(
                            input_tokens=getattr(
                                response.usage, "prompt_tokens", 0
                            ),
                            output_tokens=0,
                        )
                    return response
            return original_embeddings_create(client_self, *args, **kwargs)

        openai.resources.embeddings.Embeddings.create = _patched_embeddings_create  # type: ignore[assignment]

    def _unpatch_openai_sdk(self) -> None:
        """Restore original ``openai`` SDK methods."""
        try:
            import openai
        except ImportError:
            return

        if self._original_chat_create is not None:
            openai.resources.chat.completions.Completions.create = (
                self._original_chat_create
            )
            self._original_chat_create = None

        if self._original_embeddings_create is not None:
            openai.resources.embeddings.Embeddings.create = (
                self._original_embeddings_create
            )
            self._original_embeddings_create = None


# ======================================================================
# Span helper classes
# ======================================================================


class NIMInferenceSpan:
    """Helper for recording attributes on a NIM inference span."""

    def __init__(self, span: trace.Span, start_time: float) -> None:
        self._span = span
        self._start_time = start_time
        self._first_token_time: float | None = None

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_prompt(self, prompt: str) -> None:
        """Record prompt content as a span event."""
        self._span.add_event(
            "gen_ai.content.prompt",
            attributes={GenAIAttributes.PROMPT: prompt},
        )

    def set_completion(self, completion: str) -> None:
        """Record completion content as a span event."""
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
        """Set NIM response metadata attributes."""
        if response_id:
            self._span.set_attribute(GenAIAttributes.RESPONSE_ID, response_id)
        if model:
            self._span.set_attribute(GenAIAttributes.RESPONSE_MODEL, model)
        if finish_reasons:
            self._span.set_attribute(
                GenAIAttributes.RESPONSE_FINISH_REASONS, finish_reasons
            )

    def set_usage(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        """Set token usage attributes."""
        self._span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens)
        self._span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens)

    def set_cost(
        self,
        input_cost: float = 0.0,
        output_cost: float = 0.0,
        total_cost: float | None = None,
        currency: str = "USD",
    ) -> None:
        """Set inference cost attributes."""
        self._span.set_attribute(CostAttributes.INPUT_COST, input_cost)
        self._span.set_attribute(CostAttributes.OUTPUT_COST, output_cost)
        self._span.set_attribute(
            CostAttributes.TOTAL_COST,
            total_cost if total_cost is not None else input_cost + output_cost,
        )
        self._span.set_attribute(CostAttributes.CURRENCY, currency)

    def mark_first_token(self) -> None:
        """Mark the arrival of the first token (for streaming responses)."""
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
        """Set latency metrics for the inference request."""
        if total_ms is None:
            total_ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)
        if tokens_per_second is not None:
            self._span.set_attribute(
                LatencyAttributes.TOKENS_PER_SECOND, tokens_per_second
            )
        if queue_time_ms is not None:
            self._span.set_attribute(LatencyAttributes.QUEUE_TIME_MS, queue_time_ms)
        if inference_time_ms is not None:
            self._span.set_attribute(
                LatencyAttributes.INFERENCE_TIME_MS, inference_time_ms
            )

    def set_gpu_metrics(
        self,
        gpu_utilization_percent: float | None = None,
        gpu_memory_used_mb: int | None = None,
        gpu_memory_total_mb: int | None = None,
    ) -> None:
        """Set GPU utilization metrics observed during this inference."""
        if gpu_utilization_percent is not None:
            self._span.set_attribute(
                "nvidia.nim.gpu.utilization_percent", gpu_utilization_percent
            )
        if gpu_memory_used_mb is not None:
            self._span.set_attribute(
                "nvidia.nim.gpu.memory_used_mb", gpu_memory_used_mb
            )
        if gpu_memory_total_mb is not None:
            self._span.set_attribute(
                "nvidia.nim.gpu.memory_total_mb", gpu_memory_total_mb
            )

    def set_optimization_info(
        self,
        backend: str | None = None,
        precision: str | None = None,
        tensor_parallelism: int | None = None,
    ) -> None:
        """Record TensorRT-LLM or other optimization metadata.

        Args:
            backend: Optimization backend (e.g. ``"tensorrt_llm"``, ``"vllm"``).
            precision: Compute precision (e.g. ``"fp16"``, ``"fp8"``, ``"int8"``).
            tensor_parallelism: Tensor parallelism degree across GPUs.
        """
        if backend:
            self._span.set_attribute("nvidia.nim.optimization", backend)
        if precision:
            self._span.set_attribute("nvidia.nim.precision", precision)
        if tensor_parallelism is not None:
            self._span.set_attribute(
                "nvidia.nim.tensor_parallelism", tensor_parallelism
            )


class NIMModelLoadSpan:
    """Helper for recording attributes on a NIM model load span."""

    def __init__(self, span: trace.Span, start_time: float) -> None:
        self._span = span
        self._start_time = start_time

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_load_time_ms(self, load_time_ms: float) -> None:
        """Record the total model load time in milliseconds."""
        self._span.set_attribute("nvidia.nim.model_load.time_ms", load_time_ms)

    def set_gpu_memory_used_mb(self, memory_mb: int) -> None:
        """Record GPU memory consumed by the loaded model."""
        self._span.set_attribute(
            "nvidia.nim.gpu.memory_used_mb", memory_mb
        )

    def set_model_size_bytes(self, size_bytes: int) -> None:
        """Record model artifact size in bytes."""
        self._span.set_attribute(
            "nvidia.nim.model_load.size_bytes", size_bytes
        )

    def set_container_info(
        self,
        container_image: str | None = None,
        container_tag: str | None = None,
    ) -> None:
        """Record NIM container metadata."""
        if container_image:
            self._span.set_attribute(
                "nvidia.nim.container.image", container_image
            )
        if container_tag:
            self._span.set_attribute(
                "nvidia.nim.container.tag", container_tag
            )


class NIMGPUUtilizationSpan:
    """Helper for recording GPU utilization samples."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_utilization(
        self,
        gpu_utilization_percent: float | None = None,
        gpu_memory_used_mb: int | None = None,
        gpu_memory_total_mb: int | None = None,
        gpu_temperature_celsius: float | None = None,
        gpu_power_watts: float | None = None,
    ) -> None:
        """Record a GPU utilization snapshot.

        Args:
            gpu_utilization_percent: GPU compute utilization (0-100).
            gpu_memory_used_mb: GPU memory in use (MiB).
            gpu_memory_total_mb: Total GPU memory (MiB).
            gpu_temperature_celsius: GPU temperature in degrees Celsius.
            gpu_power_watts: GPU power draw in watts.
        """
        if gpu_utilization_percent is not None:
            self._span.set_attribute(
                "nvidia.nim.gpu.utilization_percent",
                gpu_utilization_percent,
            )
        if gpu_memory_used_mb is not None:
            self._span.set_attribute(
                "nvidia.nim.gpu.memory_used_mb", gpu_memory_used_mb
            )
        if gpu_memory_total_mb is not None:
            self._span.set_attribute(
                "nvidia.nim.gpu.memory_total_mb", gpu_memory_total_mb
            )
        if gpu_temperature_celsius is not None:
            self._span.set_attribute(
                "nvidia.nim.gpu.temperature_celsius",
                gpu_temperature_celsius,
            )
        if gpu_power_watts is not None:
            self._span.set_attribute(
                "nvidia.nim.gpu.power_watts", gpu_power_watts
            )


class NIMBatchInferenceSpan:
    """Helper for recording batch inference attributes."""

    def __init__(
        self, span: trace.Span, start_time: float, batch_size: int
    ) -> None:
        self._span = span
        self._start_time = start_time
        self._batch_size = batch_size

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_usage(
        self,
        total_input_tokens: int = 0,
        total_output_tokens: int = 0,
    ) -> None:
        """Set aggregate token usage for the entire batch."""
        self._span.set_attribute(
            GenAIAttributes.USAGE_INPUT_TOKENS, total_input_tokens
        )
        self._span.set_attribute(
            GenAIAttributes.USAGE_OUTPUT_TOKENS, total_output_tokens
        )

    def set_throughput(
        self,
        tokens_per_second: float | None = None,
        requests_per_second: float | None = None,
    ) -> None:
        """Set throughput metrics for the batch."""
        if tokens_per_second is not None:
            self._span.set_attribute(
                LatencyAttributes.TOKENS_PER_SECOND, tokens_per_second
            )
        if requests_per_second is not None:
            self._span.set_attribute(
                "nvidia.nim.batch.requests_per_second",
                requests_per_second,
            )

    def set_latency(
        self,
        total_ms: float | None = None,
        avg_per_request_ms: float | None = None,
    ) -> None:
        """Set latency metrics for the batch."""
        if total_ms is None:
            total_ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)
        if avg_per_request_ms is not None:
            self._span.set_attribute(
                "nvidia.nim.batch.avg_request_latency_ms",
                avg_per_request_ms,
            )

    def set_batch_results(
        self,
        successful: int | None = None,
        failed: int | None = None,
    ) -> None:
        """Record how many requests in the batch succeeded or failed."""
        if successful is not None:
            self._span.set_attribute(
                "nvidia.nim.batch.successful", successful
            )
        if failed is not None:
            self._span.set_attribute("nvidia.nim.batch.failed", failed)


class NIMHealthCheckSpan:
    """Helper for recording NIM health check results."""

    def __init__(self, span: trace.Span, start_time: float) -> None:
        self._span = span
        self._start_time = start_time

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_status(self, status: str, latency_ms: float | None = None) -> None:
        """Record health check status and latency.

        Args:
            status: Health status string (e.g. ``"healthy"``, ``"unhealthy"``,
                ``"degraded"``).
            latency_ms: Health check response time in milliseconds.
        """
        self._span.set_attribute(
            ModelOpsAttributes.DEPLOYMENT_HEALTH_STATUS, status
        )
        if latency_ms is not None:
            self._span.set_attribute(
                ModelOpsAttributes.DEPLOYMENT_HEALTH_LATENCY, latency_ms
            )
        else:
            elapsed = (time.monotonic() - self._start_time) * 1000
            self._span.set_attribute(
                ModelOpsAttributes.DEPLOYMENT_HEALTH_LATENCY, elapsed
            )

    def set_model_status(
        self,
        model: str,
        ready: bool,
        reason: str | None = None,
    ) -> None:
        """Record per-model readiness within a health check.

        Args:
            model: Model identifier.
            ready: Whether the model is ready to serve.
            reason: Optional reason if not ready.
        """
        self._span.add_event(
            "nim.model_status",
            attributes={
                GenAIAttributes.REQUEST_MODEL: model,
                "nvidia.nim.health.model_ready": ready,
                **(
                    {"nvidia.nim.health.model_reason": reason}
                    if reason
                    else {}
                ),
            },
        )
