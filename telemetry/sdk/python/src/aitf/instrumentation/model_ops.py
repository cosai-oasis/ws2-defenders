"""AITF Model Operations (LLMOps/MLOps) Instrumentation.

Provides tracing for the complete AI model lifecycle: training, evaluation,
registry, deployment, serving (routing/fallback/caching), monitoring, and
prompt versioning.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import ModelOpsAttributes

_TRACER_NAME = "aitf.instrumentation.model_ops"


class ModelOpsInstrumentor:
    """Instrumentor for AI model lifecycle operations."""

    def __init__(self, tracer_provider: TracerProvider | None = None):
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False

    def instrument(self) -> None:
        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)
        self._instrumented = True

    def uninstrument(self) -> None:
        self._tracer = None
        self._instrumented = False

    def get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    # ── Training ──────────────────────────────────────────────────────

    @contextmanager
    def trace_training(
        self,
        run_id: str | None = None,
        training_type: str = "fine_tuning",
        base_model: str = "",
        framework: str | None = None,
        dataset_id: str | None = None,
        dataset_version: str | None = None,
        dataset_size: int | None = None,
        hyperparameters: str | None = None,
        epochs: int | None = None,
        experiment_id: str | None = None,
        experiment_name: str | None = None,
    ) -> Generator[TrainingRun, None, None]:
        """Context manager for tracing a training/fine-tuning run.

        Usage:
            with model_ops.trace_training(
                training_type="lora",
                base_model="meta-llama/Llama-3.1-70B",
                dataset_id="customer-support-v3",
            ) as run:
                # ... perform training ...
                run.set_loss(0.42)
                run.set_output_model("cs-llama-70b-lora-v3", "sha256:abc")
        """
        tracer = self.get_tracer()
        run_id = run_id or str(uuid.uuid4())

        attributes: dict[str, Any] = {
            ModelOpsAttributes.TRAINING_RUN_ID: run_id,
            ModelOpsAttributes.TRAINING_TYPE: training_type,
            ModelOpsAttributes.TRAINING_BASE_MODEL: base_model,
        }
        if framework:
            attributes[ModelOpsAttributes.TRAINING_FRAMEWORK] = framework
        if dataset_id:
            attributes[ModelOpsAttributes.TRAINING_DATASET_ID] = dataset_id
        if dataset_version:
            attributes[ModelOpsAttributes.TRAINING_DATASET_VERSION] = dataset_version
        if dataset_size is not None:
            attributes[ModelOpsAttributes.TRAINING_DATASET_SIZE] = dataset_size
        if hyperparameters:
            attributes[ModelOpsAttributes.TRAINING_HYPERPARAMETERS] = hyperparameters
        if epochs is not None:
            attributes[ModelOpsAttributes.TRAINING_EPOCHS] = epochs
        if experiment_id:
            attributes[ModelOpsAttributes.TRAINING_EXPERIMENT_ID] = experiment_id
        if experiment_name:
            attributes[ModelOpsAttributes.TRAINING_EXPERIMENT_NAME] = experiment_name

        with tracer.start_as_current_span(
            name=f"model_ops.training {run_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            run = TrainingRun(span, run_id)
            try:
                yield run
                span.set_status(StatusCode.OK)
                span.set_attribute(ModelOpsAttributes.TRAINING_STATUS, "completed")
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.set_attribute(ModelOpsAttributes.TRAINING_STATUS, "failed")
                span.record_exception(exc)
                raise

    # ── Evaluation ────────────────────────────────────────────────────

    @contextmanager
    def trace_evaluation(
        self,
        model_id: str,
        eval_type: str = "benchmark",
        run_id: str | None = None,
        dataset_id: str | None = None,
        dataset_size: int | None = None,
        judge_model: str | None = None,
        baseline_model: str | None = None,
    ) -> Generator[EvaluationRun, None, None]:
        """Context manager for tracing a model evaluation run.

        Usage:
            with model_ops.trace_evaluation(
                model_id="cs-llama-70b-lora-v3",
                eval_type="llm_judge",
                judge_model="gpt-4o",
            ) as eval_run:
                eval_run.set_metrics({"accuracy": 0.94, "f1": 0.91})
                eval_run.set_pass(True)
        """
        tracer = self.get_tracer()
        run_id = run_id or str(uuid.uuid4())

        attributes: dict[str, Any] = {
            ModelOpsAttributes.EVALUATION_RUN_ID: run_id,
            ModelOpsAttributes.EVALUATION_MODEL_ID: model_id,
            ModelOpsAttributes.EVALUATION_TYPE: eval_type,
        }
        if dataset_id:
            attributes[ModelOpsAttributes.EVALUATION_DATASET_ID] = dataset_id
        if dataset_size is not None:
            attributes[ModelOpsAttributes.EVALUATION_DATASET_SIZE] = dataset_size
        if judge_model:
            attributes[ModelOpsAttributes.EVALUATION_JUDGE_MODEL] = judge_model
        if baseline_model:
            attributes[ModelOpsAttributes.EVALUATION_BASELINE_MODEL] = baseline_model

        with tracer.start_as_current_span(
            name=f"model_ops.evaluation {run_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            eval_run = EvaluationRun(span, run_id)
            try:
                yield eval_run
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Registry ──────────────────────────────────────────────────────

    @contextmanager
    def trace_registry(
        self,
        model_id: str,
        operation: str,
        model_version: str | None = None,
        stage: str | None = None,
        model_alias: str | None = None,
        owner: str | None = None,
        training_run_id: str | None = None,
        parent_model_id: str | None = None,
    ) -> Generator[trace.Span, None, None]:
        """Context manager for tracing model registry operations."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            ModelOpsAttributes.REGISTRY_OPERATION: operation,
            ModelOpsAttributes.REGISTRY_MODEL_ID: model_id,
        }
        if model_version:
            attributes[ModelOpsAttributes.REGISTRY_MODEL_VERSION] = model_version
        if stage:
            attributes[ModelOpsAttributes.REGISTRY_STAGE] = stage
        if model_alias:
            attributes[ModelOpsAttributes.REGISTRY_MODEL_ALIAS] = model_alias
        if owner:
            attributes[ModelOpsAttributes.REGISTRY_OWNER] = owner
        if training_run_id:
            attributes[ModelOpsAttributes.REGISTRY_LINEAGE_TRAINING_RUN_ID] = training_run_id
        if parent_model_id:
            attributes[ModelOpsAttributes.REGISTRY_LINEAGE_PARENT_MODEL_ID] = parent_model_id

        with tracer.start_as_current_span(
            name=f"model_ops.registry.{operation} {model_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Deployment ────────────────────────────────────────────────────

    @contextmanager
    def trace_deployment(
        self,
        model_id: str,
        strategy: str = "rolling",
        deployment_id: str | None = None,
        environment: str = "production",
        endpoint: str | None = None,
        canary_percent: float | None = None,
        infrastructure_provider: str | None = None,
    ) -> Generator[DeploymentOperation, None, None]:
        """Context manager for tracing a model deployment."""
        tracer = self.get_tracer()
        deployment_id = deployment_id or str(uuid.uuid4())

        attributes: dict[str, Any] = {
            ModelOpsAttributes.DEPLOYMENT_ID: deployment_id,
            ModelOpsAttributes.DEPLOYMENT_MODEL_ID: model_id,
            ModelOpsAttributes.DEPLOYMENT_STRATEGY: strategy,
            ModelOpsAttributes.DEPLOYMENT_ENVIRONMENT: environment,
        }
        if endpoint:
            attributes[ModelOpsAttributes.DEPLOYMENT_ENDPOINT] = endpoint
        if canary_percent is not None:
            attributes[ModelOpsAttributes.DEPLOYMENT_CANARY_PERCENT] = canary_percent
        if infrastructure_provider:
            attributes[ModelOpsAttributes.DEPLOYMENT_INFRA_PROVIDER] = infrastructure_provider

        with tracer.start_as_current_span(
            name=f"model_ops.deployment {deployment_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            op = DeploymentOperation(span, deployment_id)
            try:
                yield op
                span.set_status(StatusCode.OK)
                span.set_attribute(ModelOpsAttributes.DEPLOYMENT_STATUS, "completed")
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.set_attribute(ModelOpsAttributes.DEPLOYMENT_STATUS, "failed")
                span.record_exception(exc)
                raise

    # ── Serving ───────────────────────────────────────────────────────

    @contextmanager
    def trace_route(
        self,
        selected_model: str,
        reason: str = "capability",
        candidates: list[str] | None = None,
    ) -> Generator[trace.Span, None, None]:
        """Trace a model routing decision."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            ModelOpsAttributes.SERVING_OPERATION: "route",
            ModelOpsAttributes.SERVING_ROUTE_SELECTED_MODEL: selected_model,
            ModelOpsAttributes.SERVING_ROUTE_REASON: reason,
        }
        if candidates:
            attributes[ModelOpsAttributes.SERVING_ROUTE_CANDIDATES] = candidates

        with tracer.start_as_current_span(
            name="model_ops.serving.route",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_fallback(
        self,
        original_model: str,
        final_model: str,
        trigger: str = "error",
        chain: list[str] | None = None,
        depth: int = 1,
    ) -> Generator[trace.Span, None, None]:
        """Trace a model serving fallback."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            ModelOpsAttributes.SERVING_OPERATION: "fallback",
            ModelOpsAttributes.SERVING_FALLBACK_TRIGGER: trigger,
            ModelOpsAttributes.SERVING_FALLBACK_ORIGINAL_MODEL: original_model,
            ModelOpsAttributes.SERVING_FALLBACK_FINAL_MODEL: final_model,
            ModelOpsAttributes.SERVING_FALLBACK_DEPTH: depth,
        }
        if chain:
            attributes[ModelOpsAttributes.SERVING_FALLBACK_CHAIN] = chain

        with tracer.start_as_current_span(
            name="model_ops.serving.fallback",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_cache_lookup(
        self,
        cache_type: str = "semantic",
    ) -> Generator[CacheLookup, None, None]:
        """Trace a cache lookup operation."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            ModelOpsAttributes.SERVING_OPERATION: "cache_lookup",
            ModelOpsAttributes.SERVING_CACHE_TYPE: cache_type,
        }

        with tracer.start_as_current_span(
            name="model_ops.serving.cache_lookup",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            lookup = CacheLookup(span)
            try:
                yield lookup
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Monitoring ────────────────────────────────────────────────────

    @contextmanager
    def trace_monitoring_check(
        self,
        model_id: str,
        check_type: str,
        metric_name: str | None = None,
    ) -> Generator[MonitoringCheck, None, None]:
        """Trace a model monitoring check (drift, performance, SLA)."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            ModelOpsAttributes.MONITORING_CHECK_TYPE: check_type,
            ModelOpsAttributes.MONITORING_MODEL_ID: model_id,
        }
        if metric_name:
            attributes[ModelOpsAttributes.MONITORING_METRIC_NAME] = metric_name

        with tracer.start_as_current_span(
            name=f"model_ops.monitoring.{check_type}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            check = MonitoringCheck(span)
            try:
                yield check
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Prompt Lifecycle ──────────────────────────────────────────────

    @contextmanager
    def trace_prompt(
        self,
        name: str,
        operation: str,
        version: str | None = None,
        label: str | None = None,
        model_target: str | None = None,
    ) -> Generator[PromptOperation, None, None]:
        """Trace a prompt lifecycle operation."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            ModelOpsAttributes.PROMPT_NAME: name,
            ModelOpsAttributes.PROMPT_OPERATION: operation,
        }
        if version:
            attributes[ModelOpsAttributes.PROMPT_VERSION] = version
        if label:
            attributes[ModelOpsAttributes.PROMPT_LABEL] = label
        if model_target:
            attributes[ModelOpsAttributes.PROMPT_MODEL_TARGET] = model_target

        with tracer.start_as_current_span(
            name=f"model_ops.prompt.{operation} {name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            op = PromptOperation(span)
            try:
                yield op
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


# ── Helper Classes ────────────────────────────────────────────────────


class TrainingRun:
    """Helper for recording training run attributes."""

    def __init__(self, span: trace.Span, run_id: str):
        self._span = span
        self.run_id = run_id

    def set_loss(self, loss: float, val_loss: float | None = None) -> None:
        self._span.set_attribute(ModelOpsAttributes.TRAINING_LOSS_FINAL, loss)
        if val_loss is not None:
            self._span.set_attribute(ModelOpsAttributes.TRAINING_VAL_LOSS_FINAL, val_loss)

    def set_output_model(self, model_id: str, model_hash: str | None = None) -> None:
        self._span.set_attribute(ModelOpsAttributes.TRAINING_OUTPUT_MODEL_ID, model_id)
        if model_hash:
            self._span.set_attribute(ModelOpsAttributes.TRAINING_OUTPUT_MODEL_HASH, model_hash)

    def set_compute(
        self, gpu_type: str, gpu_count: int, gpu_hours: float
    ) -> None:
        self._span.set_attribute(ModelOpsAttributes.TRAINING_COMPUTE_GPU_TYPE, gpu_type)
        self._span.set_attribute(ModelOpsAttributes.TRAINING_COMPUTE_GPU_COUNT, gpu_count)
        self._span.set_attribute(ModelOpsAttributes.TRAINING_COMPUTE_GPU_HOURS, gpu_hours)

    def set_code_commit(self, commit: str) -> None:
        self._span.set_attribute(ModelOpsAttributes.TRAINING_CODE_COMMIT, commit)

    @property
    def span(self) -> trace.Span:
        return self._span


class EvaluationRun:
    """Helper for recording evaluation run attributes."""

    def __init__(self, span: trace.Span, run_id: str):
        self._span = span
        self.run_id = run_id

    def set_metrics(self, metrics: dict[str, Any]) -> None:
        import json
        self._span.set_attribute(
            ModelOpsAttributes.EVALUATION_METRICS, json.dumps(metrics)
        )

    def set_pass(self, passed: bool, regression_detected: bool = False) -> None:
        self._span.set_attribute(ModelOpsAttributes.EVALUATION_PASS, passed)
        self._span.set_attribute(
            ModelOpsAttributes.EVALUATION_REGRESSION_DETECTED, regression_detected
        )

    @property
    def span(self) -> trace.Span:
        return self._span


class DeploymentOperation:
    """Helper for recording deployment attributes."""

    def __init__(self, span: trace.Span, deployment_id: str):
        self._span = span
        self.deployment_id = deployment_id

    def set_health(self, status: str, latency_ms: float | None = None) -> None:
        self._span.set_attribute(ModelOpsAttributes.DEPLOYMENT_HEALTH_STATUS, status)
        if latency_ms is not None:
            self._span.set_attribute(ModelOpsAttributes.DEPLOYMENT_HEALTH_LATENCY, latency_ms)

    def set_infrastructure(
        self, gpu_type: str | None = None, replicas: int | None = None
    ) -> None:
        if gpu_type:
            self._span.set_attribute(ModelOpsAttributes.DEPLOYMENT_INFRA_GPU_TYPE, gpu_type)
        if replicas is not None:
            self._span.set_attribute(ModelOpsAttributes.DEPLOYMENT_INFRA_REPLICAS, replicas)

    @property
    def span(self) -> trace.Span:
        return self._span


class CacheLookup:
    """Helper for recording cache lookup results."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_hit(
        self,
        hit: bool,
        similarity_score: float | None = None,
        cost_saved_usd: float | None = None,
    ) -> None:
        self._span.set_attribute(ModelOpsAttributes.SERVING_CACHE_HIT, hit)
        if similarity_score is not None:
            self._span.set_attribute(
                ModelOpsAttributes.SERVING_CACHE_SIMILARITY_SCORE, similarity_score
            )
        if cost_saved_usd is not None:
            self._span.set_attribute(
                ModelOpsAttributes.SERVING_CACHE_COST_SAVED, cost_saved_usd
            )

    @property
    def span(self) -> trace.Span:
        return self._span


class MonitoringCheck:
    """Helper for recording monitoring check results."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_result(
        self,
        result: str,
        metric_value: float | None = None,
        baseline_value: float | None = None,
        drift_score: float | None = None,
        drift_type: str | None = None,
        action_triggered: str | None = None,
    ) -> None:
        self._span.set_attribute(ModelOpsAttributes.MONITORING_RESULT, result)
        if metric_value is not None:
            self._span.set_attribute(ModelOpsAttributes.MONITORING_METRIC_VALUE, metric_value)
        if baseline_value is not None:
            self._span.set_attribute(ModelOpsAttributes.MONITORING_BASELINE_VALUE, baseline_value)
        if drift_score is not None:
            self._span.set_attribute(ModelOpsAttributes.MONITORING_DRIFT_SCORE, drift_score)
        if drift_type:
            self._span.set_attribute(ModelOpsAttributes.MONITORING_DRIFT_TYPE, drift_type)
        if action_triggered:
            self._span.set_attribute(ModelOpsAttributes.MONITORING_ACTION_TRIGGERED, action_triggered)

    @property
    def span(self) -> trace.Span:
        return self._span


class PromptOperation:
    """Helper for recording prompt lifecycle attributes."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_evaluation(self, score: float, passed: bool) -> None:
        self._span.set_attribute(ModelOpsAttributes.PROMPT_EVAL_SCORE, score)
        self._span.set_attribute(ModelOpsAttributes.PROMPT_EVAL_PASS, passed)

    def set_content_hash(self, hash_value: str) -> None:
        self._span.set_attribute(ModelOpsAttributes.PROMPT_CONTENT_HASH, hash_value)

    def set_ab_test(self, test_id: str, variant: str, traffic_pct: float | None = None) -> None:
        self._span.set_attribute(ModelOpsAttributes.PROMPT_AB_TEST_ID, test_id)
        self._span.set_attribute(ModelOpsAttributes.PROMPT_AB_TEST_VARIANT, variant)

    @property
    def span(self) -> trace.Span:
        return self._span
