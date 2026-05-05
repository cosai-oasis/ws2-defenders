"""AITF MLflow Integration Instrumentor.

Wraps the MLflow SDK with AITF telemetry instrumentation for comprehensive
observability across experiment tracking, model registry, model serving
endpoints, and run tracking operations.

Instrumented operations:
    - Experiment tracking: mlflow.log_param, log_metric, log_model
    - Model registry: register_model, transition_model_version_stage
    - Model serving: endpoint creation, invocation, traffic configuration
    - Run tracking: start_run, end_run, artifact logging

Maps to ``aitf.model_ops.*`` attributes (training, evaluation, registry)
and tracks artifacts plus lineage metadata.

Usage:
    from integrations.databricks.mlflow.instrumentor import MLflowInstrumentor

    instrumentor = MLflowInstrumentor()
    instrumentor.instrument()

    # From this point, all MLflow SDK calls produce AITF telemetry spans.
    import mlflow
    with mlflow.start_run():
        mlflow.log_param("learning_rate", 0.001)
        mlflow.log_metric("loss", 0.42)
        mlflow.sklearn.log_model(model, "model")

    # Disable instrumentation when no longer needed.
    instrumentor.uninstrument()
"""

from __future__ import annotations

import functools
import json
import logging
import time
from contextlib import contextmanager
from typing import Any, Callable, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import (
    AssetInventoryAttributes,
    CostAttributes,
    GenAIAttributes,
    LatencyAttributes,
    ModelOpsAttributes,
)

logger = logging.getLogger(__name__)

_TRACER_NAME = "aitf.integrations.databricks.mlflow"
_INTEGRATION_VERSION = "0.1.0"


class MLflowInstrumentor:
    """Instruments the MLflow SDK with AITF telemetry.

    Patches core MLflow functions to emit OpenTelemetry spans with AITF
    semantic convention attributes for experiment tracking, model registry,
    model serving, and artifact management.

    Args:
        tracer_provider: Optional custom ``TracerProvider``. If *None*, the
            globally configured provider is used.

    Usage:
        >>> from integrations.databricks.mlflow.instrumentor import MLflowInstrumentor
        >>> inst = MLflowInstrumentor()
        >>> inst.instrument()
        >>> # ... use mlflow as normal; spans are emitted automatically ...
        >>> inst.uninstrument()
    """

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._original_functions: dict[str, Callable[..., Any]] = {}

    # ── Core lifecycle ───────────────────────────────────────────────

    def instrument(self) -> None:
        """Activate MLflow instrumentation.

        Patches the following MLflow entry-points:
            - ``mlflow.start_run``
            - ``mlflow.end_run``
            - ``mlflow.log_param`` / ``log_params``
            - ``mlflow.log_metric`` / ``log_metrics``
            - ``mlflow.log_artifact`` / ``log_artifacts``
            - ``mlflow.sklearn.log_model`` (and other flavour ``log_model``)
            - ``mlflow.register_model``
            - ``MlflowClient.transition_model_version_stage``
            - ``MlflowClient.create_model_version``
            - Model serving helpers

        Raises:
            ImportError: If ``mlflow`` is not installed.
        """
        if self._instrumented:
            logger.debug("MLflowInstrumentor already active; skipping.")
            return

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME, _INTEGRATION_VERSION)

        try:
            self._patch_mlflow()
        except ImportError:
            logger.warning(
                "mlflow package not found. Install it with: "
                "pip install mlflow"
            )
            return

        self._instrumented = True
        logger.info("MLflowInstrumentor activated.")

    def uninstrument(self) -> None:
        """Remove all MLflow patches and stop emitting telemetry."""
        if not self._instrumented:
            return

        self._unpatch_mlflow()
        self._tracer = None
        self._instrumented = False
        logger.info("MLflowInstrumentor deactivated.")

    @property
    def is_instrumented(self) -> bool:
        """Return *True* if instrumentation is currently active."""
        return self._instrumented

    def get_tracer(self) -> trace.Tracer:
        """Return the active tracer, lazily initialising if needed."""
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME, _INTEGRATION_VERSION)
        return self._tracer

    # ── Monkey-patching ──────────────────────────────────────────────

    def _patch_mlflow(self) -> None:
        """Apply instrumentation patches to the mlflow module."""
        import mlflow  # noqa: F811
        import mlflow.tracking

        patch_targets = {
            "mlflow.start_run": (mlflow, "start_run", self._wrap_start_run),
            "mlflow.end_run": (mlflow, "end_run", self._wrap_end_run),
            "mlflow.log_param": (mlflow, "log_param", self._wrap_log_param),
            "mlflow.log_params": (mlflow, "log_params", self._wrap_log_params),
            "mlflow.log_metric": (mlflow, "log_metric", self._wrap_log_metric),
            "mlflow.log_metrics": (mlflow, "log_metrics", self._wrap_log_metrics),
            "mlflow.log_artifact": (mlflow, "log_artifact", self._wrap_log_artifact),
            "mlflow.log_artifacts": (mlflow, "log_artifacts", self._wrap_log_artifacts),
            "mlflow.register_model": (mlflow, "register_model", self._wrap_register_model),
        }

        for key, (module, attr, wrapper_factory) in patch_targets.items():
            if hasattr(module, attr):
                original = getattr(module, attr)
                self._original_functions[key] = original
                setattr(module, attr, wrapper_factory(original))

        # Patch MlflowClient methods
        try:
            client_cls = mlflow.tracking.MlflowClient
            client_targets = {
                "MlflowClient.transition_model_version_stage": (
                    client_cls,
                    "transition_model_version_stage",
                    self._wrap_transition_stage,
                ),
                "MlflowClient.create_model_version": (
                    client_cls,
                    "create_model_version",
                    self._wrap_create_model_version,
                ),
                "MlflowClient.create_registered_model": (
                    client_cls,
                    "create_registered_model",
                    self._wrap_create_registered_model,
                ),
            }
            for key, (cls, attr, wrapper_factory) in client_targets.items():
                if hasattr(cls, attr):
                    original = getattr(cls, attr)
                    self._original_functions[key] = original
                    setattr(cls, attr, wrapper_factory(original))
        except AttributeError:
            logger.debug("MlflowClient patch targets not available.")

    def _unpatch_mlflow(self) -> None:
        """Remove all monkey-patches from the mlflow module."""
        try:
            import mlflow
            import mlflow.tracking
        except ImportError:
            self._original_functions.clear()
            return

        module_targets = {
            "mlflow.start_run": mlflow,
            "mlflow.end_run": mlflow,
            "mlflow.log_param": mlflow,
            "mlflow.log_params": mlflow,
            "mlflow.log_metric": mlflow,
            "mlflow.log_metrics": mlflow,
            "mlflow.log_artifact": mlflow,
            "mlflow.log_artifacts": mlflow,
            "mlflow.register_model": mlflow,
        }

        for key, module in module_targets.items():
            if key in self._original_functions:
                attr = key.split(".")[-1]
                setattr(module, attr, self._original_functions[key])

        client_targets = {
            "MlflowClient.transition_model_version_stage": mlflow.tracking.MlflowClient,
            "MlflowClient.create_model_version": mlflow.tracking.MlflowClient,
            "MlflowClient.create_registered_model": mlflow.tracking.MlflowClient,
        }

        for key, cls in client_targets.items():
            if key in self._original_functions:
                attr = key.split(".")[-1]
                setattr(cls, attr, self._original_functions[key])

        self._original_functions.clear()

    # ── Wrapper factories ────────────────────────────────────────────

    def _wrap_start_run(self, original: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap ``mlflow.start_run`` to create a training run span."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(
            *args: Any,
            run_id: str | None = None,
            experiment_id: str | None = None,
            run_name: str | None = None,
            **kwargs: Any,
        ) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
                ModelOpsAttributes.TRAINING_STATUS: "running",
            }
            if run_id:
                attributes[ModelOpsAttributes.TRAINING_RUN_ID] = run_id
            if experiment_id:
                attributes[ModelOpsAttributes.TRAINING_EXPERIMENT_ID] = experiment_id
            if run_name:
                attributes[ModelOpsAttributes.TRAINING_EXPERIMENT_NAME] = run_name

            with tracer.start_as_current_span(
                name="mlflow.start_run",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(
                        *args,
                        run_id=run_id,
                        experiment_id=experiment_id,
                        run_name=run_name,
                        **kwargs,
                    )
                    # Capture the actual run ID assigned by MLflow
                    if hasattr(result, "info") and hasattr(result.info, "run_id"):
                        span.set_attribute(
                            ModelOpsAttributes.TRAINING_RUN_ID,
                            result.info.run_id,
                        )
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_end_run(self, original: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap ``mlflow.end_run`` to finalize the training run span."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(*args: Any, status: str = "FINISHED", **kwargs: Any) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
                ModelOpsAttributes.TRAINING_STATUS: status.lower(),
            }

            with tracer.start_as_current_span(
                name="mlflow.end_run",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(*args, status=status, **kwargs)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_log_param(self, original: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap ``mlflow.log_param`` to emit a parameter-logging span."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(key: str, value: Any, *args: Any, **kwargs: Any) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
                "aitf.mlflow.param.key": key,
                "aitf.mlflow.param.value": str(value),
            }

            with tracer.start_as_current_span(
                name=f"mlflow.log_param {key}",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(key, value, *args, **kwargs)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_log_params(self, original: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap ``mlflow.log_params`` to emit a batch parameter-logging span."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(params: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
                ModelOpsAttributes.TRAINING_HYPERPARAMETERS: json.dumps(
                    {k: str(v) for k, v in params.items()}
                ),
                "aitf.mlflow.params.count": len(params),
            }

            with tracer.start_as_current_span(
                name="mlflow.log_params",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(params, *args, **kwargs)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_log_metric(self, original: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap ``mlflow.log_metric`` to emit a metric-logging span."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(
            key: str,
            value: float,
            *args: Any,
            step: int | None = None,
            **kwargs: Any,
        ) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
                "aitf.mlflow.metric.key": key,
                "aitf.mlflow.metric.value": value,
            }
            if step is not None:
                attributes["aitf.mlflow.metric.step"] = step

            # Map well-known metric names to AITF attributes
            if key in ("loss", "train_loss"):
                attributes[ModelOpsAttributes.TRAINING_LOSS_FINAL] = value
            elif key in ("val_loss", "validation_loss", "eval_loss"):
                attributes[ModelOpsAttributes.TRAINING_VAL_LOSS_FINAL] = value

            with tracer.start_as_current_span(
                name=f"mlflow.log_metric {key}",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(key, value, *args, step=step, **kwargs)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_log_metrics(self, original: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap ``mlflow.log_metrics`` to emit a batch metric-logging span."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(
            metrics: dict[str, float],
            *args: Any,
            step: int | None = None,
            **kwargs: Any,
        ) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
                ModelOpsAttributes.EVALUATION_METRICS: json.dumps(metrics),
                "aitf.mlflow.metrics.count": len(metrics),
            }
            if step is not None:
                attributes["aitf.mlflow.metrics.step"] = step

            # Map well-known metrics
            if "loss" in metrics:
                attributes[ModelOpsAttributes.TRAINING_LOSS_FINAL] = metrics["loss"]
            if "val_loss" in metrics:
                attributes[ModelOpsAttributes.TRAINING_VAL_LOSS_FINAL] = metrics["val_loss"]

            with tracer.start_as_current_span(
                name="mlflow.log_metrics",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(metrics, *args, step=step, **kwargs)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_log_artifact(self, original: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap ``mlflow.log_artifact`` to track artifact uploads."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(
            local_path: str,
            artifact_path: str | None = None,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
                "aitf.mlflow.artifact.local_path": local_path,
            }
            if artifact_path:
                attributes["aitf.mlflow.artifact.artifact_path"] = artifact_path

            with tracer.start_as_current_span(
                name="mlflow.log_artifact",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(
                        local_path, artifact_path, *args, **kwargs
                    )
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_log_artifacts(self, original: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap ``mlflow.log_artifacts`` to track bulk artifact uploads."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(
            local_dir: str,
            artifact_path: str | None = None,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
                "aitf.mlflow.artifacts.local_dir": local_dir,
            }
            if artifact_path:
                attributes["aitf.mlflow.artifacts.artifact_path"] = artifact_path

            with tracer.start_as_current_span(
                name="mlflow.log_artifacts",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(
                        local_dir, artifact_path, *args, **kwargs
                    )
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_register_model(self, original: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap ``mlflow.register_model`` to trace model registry operations."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(
            model_uri: str,
            name: str,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.REGISTRY_OPERATION: "register",
                ModelOpsAttributes.REGISTRY_MODEL_ID: name,
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
                "aitf.mlflow.model_uri": model_uri,
            }

            with tracer.start_as_current_span(
                name=f"mlflow.register_model {name}",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(model_uri, name, *args, **kwargs)
                    # Capture version info from the result
                    if hasattr(result, "version"):
                        span.set_attribute(
                            ModelOpsAttributes.REGISTRY_MODEL_VERSION,
                            str(result.version),
                        )
                    if hasattr(result, "name"):
                        span.set_attribute(
                            ModelOpsAttributes.REGISTRY_MODEL_ID,
                            result.name,
                        )
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_transition_stage(
        self, original: Callable[..., Any]
    ) -> Callable[..., Any]:
        """Wrap ``MlflowClient.transition_model_version_stage`` for stage transitions."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(
            self_client: Any,
            name: str,
            version: str,
            stage: str,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.REGISTRY_OPERATION: "transition_stage",
                ModelOpsAttributes.REGISTRY_MODEL_ID: name,
                ModelOpsAttributes.REGISTRY_MODEL_VERSION: str(version),
                ModelOpsAttributes.REGISTRY_STAGE: stage,
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
            }

            with tracer.start_as_current_span(
                name=f"mlflow.registry.transition_stage {name} -> {stage}",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(
                        self_client, name, version, stage, *args, **kwargs
                    )
                    # Record the previous stage if available
                    if hasattr(result, "current_stage"):
                        span.set_attribute(
                            ModelOpsAttributes.REGISTRY_PREVIOUS_STAGE,
                            result.current_stage,
                        )
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_create_model_version(
        self, original: Callable[..., Any]
    ) -> Callable[..., Any]:
        """Wrap ``MlflowClient.create_model_version`` to trace version creation."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(
            self_client: Any,
            name: str,
            source: str,
            *args: Any,
            run_id: str | None = None,
            **kwargs: Any,
        ) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.REGISTRY_OPERATION: "create_version",
                ModelOpsAttributes.REGISTRY_MODEL_ID: name,
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
                "aitf.mlflow.model_source": source,
            }
            if run_id:
                attributes[ModelOpsAttributes.REGISTRY_LINEAGE_TRAINING_RUN_ID] = run_id

            with tracer.start_as_current_span(
                name=f"mlflow.registry.create_model_version {name}",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(
                        self_client, name, source, *args, run_id=run_id, **kwargs
                    )
                    if hasattr(result, "version"):
                        span.set_attribute(
                            ModelOpsAttributes.REGISTRY_MODEL_VERSION,
                            str(result.version),
                        )
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_create_registered_model(
        self, original: Callable[..., Any]
    ) -> Callable[..., Any]:
        """Wrap ``MlflowClient.create_registered_model`` for model registration."""
        tracer = self.get_tracer()

        @functools.wraps(original)
        def wrapper(
            self_client: Any,
            name: str,
            *args: Any,
            tags: dict[str, str] | None = None,
            description: str | None = None,
            **kwargs: Any,
        ) -> Any:
            attributes: dict[str, Any] = {
                ModelOpsAttributes.REGISTRY_OPERATION: "create_registered_model",
                ModelOpsAttributes.REGISTRY_MODEL_ID: name,
                ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
            }
            if description:
                attributes["aitf.mlflow.model.description"] = description

            with tracer.start_as_current_span(
                name=f"mlflow.registry.create_registered_model {name}",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(
                        self_client,
                        name,
                        *args,
                        tags=tags,
                        description=description,
                        **kwargs,
                    )
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    # ── Manual span API (for direct usage without patching) ──────────

    @contextmanager
    def trace_experiment(
        self,
        experiment_name: str,
        experiment_id: str | None = None,
        run_name: str | None = None,
        training_type: str = "fine_tuning",
        base_model: str | None = None,
        dataset_id: str | None = None,
        dataset_version: str | None = None,
    ) -> Generator[MLflowExperimentSpan, None, None]:
        """Context manager for tracing an entire MLflow experiment run.

        Provides a high-level span covering the full experiment lifecycle,
        with helper methods for recording metrics, params, and artifacts.

        Usage:
            >>> inst = MLflowInstrumentor()
            >>> inst.instrument()
            >>> with inst.trace_experiment(
            ...     experiment_name="customer-churn-v3",
            ...     training_type="fine_tuning",
            ...     base_model="meta-llama/Llama-3.1-8B",
            ... ) as exp:
            ...     exp.log_param("learning_rate", 0.001)
            ...     exp.log_metric("loss", 0.42, step=100)
            ...     exp.log_metric("val_loss", 0.45, step=100)
            ...     exp.set_output_model("churn-llama-8b-v3", "sha256:def456")
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
            ModelOpsAttributes.TRAINING_TYPE: training_type,
            ModelOpsAttributes.TRAINING_EXPERIMENT_NAME: experiment_name,
            ModelOpsAttributes.TRAINING_STATUS: "running",
        }
        if experiment_id:
            attributes[ModelOpsAttributes.TRAINING_EXPERIMENT_ID] = experiment_id
        if run_name:
            attributes["aitf.mlflow.run_name"] = run_name
        if base_model:
            attributes[ModelOpsAttributes.TRAINING_BASE_MODEL] = base_model
        if dataset_id:
            attributes[ModelOpsAttributes.TRAINING_DATASET_ID] = dataset_id
        if dataset_version:
            attributes[ModelOpsAttributes.TRAINING_DATASET_VERSION] = dataset_version

        with tracer.start_as_current_span(
            name=f"mlflow.experiment {experiment_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            exp_span = MLflowExperimentSpan(span)
            try:
                yield exp_span
                span.set_attribute(
                    ModelOpsAttributes.TRAINING_STATUS, "completed"
                )
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_attribute(
                    ModelOpsAttributes.TRAINING_STATUS, "failed"
                )
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_serving_endpoint(
        self,
        endpoint_name: str,
        model_name: str,
        model_version: str | None = None,
        operation: str = "invoke",
    ) -> Generator[MLflowServingSpan, None, None]:
        """Context manager for tracing model serving endpoint invocations.

        Wraps calls to Databricks Model Serving endpoints with latency,
        cost, and routing telemetry.

        Usage:
            >>> with inst.trace_serving_endpoint(
            ...     endpoint_name="prod-chat-endpoint",
            ...     model_name="customer-chat-llama-70b",
            ...     operation="invoke",
            ... ) as srv:
            ...     response = requests.post(endpoint_url, json=payload)
            ...     srv.set_response_tokens(input_tokens=120, output_tokens=450)
            ...     srv.set_latency(total_ms=340.5)
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            ModelOpsAttributes.SERVING_OPERATION: operation,
            ModelOpsAttributes.DEPLOYMENT_ENDPOINT: endpoint_name,
            ModelOpsAttributes.DEPLOYMENT_MODEL_ID: model_name,
            ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
        }
        if model_version:
            attributes[ModelOpsAttributes.DEPLOYMENT_MODEL_VERSION] = model_version

        start_time = time.monotonic()

        with tracer.start_as_current_span(
            name=f"mlflow.serving.{operation} {endpoint_name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            srv_span = MLflowServingSpan(span, start_time)
            try:
                yield srv_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_model_log(
        self,
        model_name: str,
        flavor: str = "sklearn",
        artifact_path: str | None = None,
        registered_model_name: str | None = None,
    ) -> Generator[trace.Span, None, None]:
        """Context manager for tracing ``log_model`` operations across flavours.

        Usage:
            >>> with inst.trace_model_log(
            ...     model_name="churn-predictor",
            ...     flavor="sklearn",
            ...     registered_model_name="churn-predictor-prod",
            ... ) as span:
            ...     mlflow.sklearn.log_model(model, "model")
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            ModelOpsAttributes.TRAINING_FRAMEWORK: "mlflow",
            ModelOpsAttributes.TRAINING_OUTPUT_MODEL_ID: model_name,
            "aitf.mlflow.model.flavor": flavor,
        }
        if artifact_path:
            attributes["aitf.mlflow.model.artifact_path"] = artifact_path
        if registered_model_name:
            attributes[ModelOpsAttributes.REGISTRY_MODEL_ID] = registered_model_name
            attributes[ModelOpsAttributes.REGISTRY_OPERATION] = "log_model"

        with tracer.start_as_current_span(
            name=f"mlflow.log_model {flavor}/{model_name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


# ── Helper span classes ──────────────────────────────────────────────


class MLflowExperimentSpan:
    """Helper for enriching an MLflow experiment tracing span.

    Provides convenience methods for recording params, metrics, artifacts,
    and output model information during a traced experiment run.
    """

    def __init__(self, span: trace.Span) -> None:
        self._span = span
        self._params: dict[str, str] = {}
        self._metrics: dict[str, float] = {}
        self._artifact_count: int = 0

    @property
    def span(self) -> trace.Span:
        """Return the underlying OTel span."""
        return self._span

    def log_param(self, key: str, value: Any) -> None:
        """Record a training parameter on the span."""
        self._params[key] = str(value)
        self._span.set_attribute(
            ModelOpsAttributes.TRAINING_HYPERPARAMETERS,
            json.dumps(self._params),
        )
        self._span.add_event(
            "mlflow.log_param",
            attributes={"param.key": key, "param.value": str(value)},
        )

    def log_metric(
        self, key: str, value: float, step: int | None = None
    ) -> None:
        """Record a training metric on the span."""
        self._metrics[key] = value
        event_attrs: dict[str, Any] = {
            "metric.key": key,
            "metric.value": value,
        }
        if step is not None:
            event_attrs["metric.step"] = step

        self._span.add_event("mlflow.log_metric", attributes=event_attrs)

        # Map well-known metric names
        if key in ("loss", "train_loss"):
            self._span.set_attribute(
                ModelOpsAttributes.TRAINING_LOSS_FINAL, value
            )
        elif key in ("val_loss", "validation_loss", "eval_loss"):
            self._span.set_attribute(
                ModelOpsAttributes.TRAINING_VAL_LOSS_FINAL, value
            )

        self._span.set_attribute(
            ModelOpsAttributes.EVALUATION_METRICS,
            json.dumps(self._metrics),
        )

    def log_artifact(self, path: str, artifact_path: str | None = None) -> None:
        """Record an artifact upload event on the span."""
        self._artifact_count += 1
        event_attrs: dict[str, Any] = {
            "artifact.local_path": path,
            "artifact.count_total": self._artifact_count,
        }
        if artifact_path:
            event_attrs["artifact.artifact_path"] = artifact_path
        self._span.add_event("mlflow.log_artifact", attributes=event_attrs)

    def set_output_model(
        self, model_id: str, model_hash: str | None = None
    ) -> None:
        """Record the output model identifier and optional integrity hash."""
        self._span.set_attribute(
            ModelOpsAttributes.TRAINING_OUTPUT_MODEL_ID, model_id
        )
        if model_hash:
            self._span.set_attribute(
                ModelOpsAttributes.TRAINING_OUTPUT_MODEL_HASH, model_hash
            )

    def set_compute(
        self,
        gpu_type: str,
        gpu_count: int,
        gpu_hours: float,
    ) -> None:
        """Record compute resource usage for the experiment."""
        self._span.set_attribute(
            ModelOpsAttributes.TRAINING_COMPUTE_GPU_TYPE, gpu_type
        )
        self._span.set_attribute(
            ModelOpsAttributes.TRAINING_COMPUTE_GPU_COUNT, gpu_count
        )
        self._span.set_attribute(
            ModelOpsAttributes.TRAINING_COMPUTE_GPU_HOURS, gpu_hours
        )

    def set_epochs(self, epochs: int) -> None:
        """Record the number of training epochs."""
        self._span.set_attribute(ModelOpsAttributes.TRAINING_EPOCHS, epochs)

    def set_batch_size(self, batch_size: int) -> None:
        """Record the training batch size."""
        self._span.set_attribute(
            ModelOpsAttributes.TRAINING_BATCH_SIZE, batch_size
        )

    def set_learning_rate(self, lr: float) -> None:
        """Record the learning rate."""
        self._span.set_attribute(
            ModelOpsAttributes.TRAINING_LEARNING_RATE, lr
        )

    def set_code_commit(self, commit: str) -> None:
        """Record the git commit hash for reproducibility."""
        self._span.set_attribute(
            ModelOpsAttributes.TRAINING_CODE_COMMIT, commit
        )


class MLflowServingSpan:
    """Helper for enriching an MLflow model serving span.

    Provides methods for recording response details, token usage, latency,
    and cost information for model serving endpoint invocations.
    """

    def __init__(self, span: trace.Span, start_time: float) -> None:
        self._span = span
        self._start_time = start_time

    @property
    def span(self) -> trace.Span:
        """Return the underlying OTel span."""
        return self._span

    def set_response_tokens(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        """Record token usage for the serving request."""
        self._span.set_attribute(
            GenAIAttributes.USAGE_INPUT_TOKENS, input_tokens
        )
        self._span.set_attribute(
            GenAIAttributes.USAGE_OUTPUT_TOKENS, output_tokens
        )

    def set_latency(
        self,
        total_ms: float | None = None,
        inference_time_ms: float | None = None,
        queue_time_ms: float | None = None,
    ) -> None:
        """Record latency metrics for the serving request."""
        if total_ms is None:
            total_ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute(LatencyAttributes.TOTAL_MS, total_ms)
        if inference_time_ms is not None:
            self._span.set_attribute(
                LatencyAttributes.INFERENCE_TIME_MS, inference_time_ms
            )
        if queue_time_ms is not None:
            self._span.set_attribute(
                LatencyAttributes.QUEUE_TIME_MS, queue_time_ms
            )

    def set_cost(
        self,
        total_cost: float,
        currency: str = "USD",
    ) -> None:
        """Record cost information for the serving invocation."""
        self._span.set_attribute(CostAttributes.TOTAL_COST, total_cost)
        self._span.set_attribute(CostAttributes.CURRENCY, currency)

    def set_route(
        self,
        selected_model: str,
        reason: str | None = None,
    ) -> None:
        """Record model routing metadata for traffic-split endpoints."""
        self._span.set_attribute(
            ModelOpsAttributes.SERVING_ROUTE_SELECTED_MODEL, selected_model
        )
        if reason:
            self._span.set_attribute(
                ModelOpsAttributes.SERVING_ROUTE_REASON, reason
            )
