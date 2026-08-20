"""AITF Azure Machine Learning Instrumentor.

Wraps the ``azure-ai-ml`` Python SDK (``MLClient``) with AITF telemetry.
Monkey-patches key operations on ``MLClient`` to emit OpenTelemetry spans
enriched with ``aitf.model_ops.*`` attributes.

Instrumented operations:

* **Model Deployment** -- ``MLClient.online_deployments.begin_create_or_update()``
* **Online Endpoints** -- ``MLClient.online_endpoints.begin_create_or_update()``,
  ``MLClient.online_endpoints.invoke()``
* **Batch Endpoints** -- ``MLClient.batch_endpoints.begin_create_or_update()``,
  ``MLClient.batch_endpoints.invoke()``
* **Model Registration** -- ``MLClient.models.create_or_update()``
* **Managed Compute** -- ``MLClient.compute.begin_create_or_update()``,
  ``MLClient.compute.begin_delete()``

Usage:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

    from integrations.azure_ai.azure_ml.instrumentor import AzureMLInstrumentor

    # Set up tracing
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    # Instrument Azure ML
    instrumentor = AzureMLInstrumentor(tracer_provider=provider)
    instrumentor.instrument()

    # Use the SDK as normal -- all calls are now traced
    from azure.ai.ml import MLClient
    from azure.identity import DefaultAzureCredential

    ml_client = MLClient(
        credential=DefaultAzureCredential(),
        subscription_id="...",
        resource_group_name="my-rg",
        workspace_name="my-workspace",
    )

    # Register a model
    from azure.ai.ml.entities import Model
    ml_client.models.create_or_update(
        Model(name="my-model", version="1", path="./model")
    )

    # To remove instrumentation
    instrumentor.uninstrument()
"""

from __future__ import annotations

import json
import logging
import time
from functools import wraps
from typing import Any, Callable

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.instrumentation import ModelOpsInstrumentor
from aitf.semantic_conventions.attributes import (
    CostAttributes,
    GenAIAttributes,
    ModelOpsAttributes,
)

logger = logging.getLogger(__name__)

_TRACER_NAME = "aitf.integrations.azure_ml"

# Azure ML-specific attribute keys (aitf.azure_ml.* namespace)
_AZURE_ML_WORKSPACE = "aitf.azure_ml.workspace"
_AZURE_ML_RESOURCE_GROUP = "aitf.azure_ml.resource_group"
_AZURE_ML_SUBSCRIPTION_ID = "aitf.azure_ml.subscription_id"
_AZURE_ML_ENDPOINT_NAME = "aitf.azure_ml.endpoint.name"
_AZURE_ML_ENDPOINT_TYPE = "aitf.azure_ml.endpoint.type"
_AZURE_ML_ENDPOINT_AUTH_MODE = "aitf.azure_ml.endpoint.auth_mode"
_AZURE_ML_DEPLOYMENT_NAME = "aitf.azure_ml.deployment.name"
_AZURE_ML_DEPLOYMENT_INSTANCE_TYPE = "aitf.azure_ml.deployment.instance_type"
_AZURE_ML_DEPLOYMENT_INSTANCE_COUNT = "aitf.azure_ml.deployment.instance_count"
_AZURE_ML_DEPLOYMENT_SCORING_URI = "aitf.azure_ml.deployment.scoring_uri"
_AZURE_ML_MODEL_NAME = "aitf.azure_ml.model.name"
_AZURE_ML_MODEL_VERSION = "aitf.azure_ml.model.version"
_AZURE_ML_MODEL_TYPE = "aitf.azure_ml.model.type"
_AZURE_ML_MODEL_PATH = "aitf.azure_ml.model.path"
_AZURE_ML_COMPUTE_NAME = "aitf.azure_ml.compute.name"
_AZURE_ML_COMPUTE_TYPE = "aitf.azure_ml.compute.type"
_AZURE_ML_COMPUTE_SIZE = "aitf.azure_ml.compute.size"
_AZURE_ML_COMPUTE_MIN_INSTANCES = "aitf.azure_ml.compute.min_instances"
_AZURE_ML_COMPUTE_MAX_INSTANCES = "aitf.azure_ml.compute.max_instances"
_AZURE_ML_BATCH_JOB_NAME = "aitf.azure_ml.batch.job_name"
_AZURE_ML_BATCH_MINI_BATCH_SIZE = "aitf.azure_ml.batch.mini_batch_size"
_AZURE_ML_BATCH_OUTPUT_ACTION = "aitf.azure_ml.batch.output_action"


# ------------------------------------------------------------------
# Patch descriptor -- keeps track of what was patched and the original
# ------------------------------------------------------------------

class _PatchRecord:
    """Stores the target class, method name, and original callable for a patch."""

    __slots__ = ("target_cls", "method_name", "original")

    def __init__(self, target_cls: type, method_name: str, original: Callable) -> None:
        self.target_cls = target_cls
        self.method_name = method_name
        self.original = original

    def restore(self) -> None:
        setattr(self.target_cls, self.method_name, self.original)


class AzureMLInstrumentor:
    """Instruments ``MLClient`` operations for Azure Machine Learning.

    Wraps model deployment, online/batch endpoint, model registration, and
    managed compute operations with OpenTelemetry spans carrying
    ``aitf.model_ops.*`` and ``aitf.azure_ml.*`` attributes.

    Args:
        tracer_provider: Optional ``TracerProvider``. When ``None``, the
            globally registered provider is used.

    Example:
        >>> instrumentor = AzureMLInstrumentor()
        >>> instrumentor.instrument()
        >>> # MLClient operations now emit spans
        >>> instrumentor.uninstrument()
    """

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._patches: list[_PatchRecord] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Apply monkey-patches to Azure ML SDK classes.

        After calling this method, operations on ``MLClient.online_deployments``,
        ``MLClient.online_endpoints``, ``MLClient.batch_endpoints``,
        ``MLClient.models``, and ``MLClient.compute`` will emit
        OpenTelemetry spans.

        This method is idempotent.
        """
        if self._instrumented:
            logger.debug("AzureMLInstrumentor is already instrumented.")
            return

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        try:
            from azure.ai.ml.operations import (
                BatchDeploymentOperations,
                BatchEndpointOperations,
                ComputeOperations,
                ModelOperations,
                OnlineDeploymentOperations,
                OnlineEndpointOperations,
            )
        except ImportError as exc:
            raise ImportError(
                "The 'azure-ai-ml' package is required for AzureMLInstrumentor. "
                "Install it with: pip install azure-ai-ml"
            ) from exc

        # -- Online Deployments --
        self._patch(
            OnlineDeploymentOperations,
            "begin_create_or_update",
            self._wrap_online_deployment_create,
        )

        # -- Online Endpoints --
        self._patch(
            OnlineEndpointOperations,
            "begin_create_or_update",
            self._wrap_online_endpoint_create,
        )
        self._patch(
            OnlineEndpointOperations,
            "invoke",
            self._wrap_online_endpoint_invoke,
        )

        # -- Batch Endpoints --
        self._patch(
            BatchEndpointOperations,
            "begin_create_or_update",
            self._wrap_batch_endpoint_create,
        )
        self._patch(
            BatchEndpointOperations,
            "invoke",
            self._wrap_batch_endpoint_invoke,
        )

        # -- Model Registration --
        self._patch(
            ModelOperations,
            "create_or_update",
            self._wrap_model_register,
        )

        # -- Managed Compute --
        self._patch(
            ComputeOperations,
            "begin_create_or_update",
            self._wrap_compute_create,
        )
        self._patch(
            ComputeOperations,
            "begin_delete",
            self._wrap_compute_delete,
        )

        self._instrumented = True
        logger.info("AzureMLInstrumentor: instrumentation enabled.")

    def uninstrument(self) -> None:
        """Remove monkey-patches and restore original SDK behaviour.

        This method is idempotent.
        """
        if not self._instrumented:
            return

        for patch in self._patches:
            try:
                patch.restore()
            except Exception:  # noqa: BLE001
                logger.warning(
                    "AzureMLInstrumentor: failed to restore %s.%s",
                    patch.target_cls.__name__,
                    patch.method_name,
                )

        self._patches.clear()
        self._tracer = None
        self._instrumented = False
        logger.info("AzureMLInstrumentor: instrumentation removed.")

    @property
    def is_instrumented(self) -> bool:
        """Return ``True`` if the instrumentor is currently active."""
        return self._instrumented

    # ------------------------------------------------------------------
    # Patch helper
    # ------------------------------------------------------------------

    def _patch(
        self,
        target_cls: type,
        method_name: str,
        wrapper_factory: Callable,
    ) -> None:
        """Replace *method_name* on *target_cls* with an instrumented wrapper."""
        original = getattr(target_cls, method_name)
        wrapped = wrapper_factory(original)
        setattr(target_cls, method_name, wrapped)
        self._patches.append(_PatchRecord(target_cls, method_name, original))

    def _get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    # ------------------------------------------------------------------
    # Workspace context extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_workspace_context(operations_instance: Any) -> dict[str, str]:
        """Extract workspace, resource group, and subscription from the operations object."""
        ctx: dict[str, str] = {}
        try:
            # Operations hold a reference to the workspace scope
            ws_scope = getattr(operations_instance, "_workspace_scope", None)
            if ws_scope is not None:
                ctx[_AZURE_ML_WORKSPACE] = getattr(ws_scope, "workspace_name", "") or ""
                ctx[_AZURE_ML_RESOURCE_GROUP] = getattr(ws_scope, "resource_group_name", "") or ""
                ctx[_AZURE_ML_SUBSCRIPTION_ID] = getattr(ws_scope, "subscription_id", "") or ""
            else:
                # Fallback: some operations expose it directly
                for attr in ("_subscription_id", "_resource_group_name", "_workspace_name"):
                    value = getattr(operations_instance, attr, None)
                    if value is not None:
                        key = {
                            "_subscription_id": _AZURE_ML_SUBSCRIPTION_ID,
                            "_resource_group_name": _AZURE_ML_RESOURCE_GROUP,
                            "_workspace_name": _AZURE_ML_WORKSPACE,
                        }[attr]
                        ctx[key] = str(value)
        except AttributeError:
            pass
        return ctx

    # ------------------------------------------------------------------
    # Online Deployment wrapper
    # ------------------------------------------------------------------

    def _wrap_online_deployment_create(self, original: Callable) -> Callable:
        """Wrap ``OnlineDeploymentOperations.begin_create_or_update``."""
        instrumentor = self

        @wraps(original)
        def wrapped(ops_self: Any, deployment: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._get_tracer()
            ws_ctx = instrumentor._extract_workspace_context(ops_self)

            # Extract deployment metadata
            deploy_name = getattr(deployment, "name", "unknown")
            endpoint_name = getattr(deployment, "endpoint_name", "unknown")
            model_ref = getattr(deployment, "model", None)
            instance_type = getattr(deployment, "instance_type", None)
            instance_count = getattr(deployment, "instance_count", None)

            model_id = str(model_ref) if model_ref else "unknown"

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: GenAIAttributes.System.AZURE,
                ModelOpsAttributes.DEPLOYMENT_MODEL_ID: model_id,
                ModelOpsAttributes.DEPLOYMENT_STRATEGY: ModelOpsAttributes.DeploymentStrategy.ROLLING,
                ModelOpsAttributes.DEPLOYMENT_ENVIRONMENT: "azure_ml",
                ModelOpsAttributes.DEPLOYMENT_ENDPOINT: endpoint_name,
                ModelOpsAttributes.DEPLOYMENT_INFRA_PROVIDER: "azure",
                _AZURE_ML_DEPLOYMENT_NAME: deploy_name,
                _AZURE_ML_ENDPOINT_NAME: endpoint_name,
            }
            attributes.update(ws_ctx)

            if instance_type:
                attributes[_AZURE_ML_DEPLOYMENT_INSTANCE_TYPE] = str(instance_type)
                attributes[ModelOpsAttributes.DEPLOYMENT_INFRA_GPU_TYPE] = str(instance_type)
            if instance_count is not None:
                attributes[_AZURE_ML_DEPLOYMENT_INSTANCE_COUNT] = int(instance_count)
                attributes[ModelOpsAttributes.DEPLOYMENT_INFRA_REPLICAS] = int(instance_count)

            span_name = f"model_ops.deployment.create {deploy_name}"

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                start = time.monotonic()
                try:
                    result = original(ops_self, deployment, *args, **kwargs)
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.set_attribute(ModelOpsAttributes.DEPLOYMENT_STATUS, "failed")
                    span.record_exception(exc)
                    raise

                elapsed_ms = (time.monotonic() - start) * 1000.0
                span.set_attribute(ModelOpsAttributes.DEPLOYMENT_STATUS, "provisioning")
                span.set_attribute("aitf.latency.total_ms", elapsed_ms)
                span.set_status(StatusCode.OK)
                return result

        return wrapped

    # ------------------------------------------------------------------
    # Online Endpoint wrappers
    # ------------------------------------------------------------------

    def _wrap_online_endpoint_create(self, original: Callable) -> Callable:
        """Wrap ``OnlineEndpointOperations.begin_create_or_update``."""
        instrumentor = self

        @wraps(original)
        def wrapped(ops_self: Any, endpoint: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._get_tracer()
            ws_ctx = instrumentor._extract_workspace_context(ops_self)

            ep_name = getattr(endpoint, "name", "unknown")
            auth_mode = getattr(endpoint, "auth_mode", None)

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: GenAIAttributes.System.AZURE,
                ModelOpsAttributes.DEPLOYMENT_ENDPOINT: ep_name,
                ModelOpsAttributes.DEPLOYMENT_INFRA_PROVIDER: "azure",
                _AZURE_ML_ENDPOINT_NAME: ep_name,
                _AZURE_ML_ENDPOINT_TYPE: "online",
            }
            attributes.update(ws_ctx)

            if auth_mode:
                attributes[_AZURE_ML_ENDPOINT_AUTH_MODE] = str(auth_mode)

            span_name = f"model_ops.endpoint.create {ep_name}"

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                start = time.monotonic()
                try:
                    result = original(ops_self, endpoint, *args, **kwargs)
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

                elapsed_ms = (time.monotonic() - start) * 1000.0
                span.set_attribute("aitf.latency.total_ms", elapsed_ms)
                span.set_status(StatusCode.OK)
                return result

        return wrapped

    def _wrap_online_endpoint_invoke(self, original: Callable) -> Callable:
        """Wrap ``OnlineEndpointOperations.invoke``."""
        instrumentor = self

        @wraps(original)
        def wrapped(ops_self: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._get_tracer()
            ws_ctx = instrumentor._extract_workspace_context(ops_self)

            # endpoint_name may be positional or keyword
            ep_name = kwargs.get("endpoint_name") or (args[0] if args else "unknown")
            deployment_name = kwargs.get("deployment_name")

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: GenAIAttributes.System.AZURE,
                ModelOpsAttributes.SERVING_OPERATION: "invoke",
                ModelOpsAttributes.DEPLOYMENT_ENDPOINT: str(ep_name),
                _AZURE_ML_ENDPOINT_NAME: str(ep_name),
                _AZURE_ML_ENDPOINT_TYPE: "online",
            }
            attributes.update(ws_ctx)

            if deployment_name:
                attributes[_AZURE_ML_DEPLOYMENT_NAME] = str(deployment_name)
                attributes[ModelOpsAttributes.SERVING_ROUTE_SELECTED_MODEL] = str(deployment_name)

            # Estimate request payload size
            request_file = kwargs.get("request_file")
            if request_file and isinstance(request_file, str):
                attributes["aitf.azure_ml.invoke.request_file"] = request_file

            span_name = f"model_ops.endpoint.invoke {ep_name}"

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                start = time.monotonic()
                try:
                    result = original(ops_self, *args, **kwargs)
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

                elapsed_ms = (time.monotonic() - start) * 1000.0
                span.set_attribute("aitf.latency.total_ms", elapsed_ms)
                span.set_attribute(CostAttributes.TOTAL_COST, 0.0)
                span.set_attribute(CostAttributes.CURRENCY, "USD")
                span.set_status(StatusCode.OK)
                return result

        return wrapped

    # ------------------------------------------------------------------
    # Batch Endpoint wrappers
    # ------------------------------------------------------------------

    def _wrap_batch_endpoint_create(self, original: Callable) -> Callable:
        """Wrap ``BatchEndpointOperations.begin_create_or_update``."""
        instrumentor = self

        @wraps(original)
        def wrapped(ops_self: Any, endpoint: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._get_tracer()
            ws_ctx = instrumentor._extract_workspace_context(ops_self)

            ep_name = getattr(endpoint, "name", "unknown")

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: GenAIAttributes.System.AZURE,
                ModelOpsAttributes.DEPLOYMENT_ENDPOINT: ep_name,
                ModelOpsAttributes.DEPLOYMENT_INFRA_PROVIDER: "azure",
                _AZURE_ML_ENDPOINT_NAME: ep_name,
                _AZURE_ML_ENDPOINT_TYPE: "batch",
            }
            attributes.update(ws_ctx)

            span_name = f"model_ops.batch_endpoint.create {ep_name}"

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                start = time.monotonic()
                try:
                    result = original(ops_self, endpoint, *args, **kwargs)
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

                elapsed_ms = (time.monotonic() - start) * 1000.0
                span.set_attribute("aitf.latency.total_ms", elapsed_ms)
                span.set_status(StatusCode.OK)
                return result

        return wrapped

    def _wrap_batch_endpoint_invoke(self, original: Callable) -> Callable:
        """Wrap ``BatchEndpointOperations.invoke``."""
        instrumentor = self

        @wraps(original)
        def wrapped(ops_self: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._get_tracer()
            ws_ctx = instrumentor._extract_workspace_context(ops_self)

            ep_name = kwargs.get("endpoint_name") or (args[0] if args else "unknown")
            deployment_name = kwargs.get("deployment_name")

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: GenAIAttributes.System.AZURE,
                ModelOpsAttributes.SERVING_OPERATION: "batch_invoke",
                ModelOpsAttributes.DEPLOYMENT_ENDPOINT: str(ep_name),
                _AZURE_ML_ENDPOINT_NAME: str(ep_name),
                _AZURE_ML_ENDPOINT_TYPE: "batch",
            }
            attributes.update(ws_ctx)

            if deployment_name:
                attributes[_AZURE_ML_DEPLOYMENT_NAME] = str(deployment_name)

            # Batch-specific metadata
            input_data = kwargs.get("input")
            if input_data is not None:
                input_str = str(input_data)
                if len(input_str) <= 256:
                    attributes["aitf.azure_ml.batch.input"] = input_str

            span_name = f"model_ops.batch_endpoint.invoke {ep_name}"

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                start = time.monotonic()
                try:
                    result = original(ops_self, *args, **kwargs)
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

                elapsed_ms = (time.monotonic() - start) * 1000.0
                span.set_attribute("aitf.latency.total_ms", elapsed_ms)

                # Extract batch job name from result if available
                job_name = getattr(result, "name", None)
                if job_name:
                    span.set_attribute(_AZURE_ML_BATCH_JOB_NAME, str(job_name))

                span.set_attribute(CostAttributes.TOTAL_COST, 0.0)
                span.set_attribute(CostAttributes.CURRENCY, "USD")
                span.set_status(StatusCode.OK)
                return result

        return wrapped

    # ------------------------------------------------------------------
    # Model Registration wrapper
    # ------------------------------------------------------------------

    def _wrap_model_register(self, original: Callable) -> Callable:
        """Wrap ``ModelOperations.create_or_update``."""
        instrumentor = self

        @wraps(original)
        def wrapped(ops_self: Any, model: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._get_tracer()
            ws_ctx = instrumentor._extract_workspace_context(ops_self)

            model_name = getattr(model, "name", "unknown")
            model_version = getattr(model, "version", None)
            model_type = getattr(model, "type", None)
            model_path = getattr(model, "path", None)
            model_description = getattr(model, "description", None)

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: GenAIAttributes.System.AZURE,
                ModelOpsAttributes.REGISTRY_OPERATION: "register",
                ModelOpsAttributes.REGISTRY_MODEL_ID: model_name,
                _AZURE_ML_MODEL_NAME: model_name,
            }
            attributes.update(ws_ctx)

            if model_version is not None:
                attributes[ModelOpsAttributes.REGISTRY_MODEL_VERSION] = str(model_version)
                attributes[_AZURE_ML_MODEL_VERSION] = str(model_version)
            if model_type:
                attributes[_AZURE_ML_MODEL_TYPE] = str(model_type)
            if model_path:
                attributes[_AZURE_ML_MODEL_PATH] = str(model_path)

            # Extract tags and properties for lineage
            tags = getattr(model, "tags", None)
            if tags and isinstance(tags, dict):
                if "training_run_id" in tags:
                    attributes[ModelOpsAttributes.REGISTRY_LINEAGE_TRAINING_RUN_ID] = tags[
                        "training_run_id"
                    ]
                if "parent_model_id" in tags:
                    attributes[ModelOpsAttributes.REGISTRY_LINEAGE_PARENT_MODEL_ID] = tags[
                        "parent_model_id"
                    ]
                if "stage" in tags:
                    attributes[ModelOpsAttributes.REGISTRY_STAGE] = tags["stage"]
                if "owner" in tags:
                    attributes[ModelOpsAttributes.REGISTRY_OWNER] = tags["owner"]

            span_name = f"model_ops.registry.register {model_name}"

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                start = time.monotonic()
                try:
                    result = original(ops_self, model, *args, **kwargs)
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

                elapsed_ms = (time.monotonic() - start) * 1000.0
                span.set_attribute("aitf.latency.total_ms", elapsed_ms)

                # Enrich with registered model details from the result
                registered_name = getattr(result, "name", None)
                registered_version = getattr(result, "version", None)
                registered_id = getattr(result, "id", None)
                if registered_name:
                    span.set_attribute(ModelOpsAttributes.REGISTRY_MODEL_ID, registered_name)
                if registered_version:
                    span.set_attribute(
                        ModelOpsAttributes.REGISTRY_MODEL_VERSION, str(registered_version)
                    )
                if registered_id:
                    span.set_attribute("aitf.azure_ml.model.resource_id", str(registered_id))

                span.set_status(StatusCode.OK)
                return result

        return wrapped

    # ------------------------------------------------------------------
    # Managed Compute wrappers
    # ------------------------------------------------------------------

    def _wrap_compute_create(self, original: Callable) -> Callable:
        """Wrap ``ComputeOperations.begin_create_or_update``."""
        instrumentor = self

        @wraps(original)
        def wrapped(ops_self: Any, compute: Any, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._get_tracer()
            ws_ctx = instrumentor._extract_workspace_context(ops_self)

            compute_name = getattr(compute, "name", "unknown")
            compute_type = type(compute).__name__
            compute_size = getattr(compute, "size", None)

            # Extract scaling settings where applicable
            min_instances = None
            max_instances = None
            scale_settings = getattr(compute, "scale_settings", None)
            if scale_settings is not None:
                min_instances = getattr(scale_settings, "min_instances", None)
                max_instances = getattr(scale_settings, "max_instances", None)

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: GenAIAttributes.System.AZURE,
                ModelOpsAttributes.DEPLOYMENT_INFRA_PROVIDER: "azure",
                _AZURE_ML_COMPUTE_NAME: compute_name,
                _AZURE_ML_COMPUTE_TYPE: compute_type,
            }
            attributes.update(ws_ctx)

            if compute_size:
                attributes[_AZURE_ML_COMPUTE_SIZE] = str(compute_size)
                attributes[ModelOpsAttributes.DEPLOYMENT_INFRA_GPU_TYPE] = str(compute_size)
            if min_instances is not None:
                attributes[_AZURE_ML_COMPUTE_MIN_INSTANCES] = int(min_instances)
            if max_instances is not None:
                attributes[_AZURE_ML_COMPUTE_MAX_INSTANCES] = int(max_instances)
                attributes[ModelOpsAttributes.DEPLOYMENT_INFRA_REPLICAS] = int(max_instances)

            span_name = f"model_ops.compute.create {compute_name}"

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                start = time.monotonic()
                try:
                    result = original(ops_self, compute, *args, **kwargs)
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

                elapsed_ms = (time.monotonic() - start) * 1000.0
                span.set_attribute("aitf.latency.total_ms", elapsed_ms)
                span.set_attribute(CostAttributes.TOTAL_COST, 0.0)
                span.set_attribute(CostAttributes.CURRENCY, "USD")
                span.set_status(StatusCode.OK)
                return result

        return wrapped

    def _wrap_compute_delete(self, original: Callable) -> Callable:
        """Wrap ``ComputeOperations.begin_delete``."""
        instrumentor = self

        @wraps(original)
        def wrapped(ops_self: Any, name: str, *args: Any, **kwargs: Any) -> Any:
            tracer = instrumentor._get_tracer()
            ws_ctx = instrumentor._extract_workspace_context(ops_self)

            attributes: dict[str, Any] = {
                GenAIAttributes.SYSTEM: GenAIAttributes.System.AZURE,
                ModelOpsAttributes.DEPLOYMENT_INFRA_PROVIDER: "azure",
                _AZURE_ML_COMPUTE_NAME: name,
            }
            attributes.update(ws_ctx)

            span_name = f"model_ops.compute.delete {name}"

            with tracer.start_as_current_span(
                name=span_name,
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                start = time.monotonic()
                try:
                    result = original(ops_self, name, *args, **kwargs)
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

                elapsed_ms = (time.monotonic() - start) * 1000.0
                span.set_attribute("aitf.latency.total_ms", elapsed_ms)
                span.set_status(StatusCode.OK)
                return result

        return wrapped
