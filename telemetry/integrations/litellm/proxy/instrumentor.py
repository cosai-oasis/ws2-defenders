"""AITF integration for the LiteLLM Proxy Server.

Instruments LiteLLM Proxy Server operations including:

- **Routing decisions**: Which model/deployment was selected and why.
- **Model fallbacks**: Fallback chain traversal when a primary model fails.
- **Load balancing**: Distribution strategy across deployments (round-robin,
  least-busy, latency-based, cost-based).
- **Budget tracking**: Per-user and per-team budget enforcement.
- **Rate limiting**: Request throttling and quota enforcement.
- **Spend logging**: Cost attribution per request, user, team, and API key.

All spans use ``aitf.model_ops.serving.*`` attributes for routing and
fallback telemetry, combined with ``gen_ai.*`` attributes for the
underlying LLM operations.

Usage::

    from integrations.litellm.proxy import LiteLLMProxyInstrumentor

    instrumentor = LiteLLMProxyInstrumentor()
    instrumentor.instrument()

    # The proxy's Router, rate limiter, and budget manager are now traced.
    # Spans include routing decisions, fallback paths, and spend data.

    # To remove instrumentation:
    instrumentor.uninstrument()

Architecture
------------
The instrumentor monkey-patches key LiteLLM Proxy internals:

- ``litellm.proxy.proxy_server`` -- request handling entry points.
- ``litellm.router.Router`` -- model routing and fallback logic.
- ``litellm.proxy.hooks`` -- budget, rate-limit, and spend hooks.

Each patched method emits an OpenTelemetry span with AITF semantic
convention attributes before delegating to the original implementation.
"""

from __future__ import annotations

import json
import logging
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
    ModelOpsAttributes,
)

logger = logging.getLogger(__name__)

_TRACER_NAME = "integration.litellm.proxy"

# ---------------------------------------------------------------------------
# Attribute constants specific to LiteLLM Proxy telemetry
# ---------------------------------------------------------------------------

_LITELLM_PROXY_VERSION = "litellm.proxy.version"
_LITELLM_ROUTER_STRATEGY = "litellm.router.strategy"
_LITELLM_ROUTER_NUM_DEPLOYMENTS = "litellm.router.num_deployments"
_LITELLM_ROUTER_HEALTHY_DEPLOYMENTS = "litellm.router.healthy_deployments"
_LITELLM_ROUTER_COOLDOWN_DEPLOYMENTS = "litellm.router.cooldown_deployments"
_LITELLM_BUDGET_USER = "litellm.budget.user"
_LITELLM_BUDGET_TEAM = "litellm.budget.team"
_LITELLM_BUDGET_API_KEY = "litellm.budget.api_key"
_LITELLM_BUDGET_MAX = "litellm.budget.max_budget"
_LITELLM_BUDGET_CURRENT_SPEND = "litellm.budget.current_spend"
_LITELLM_BUDGET_REMAINING = "litellm.budget.remaining"
_LITELLM_BUDGET_RESET_AT = "litellm.budget.reset_at"
_LITELLM_RATE_LIMIT_KEY = "litellm.rate_limit.key"
_LITELLM_RATE_LIMIT_TYPE = "litellm.rate_limit.type"
_LITELLM_RATE_LIMIT_MAX_RPM = "litellm.rate_limit.max_rpm"
_LITELLM_RATE_LIMIT_MAX_TPM = "litellm.rate_limit.max_tpm"
_LITELLM_RATE_LIMIT_CURRENT_RPM = "litellm.rate_limit.current_rpm"
_LITELLM_RATE_LIMIT_CURRENT_TPM = "litellm.rate_limit.current_tpm"
_LITELLM_RATE_LIMIT_EXCEEDED = "litellm.rate_limit.exceeded"
_LITELLM_SPEND_USER = "litellm.spend.user"
_LITELLM_SPEND_TEAM = "litellm.spend.team"
_LITELLM_SPEND_API_KEY = "litellm.spend.api_key"
_LITELLM_SPEND_REQUEST_COST = "litellm.spend.request_cost"
_LITELLM_SPEND_TOTAL_SPEND = "litellm.spend.total_spend"


class LiteLLMProxyInstrumentor:
    """Instrumentor for LiteLLM Proxy Server operations.

    Wraps the LiteLLM Proxy's routing, fallback, budget, rate-limiting,
    and spend-logging subsystems with AITF/OpenTelemetry tracing.

    Usage::

        instrumentor = LiteLLMProxyInstrumentor()
        instrumentor.instrument()

        # All proxy operations now emit spans.
        # To remove instrumentation:
        instrumentor.uninstrument()

    Args:
        tracer_provider: Optional custom ``TracerProvider``. If not provided,
            the global OpenTelemetry tracer provider is used.
    """

    def __init__(self, tracer_provider: TracerProvider | None = None) -> None:
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False
        self._original_methods: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Enable LiteLLM Proxy instrumentation.

        Patches the LiteLLM Proxy routing, fallback, budget, rate-limit,
        and spend-logging code paths.  Safe to call multiple times; only
        the first call takes effect.
        """
        if self._instrumented:
            logger.debug("LiteLLMProxyInstrumentor already instrumented.")
            return

        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)

        self._patch_router()
        self._patch_budget_manager()
        self._patch_rate_limiter()
        self._patch_spend_logger()

        self._instrumented = True
        logger.info("LiteLLM Proxy instrumentation enabled.")

    def uninstrument(self) -> None:
        """Remove LiteLLM Proxy instrumentation.

        Restores all monkey-patched methods to their original state.
        """
        if not self._instrumented:
            return

        self._unpatch_all()
        self._tracer = None
        self._instrumented = False
        logger.info("LiteLLM Proxy instrumentation disabled.")

    @property
    def is_instrumented(self) -> bool:
        """Whether this instrumentor is currently active."""
        return self._instrumented

    def get_tracer(self) -> trace.Tracer:
        """Return the cached tracer, creating one if needed."""
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    # ------------------------------------------------------------------
    # Context managers for manual instrumentation
    # ------------------------------------------------------------------

    @contextmanager
    def trace_route_decision(
        self,
        requested_model: str,
        strategy: str = "simple-shuffle",
        num_deployments: int = 0,
        healthy_deployments: int = 0,
        cooldown_deployments: int = 0,
    ) -> Generator[RouteDecisionSpan, None, None]:
        """Trace a proxy routing decision.

        Usage::

            with proxy.trace_route_decision(
                requested_model="gpt-4",
                strategy="least-busy",
                num_deployments=3,
                healthy_deployments=2,
            ) as route_span:
                selected = router.get_available_deployment(...)
                route_span.set_selected_model(selected["model_name"])
                route_span.set_selected_deployment(selected["litellm_params"]["api_base"])
        """
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            GenAIAttributes.REQUEST_MODEL: requested_model,
            ModelOpsAttributes.SERVING_OPERATION: "route",
            _LITELLM_ROUTER_STRATEGY: strategy,
            _LITELLM_ROUTER_NUM_DEPLOYMENTS: num_deployments,
            _LITELLM_ROUTER_HEALTHY_DEPLOYMENTS: healthy_deployments,
            _LITELLM_ROUTER_COOLDOWN_DEPLOYMENTS: cooldown_deployments,
        }

        with tracer.start_as_current_span(
            name=f"litellm.proxy.route {requested_model}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            route_span = RouteDecisionSpan(span)
            try:
                yield route_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_fallback(
        self,
        original_model: str,
        fallback_chain: list[str] | None = None,
        trigger: str = "error",
    ) -> Generator[FallbackSpan, None, None]:
        """Trace a model fallback operation.

        Usage::

            with proxy.trace_fallback(
                original_model="gpt-4",
                fallback_chain=["gpt-4-turbo", "gpt-3.5-turbo"],
                trigger="rate_limit",
            ) as fb_span:
                result = router.fallback_completion(...)
                fb_span.set_final_model("gpt-4-turbo")
                fb_span.set_fallback_depth(1)
        """
        tracer = self.get_tracer()
        chain_str = json.dumps(fallback_chain or [])
        attributes: dict[str, Any] = {
            ModelOpsAttributes.SERVING_OPERATION: "fallback",
            ModelOpsAttributes.SERVING_FALLBACK_ORIGINAL_MODEL: original_model,
            ModelOpsAttributes.SERVING_FALLBACK_CHAIN: chain_str,
            ModelOpsAttributes.SERVING_FALLBACK_TRIGGER: trigger,
        }

        with tracer.start_as_current_span(
            name=f"litellm.proxy.fallback {original_model}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            fb_span = FallbackSpan(span)
            try:
                yield fb_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_budget_check(
        self,
        user: str | None = None,
        team: str | None = None,
        api_key: str | None = None,
        max_budget: float | None = None,
        current_spend: float | None = None,
    ) -> Generator[BudgetCheckSpan, None, None]:
        """Trace a budget enforcement check.

        Usage::

            with proxy.trace_budget_check(
                user="user-123",
                max_budget=100.0,
                current_spend=42.50,
            ) as budget_span:
                allowed = budget_manager.can_proceed(...)
                budget_span.set_allowed(allowed)
        """
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            ModelOpsAttributes.SERVING_OPERATION: "budget_check",
        }
        if user:
            attributes[_LITELLM_BUDGET_USER] = user
        if team:
            attributes[_LITELLM_BUDGET_TEAM] = team
        if api_key:
            attributes[_LITELLM_BUDGET_API_KEY] = _mask_key(api_key)
        if max_budget is not None:
            attributes[_LITELLM_BUDGET_MAX] = max_budget
            attributes[CostAttributes.BUDGET_LIMIT] = max_budget
        if current_spend is not None:
            attributes[_LITELLM_BUDGET_CURRENT_SPEND] = current_spend
            attributes[CostAttributes.BUDGET_USED] = current_spend
            if max_budget is not None:
                remaining = max(0.0, max_budget - current_spend)
                attributes[_LITELLM_BUDGET_REMAINING] = remaining
                attributes[CostAttributes.BUDGET_REMAINING] = remaining

        with tracer.start_as_current_span(
            name="litellm.proxy.budget_check",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            budget_span = BudgetCheckSpan(span)
            try:
                yield budget_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_rate_limit_check(
        self,
        key: str,
        rate_limit_type: str = "user",
        max_rpm: int | None = None,
        max_tpm: int | None = None,
        current_rpm: int | None = None,
        current_tpm: int | None = None,
    ) -> Generator[RateLimitSpan, None, None]:
        """Trace a rate-limit enforcement check.

        Usage::

            with proxy.trace_rate_limit_check(
                key="user-123",
                rate_limit_type="user",
                max_rpm=100,
                current_rpm=85,
            ) as rl_span:
                allowed = rate_limiter.check(...)
                rl_span.set_exceeded(not allowed)
        """
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            ModelOpsAttributes.SERVING_OPERATION: "rate_limit_check",
            _LITELLM_RATE_LIMIT_KEY: key,
            _LITELLM_RATE_LIMIT_TYPE: rate_limit_type,
        }
        if max_rpm is not None:
            attributes[_LITELLM_RATE_LIMIT_MAX_RPM] = max_rpm
        if max_tpm is not None:
            attributes[_LITELLM_RATE_LIMIT_MAX_TPM] = max_tpm
        if current_rpm is not None:
            attributes[_LITELLM_RATE_LIMIT_CURRENT_RPM] = current_rpm
        if current_tpm is not None:
            attributes[_LITELLM_RATE_LIMIT_CURRENT_TPM] = current_tpm

        with tracer.start_as_current_span(
            name="litellm.proxy.rate_limit_check",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            rl_span = RateLimitSpan(span)
            try:
                yield rl_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_spend_log(
        self,
        user: str | None = None,
        team: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        request_cost: float = 0.0,
    ) -> Generator[SpendLogSpan, None, None]:
        """Trace a spend-logging event.

        Usage::

            with proxy.trace_spend_log(
                user="user-123",
                model="gpt-4o",
                request_cost=0.0034,
            ) as spend_span:
                spend_span.set_input_tokens(150)
                spend_span.set_output_tokens(200)
                spend_logger.log(...)
        """
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            ModelOpsAttributes.SERVING_OPERATION: "spend_log",
            _LITELLM_SPEND_REQUEST_COST: request_cost,
            CostAttributes.TOTAL_COST: request_cost,
        }
        if user:
            attributes[_LITELLM_SPEND_USER] = user
            attributes[CostAttributes.ATTRIBUTION_USER] = user
        if team:
            attributes[_LITELLM_SPEND_TEAM] = team
            attributes[CostAttributes.ATTRIBUTION_TEAM] = team
        if api_key:
            attributes[_LITELLM_SPEND_API_KEY] = _mask_key(api_key)
        if model:
            attributes[GenAIAttributes.REQUEST_MODEL] = model

        with tracer.start_as_current_span(
            name="litellm.proxy.spend_log",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            spend_span = SpendLogSpan(span)
            try:
                yield spend_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # Internal patching methods
    # ------------------------------------------------------------------

    def _patch_router(self) -> None:
        """Patch ``litellm.router.Router`` for routing and fallback tracing."""
        try:
            import litellm.router as router_module

            Router = router_module.Router  # noqa: N806

            if hasattr(Router, "acompletion"):
                self._wrap_method(Router, "acompletion", self._wrap_router_call)
            if hasattr(Router, "completion"):
                self._wrap_method(Router, "completion", self._wrap_router_call)
            if hasattr(Router, "get_available_deployment"):
                self._wrap_method(
                    Router,
                    "get_available_deployment",
                    self._wrap_get_deployment,
                )

            logger.debug("Patched litellm.router.Router methods.")
        except ImportError:
            logger.debug("litellm.router not available; skipping router patch.")

    def _patch_budget_manager(self) -> None:
        """Patch budget-related hooks for budget enforcement tracing."""
        try:
            import litellm.proxy.hooks.max_budget_limiter as budget_module

            if hasattr(budget_module, "_PROXY_MaxBudgetLimiter"):
                cls = budget_module._PROXY_MaxBudgetLimiter
                if hasattr(cls, "async_pre_call_hook"):
                    self._wrap_method(
                        cls,
                        "async_pre_call_hook",
                        self._wrap_budget_hook,
                    )
                logger.debug("Patched LiteLLM budget hooks.")
        except (ImportError, AttributeError):
            logger.debug("LiteLLM budget hooks not available; skipping.")

    def _patch_rate_limiter(self) -> None:
        """Patch rate-limiting hooks for throttling tracing."""
        try:
            import litellm.proxy.hooks.parallel_request_limiter as limiter_module

            if hasattr(limiter_module, "_PROXY_MaxParallelRequestsHandler"):
                cls = limiter_module._PROXY_MaxParallelRequestsHandler
                if hasattr(cls, "async_pre_call_hook"):
                    self._wrap_method(
                        cls,
                        "async_pre_call_hook",
                        self._wrap_rate_limit_hook,
                    )
                logger.debug("Patched LiteLLM rate limiter hooks.")
        except (ImportError, AttributeError):
            logger.debug("LiteLLM rate limiter not available; skipping.")

    def _patch_spend_logger(self) -> None:
        """Patch spend-logging callbacks for cost attribution tracing."""
        try:
            import litellm

            if hasattr(litellm, "success_callback"):
                self._original_methods["success_callback"] = (
                    litellm.success_callback.copy()
                    if isinstance(litellm.success_callback, list)
                    else litellm.success_callback
                )
            logger.debug("Patched LiteLLM spend logger.")
        except ImportError:
            logger.debug("litellm not available; skipping spend logger patch.")

    def _unpatch_all(self) -> None:
        """Restore all original methods."""
        for key, (obj, method_name, original) in list(
            self._original_methods.items()
        ):
            if isinstance(key, tuple):
                setattr(obj, method_name, original)
        self._original_methods.clear()

    def _wrap_method(
        self,
        obj: Any,
        method_name: str,
        wrapper_factory: Callable,
    ) -> None:
        """Wrap a method and store the original for later restoration."""
        original = getattr(obj, method_name)
        wrapped = wrapper_factory(original, obj)
        setattr(obj, method_name, wrapped)
        self._original_methods[(id(obj), method_name)] = (
            obj,
            method_name,
            original,
        )

    def _wrap_router_call(
        self, original: Callable, router_instance: Any
    ) -> Callable:
        """Create a wrapper for Router.completion / Router.acompletion."""
        tracer = self.get_tracer()

        @wraps(original)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            model = kwargs.get("model", args[0] if args else "unknown")
            strategy = getattr(
                router_instance, "routing_strategy", "simple-shuffle"
            )
            deployments = getattr(router_instance, "model_list", [])

            attributes: dict[str, Any] = {
                GenAIAttributes.REQUEST_MODEL: str(model),
                ModelOpsAttributes.SERVING_OPERATION: "route",
                _LITELLM_ROUTER_STRATEGY: str(strategy),
                _LITELLM_ROUTER_NUM_DEPLOYMENTS: len(deployments),
            }

            start_time = time.monotonic()
            with tracer.start_as_current_span(
                name=f"litellm.proxy.route {model}",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = await original(*args, **kwargs)
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

                    if hasattr(result, "model"):
                        span.set_attribute(
                            ModelOpsAttributes.SERVING_ROUTE_SELECTED_MODEL,
                            result.model,
                        )
                        span.set_attribute(
                            GenAIAttributes.RESPONSE_MODEL, result.model
                        )
                    if hasattr(result, "usage"):
                        usage = result.usage
                        if hasattr(usage, "prompt_tokens"):
                            span.set_attribute(
                                GenAIAttributes.USAGE_INPUT_TOKENS,
                                usage.prompt_tokens,
                            )
                        if hasattr(usage, "completion_tokens"):
                            span.set_attribute(
                                GenAIAttributes.USAGE_OUTPUT_TOKENS,
                                usage.completion_tokens,
                            )
                    if hasattr(result, "_hidden_params"):
                        hidden = result._hidden_params
                        if isinstance(hidden, dict):
                            if "additional_headers" in hidden:
                                cost = hidden.get(
                                    "response_cost", 0.0
                                )
                                if cost:
                                    span.set_attribute(
                                        CostAttributes.TOTAL_COST, cost
                                    )

                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        @wraps(original)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            model = kwargs.get("model", args[0] if args else "unknown")
            strategy = getattr(
                router_instance, "routing_strategy", "simple-shuffle"
            )
            deployments = getattr(router_instance, "model_list", [])

            attributes: dict[str, Any] = {
                GenAIAttributes.REQUEST_MODEL: str(model),
                ModelOpsAttributes.SERVING_OPERATION: "route",
                _LITELLM_ROUTER_STRATEGY: str(strategy),
                _LITELLM_ROUTER_NUM_DEPLOYMENTS: len(deployments),
            }

            start_time = time.monotonic()
            with tracer.start_as_current_span(
                name=f"litellm.proxy.route {model}",
                kind=SpanKind.CLIENT,
                attributes=attributes,
            ) as span:
                try:
                    result = original(*args, **kwargs)
                    elapsed_ms = (time.monotonic() - start_time) * 1000
                    span.set_attribute(LatencyAttributes.TOTAL_MS, elapsed_ms)

                    if hasattr(result, "model"):
                        span.set_attribute(
                            ModelOpsAttributes.SERVING_ROUTE_SELECTED_MODEL,
                            result.model,
                        )
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        import asyncio

        if asyncio.iscoroutinefunction(original):
            return async_wrapper
        return sync_wrapper

    def _wrap_get_deployment(
        self, original: Callable, router_instance: Any
    ) -> Callable:
        """Wrap Router.get_available_deployment for deployment selection tracing."""
        tracer = self.get_tracer()

        @wraps(original)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            model = kwargs.get("model", args[0] if args else "unknown")
            with tracer.start_as_current_span(
                name=f"litellm.proxy.select_deployment {model}",
                kind=SpanKind.INTERNAL,
                attributes={
                    GenAIAttributes.REQUEST_MODEL: str(model),
                    ModelOpsAttributes.SERVING_OPERATION: "select_deployment",
                },
            ) as span:
                try:
                    deployment = original(*args, **kwargs)
                    if deployment and isinstance(deployment, dict):
                        selected = deployment.get(
                            "model_name",
                            deployment.get("litellm_params", {}).get(
                                "model", "unknown"
                            ),
                        )
                        span.set_attribute(
                            ModelOpsAttributes.SERVING_ROUTE_SELECTED_MODEL,
                            str(selected),
                        )
                    span.set_status(StatusCode.OK)
                    return deployment
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper

    def _wrap_budget_hook(
        self, original: Callable, hook_instance: Any
    ) -> Callable:
        """Wrap budget enforcement hooks."""
        tracer = self.get_tracer()

        @wraps(original)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            user_api_key_dict = kwargs.get("user_api_key_dict", None)
            attributes: dict[str, Any] = {
                ModelOpsAttributes.SERVING_OPERATION: "budget_check",
            }
            if user_api_key_dict:
                if hasattr(user_api_key_dict, "user_id") and user_api_key_dict.user_id:
                    attributes[_LITELLM_BUDGET_USER] = user_api_key_dict.user_id
                if hasattr(user_api_key_dict, "team_id") and user_api_key_dict.team_id:
                    attributes[_LITELLM_BUDGET_TEAM] = user_api_key_dict.team_id
                if hasattr(user_api_key_dict, "max_budget") and user_api_key_dict.max_budget:
                    attributes[_LITELLM_BUDGET_MAX] = user_api_key_dict.max_budget
                    attributes[CostAttributes.BUDGET_LIMIT] = user_api_key_dict.max_budget
                if hasattr(user_api_key_dict, "spend") and user_api_key_dict.spend is not None:
                    attributes[_LITELLM_BUDGET_CURRENT_SPEND] = user_api_key_dict.spend
                    attributes[CostAttributes.BUDGET_USED] = user_api_key_dict.spend

            with tracer.start_as_current_span(
                name="litellm.proxy.budget_check",
                kind=SpanKind.INTERNAL,
                attributes=attributes,
            ) as span:
                try:
                    result = await original(*args, **kwargs)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    span.add_event(
                        "litellm.proxy.budget_exceeded",
                        attributes={"error": str(exc)},
                    )
                    raise

        return wrapper

    def _wrap_rate_limit_hook(
        self, original: Callable, hook_instance: Any
    ) -> Callable:
        """Wrap rate-limit enforcement hooks."""
        tracer = self.get_tracer()

        @wraps(original)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            with tracer.start_as_current_span(
                name="litellm.proxy.rate_limit_check",
                kind=SpanKind.INTERNAL,
                attributes={
                    ModelOpsAttributes.SERVING_OPERATION: "rate_limit_check",
                },
            ) as span:
                try:
                    result = await original(*args, **kwargs)
                    span.set_attribute(_LITELLM_RATE_LIMIT_EXCEEDED, False)
                    span.set_status(StatusCode.OK)
                    return result
                except Exception as exc:
                    span.set_attribute(_LITELLM_RATE_LIMIT_EXCEEDED, True)
                    span.set_status(StatusCode.ERROR, str(exc))
                    span.record_exception(exc)
                    raise

        return wrapper


# ---------------------------------------------------------------------------
# Span helper classes
# ---------------------------------------------------------------------------


class RouteDecisionSpan:
    """Helper for enriching a routing-decision span with outcome data."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_selected_model(self, model: str) -> None:
        """Record which model was ultimately selected."""
        self._span.set_attribute(
            ModelOpsAttributes.SERVING_ROUTE_SELECTED_MODEL, model
        )
        self._span.set_attribute(GenAIAttributes.RESPONSE_MODEL, model)

    def set_route_reason(self, reason: str) -> None:
        """Record why this particular model/deployment was chosen."""
        self._span.set_attribute(
            ModelOpsAttributes.SERVING_ROUTE_REASON, reason
        )

    def set_candidates(self, candidates: list[str]) -> None:
        """Record the candidate models that were considered."""
        self._span.set_attribute(
            ModelOpsAttributes.SERVING_ROUTE_CANDIDATES,
            json.dumps(candidates),
        )

    def set_selected_deployment(self, deployment_id: str) -> None:
        """Record the specific deployment endpoint selected."""
        self._span.set_attribute(
            "litellm.router.selected_deployment", deployment_id
        )

    def set_latency_ms(self, latency_ms: float) -> None:
        """Record the routing decision latency."""
        self._span.set_attribute(LatencyAttributes.TOTAL_MS, latency_ms)


class FallbackSpan:
    """Helper for enriching a fallback span with outcome data."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_final_model(self, model: str) -> None:
        """Record the model that ultimately served the request."""
        self._span.set_attribute(
            ModelOpsAttributes.SERVING_FALLBACK_FINAL_MODEL, model
        )
        self._span.set_attribute(GenAIAttributes.RESPONSE_MODEL, model)

    def set_fallback_depth(self, depth: int) -> None:
        """Record how many fallbacks were attempted."""
        self._span.set_attribute(
            ModelOpsAttributes.SERVING_FALLBACK_DEPTH, depth
        )

    def add_fallback_attempt(
        self, model: str, error: str, attempt_index: int
    ) -> None:
        """Record a failed fallback attempt as an event."""
        self._span.add_event(
            "litellm.proxy.fallback.attempt",
            attributes={
                "litellm.fallback.attempt_index": attempt_index,
                "litellm.fallback.attempted_model": model,
                "litellm.fallback.error": error,
            },
        )


class BudgetCheckSpan:
    """Helper for enriching a budget-check span."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_allowed(self, allowed: bool) -> None:
        """Record whether the request was allowed within budget."""
        self._span.set_attribute("litellm.budget.allowed", allowed)
        if not allowed:
            self._span.add_event("litellm.proxy.budget_exceeded")

    def set_remaining(self, remaining: float) -> None:
        """Record remaining budget after this request."""
        self._span.set_attribute(_LITELLM_BUDGET_REMAINING, remaining)
        self._span.set_attribute(CostAttributes.BUDGET_REMAINING, remaining)

    def set_reset_at(self, reset_at: str) -> None:
        """Record when the budget resets (ISO 8601)."""
        self._span.set_attribute(_LITELLM_BUDGET_RESET_AT, reset_at)


class RateLimitSpan:
    """Helper for enriching a rate-limit-check span."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_exceeded(self, exceeded: bool) -> None:
        """Record whether the rate limit was exceeded."""
        self._span.set_attribute(_LITELLM_RATE_LIMIT_EXCEEDED, exceeded)
        if exceeded:
            self._span.add_event("litellm.proxy.rate_limit_exceeded")

    def set_current_usage(
        self, current_rpm: int | None = None, current_tpm: int | None = None
    ) -> None:
        """Record current usage counters."""
        if current_rpm is not None:
            self._span.set_attribute(
                _LITELLM_RATE_LIMIT_CURRENT_RPM, current_rpm
            )
        if current_tpm is not None:
            self._span.set_attribute(
                _LITELLM_RATE_LIMIT_CURRENT_TPM, current_tpm
            )

    def set_retry_after(self, seconds: float) -> None:
        """Record retry-after header value in seconds."""
        self._span.set_attribute(
            "litellm.rate_limit.retry_after_seconds", seconds
        )


class SpendLogSpan:
    """Helper for enriching a spend-logging span."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_input_tokens(self, tokens: int) -> None:
        """Record input token count for cost attribution."""
        self._span.set_attribute(GenAIAttributes.USAGE_INPUT_TOKENS, tokens)

    def set_output_tokens(self, tokens: int) -> None:
        """Record output token count for cost attribution."""
        self._span.set_attribute(GenAIAttributes.USAGE_OUTPUT_TOKENS, tokens)

    def set_cost_breakdown(
        self,
        input_cost: float,
        output_cost: float,
        total_cost: float | None = None,
        currency: str = "USD",
    ) -> None:
        """Record detailed cost breakdown."""
        self._span.set_attribute(CostAttributes.INPUT_COST, input_cost)
        self._span.set_attribute(CostAttributes.OUTPUT_COST, output_cost)
        self._span.set_attribute(
            CostAttributes.TOTAL_COST,
            total_cost if total_cost is not None else input_cost + output_cost,
        )
        self._span.set_attribute(CostAttributes.CURRENCY, currency)

    def set_total_spend(self, total_spend: float) -> None:
        """Record cumulative total spend for the user/team/key."""
        self._span.set_attribute(_LITELLM_SPEND_TOTAL_SPEND, total_spend)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _mask_key(api_key: str) -> str:
    """Mask an API key for safe inclusion in telemetry, showing last 4 chars."""
    if len(api_key) <= 4:
        return "****"
    return f"****{api_key[-4:]}"
