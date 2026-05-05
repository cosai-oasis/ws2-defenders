"""AITF Cost Processor.

OTel SpanProcessor that calculates and attributes costs for AI operations
based on model pricing tables and token usage.
"""

from __future__ import annotations

import threading
from typing import Any

from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor

from aitf.semantic_conventions.attributes import CostAttributes, GenAIAttributes

# Maximum reasonable token count per request (prevents overflow/abuse)
_MAX_TOKENS = 10_000_000

# Model pricing per 1M tokens (USD) - updated Feb 2026
MODEL_PRICING: dict[str, dict[str, float]] = {
    # OpenAI
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00},
    "gpt-4": {"input": 30.00, "output": 60.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    "o1": {"input": 15.00, "output": 60.00},
    "o1-mini": {"input": 3.00, "output": 12.00},
    "o3-mini": {"input": 1.10, "output": 4.40},
    "text-embedding-3-small": {"input": 0.02, "output": 0.0},
    "text-embedding-3-large": {"input": 0.13, "output": 0.0},
    # Anthropic
    "claude-opus-4-6": {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-5-20250929": {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
    "claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
    "claude-3-5-haiku-20241022": {"input": 0.80, "output": 4.00},
    "claude-3-opus-20240229": {"input": 15.00, "output": 75.00},
    # Google
    "gemini-2.0-flash": {"input": 0.10, "output": 0.40},
    "gemini-1.5-pro": {"input": 1.25, "output": 5.00},
    "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
    # Mistral
    "mistral-large-latest": {"input": 2.00, "output": 6.00},
    "mistral-small-latest": {"input": 0.20, "output": 0.60},
    # Meta (via API providers)
    "llama-3.1-405b": {"input": 3.00, "output": 3.00},
    "llama-3.1-70b": {"input": 0.80, "output": 0.80},
    "llama-3.1-8b": {"input": 0.10, "output": 0.10},
    # Cohere
    "command-r-plus": {"input": 2.50, "output": 10.00},
    "command-r": {"input": 0.15, "output": 0.60},
}


class CostProcessor(SpanProcessor):
    """OTel SpanProcessor that calculates costs for AI operations.

    Automatically computes cost based on model and token usage,
    and adds cost attribution attributes.

    Usage:
        provider.add_span_processor(CostProcessor(
            custom_pricing={"my-model": {"input": 1.0, "output": 3.0}},
            default_user="system",
            budget_limit=100.0,
        ))
    """

    def __init__(
        self,
        custom_pricing: dict[str, dict[str, float]] | None = None,
        default_user: str | None = None,
        default_team: str | None = None,
        default_project: str | None = None,
        budget_limit: float | None = None,
        currency: str = "USD",
    ):
        self._pricing = dict(MODEL_PRICING)
        if custom_pricing:
            self._pricing.update(custom_pricing)
        self._default_user = default_user
        self._default_team = default_team
        self._default_project = default_project
        self._budget_limit = budget_limit
        self._currency = currency
        self._total_cost = 0.0
        self._lock = threading.Lock()

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        """Add default attribution attributes."""
        if self._default_user:
            span.set_attribute(CostAttributes.ATTRIBUTION_USER, self._default_user)
        if self._default_team:
            span.set_attribute(CostAttributes.ATTRIBUTION_TEAM, self._default_team)
        if self._default_project:
            span.set_attribute(CostAttributes.ATTRIBUTION_PROJECT, self._default_project)

    def on_end(self, span: ReadableSpan) -> None:
        """Calculate cost from token usage."""
        attrs = span.attributes or {}
        model = attrs.get(GenAIAttributes.REQUEST_MODEL) or attrs.get(GenAIAttributes.RESPONSE_MODEL)
        if not model:
            return

        input_tokens = attrs.get(GenAIAttributes.USAGE_INPUT_TOKENS, 0)
        output_tokens = attrs.get(GenAIAttributes.USAGE_OUTPUT_TOKENS, 0)
        if not input_tokens and not output_tokens:
            return

        cost = self.calculate_cost(str(model), int(input_tokens), int(output_tokens))
        if cost:
            with self._lock:
                self._total_cost += cost["total_cost"]

    def calculate_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> dict[str, float] | None:
        """Calculate cost for a given model and token count.

        Returns dict with input_cost, output_cost, total_cost, or None if model unknown.
        """
        # Validate token counts
        input_tokens = max(0, min(input_tokens, _MAX_TOKENS))
        output_tokens = max(0, min(output_tokens, _MAX_TOKENS))

        pricing = self._get_pricing(model)
        if not pricing:
            return None

        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        total_cost = input_cost + output_cost

        return {
            "input_cost": round(input_cost, 8),
            "output_cost": round(output_cost, 8),
            "total_cost": round(total_cost, 8),
            "currency": self._currency,
        }

    def get_cost_attributes(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> dict[str, Any]:
        """Get cost attributes suitable for span attributes."""
        cost = self.calculate_cost(model, input_tokens, output_tokens)
        if not cost:
            return {}

        attributes: dict[str, Any] = {
            CostAttributes.INPUT_COST: cost["input_cost"],
            CostAttributes.OUTPUT_COST: cost["output_cost"],
            CostAttributes.TOTAL_COST: cost["total_cost"],
            CostAttributes.CURRENCY: cost["currency"],
        }

        # Add pricing info
        pricing = self._get_pricing(model)
        if pricing:
            attributes[CostAttributes.PRICING_INPUT_PER_1M] = pricing["input"]
            attributes[CostAttributes.PRICING_OUTPUT_PER_1M] = pricing["output"]

        # Add budget info
        if self._budget_limit:
            with self._lock:
                total = self._total_cost
            attributes[CostAttributes.BUDGET_LIMIT] = self._budget_limit
            attributes[CostAttributes.BUDGET_USED] = total
            attributes[CostAttributes.BUDGET_REMAINING] = max(
                0, self._budget_limit - total
            )

        return attributes

    @property
    def total_cost(self) -> float:
        with self._lock:
            return self._total_cost

    @property
    def budget_remaining(self) -> float | None:
        if self._budget_limit is None:
            return None
        with self._lock:
            return max(0, self._budget_limit - self._total_cost)

    @property
    def budget_exceeded(self) -> bool:
        if self._budget_limit is None:
            return False
        with self._lock:
            return self._total_cost > self._budget_limit

    def _get_pricing(self, model: str) -> dict[str, float] | None:
        """Look up pricing for a model, with fuzzy matching."""
        if model in self._pricing:
            return self._pricing[model]
        # Try prefix match (e.g., "gpt-4o-2024-08-06" -> "gpt-4o")
        for key in sorted(self._pricing.keys(), key=len, reverse=True):
            if model.startswith(key):
                return self._pricing[key]
        return None

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
