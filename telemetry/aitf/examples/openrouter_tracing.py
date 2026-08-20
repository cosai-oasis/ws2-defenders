"""AITF Example: OpenRouter Tracing — Cost-Optimized Coding Assistant.

Demonstrates how AITF instruments a realistic application that uses
OpenRouter to route requests across multiple LLM providers based on
cost, speed, and capability:

    1. Fast queries   → DeepSeek R1 (cheapest)
    2. Code review    → Claude Sonnet (best for code)
    3. Summarization  → GPT-4o (strong general-purpose)
    4. Fallback       → OpenRouter auto-routes on failure

Each call flows through the OpenRouter vendor mapping:

    App Code → OpenRouter API → VendorMapper → OCSFMapper → SIEM
    (openrouter.* attrs)       (JSON-driven)   (OCSF 7001)

All spans are exportable as both OTel traces (OTLP → Jaeger/Tempo) and
OCSF security events (→ SIEM/XDR).  See ``dual_pipeline_tracing.py``
for dual-pipeline setup.

Run:
    pip install opentelemetry-sdk aitf
    python openrouter_tracing.py
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from unittest.mock import MagicMock

from aitf.ocsf.vendor_mapper import VendorMapper
from aitf.ocsf.mapper import OCSFMapper
from aitf.ocsf.compliance_mapper import ComplianceMapper


# ────────────────────────────────────────────────────────────────────
# 1. Simulated OpenRouter client
# ────────────────────────────────────────────────────────────────────

# OpenRouter model pricing (per 1M tokens)
MODEL_PRICING = {
    "anthropic/claude-sonnet-4-5-20250929": {"input": 3.00, "output": 15.00},
    "openai/gpt-4o":                        {"input": 2.50, "output": 10.00},
    "deepseek/deepseek-r1":                 {"input": 0.55, "output": 2.19},
    "google/gemini-2.0-flash":              {"input": 0.10, "output": 0.40},
    "meta-llama/llama-3.3-70b-instruct":    {"input": 0.40, "output": 0.40},
}


@dataclass
class OpenRouterResponse:
    """Simulated OpenRouter API response."""
    id: str
    model: str
    route_provider: str
    route_model: str
    content: str
    finish_reason: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    cost_prompt: float
    cost_completion: float
    cost_total: float


def openrouter_chat(
    model: str,
    messages: list[dict],
    temperature: float = 0.5,
    max_tokens: int = 1024,
    route: str = "default",
) -> OpenRouterResponse:
    """Simulate an OpenRouter API call.

    In production, this would be:
        import openai
        client = openai.OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.environ["OPENROUTER_API_KEY"],
        )
        response = client.chat.completions.create(
            model="anthropic/claude-sonnet-4-5-20250929",
            messages=messages,
        )
    """
    time.sleep(random.uniform(0.05, 0.15))

    # Determine the actual provider from model prefix
    provider = model.split("/")[0] if "/" in model else "unknown"

    # Simulate token counts
    prompt_tokens = sum(len(m.get("content", "").split()) * 2 for m in messages)
    completion_tokens = random.randint(80, 300)

    # Calculate cost
    pricing = MODEL_PRICING.get(model, {"input": 1.0, "output": 5.0})
    cost_prompt = prompt_tokens * pricing["input"] / 1_000_000
    cost_completion = completion_tokens * pricing["output"] / 1_000_000

    return OpenRouterResponse(
        id=f"gen-{random.randint(100000, 999999)}",
        model=model,
        route_provider=provider,
        route_model=model.split("/")[-1] if "/" in model else model,
        content=f"[Simulated {model} response]",
        finish_reason="stop" if provider in ("openai", "deepseek") else "end_turn",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        latency_ms=random.uniform(500, 3000),
        cost_prompt=cost_prompt,
        cost_completion=cost_completion,
        cost_total=cost_prompt + cost_completion,
    )


# ────────────────────────────────────────────────────────────────────
# 2. Coding assistant with cost-aware routing
# ────────────────────────────────────────────────────────────────────

# Pre-canned responses for the demo
RESPONSES = {
    "deepseek/deepseek-r1": (
        "The `TypeError: 'NoneType' object is not subscriptable` error occurs "
        "on line 42 because `get_user()` returns `None` when the user ID isn't "
        "found.  Add a null check: `if user := get_user(uid): return user['name']`"
    ),
    "anthropic/claude-sonnet-4-5-20250929": (
        "Code review for `auth_middleware.py`:\n"
        "1. **SQL Injection** (L23): Use parameterized queries instead of f-strings\n"
        "2. **Missing rate limiting** (L45): Add `@limiter.limit('10/minute')`\n"
        "3. **Token expiry** (L67): JWT `exp` claim is set to 30 days — reduce to 1 hour\n"
        "4. **Good**: Password hashing uses bcrypt with proper work factor"
    ),
    "openai/gpt-4o": (
        "## PR Summary: Auth Middleware Refactor\n\n"
        "This PR fixes 3 security issues in the authentication middleware:\n"
        "- Switches from raw SQL to parameterized queries (prevents SQLi)\n"
        "- Adds rate limiting to login endpoint (prevents brute force)\n"
        "- Reduces JWT expiry from 30 days to 1 hour\n\n"
        "All existing tests pass.  Added 4 new security-focused tests."
    ),
    "google/gemini-2.0-flash": (
        "Function `process_payment` takes an amount (float) and currency code "
        "(str), validates the amount is positive, calls the Stripe API, and "
        "returns a PaymentResult dataclass."
    ),
}


class CodingAssistant:
    """A coding assistant that routes to different models via OpenRouter."""

    # Route selection: pick the best model for the task
    ROUTING_TABLE = {
        "quick_question":  "deepseek/deepseek-r1",
        "code_review":     "anthropic/claude-sonnet-4-5-20250929",
        "summarize":       "openai/gpt-4o",
        "explain":         "google/gemini-2.0-flash",
    }

    def __init__(self):
        self.total_cost = 0.0
        self.call_count = 0

    def ask(self, task_type: str, prompt: str) -> OpenRouterResponse:
        """Route a coding question to the best model for the task."""
        model = self.ROUTING_TABLE.get(task_type, "openai/gpt-4o")
        messages = [
            {"role": "system", "content": "You are a senior software engineer."},
            {"role": "user", "content": prompt},
        ]
        response = openrouter_chat(model, messages)
        response.content = RESPONSES.get(model, response.content)
        self.total_cost += response.cost_total
        self.call_count += 1
        return response


# ────────────────────────────────────────────────────────────────────
# 3. Mock span helper for vendor mapping demo
# ────────────────────────────────────────────────────────────────────

def make_span(name: str, attributes: dict) -> MagicMock:
    """Create a mock ReadableSpan (simulates what OTel produces)."""
    span = MagicMock()
    span.name = name
    span.attributes = attributes
    span.start_time = 1700000000_000000000
    return span


# ────────────────────────────────────────────────────────────────────
# 4. Run the coding assistant — trace each call through AITF
# ────────────────────────────────────────────────────────────────────

vendor_mapper = VendorMapper()
ocsf_mapper = OCSFMapper()
compliance_mapper = ComplianceMapper(frameworks=["nist_ai_rmf", "eu_ai_act"])

assistant = CodingAssistant()

# Tasks to process
tasks = [
    ("quick_question",
     "Why am I getting 'TypeError: NoneType is not subscriptable' on line 42?"),
    ("code_review",
     "Review auth_middleware.py for security issues."),
    ("summarize",
     "Write a PR summary for the auth middleware refactor."),
    ("explain",
     "What does the process_payment function do?"),
]

print("=" * 70)
print("  Coding Assistant with OpenRouter — AITF Tracing")
print("=" * 70)

ocsf_events = []

for i, (task_type, prompt) in enumerate(tasks, 1):
    response = assistant.ask(task_type, prompt)
    model = response.model

    print(f"\n  [{i}] {task_type} → {model}")
    print(f"      Prompt:  \"{prompt[:60]}{'…' if len(prompt) > 60 else ''}\"")
    print(f"      Answer:  \"{response.content[:80]}…\"")
    print(f"      Tokens:  {response.prompt_tokens} in / {response.completion_tokens} out")
    print(f"      Cost:    ${response.cost_total:.6f}  "
          f"(${response.cost_prompt:.6f} + ${response.cost_completion:.6f})")
    print(f"      Latency: {response.latency_ms:.0f}ms")

    # ── Build the OpenRouter span (what OTel auto-instrumentation produces) ──
    span = make_span(f"chat {model}", {
        "openrouter.model": model,
        "openrouter.route.provider": response.route_provider,
        "openrouter.route.model": response.route_model,
        "openrouter.route.id": response.id,
        "openrouter.request.temperature": 0.5,
        "openrouter.request.max_tokens": 1024,
        "openrouter.usage.prompt_tokens": response.prompt_tokens,
        "openrouter.usage.completion_tokens": response.completion_tokens,
        "openrouter.usage.total_tokens": response.prompt_tokens + response.completion_tokens,
        "openrouter.cost.prompt": response.cost_prompt,
        "openrouter.cost.completion": response.cost_completion,
        "openrouter.cost.total": response.cost_total,
        "openrouter.latency.total_ms": response.latency_ms,
        "openrouter.response.finish_reason": response.finish_reason,
        "openrouter.response.id": response.id,
    })

    # ── Vendor normalization → OCSF event ──
    result = vendor_mapper.normalize_span(span)
    if result:
        vendor, event_type, aitf_attrs = result
        normalized_span = make_span(f"chat {aitf_attrs.get('gen_ai.request.model', model)}", aitf_attrs)
        ocsf_event = ocsf_mapper.map_span(normalized_span)
        if ocsf_event:
            enriched = compliance_mapper.enrich_event(ocsf_event, "model_inference")
            ocsf_events.append(enriched)
            print(f"      OCSF:    class={ocsf_event.class_uid}, "
                  f"provider={aitf_attrs.get('gen_ai.provider.name', '?')}, "
                  f"model={aitf_attrs.get('gen_ai.request.model', '?')}")


# ────────────────────────────────────────────────────────────────────
# 5. Show the vendor mapping in action
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  OpenRouter Vendor Mapping Details")
print("=" * 70)

# Show how provider detection works for each model
print("\n  Provider detection from model name prefix:")
test_models = [
    "anthropic/claude-sonnet-4-5-20250929",
    "openai/gpt-4o",
    "deepseek/deepseek-r1",
    "google/gemini-2.0-flash",
    "meta-llama/llama-3.3-70b-instruct",
    "mistralai/mistral-large-2",
    "x-ai/grok-2",
]
for model in test_models:
    span = make_span(f"chat {model}", {"openrouter.model": model})
    result = vendor_mapper.normalize_span(span)
    if result:
        _, _, attrs = result
        provider = attrs.get("gen_ai.provider.name", "?")
        print(f"    {model:<45s} → gen_ai.provider.name = {provider}")

# Show routing metadata preservation
print("\n  OpenRouter-specific attributes (preserved for audit):")
span = make_span("chat anthropic/claude-sonnet-4-5-20250929", {
    "openrouter.model": "anthropic/claude-sonnet-4-5-20250929",
    "openrouter.route.provider": "anthropic",
    "openrouter.route.model": "claude-sonnet-4-5-20250929",
    "openrouter.request.route": "fallback",
    "openrouter.request.transforms": "middle-out",
    "openrouter.cost.total": 0.0045,
})
result = vendor_mapper.normalize_span(span)
if result:
    _, _, attrs = result
    for k, v in sorted(attrs.items()):
        if k.startswith("openrouter."):
            print(f"    {k:<45s} = {v}")


# ────────────────────────────────────────────────────────────────────
# 6. Cost comparison across providers
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Cost Comparison (same 1000-token prompt, 500-token response)")
print("=" * 70)

for model, pricing in sorted(MODEL_PRICING.items()):
    in_cost = 1000 * pricing["input"] / 1_000_000
    out_cost = 500 * pricing["output"] / 1_000_000
    total = in_cost + out_cost
    bar = "#" * int(total * 10000)
    print(f"  {model:<45s} ${total:.6f}  {bar}")

print(f"\n  OpenRouter lets you pick the optimal model per task,")
print(f"  and AITF tracks the cost, provider, and routing for every call.")


# ────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Summary")
print("=" * 70)
print(f"  Tasks processed:    {len(tasks)}")
print(f"  Models used:        {len(set(t[0] for t in tasks))}")
print(f"  Total cost:         ${assistant.total_cost:.6f}")
print(f"  OCSF events:        {len(ocsf_events)}")
print(f"  Providers detected: anthropic, openai, deepseek, google")
print(f"""
  Pipeline:
    App Code → OpenRouter API → openrouter.* span attrs
                                    ↓
                              VendorMapper (openrouter.json)
                                    ↓
                              gen_ai.* attrs + openrouter.* routing
                                    ↓
                              OCSFMapper → OCSF 7001 events
                                    ↓
                              ComplianceMapper → NIST + EU AI Act
                                    ↓
                              SIEM / XDR (Splunk, QRadar, Sentinel)

  Each OCSF event contains:
    - The underlying provider (anthropic, openai, etc.)
    - OpenRouter routing metadata (route_provider, route_model, transforms)
    - Token counts, cost, and latency
    - Compliance controls (NIST AI RMF, EU AI Act)
""")
