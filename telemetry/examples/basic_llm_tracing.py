"""AITF Example: Basic LLM Tracing — Customer Support Chatbot.

Demonstrates how AITF instruments a realistic multi-turn chatbot.  The
simulated ``ChatBot`` class mirrors what you would build with the OpenAI
or Anthropic SDK; AITF wraps every inference call so that every prompt,
completion, token count, latency, and cost is captured as **both** an
OTel trace span (for observability and security analytics) and an OCSF
event (for OCSF-native SIEMs).

Pipeline options (set via AITF_PIPELINE env var):
  - "dual"  → OTLP to Jaeger/Tempo AND OCSF to SIEM (default)
  - "otel"  → OTLP only (observability & security analytics)
  - "ocsf"  → OCSF only (OCSF-native SIEM)

Run:
    pip install opentelemetry-sdk aitf
    python basic_llm_tracing.py
"""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass, field

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

from aitf.instrumentation.llm import LLMInstrumentor
from aitf.pipeline import DualPipelineProvider
from aitf.processors.cost_processor import CostProcessor
from aitf.processors.security_processor import SecurityProcessor
from aitf.exporters.ocsf_exporter import OCSFExporter


# ────────────────────────────────────────────────────────────────────
# 1. Simulated LLM client (stands in for openai.ChatCompletion, etc.)
# ────────────────────────────────────────────────────────────────────

@dataclass
class Message:
    role: str          # "system" | "user" | "assistant"
    content: str


@dataclass
class ChatResponse:
    """Mirrors an OpenAI-style chat completion response."""
    id: str
    model: str
    content: str
    finish_reason: str = "stop"
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0


# Pre-canned responses for the demo (keyed by keyword in the user message)
_RESPONSES = {
    "refund": (
        "I can help with your refund!  Our policy allows returns within 30 "
        "days of purchase.  Could you share your order number so I can look "
        "it up?"
    ),
    "order": (
        "I found order #ORD-88421.  It shipped on Feb 20 via FedEx and is "
        "currently in transit.  Expected delivery is Feb 28.  Would you like "
        "me to send you the tracking link?"
    ),
    "tracking": (
        "Here is your tracking link: https://track.example.com/FX-98234\n"
        "The package is at the Memphis hub as of this morning."
    ),
}
_DEFAULT_RESPONSE = (
    "Thanks for reaching out!  I'm the Acme Support Bot — I can help with "
    "orders, refunds, and shipping.  What can I do for you today?"
)


def _simulate_llm_call(
    messages: list[Message], model: str = "gpt-4o"
) -> ChatResponse:
    """Pretend to call an LLM API.  Returns a canned response and fake metrics."""
    user_msg = next(
        (m.content for m in reversed(messages) if m.role == "user"), ""
    )
    # Pick a response based on keyword matching
    reply = _DEFAULT_RESPONSE
    for keyword, text in _RESPONSES.items():
        if keyword in user_msg.lower():
            reply = text
            break

    input_tokens = sum(len(m.content.split()) * 2 for m in messages)
    output_tokens = len(reply.split()) * 2
    latency = random.uniform(400, 1200)
    time.sleep(latency / 5000)  # tiny sleep so spans have real duration

    return ChatResponse(
        id=f"chatcmpl-{random.randint(100000, 999999)}",
        model=model,
        content=reply,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=latency,
    )


# ────────────────────────────────────────────────────────────────────
# 2. Chatbot with conversation history
# ────────────────────────────────────────────────────────────────────

class ChatBot:
    """A simple multi-turn customer-support chatbot."""

    SYSTEM_PROMPT = (
        "You are the Acme Corp support assistant.  Be helpful, concise, and "
        "professional.  If you cannot answer a question, offer to escalate to "
        "a human agent."
    )

    def __init__(self, model: str = "gpt-4o"):
        self.model = model
        self.history: list[Message] = [
            Message(role="system", content=self.SYSTEM_PROMPT),
        ]

    def chat(self, user_input: str) -> str:
        """Send a message and return the assistant's reply."""
        self.history.append(Message(role="user", content=user_input))
        response = _simulate_llm_call(self.history, model=self.model)
        self.history.append(Message(role="assistant", content=response.content))
        return response


# ────────────────────────────────────────────────────────────────────
# 3. AITF Setup — dual pipeline: OTLP (observability & security) + OCSF (SIEM)
# ────────────────────────────────────────────────────────────────────
#
# AITF supports three pipeline modes from the same instrumentation:
#   "dual" → OTLP to Jaeger/Tempo AND OCSF to SIEM (recommended)
#   "otel" → OTLP only (observability & security analytics)
#   "ocsf" → OCSF only (OCSF-native SIEM)
#
pipeline_mode = os.environ.get("AITF_PIPELINE", "ocsf")

if pipeline_mode == "dual":
    # ── Dual pipeline: OTLP (observability & security) + OCSF (SIEM) ──
    pipeline = DualPipelineProvider(
        otlp_endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"),
        ocsf_output_file="/tmp/aitf_ocsf_events.jsonl",
        compliance_frameworks=["nist_ai_rmf", "mitre_atlas", "eu_ai_act"],
        service_name="acme-support-bot",
        console=True,
    )
    provider = pipeline.tracer_provider
elif pipeline_mode == "otel":
    # ── OTel-only: traces go to Jaeger/Tempo/Datadog ──
    pipeline = DualPipelineProvider(
        otlp_endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"),
        service_name="acme-support-bot",
        console=True,
    )
    provider = pipeline.tracer_provider
else:
    # ── OCSF-only: OCSF-normalized events to SIEM (default for this demo) ──
    provider = TracerProvider()

# Security processor — watches every prompt for OWASP LLM Top 10 threats
provider.add_span_processor(SecurityProcessor(
    detect_prompt_injection=True,
    detect_jailbreak=True,
    detect_data_exfiltration=True,
))

# Cost processor — tracks per-project token spend against a budget
provider.add_span_processor(CostProcessor(
    default_project="acme-support-bot",
    budget_limit=50.0,  # $50 daily budget
))

# For OCSF-only mode, add the OCSF exporter manually
if pipeline_mode not in ("dual", "otel"):
    ocsf_exporter = OCSFExporter(
        output_file="/tmp/aitf_ocsf_events.jsonl",
        compliance_frameworks=["nist_ai_rmf", "mitre_atlas", "eu_ai_act"],
    )
    provider.add_span_processor(SimpleSpanProcessor(ocsf_exporter))
    provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

trace.set_tracer_provider(provider)

llm = LLMInstrumentor(tracer_provider=provider)
llm.instrument()


# ────────────────────────────────────────────────────────────────────
# 4. Run the chatbot — every LLM call is automatically traced
# ────────────────────────────────────────────────────────────────────

# Pricing per 1M tokens (same ballpark as real GPT-4o pricing)
INPUT_COST_PER_TOKEN = 2.50 / 1_000_000
OUTPUT_COST_PER_TOKEN = 10.00 / 1_000_000

bot = ChatBot(model="gpt-4o")

# Simulate a realistic multi-turn support conversation
conversation = [
    "Hi, I'd like to check on my order status.",
    "My order number is ORD-88421.",
    "Can you send me the tracking link?",
]

print("=" * 70)
print("  Acme Corp Customer Support — Chatbot Demo with AITF Tracing")
print("=" * 70)

for turn, user_msg in enumerate(conversation, 1):
    print(f"\n--- Turn {turn} ---")
    print(f"  Customer: {user_msg}")

    # ── Wrap the LLM call with AITF tracing ──
    with llm.trace_inference(
        model=bot.model,
        system="openai",
        operation="chat",
        temperature=0.4,
        max_tokens=1024,
    ) as span:
        # Build the prompt from conversation history (what goes to the model)
        span.set_prompt(
            "\n".join(f"[{m.role}] {m.content}" for m in bot.history)
            + f"\n[user] {user_msg}"
        )

        # ── Actual LLM call ──
        response = bot.chat(user_msg)

        # ── Record what came back ──
        span.set_completion(response.content)
        span.set_response(
            response_id=response.id,
            model=response.model,
            finish_reasons=[response.finish_reason],
        )
        span.set_usage(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
        span.set_cost(
            input_cost=response.input_tokens * INPUT_COST_PER_TOKEN,
            output_cost=response.output_tokens * OUTPUT_COST_PER_TOKEN,
        )
        span.set_latency(
            total_ms=response.latency_ms,
            tokens_per_second=response.output_tokens / (response.latency_ms / 1000),
        )

    print(f"  Bot:      {response.content}")
    print(f"  (tokens: {response.input_tokens} in / {response.output_tokens} out, "
          f"{response.latency_ms:.0f} ms)")


# ────────────────────────────────────────────────────────────────────
# 5. Embeddings — trace a query embedding (used before vector search)
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Embedding a support query for knowledge-base lookup")
print("=" * 70)

query = "How do I return a damaged item?"
with llm.trace_inference(
    model="text-embedding-3-small",
    system="openai",
    operation="embeddings",
) as span:
    span.set_prompt(query)
    # Simulate embedding call
    time.sleep(0.05)
    fake_tokens = len(query.split()) * 2
    span.set_usage(input_tokens=fake_tokens)
    span.set_cost(input_cost=fake_tokens * (0.02 / 1_000_000))
    span.set_latency(total_ms=85.0)

print(f"  Query:  \"{query}\"")
print(f"  Model:  text-embedding-3-small")
print(f"  Tokens: {fake_tokens}")


# ────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Summary")
print("=" * 70)
print(f"  Pipeline mode:        {pipeline_mode}")
print(f"  Conversation turns:   {len(conversation)}")
if pipeline_mode == "dual":
    print(f"  OTel traces sent to:  OTLP endpoint (Jaeger/Tempo/Datadog)")
    print(f"  OCSF events written:  /tmp/aitf_ocsf_events.jsonl")
elif pipeline_mode == "otel":
    print(f"  OTel traces sent to:  OTLP endpoint (Jaeger/Tempo/Datadog)")
else:
    print(f"  OCSF events exported: {ocsf_exporter.event_count}")
    print(f"  Events written to:    /tmp/aitf_ocsf_events.jsonl")
print(f"\n  Every LLM call produces a span that can be exported as:")
print(f"    OTel (OTLP):  Security-enriched trace span for observability & security backends")
print(f"    OCSF (7001):  Security event for SIEM/XDR with:")
print(f"      - Model, provider, prompt/completion content")
print(f"      - Token counts, cost, and latency")
print(f"      - NIST AI RMF + EU AI Act + MITRE ATLAS compliance controls")
print(f"      - OWASP LLM Top 10 security scan results")
print(f"\n  Set AITF_PIPELINE=dual to enable both pipelines simultaneously.")
