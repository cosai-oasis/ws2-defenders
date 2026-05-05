"""AITF Example: Dual Pipeline Tracing — OTel + OCSF Simultaneously.

Demonstrates AITF's dual-pipeline architecture where the **same spans**
are exported to both:
  - **OTLP** → OTLP-compatible backends for observability and security analytics
            (Jaeger, Grafana Tempo, Datadog, Elastic Security)
  - **OCSF** → OCSF-native SIEM/XDR platforms (Splunk, AWS Security Lake, QRadar)

This is the recommended production setup.  You instrument once and get
security-enriched spans in both formats from the same telemetry.

The example simulates a research assistant that:
  1. Takes a user question
  2. Makes an LLM call to plan the research approach
  3. Retrieves documents via RAG
  4. Generates a final answer with citations
  5. Runs a security scan on the output

All four operations are traced and exported via both pipelines.

Run:
    pip install opentelemetry-sdk aitf
    python dual_pipeline_tracing.py

    # To see traces in Jaeger, start a local Jaeger instance:
    # docker run -d -p 16686:16686 -p 4317:4317 jaegertracing/all-in-one
    # Then set OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
"""

from __future__ import annotations

import json
import os
import random
import time

from aitf import AITFInstrumentor, DualPipelineProvider
from aitf.exporters.ocsf_exporter import OCSFExporter
from aitf.processors.security_processor import SecurityProcessor
from aitf.processors.cost_processor import CostProcessor

# ────────────────────────────────────────────────────────────────────
# 1. Configure the dual pipeline
# ────────────────────────────────────────────────────────────────────

OCSF_OUTPUT = "/tmp/aitf_dual_pipeline_events.jsonl"

pipeline = DualPipelineProvider(
    # Observability pipeline: OTLP → Jaeger / Grafana Tempo / Datadog
    otlp_endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"),  # None = skip OTLP
    # Security pipeline: OCSF → SIEM / file
    ocsf_output_file=OCSF_OUTPUT,
    compliance_frameworks=["nist_ai_rmf", "eu_ai_act", "mitre_atlas"],
    # Service identification
    service_name="research-assistant",
    resource_attributes={
        "deployment.environment": "production",
        "service.version": "2.1.0",
    },
    # Console output for demo visibility
    console=True,
)

provider = pipeline.tracer_provider

# Add processors (enrich spans before they reach either exporter)
provider.add_span_processor(SecurityProcessor(
    detect_prompt_injection=True,
    detect_jailbreak=True,
))
provider.add_span_processor(CostProcessor(
    default_project="research-team",
    budget_limit=100.0,
))

pipeline.set_as_global()

# Instrument all AITF components
instrumentor = AITFInstrumentor(tracer_provider=provider)
instrumentor.instrument_all()


# ────────────────────────────────────────────────────────────────────
# 2. Simulated AI operations
# ────────────────────────────────────────────────────────────────────

PRICING = {"gpt-4o": (2.50, 10.00), "text-embedding-3-small": (0.02, 0.0)}


def simulate_llm_call(model: str, prompt: str) -> dict:
    """Simulate an LLM API call with realistic metrics."""
    time.sleep(random.uniform(0.05, 0.15))
    input_tokens = len(prompt.split()) * 2
    output_tokens = random.randint(80, 250)
    latency = random.uniform(300, 900)
    in_rate, out_rate = PRICING.get(model, (5.0, 15.0))
    return {
        "id": f"chatcmpl-{random.randint(100000, 999999)}",
        "model": model,
        "content": f"[Simulated {model} response to: {prompt[:60]}...]",
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "latency_ms": latency,
        "input_cost": input_tokens * in_rate / 1_000_000,
        "output_cost": output_tokens * out_rate / 1_000_000,
    }


def simulate_vector_search(query: str, top_k: int = 5) -> list[dict]:
    """Simulate a vector database retrieval."""
    time.sleep(random.uniform(0.02, 0.08))
    return [
        {"doc_id": f"doc-{i}", "score": round(random.uniform(0.75, 0.98), 3),
         "title": f"Research paper #{i}: {query[:30]}...",
         "snippet": f"...relevant excerpt about {query[:20]}..."}
        for i in range(1, top_k + 1)
    ]


# ────────────────────────────────────────────────────────────────────
# 3. Run the research assistant pipeline (fully traced)
# ────────────────────────────────────────────────────────────────────

question = "What are the security implications of tool-use in agentic AI systems?"

print("=" * 72)
print("  AITF Dual Pipeline Demo — Research Assistant")
print("  Traces export to: OTLP (Jaeger/Tempo) + OCSF (SIEM/file)")
print("=" * 72)

# Step 1: Plan the research approach (LLM inference)
print("\n[Step 1] Planning research approach...")
with instrumentor.llm.trace_inference(
    model="gpt-4o", system="openai", operation="chat",
    temperature=0.3, max_tokens=500,
) as span:
    plan_prompt = (
        f"Plan a research approach for: {question}\n"
        "List 3-4 key areas to investigate."
    )
    span.set_prompt(plan_prompt)
    result = simulate_llm_call("gpt-4o", plan_prompt)
    span.set_completion(result["content"])
    span.set_response(response_id=result["id"], model=result["model"],
                      finish_reasons=["stop"])
    span.set_usage(input_tokens=result["input_tokens"],
                   output_tokens=result["output_tokens"])
    span.set_cost(input_cost=result["input_cost"],
                  output_cost=result["output_cost"])
    span.set_latency(total_ms=result["latency_ms"])
print(f"  → Planned approach ({result['input_tokens']}+{result['output_tokens']} tokens)")

# Step 2: Retrieve documents (RAG pipeline)
print("\n[Step 2] Retrieving relevant documents...")
with instrumentor.rag.trace_pipeline(
    pipeline_name="research-rag", stage="retrieve",
) as rag_span:
    rag_span.set_retrieval(
        database="pgvector-research-papers",
        top_k=5,
        query=question,
    )
    docs = simulate_vector_search(question, top_k=5)
    rag_span.set_results(
        results_count=len(docs),
        min_score=min(d["score"] for d in docs),
        max_score=max(d["score"] for d in docs),
    )
print(f"  → Retrieved {len(docs)} documents (scores: "
      f"{min(d['score'] for d in docs):.3f}–{max(d['score'] for d in docs):.3f})")

# Step 3: Generate answer with citations (LLM inference)
print("\n[Step 3] Generating research summary...")
with instrumentor.llm.trace_inference(
    model="gpt-4o", system="openai", operation="chat",
    temperature=0.7, max_tokens=2000,
) as span:
    context = "\n".join(d["snippet"] for d in docs)
    gen_prompt = (
        f"Based on these research excerpts:\n{context}\n\n"
        f"Answer: {question}\n\nCite your sources."
    )
    span.set_prompt(gen_prompt)
    result = simulate_llm_call("gpt-4o", gen_prompt)
    span.set_completion(result["content"])
    span.set_response(response_id=result["id"], model=result["model"],
                      finish_reasons=["stop"])
    span.set_usage(input_tokens=result["input_tokens"],
                   output_tokens=result["output_tokens"])
    span.set_cost(input_cost=result["input_cost"],
                  output_cost=result["output_cost"])
    span.set_latency(total_ms=result["latency_ms"])
print(f"  → Generated summary ({result['input_tokens']}+{result['output_tokens']} tokens)")

# Step 4: Embed the question for future retrieval
print("\n[Step 4] Embedding question for retrieval index...")
with instrumentor.llm.trace_inference(
    model="text-embedding-3-small", system="openai", operation="embeddings",
) as span:
    span.set_prompt(question)
    time.sleep(0.03)
    embed_tokens = len(question.split()) * 2
    span.set_usage(input_tokens=embed_tokens)
    span.set_cost(input_cost=embed_tokens * 0.02 / 1_000_000)
    span.set_latency(total_ms=45.0)
print(f"  → Embedded ({embed_tokens} tokens)")


# ────────────────────────────────────────────────────────────────────
# 4. Summary: show what went where
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 72}")
print("  Dual Pipeline Summary")
print("=" * 72)

otlp_ep = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
if otlp_ep:
    print(f"\n  OTLP Pipeline (Observability & Security Analytics):")
    print(f"    Endpoint:  {otlp_ep}")
    print(f"    View in:   Jaeger UI / Grafana Tempo / Datadog APM")
    print(f"    Signals:   4 trace spans (2 LLM + 1 RAG + 1 Embedding)")
else:
    print(f"\n  OTLP Pipeline: SKIPPED (set OTEL_EXPORTER_OTLP_ENDPOINT to enable)")

print(f"\n  OCSF Pipeline (OCSF-Native SIEM):")
print(f"    Output:    {OCSF_OUTPUT}")
print(f"    Events:    OCSF Category 7 JSON (7001 Model Inference, 7004 Data Retrieval)")
print(f"    Enriched:  NIST AI RMF + EU AI Act + MITRE ATLAS compliance controls")

print(f"\n  Both pipelines received the SAME security-enriched spans from a SINGLE instrumentation pass.")
print(f"  OTLP carries full security.* context.  OCSF normalizes to Category 7 for SIEMs.")

print(f"\n  Pipeline modes:")
print(f"    from aitf import create_dual_pipeline_provider  # OTel + OCSF")
print(f"    from aitf import create_otel_only_provider      # OTel only")
print(f"    from aitf import create_ocsf_only_provider      # OCSF only")
