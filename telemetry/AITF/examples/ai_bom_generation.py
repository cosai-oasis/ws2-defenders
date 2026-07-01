"""AITF Example: AI-BOM Generation — Fraud Detection Platform.

Demonstrates how to generate an AI Bill of Materials (AI-BOM) by
simulating a realistic fraud-detection platform that uses multiple
models, vector stores, MCP tools, and agent frameworks.

The AI-BOM answers: "What AI components are running in production,
who supplies them, and are any of them vulnerable?"

All spans are exportable as both OTel traces (OTLP → Jaeger/Tempo) and
OCSF security events (→ SIEM/XDR).  See ``dual_pipeline_tracing.py``
for dual-pipeline setup.

Run:
    pip install opentelemetry-sdk aitf
    python ai_bom_generation.py
"""

from __future__ import annotations

import json
import time

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from aitf.generators.ai_bom import AIBOMGenerator
from aitf.instrumentation.llm import LLMInstrumentor
from aitf.instrumentation.agent import AgentInstrumentor
from aitf.instrumentation.mcp import MCPInstrumentor
from aitf.instrumentation.rag import RAGInstrumentor


# ────────────────────────────────────────────────────────────────────
# 1. AITF Setup — AI-BOM generator collects from every traced span
# ────────────────────────────────────────────────────────────────────

provider = TracerProvider()

bom_generator = AIBOMGenerator(
    system_name="fraud-detection-platform",
    system_version="4.2.0",
)
provider.add_span_processor(SimpleSpanProcessor(bom_generator))
trace.set_tracer_provider(provider)

llm = LLMInstrumentor(tracer_provider=provider)
agent = AgentInstrumentor(tracer_provider=provider)
mcp = MCPInstrumentor(tracer_provider=provider)
rag = RAGInstrumentor(tracer_provider=provider)

llm.instrument()
agent.instrument()
mcp.instrument()
rag.instrument()


# ────────────────────────────────────────────────────────────────────
# 2. Simulate a realistic fraud-detection workload
# ────────────────────────────────────────────────────────────────────

print("=" * 70)
print("  Fraud Detection Platform — AI-BOM Discovery")
print("=" * 70)
print("\n  Simulating production workload to discover AI components …\n")

# --- Transaction scoring (primary model) ---
print("  [1/6] Transaction scoring — Claude Sonnet")
with llm.trace_inference(
    model="claude-sonnet-4-5-20250929",
    system="anthropic",
    operation="chat",
    temperature=0.0,
    max_tokens=256,
) as span:
    span.set_prompt(
        "Analyze this transaction for fraud indicators:\n"
        "  Amount: $4,299.00\n"
        "  Merchant: Electronics Warehouse\n"
        "  Location: Lagos, Nigeria\n"
        "  Card: ending 4421 (issuer: US)\n"
        "  Time: 03:14 AM cardholder local time"
    )
    span.set_completion(
        "HIGH RISK (score: 0.89). Indicators: 1) International purchase "
        "from US-issued card, 2) High-value electronics, 3) Transaction "
        "at unusual hour.  Recommend: hold for manual review."
    )
    span.set_usage(input_tokens=120, output_tokens=65)
    time.sleep(0.05)

# --- Embedding for similarity search ---
print("  [2/6] Transaction embedding — text-embedding-3-large")
with llm.trace_inference(
    model="text-embedding-3-large",
    system="openai",
    operation="embeddings",
) as span:
    span.set_prompt("$4299 electronics Lagos Nigeria 03:14AM")
    span.set_usage(input_tokens=12)
    time.sleep(0.03)

# --- RAG: search past fraud cases ---
print("  [3/6] Similar-case retrieval — Pinecone")
with rag.trace_retrieval(
    database="pinecone",
    query="high-value electronics international unusual hour",
    top_k=10,
    embedding_model="text-embedding-3-large",
) as retrieval:
    # Simulate finding similar past fraud cases
    retrieval.set_results_count(7)
    retrieval.set_max_score(0.94)
    time.sleep(0.04)

# --- Agent: investigate the transaction ---
print("  [4/6] Investigation agent — LangChain ReAct")
with agent.trace_session(
    agent_name="fraud-investigator",
    agent_type="autonomous",
    framework="langchain",
    description="Investigates high-risk transactions using tools",
) as session:
    with session.step("reasoning") as step:
        step.set_thought(
            "Transaction flagged as high-risk.  Similar to 7 past fraud cases.  "
            "Let me check the merchant reputation and cardholder history."
        )
    with session.step("tool_use") as step:
        step.set_action("check_merchant_reputation(Electronics Warehouse, Lagos)")
    time.sleep(0.05)

# --- MCP tool: check merchant reputation ---
print("  [5/6] Merchant check — MCP tool")
with mcp.trace_tool(
    tool_name="check_merchant_reputation",
    server_name="merchant-risk-server",
    server_version="2.3.0",
    transport="stdio",
) as tool:
    tool.set_input(json.dumps({
        "merchant_name": "Electronics Warehouse",
        "location": "Lagos, Nigeria",
    }))
    tool.set_output(json.dumps({
        "risk_score": 0.78,
        "chargeback_rate": 0.12,
        "verified": False,
        "category": "high_risk_mcc",
    }))
    time.sleep(0.03)

# --- Secondary model: GPT-4o for report generation ---
print("  [6/6] Report generation — GPT-4o")
with llm.trace_inference(
    model="gpt-4o",
    system="openai",
    operation="chat",
    temperature=0.2,
    max_tokens=1024,
) as span:
    span.set_prompt(
        "Generate a fraud investigation report for transaction TXN-88421.\n"
        "Risk score: 0.89, Merchant risk: 0.78, Similar cases: 7 matches."
    )
    span.set_completion(
        "FRAUD INVESTIGATION REPORT — TXN-88421\n"
        "Recommendation: BLOCK\n"
        "Confidence: HIGH (0.89)\n"
        "Reasoning: Transaction matches 7 historical fraud patterns.  "
        "Merchant has 12% chargeback rate and is unverified."
    )
    span.set_usage(input_tokens=200, output_tokens=180)
    time.sleep(0.05)


# ────────────────────────────────────────────────────────────────────
# 3. Register components not captured via tracing
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Registering additional components …")
print("=" * 70)

# Frameworks and libraries
bom_generator.add_component(
    component_type="framework",
    name="langchain",
    version="0.3.12",
    provider="LangChain Inc.",
    license="MIT",
    source="https://pypi.org/project/langchain/",
)
bom_generator.add_component(
    component_type="framework",
    name="pydantic",
    version="2.10.0",
    provider="Pydantic",
    license="MIT",
)

# Guardrails
bom_generator.add_component(
    component_type="guardrail",
    name="transaction-amount-limiter",
    version="1.0",
    provider="internal",
    description="Blocks transactions > $10,000 without manager approval",
)
bom_generator.add_component(
    component_type="guardrail",
    name="pii-redaction-filter",
    version="2.4",
    provider="internal",
    description="Redacts card numbers and SSNs before model input",
)

# Prompt templates
bom_generator.add_component(
    component_type="prompt_template",
    name="fraud-scoring-v3",
    version="3.1",
    provider="internal",
    properties={"category": "fraud_detection", "reviewed": True, "last_audit": "2026-02-01"},
)
bom_generator.add_component(
    component_type="prompt_template",
    name="investigation-report-v2",
    version="2.0",
    provider="internal",
    properties={"category": "reporting", "reviewed": True},
)

# Data sources
bom_generator.add_component(
    component_type="dataset",
    name="fraud-case-embeddings",
    version="2026-02-15",
    provider="internal",
    description="128K historical fraud case embeddings for similarity search",
    properties={"record_count": 128_000, "embedding_dim": 3072},
)

# Known vulnerabilities
bom_generator.add_vulnerability(
    component_type="framework",
    component_name="langchain",
    vulnerability_id="CVE-2024-46946",
    severity="high",
    description="Arbitrary code execution via untrusted YAML deserialization",
    source="NVD",
)
bom_generator.add_vulnerability(
    component_type="framework",
    component_name="langchain",
    vulnerability_id="CVE-2024-28088",
    severity="medium",
    description="Server-side request forgery in web retrieval chain",
    source="NVD",
)

print("  Added: 2 frameworks, 2 guardrails, 2 prompt templates, 1 dataset")
print("  Added: 2 known vulnerabilities (langchain)")


# ────────────────────────────────────────────────────────────────────
# 4. Generate the AI-BOM
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  AI-BOM Generation")
print("=" * 70)

bom = bom_generator.generate(bom_id="bom-fraud-platform-2026-001")

# Component summary
summary = bom_generator.get_component_summary()
print(f"\n  Component Summary:")
print(f"  {json.dumps(summary, indent=4)}")

# AITF format
print(f"\n  {'─' * 60}")
print(f"  AITF Format")
print(f"  {'─' * 60}")
print(f"  BOM ID:           {bom.bom_id}")
print(f"  System:           {bom.system_name} v{bom.system_version}")
print(f"  Components:       {bom.component_count}")
print(f"  Component types:  {bom.component_types}")
print(f"  Vulnerabilities:  {len(bom.vulnerabilities)}")
if bom.vulnerability_summary:
    print(f"  Vuln summary:     {bom.vulnerability_summary}")

# CycloneDX format
print(f"\n  {'─' * 60}")
print(f"  CycloneDX Export")
print(f"  {'─' * 60}")
cdx = bom.to_cyclonedx()
print(f"  bomFormat:        {cdx['bomFormat']}")
print(f"  specVersion:      {cdx['specVersion']}")
print(f"  Components:       {len(cdx['components'])}")
print(f"  Vulnerabilities:  {len(cdx.get('vulnerabilities', []))}")

# Show a few components
print(f"\n  Sample components (CycloneDX):")
for comp in cdx["components"][:3]:
    print(f"    - {comp.get('name', '?')} v{comp.get('version', '?')} "
          f"({comp.get('type', '?')}) — {comp.get('supplier', {}).get('name', '?')}")

# SPDX format
print(f"\n  {'─' * 60}")
print(f"  SPDX Export")
print(f"  {'─' * 60}")
spdx = bom.to_spdx()
print(f"  spdxVersion:      {spdx['spdxVersion']}")
print(f"  Packages:         {len(spdx['packages'])}")


# ────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Summary")
print("=" * 70)
print(f"""
  The AI-BOM captures every AI component in the fraud-detection platform:

    Models:           claude-sonnet, gpt-4o, text-embedding-3-large
    Vector stores:    Pinecone (128K fraud-case embeddings)
    MCP tools:        merchant-risk-server v2.3.0
    Frameworks:       LangChain 0.3.12, Pydantic 2.10
    Guardrails:       transaction-amount-limiter, pii-redaction-filter
    Prompt templates: fraud-scoring-v3, investigation-report-v2
    Vulnerabilities:  2 (CVE-2024-46946, CVE-2024-28088)

  Export formats: AITF JSON, CycloneDX 1.6, SPDX 2.3
  Use case: regulatory compliance, supply-chain audits, vulnerability mgmt
""")

provider.shutdown()
