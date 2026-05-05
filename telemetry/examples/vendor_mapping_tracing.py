"""AITF Example: Vendor Mapping Pipeline — LangChain & CrewAI Integration.

Demonstrates how vendor JSON mapping files translate framework-native
telemetry into AITF semantic conventions before OCSF event generation.

This example simulates realistic LangChain and CrewAI workloads:
  - LangChain: ChatBot with RAG retrieval, agent with tools
  - CrewAI: Multi-agent security audit crew with LLM calls

Each framework emits its own telemetry attributes.  The VendorMapper
normalizes them to AITF conventions, then the OCSFMapper produces
SIEM-ready events — all driven by declarative JSON, no custom code.

Pipeline:
  Vendor Telemetry → VendorMapper → OCSFMapper → ComplianceMapper → SIEM

All spans are exportable as both OTel traces (OTLP → Jaeger/Tempo) and
OCSF security events (→ SIEM/XDR).  See ``dual_pipeline_tracing.py``
for dual-pipeline setup.

Run:
    pip install opentelemetry-sdk aitf
    python vendor_mapping_tracing.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from aitf.ocsf.vendor_mapper import VendorMapper
from aitf.ocsf.mapper import OCSFMapper
from aitf.ocsf.compliance_mapper import ComplianceMapper


# ────────────────────────────────────────────────────────────────────
# Helper: mock span factory
# ────────────────────────────────────────────────────────────────────

def make_span(name: str, attributes: dict) -> MagicMock:
    """Create a mock ReadableSpan (simulates what OTel produces)."""
    span = MagicMock()
    span.name = name
    span.attributes = attributes
    span.start_time = 1700000000_000000000
    return span


# ────────────────────────────────────────────────────────────────────
# Setup: load mappers
# ────────────────────────────────────────────────────────────────────

vendor_mapper = VendorMapper()
ocsf_mapper = OCSFMapper()
compliance_mapper = ComplianceMapper(frameworks=["nist_ai_rmf", "eu_ai_act"])

print("=" * 70)
print("  AITF Vendor Mapping Pipeline")
print("=" * 70)

print("\n  Loaded vendor mappings:")
for info in vendor_mapper.list_supported_vendors():
    print(f"    {info['vendor']} v{info['version']}  "
          f"({', '.join(info['event_types'])})")


# ════════════════════════════════════════════════════════════════════
# SCENARIO 1: LangChain Customer Support Bot
# ════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 70}")
print("  Scenario 1: LangChain Customer-Support Chatbot")
print("=" * 70)
print("""
  A LangChain-powered chatbot answers customer questions using RAG.
  LangChain emits its native attributes (ls_provider, ls_model_name,
  langchain.retriever.*, etc.).  The VendorMapper translates them to
  AITF conventions automatically.
""")

# Step A: LangChain ChatOpenAI inference
print("  [A] ChatOpenAI Inference")
lc_chat = make_span("ChatOpenAI", {
    # LangChain-native attributes (what LangSmith would emit)
    "ls_provider": "openai",
    "ls_model_name": "gpt-4o",
    "ls_temperature": 0.4,
    "llm.token_count.prompt": 380,
    "llm.token_count.completion": 120,
    "llm.token_count.total": 500,
    "langchain.run.response_id": "chatcmpl-abc123",
    "langchain.run.finish_reason": "stop",
})

result = vendor_mapper.normalize_span(lc_chat)
if result:
    vendor, event_type, aitf_attrs = result
    print(f"      LangChain native → AITF normalized:")
    print(f"        ls_provider           → gen_ai.provider.name  = {aitf_attrs.get('gen_ai.provider.name')}")
    print(f"        ls_model_name         → gen_ai.request.model  = {aitf_attrs.get('gen_ai.request.model')}")
    print(f"        llm.token_count.*     → gen_ai.usage.*        = {aitf_attrs.get('gen_ai.usage.input_tokens')} in / {aitf_attrs.get('gen_ai.usage.output_tokens')} out")
    print(f"        OCSF class:  {vendor_mapper.get_ocsf_class_uid(vendor, event_type)} (AI Model Inference)")

# Step B: LangChain Vector Store Retriever
print(f"\n  [B] VectorStoreRetriever — Pinecone Knowledge Base")
lc_rag = make_span("VectorStoreRetriever", {
    "langchain.retriever.name": "support-kb-pinecone",
    "langchain.retriever.type": "pinecone",
    "langchain.retriever.k": 8,
    "langchain.retriever.query": "How do I reset my password?",
    "langchain.retriever.documents": 6,
    "retriever.embeddings.model": "text-embedding-3-small",
})

result = vendor_mapper.normalize_span(lc_rag)
if result:
    vendor, event_type, aitf_attrs = result
    print(f"      LangChain native → AITF normalized:")
    print(f"        langchain.retriever.name  → gen_ai.data_source.id       = {aitf_attrs.get('gen_ai.data_source.id')}")
    print(f"        langchain.retriever.k     → rag.retrieve.top_k         = {aitf_attrs.get('rag.retrieve.top_k')}")
    print(f"        langchain.retriever.query  → rag.query                 = {aitf_attrs.get('rag.query')}")
    print(f"        OCSF class:  {vendor_mapper.get_ocsf_class_uid(vendor, event_type)} (AI Data Retrieval)")

# Step C: LangChain Agent with tool call
print(f"\n  [C] AgentExecutor — Support Agent with Tool Call")
lc_agent = make_span("AgentExecutor", {
    "langchain.agent.name": "support-agent",
    "langchain.agent.tools": "search_kb,create_ticket,escalate_to_human",
    "langchain.agent.output": "I've found the answer in our knowledge base.",
})

result = vendor_mapper.normalize_span(lc_agent)
if result:
    vendor, event_type, aitf_attrs = result
    print(f"      langchain.agent.name → gen_ai.agent.name = {aitf_attrs.get('gen_ai.agent.name')}")
    print(f"      OCSF class:  {vendor_mapper.get_ocsf_class_uid(vendor, event_type)} (AI Agent Activity)")


# ════════════════════════════════════════════════════════════════════
# SCENARIO 2: CrewAI Security Audit Crew
# ════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 70}")
print("  Scenario 2: CrewAI Security Audit Crew")
print("=" * 70)
print("""
  A CrewAI crew performs a security audit: a manager delegates to a
  vulnerability scanner and a report writer.  CrewAI emits its native
  crewai.* attributes, which the VendorMapper normalizes to AITF.
""")

# Simulate a realistic CrewAI multi-agent workflow
crewai_spans = [
    ("Agent Execution", {
        "crewai.agent.role": "security-manager",
        "crewai.agent.goal": "Coordinate security audit of the payments service",
        "crewai.agent.backstory": "Senior security architect with 15 years experience",
        "crewai.agent.id": "agent-sec-mgr-001",
        "crewai.agent.llm": "claude-sonnet-4-5-20250929",
        "crewai.agent.tools": "web_search,cve_lookup,code_scan",
        "crewai.crew.name": "security-audit-crew",
        "crewai.crew.process": "hierarchical",
    }),
    ("LLM Call claude-sonnet-4-5-20250929", {
        "crewai.llm.model": "claude-sonnet-4-5-20250929",
        "crewai.llm.provider": "anthropic",
        "crewai.llm.temperature": 0.1,
        "crewai.llm.input_tokens": 1500,
        "crewai.llm.output_tokens": 600,
        "crewai.llm.total_tokens": 2100,
        "crewai.llm.response_time_ms": 2800.0,
        "crewai.llm.finish_reason": "end_turn",
    }),
    ("Tool Execution cve_lookup", {
        "crewai.tool.name": "cve_lookup",
        "crewai.tool.description": "Search NVD for CVEs affecting a package",
        "crewai.tool.input": '{"package": "langchain", "min_severity": "high"}',
        "crewai.tool.output": '[{"id": "CVE-2024-46946", "severity": "high"}]',
        "crewai.tool.agent": "vuln-scanner",
        "crewai.tool.duration_ms": 1850.0,
        "crewai.tool.cache_hit": False,
    }),
    ("Task Delegation", {
        "crewai.delegation.from_agent": "security-manager",
        "crewai.delegation.to_agent": "report-writer",
        "crewai.delegation.task": "Write executive summary of security findings",
        "crewai.delegation.reason": "Requires professional report writing skills",
        "crewai.delegation.strategy": "capability",
    }),
    ("LLM Call gpt-4o", {
        "crewai.llm.model": "gpt-4o",
        "crewai.llm.provider": "openai",
        "crewai.llm.temperature": 0.3,
        "crewai.llm.input_tokens": 2200,
        "crewai.llm.output_tokens": 900,
        "crewai.llm.total_tokens": 3100,
        "crewai.llm.response_time_ms": 3200.0,
        "crewai.llm.finish_reason": "stop",
    }),
]

print(f"  {'Span Name':<40s} {'→ AITF Event':12s} {'OCSF':>6s}")
print(f"  {'─' * 40} {'─' * 12} {'─' * 6}")

for span_name, attrs in crewai_spans:
    span = make_span(span_name, attrs)
    result = vendor_mapper.normalize_span(span)
    if result:
        vendor, etype, aitf_a = result
        uid = vendor_mapper.get_ocsf_class_uid(vendor, etype)
        print(f"  {span_name:<40s} {etype:12s} {uid or '?':>6}")


# Show detailed attribute translation for the agent span
print(f"\n  Detailed: CrewAI Agent Execution → AITF")
print(f"  {'─' * 60}")
result = vendor_mapper.normalize_span(make_span("Agent Execution", crewai_spans[0][1]))
if result:
    _, _, aitf_attrs = result
    for k, v in sorted(aitf_attrs.items()):
        # Truncate long values for display
        display = str(v)[:60] + "…" if len(str(v)) > 60 else str(v)
        print(f"    {k:<35s} = {display}")


# ════════════════════════════════════════════════════════════════════
# SCENARIO 3: Custom Vendor Mapping (AutoGen)
# ════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 70}")
print("  Scenario 3: Loading a Custom Vendor Mapping (AutoGen)")
print("=" * 70)
print("""
  Any framework can integrate with AITF by providing a JSON mapping file.
  Here we create one for Microsoft AutoGen and load it at runtime.
""")

autogen_mapping = {
    "vendor": "autogen",
    "version": "0.4",
    "description": "Maps Microsoft AutoGen telemetry to AITF conventions",
    "homepage": "https://microsoft.github.io/autogen/",
    "span_name_patterns": {
        "inference": ["^AutoGen\\.LLM"],
        "agent": ["^AutoGen\\.Agent", "^AutoGen\\.GroupChat"],
    },
    "attribute_mappings": {
        "inference": {
            "vendor_to_aitf": {
                "autogen.llm.model": "gen_ai.request.model",
                "autogen.llm.provider": "gen_ai.provider.name",
            },
            "ocsf_class_uid": 7001,
            "ocsf_activity_id_map": {"chat": 1, "default": 1},
            "defaults": {"gen_ai.operation.name": "chat"},
        },
        "agent": {
            "vendor_to_aitf": {
                "autogen.agent.name": "gen_ai.agent.name",
                "autogen.agent.type": "agent.type",
            },
            "ocsf_class_uid": 7002,
            "ocsf_activity_id_map": {"default": 3},
            "defaults": {"agent.framework": "autogen"},
        },
    },
    "provider_detection": {
        "attribute_keys": ["autogen.llm.provider"],
        "model_prefix_to_provider": {"gpt-": "openai", "claude-": "anthropic"},
    },
    "severity_mapping": {},
    "metadata": {
        "ocsf_product": {"name": "AutoGen", "vendor_name": "Microsoft", "version": "0.4"},
    },
}

with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
    json.dump(autogen_mapping, f)
    custom_path = f.name

vendor_mapper.load_file(custom_path)
print(f"  Loaded: autogen v0.4")
print(f"  Total vendors: {len(vendor_mapper.vendors)}  ({', '.join(vendor_mapper.vendors)})")

# Test with a simulated AutoGen GroupChat span
autogen_span = make_span("AutoGen.GroupChat.execute", {
    "autogen.agent.name": "code-reviewer",
    "autogen.agent.type": "assistant",
})

result = vendor_mapper.normalize_span(autogen_span)
if result:
    v, et, aa = result
    print(f"\n  AutoGen.GroupChat.execute → {v}/{et}")
    for k, val in sorted(aa.items()):
        print(f"    {k}: {val}")


# ════════════════════════════════════════════════════════════════════
# SCENARIO 4: Full Pipeline — Vendor → AITF → OCSF → Compliance
# ════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 70}")
print("  Scenario 4: Full Pipeline (Vendor → AITF → OCSF → Compliance)")
print("=" * 70)
print("""
  A LangChain ChatAnthropic span flows through the entire pipeline:
    1. VendorMapper normalizes attributes
    2. OCSFMapper produces an OCSF 7001 event
    3. ComplianceMapper enriches with regulatory controls
""")

# Simulate a LangChain inference span
span = make_span("ChatAnthropic", {
    "ls_provider": "anthropic",
    "ls_model_name": "claude-sonnet-4-5-20250929",
    "ls_temperature": 0.5,
    "llm.token_count.prompt": 500,
    "llm.token_count.completion": 300,
    "llm.token_count.total": 800,
})

# Step 1: Vendor normalization
norm = vendor_mapper.normalize_span(span)
if norm:
    vendor, event_type, aitf_attrs = norm
    print(f"  Step 1 — Vendor Detection")
    print(f"    Vendor: {vendor}, Event: {event_type}, Attrs: {len(aitf_attrs)} keys")

    # Step 2: OCSF mapping
    normalized_span = make_span(
        f"chat {aitf_attrs.get('gen_ai.request.model', 'unknown')}", aitf_attrs
    )
    ocsf_event = ocsf_mapper.map_span(normalized_span)
    if ocsf_event:
        print(f"\n  Step 2 — OCSF Mapping")
        print(f"    Class UID:  {ocsf_event.class_uid} (AI Model Inference)")
        print(f"    Type UID:   {ocsf_event.type_uid}")
        print(f"    Model:      {ocsf_event.model.model_id}")
        print(f"    Provider:   {ocsf_event.model.provider}")

        # Step 3: Compliance enrichment
        enriched = compliance_mapper.enrich_event(ocsf_event, "model_inference")
        print(f"\n  Step 3 — Compliance Enrichment")
        if enriched.compliance:
            if enriched.compliance.nist_ai_rmf:
                print(f"    NIST AI RMF: {enriched.compliance.nist_ai_rmf}")
            if enriched.compliance.eu_ai_act:
                print(f"    EU AI Act:   {enriched.compliance.eu_ai_act}")

        event_dict = enriched.model_dump(exclude_none=True)
        print(f"\n  Final OCSF event: {len(json.dumps(event_dict))} bytes, "
              f"{len(event_dict)} top-level keys")


# ────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Summary")
print("=" * 70)
print(f"""
  Vendor mapping files provide a declarative way for framework vendors
  to integrate with AITF.  Each JSON file defines:

    1. span_name_patterns    — Regex patterns to classify spans
    2. attribute_mappings    — Vendor → AITF attribute translations
    3. provider_detection    — LLM provider inference from model names
    4. severity_mapping      — Vendor status → OCSF severity
    5. metadata              — Vendor product info for OCSF events

  Pipeline: Vendor Telemetry → VendorMapper → OCSFMapper → ComplianceMapper → SIEM

  Built-in vendors: {', '.join(vendor_mapper.vendors)}
""")
