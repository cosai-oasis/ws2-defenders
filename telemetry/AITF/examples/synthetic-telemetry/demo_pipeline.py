#!/usr/bin/env python3
"""AITF Demo Pipeline — Process 1000 Synthetic Events Through the Python SDK.

This script demonstrates the full AITF telemetry pipeline:

  1. Generate 1000 synthetic OCSF events (or load from JSONL)
  2. Replay events through the Python SDK instrumentors (LLM, Agent, MCP, etc.)
  3. Process through Security, PII, Cost, and Compliance processors
  4. Export as OCSF JSONL via the OCSFExporter
  5. Print analytics: class distribution, cost summary, security findings,
     compliance coverage, and top-N breakdowns

Usage:
    # Generate + process + export (default)
    python demo_pipeline.py

    # Load previously generated events
    python demo_pipeline.py --input synthetic_events.jsonl

    # Custom output
    python demo_pipeline.py --output /tmp/aitf_ocsf_export.jsonl

    # Reproducible with a specific seed
    python demo_pipeline.py --seed 42

Requirements:
    pip install opentelemetry-api opentelemetry-sdk pydantic

    The script adds the SDK source to sys.path so it can be run directly
    from the examples/synthetic-telemetry/ directory without installing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup — allow running without installing the SDK package
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SDK_SRC = _REPO_ROOT / "sdk" / "python" / "src"
if _SDK_SRC.is_dir():
    sys.path.insert(0, str(_SDK_SRC))

# ---------------------------------------------------------------------------
# OpenTelemetry imports
# ---------------------------------------------------------------------------
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExportResult,
)

# ---------------------------------------------------------------------------
# AITF SDK imports
# ---------------------------------------------------------------------------
from aitf.instrumentation.llm import LLMInstrumentor
from aitf.instrumentation.agent import AgentInstrumentor
from aitf.instrumentation.mcp import MCPInstrumentor
from aitf.instrumentation.rag import RAGInstrumentor
from aitf.instrumentation.skills import SkillInstrumentor
from aitf.processors.security_processor import SecurityProcessor
from aitf.processors.pii_processor import PIIProcessor
from aitf.processors.cost_processor import CostProcessor
from aitf.processors.compliance_processor import ComplianceProcessor
from aitf.exporters.ocsf_exporter import OCSFExporter
from aitf.ocsf.schema import (
    AIBaseEvent,
    AIClassUID,
    AIModelInfo,
    AITokenUsage,
    AILatencyMetrics,
    AICostInfo,
    AISecurityFinding,
    AITeamInfo,
    OCSFSeverity,
)
from aitf.ocsf.event_classes import (
    AIModelInferenceEvent,
    AIAgentActivityEvent,
    AIToolExecutionEvent,
    AIDataRetrievalEvent,
    AISecurityFindingEvent,
    AISupplyChainEvent,
    AIGovernanceEvent,
    AIIdentityEvent,
)
from aitf.ocsf.compliance_mapper import ComplianceMapper

# ---------------------------------------------------------------------------
# Synthetic generator import
# ---------------------------------------------------------------------------
from generate_synthetic_events import generate_events, strip_none

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ALL_FRAMEWORKS = [
    "nist_ai_rmf", "mitre_atlas", "iso_42001",
    "eu_ai_act", "soc2", "gdpr", "ccpa",
]

SEVERITY_NAMES = {
    0: "Unknown", 1: "Info", 2: "Low", 3: "Medium",
    4: "High", 5: "Critical", 6: "Fatal",
}

# Under OCSF class reuse, class_uid is no longer unique per AITF event type
# (e.g. Model Inference and Tool Execution both reuse API Activity 6003).
# Events are therefore grouped by AITF event type, derived from the reused
# class_uid plus a discriminating AI field, rather than by class_uid alone.
EVENT_TYPE_LABELS = {
    "model_inference": "Model Inference (API Activity 6003)",
    "agent_activity": "Agent Activity (agent_activity 9001)",
    "tool_execution": "Tool Execution (API Activity 6003)",
    "data_retrieval": "Data Retrieval (Datastore Activity 6005)",
    "security_finding": "Security Finding (Detection Finding 2004)",
    "supply_chain": "Supply Chain (Vulnerability Finding 2002)",
    "governance": "Governance (Compliance Finding 2003)",
    "identity": "Identity (Authentication 3002)",
}


def classify_event_type(evt: dict) -> str:
    """Map a reused-class OCSF event back to its AITF event type.

    class_uid alone is ambiguous under class reuse, so 6003 (API Activity)
    is disambiguated via the AI fields present on the event: inference events
    carry ``model``/``token_usage``; tool events carry ``tool_name``.
    """
    cuid = evt.get("class_uid")
    if cuid == 6003:
        if "tool_name" in evt:
            return "tool_execution"
        return "model_inference"
    return {
        9001: "agent_activity",
        6005: "data_retrieval",
        2004: "security_finding",
        2002: "supply_chain",
        2003: "governance",
        3002: "identity",
    }.get(cuid, "unknown")


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1 — Set up the full AITF pipeline
# ═══════════════════════════════════════════════════════════════════════════

def setup_pipeline(output_file: str) -> tuple[TracerProvider, OCSFExporter]:
    """Configure OTel TracerProvider with all AITF processors and exporters."""
    resource = Resource.create({
        "service.name": "aitf-demo-pipeline",
        "service.version": "1.0.0",
        "deployment.environment": "demo",
    })

    provider = TracerProvider(resource=resource)

    # --- Add AITF Processors (SpanProcessors) ---
    security_proc = SecurityProcessor(
        detect_prompt_injection=True,
        detect_jailbreak=True,
        detect_data_exfiltration=True,
        owasp_checks=True,
    )
    provider.add_span_processor(security_proc)

    pii_proc = PIIProcessor(
        detect_types=["email", "ssn", "credit_card", "api_key", "phone", "ip_address"],
        action="flag",
    )
    provider.add_span_processor(pii_proc)

    cost_proc = CostProcessor(budget_limit=500.0)
    provider.add_span_processor(cost_proc)

    compliance_proc = ComplianceProcessor(frameworks=ALL_FRAMEWORKS)
    provider.add_span_processor(compliance_proc)

    # --- Add OCSF Exporter ---
    ocsf_exporter = OCSFExporter(
        output_file=output_file,
        compliance_frameworks=ALL_FRAMEWORKS,
    )
    provider.add_span_processor(SimpleSpanProcessor(ocsf_exporter))

    # Set as global tracer provider
    trace.set_tracer_provider(provider)

    return provider, ocsf_exporter


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2 — Replay synthetic events through SDK instrumentors
# ═══════════════════════════════════════════════════════════════════════════

def replay_inference_events(events: list[dict], llm: LLMInstrumentor) -> int:
    """Replay Model Inference events (API Activity 6003) through LLMInstrumentor."""
    count = 0
    for evt in events:
        model_info = evt.get("model", {})
        model_id = model_info.get("model_id", "unknown")
        provider = model_info.get("provider", "unknown")
        params = model_info.get("parameters") or {}

        operation = "chat"
        if evt.get("activity_id") == 3:
            operation = "embeddings"
        elif evt.get("activity_id") == 2:
            operation = "text_completion"

        with llm.trace_inference(
            model=model_id,
            operation=operation,
            system=provider,
            temperature=params.get("temperature"),
            max_tokens=params.get("max_tokens"),
            stream=evt.get("streaming", False),
        ) as span:
            # Set prompt/completion
            if evt.get("request_content"):
                span.set_prompt(evt["request_content"])
            if evt.get("response_content"):
                span.set_completion(evt["response_content"])

            # Set token usage
            usage = evt.get("token_usage", {})
            span.set_usage(
                input_tokens=usage.get("input_tokens", 0),
                output_tokens=usage.get("output_tokens", 0),
                cached_tokens=usage.get("cached_tokens", 0),
                reasoning_tokens=usage.get("reasoning_tokens", 0),
            )

            # Set cost
            cost = evt.get("cost")
            if cost:
                span.set_cost(
                    input_cost=cost.get("input_cost_usd", 0.0),
                    output_cost=cost.get("output_cost_usd", 0.0),
                    total_cost=cost.get("total_cost_usd"),
                )

            # Set latency
            latency = evt.get("latency")
            if latency:
                span.set_latency(
                    total_ms=latency.get("total_ms"),
                    tokens_per_second=latency.get("tokens_per_second"),
                )
                if latency.get("time_to_first_token_ms") and evt.get("streaming"):
                    span.mark_first_token()

            # Set security on high-severity events
            if evt.get("severity_id", 1) >= 3:
                span.set_security(
                    risk_score=float(evt.get("severity_id", 1)) * 20,
                    risk_level="high" if evt.get("severity_id", 1) >= 4 else "medium",
                )

            # Set response
            span.set_response(
                finish_reasons=[evt.get("finish_reason", "stop")],
            )

        count += 1
    return count


def replay_agent_events(events: list[dict], agent_inst: AgentInstrumentor) -> int:
    """Replay Agent Activity events (agent_activity 9001) through AgentInstrumentor."""
    count = 0
    for evt in events:
        agent_name = evt.get("agent_name", "unknown")
        framework = evt.get("framework")
        activity = evt.get("activity_id", 3)

        if activity in (1, 2):
            # Session start/end — trace as session
            with agent_inst.trace_session(
                agent_name=agent_name,
                framework=framework,
            ) as session:
                pass
        elif activity == 4:
            # Delegation
            with agent_inst.trace_session(
                agent_name=agent_name,
                framework=framework,
            ) as session:
                target = evt.get("delegation_target", "unknown-agent")
                with session.delegate(target_agent=target, task="delegated task"):
                    pass
        else:
            # Step execution
            with agent_inst.trace_session(
                agent_name=agent_name,
                framework=framework,
            ) as session:
                step_type = evt.get("step_type", "act")
                step_index = evt.get("step_index", 0)
                with session.step(step_type=step_type, index=step_index) as step:
                    if evt.get("thought"):
                        step.set_thought(evt["thought"])
                    if evt.get("action"):
                        step.set_action(evt["action"])
                    if evt.get("observation"):
                        step.set_observation(evt["observation"])

        count += 1
    return count


def replay_tool_events(events: list[dict], mcp_inst: MCPInstrumentor, skill_inst: SkillInstrumentor) -> int:
    """Replay Tool Execution events (API Activity 6003) through MCP/Skills instrumentors."""
    count = 0
    for evt in events:
        tool_type = evt.get("tool_type", "function")

        if tool_type == "mcp_tool":
            server = evt.get("mcp_server", "unknown-server")
            with mcp_inst.trace_tool_invoke(
                tool_name=evt.get("tool_name", "unknown"),
                server=server,
            ) as invocation:
                if evt.get("tool_output") and not evt.get("is_error"):
                    invocation.set_output(evt["tool_output"])
                if evt.get("is_error"):
                    invocation.set_error(evt.get("tool_output", "Error"))
                if evt.get("approved") is not None:
                    invocation.set_approved(evt["approved"])

        elif tool_type == "skill":
            with skill_inst.trace_invoke(
                skill_name=evt.get("tool_name", "unknown"),
                version=evt.get("skill_version", "1.0"),
                category=evt.get("skill_category"),
            ) as invocation:
                if evt.get("tool_output"):
                    invocation.set_output(evt["tool_output"])
                invocation.set_status("error" if evt.get("is_error") else "success")

        else:
            # Plain function call — trace as MCP tool with function marker
            with mcp_inst.trace_tool_invoke(
                tool_name=evt.get("tool_name", "unknown"),
                server="local",
            ) as invocation:
                if evt.get("tool_output") and not evt.get("is_error"):
                    invocation.set_output(evt["tool_output"])
                if evt.get("is_error"):
                    invocation.set_error(evt.get("tool_output", "Error"))

        count += 1
    return count


def replay_rag_events(events: list[dict], rag_inst: RAGInstrumentor) -> int:
    """Replay Data Retrieval events (Datastore Activity 6005) through RAGInstrumentor."""
    count = 0
    for evt in events:
        pipeline_name = evt.get("pipeline_name", "default-rag")
        stage = evt.get("pipeline_stage", "retrieve")

        with rag_inst.trace_pipeline(pipeline_name=pipeline_name) as pipeline:
            if stage == "rerank":
                with pipeline.rerank(
                    model="cross-encoder",
                    top_k=evt.get("top_k", 10),
                ) as rerank:
                    rerank.set_results(
                        count=evt.get("results_count", 0),
                        min_score=evt.get("min_score"),
                        max_score=evt.get("max_score"),
                    )
            else:
                with pipeline.retrieve(
                    database=evt.get("database_name", "unknown"),
                    top_k=evt.get("top_k", 10),
                    query=evt.get("query"),
                ) as retrieve:
                    retrieve.set_results(
                        count=evt.get("results_count", 0),
                        min_score=evt.get("min_score"),
                        max_score=evt.get("max_score"),
                    )

            quality = evt.get("quality_scores")
            if quality:
                pipeline.set_quality(**quality)

        count += 1
    return count


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3 — Direct OCSF event generation for classes without instrumentors
# ═══════════════════════════════════════════════════════════════════════════

def generate_ocsf_events_direct(
    events_by_type: dict[str, list[dict]],
    compliance_mapper: ComplianceMapper,
) -> list[dict]:
    """Generate OCSF events directly for the finding/identity AITF event types.

    These AITF event types — Security Finding (Detection Finding 2004),
    Supply Chain (Vulnerability Finding 2002), Governance (Compliance
    Finding 2003), Identity (Authentication 3002) — are typically produced by
    processors or external systems, not by span-based instrumentors.
    """
    ocsf_events: list[dict] = []

    # security_finding — Detection Finding (2004)
    for evt in events_by_type.get("security_finding", []):
        finding_data = evt.get("finding", {})
        ocsf = AISecurityFindingEvent(
            activity_id=evt.get("activity_id", 1),
            severity_id=evt.get("severity_id", 3),
            status_id=evt.get("status_id", 1),
            message=evt.get("message", ""),
            time=evt.get("time", datetime.now(timezone.utc).isoformat()),
            finding=AISecurityFinding(
                finding_type=finding_data.get("finding_type", "unknown"),
                owasp_category=finding_data.get("owasp_category"),
                risk_level=finding_data.get("risk_level", "medium"),
                risk_score=finding_data.get("risk_score", 50.0),
                confidence=finding_data.get("confidence", 0.5),
                detection_method=finding_data.get("detection_method", "pattern"),
                blocked=finding_data.get("blocked", False),
                details=finding_data.get("details"),
                pii_types=finding_data.get("pii_types", []),
                matched_patterns=finding_data.get("matched_patterns", []),
                remediation=finding_data.get("remediation"),
            ),
        )
        compliance_mapper.enrich_event(ocsf, "security_finding")
        ocsf_events.append(ocsf.model_dump(exclude_none=True))

    # supply_chain — Vulnerability Finding (2002)
    for evt in events_by_type.get("supply_chain", []):
        ocsf = AISupplyChainEvent(
            activity_id=evt.get("activity_id", 1),
            severity_id=evt.get("severity_id", 1),
            status_id=evt.get("status_id", 1),
            message=evt.get("message", ""),
            time=evt.get("time", datetime.now(timezone.utc).isoformat()),
            model_source=evt.get("model_source", "unknown"),
            model_hash=evt.get("model_hash"),
            model_license=evt.get("model_license"),
            model_signed=evt.get("model_signed", False),
            model_signer=evt.get("model_signer"),
            verification_result=evt.get("verification_result"),
            ai_bom_id=evt.get("ai_bom_id"),
            ai_bom_components=evt.get("ai_bom_components"),
        )
        compliance_mapper.enrich_event(ocsf, "supply_chain")
        ocsf_events.append(ocsf.model_dump(exclude_none=True))

    # governance — Compliance Finding (2003)
    for evt in events_by_type.get("governance", []):
        ocsf = AIGovernanceEvent(
            activity_id=evt.get("activity_id", 99),
            severity_id=evt.get("severity_id", 1),
            status_id=evt.get("status_id", 1),
            message=evt.get("message", ""),
            time=evt.get("time", datetime.now(timezone.utc).isoformat()),
            frameworks=evt.get("frameworks", []),
            controls=evt.get("controls"),
            event_type=evt.get("event_type", ""),
            violation_detected=evt.get("violation_detected", False),
            violation_severity=evt.get("violation_severity"),
            remediation=evt.get("remediation"),
            audit_id=evt.get("audit_id"),
        )
        compliance_mapper.enrich_event(ocsf, "governance")
        ocsf_events.append(ocsf.model_dump(exclude_none=True))

    # identity — Authentication (3002)
    for evt in events_by_type.get("identity", []):
        ocsf = AIIdentityEvent(
            activity_id=evt.get("activity_id", 1),
            severity_id=evt.get("severity_id", 1),
            status_id=evt.get("status_id", 1),
            message=evt.get("message", ""),
            time=evt.get("time", datetime.now(timezone.utc).isoformat()),
            agent_name=evt.get("agent_name", "unknown"),
            agent_id=evt.get("agent_id", "unknown"),
            auth_method=evt.get("auth_method", "api_key"),
            auth_result=evt.get("auth_result", "success"),
            permissions=evt.get("permissions", []),
            credential_type=evt.get("credential_type"),
            delegation_chain=evt.get("delegation_chain", []),
            scope=evt.get("scope"),
        )
        compliance_mapper.enrich_event(ocsf, "identity")
        ocsf_events.append(ocsf.model_dump(exclude_none=True))

    return ocsf_events


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4 — Analytics and reporting
# ═══════════════════════════════════════════════════════════════════════════

def print_analytics(
    all_events: list[dict],
    ocsf_direct: list[dict],
    replay_counts: dict[str, int],
    ocsf_exporter: OCSFExporter,
    elapsed: float,
) -> None:
    """Print comprehensive pipeline analytics."""

    W = 72
    print("\n" + "═" * W)
    print("  AITF Demo Pipeline — Results")
    print("═" * W)

    # --- Overview ---
    total = len(all_events)
    print(f"\n  Total synthetic events:    {total}")
    print(f"  Pipeline execution time:   {elapsed:.2f}s")
    print(f"  Events/second:             {total / elapsed:,.0f}")
    print(f"  OCSF events from spans:    {ocsf_exporter.event_count}")
    print(f"  OCSF events direct:        {len(ocsf_direct)}")
    print(f"  Total OCSF events:         {ocsf_exporter.event_count + len(ocsf_direct)}")

    # --- AITF event-type distribution ---
    # Under OCSF class reuse, class_uid is no longer unique per AITF event type
    # (inference and tool execution both reuse API Activity 6003), so we report
    # the distribution by AITF event type.
    type_counts = Counter(classify_event_type(e) for e in all_events)
    print(f"\n  {'─' * 62}")
    print(f"  AITF Event Type Distribution (reused OCSF class):")
    print(f"  {'─' * 62}")
    print(f"  {'Event Type':<40s}  {'Count':>5s}  {'Replayed':>8s}")
    print(f"  {'─' * 62}")
    for etype in sorted(type_counts):
        name = EVENT_TYPE_LABELS.get(etype, etype)
        cnt = type_counts[etype]
        replayed = replay_counts.get(etype, 0)
        print(f"  {name:<40s}  {cnt:>5d}  {replayed:>8d}")
    print(f"  {'─' * 62}")
    print(f"  {'Total':<40s}  {total:>5d}  {sum(replay_counts.values()):>8d}")

    # --- Severity distribution ---
    sev_counts = Counter(e.get("severity_id", 0) for e in all_events)
    print(f"\n  {'─' * 40}")
    print(f"  Severity Distribution:")
    print(f"  {'─' * 40}")
    for sid in sorted(sev_counts):
        name = SEVERITY_NAMES.get(sid, f"({sid})")
        cnt = sev_counts[sid]
        pct = cnt / total * 100
        print(f"  {name:<12s}  {cnt:>5d}  ({pct:5.1f}%)")

    # --- Cost summary (from Model Inference / API Activity 6003 events) ---
    inference_events = [e for e in all_events if classify_event_type(e) == "model_inference"]
    total_cost = sum(
        e.get("cost", {}).get("total_cost_usd", 0.0)
        for e in inference_events
        if isinstance(e.get("cost"), dict)
    )
    total_input_tokens = sum(
        e.get("token_usage", {}).get("input_tokens", 0)
        for e in inference_events
    )
    total_output_tokens = sum(
        e.get("token_usage", {}).get("output_tokens", 0)
        for e in inference_events
    )

    print(f"\n  {'─' * 50}")
    print(f"  Cost & Token Summary (Model Inference only):")
    print(f"  {'─' * 50}")
    print(f"  Total inference requests:  {len(inference_events)}")
    print(f"  Total input tokens:        {total_input_tokens:>12,d}")
    print(f"  Total output tokens:       {total_output_tokens:>12,d}")
    print(f"  Total tokens:              {total_input_tokens + total_output_tokens:>12,d}")
    print(f"  Total estimated cost:      ${total_cost:>12,.4f} USD")
    if inference_events:
        print(f"  Avg cost per request:      ${total_cost / len(inference_events):>12,.6f} USD")

    # --- Cost by model ---
    model_costs: dict[str, dict] = defaultdict(lambda: {"count": 0, "cost": 0.0, "tokens": 0})
    for e in inference_events:
        mid = e.get("model", {}).get("model_id", "unknown")
        mc = model_costs[mid]
        mc["count"] += 1
        mc["cost"] += e.get("cost", {}).get("total_cost_usd", 0.0) if isinstance(e.get("cost"), dict) else 0.0
        mc["tokens"] += e.get("token_usage", {}).get("total_tokens", 0)

    print(f"\n  Top Models by Cost:")
    print(f"  {'─' * 60}")
    print(f"  {'Model':<30s}  {'Requests':>8s}  {'Tokens':>10s}  {'Cost':>10s}")
    print(f"  {'─' * 60}")
    for mid, mc in sorted(model_costs.items(), key=lambda x: x[1]["cost"], reverse=True)[:8]:
        print(f"  {mid:<30s}  {mc['count']:>8d}  {mc['tokens']:>10,d}  ${mc['cost']:>9,.4f}")

    # --- Security findings (Detection Finding 2004) ---
    security_events = [e for e in all_events if classify_event_type(e) == "security_finding"]
    if security_events:
        finding_types = Counter(
            e.get("finding", {}).get("finding_type", "unknown")
            for e in security_events
        )
        blocked_count = sum(1 for e in security_events if e.get("finding", {}).get("blocked"))

        print(f"\n  {'─' * 50}")
        print(f"  Security Findings:")
        print(f"  {'─' * 50}")
        print(f"  Total findings:   {len(security_events)}")
        print(f"  Blocked:          {blocked_count} ({blocked_count/len(security_events)*100:.0f}%)")
        print(f"\n  By Type:")
        for ftype, cnt in finding_types.most_common():
            print(f"    {ftype:<25s}  {cnt:>4d}")

        owasp_counts = Counter(
            e.get("finding", {}).get("owasp_category", "N/A")
            for e in security_events
        )
        print(f"\n  By OWASP Category:")
        for cat, cnt in owasp_counts.most_common():
            print(f"    {cat:<10s}  {cnt:>4d}")

    # --- Agent activity (agent_activity 9001) ---
    agent_events = [e for e in all_events if classify_event_type(e) == "agent_activity"]
    if agent_events:
        agent_names = Counter(e.get("agent_name", "unknown") for e in agent_events)
        frameworks = Counter(e.get("framework", "unknown") for e in agent_events)
        delegation_count = sum(1 for e in agent_events if e.get("delegation_target"))
        team_count = sum(1 for e in agent_events if e.get("team_info"))

        print(f"\n  {'─' * 50}")
        print(f"  Agent Activity:")
        print(f"  {'─' * 50}")
        print(f"  Total agent events:  {len(agent_events)}")
        print(f"  Delegations:         {delegation_count}")
        print(f"  Team orchestrations: {team_count}")
        print(f"\n  By Agent:")
        for name, cnt in agent_names.most_common():
            print(f"    {name:<20s}  {cnt:>4d}")
        print(f"\n  By Framework:")
        for fw, cnt in frameworks.most_common():
            print(f"    {fw:<15s}  {cnt:>4d}")

    # --- Tool execution (API Activity 6003) ---
    tool_events = [e for e in all_events if classify_event_type(e) == "tool_execution"]
    if tool_events:
        tool_types = Counter(e.get("tool_type", "unknown") for e in tool_events)
        tool_names = Counter(e.get("tool_name", "unknown") for e in tool_events)
        error_count = sum(1 for e in tool_events if e.get("is_error"))

        print(f"\n  {'─' * 50}")
        print(f"  Tool Execution:")
        print(f"  {'─' * 50}")
        print(f"  Total tool events:  {len(tool_events)}")
        print(f"  Errors:             {error_count} ({error_count/len(tool_events)*100:.0f}%)")
        print(f"\n  By Type:")
        for tt, cnt in tool_types.most_common():
            print(f"    {tt:<15s}  {cnt:>4d}")
        print(f"\n  Top Tools:")
        for tn, cnt in tool_names.most_common(8):
            print(f"    {tn:<25s}  {cnt:>4d}")

    # --- Identity (Authentication 3002) ---
    identity_events = [e for e in all_events if classify_event_type(e) == "identity"]
    if identity_events:
        auth_results = Counter(e.get("auth_result", "unknown") for e in identity_events)
        auth_methods = Counter(e.get("auth_method", "unknown") for e in identity_events)

        print(f"\n  {'─' * 50}")
        print(f"  Identity & Authentication:")
        print(f"  {'─' * 50}")
        print(f"  Total identity events:  {len(identity_events)}")
        print(f"\n  Auth Results:")
        for res, cnt in auth_results.most_common():
            print(f"    {res:<12s}  {cnt:>4d}")
        print(f"\n  Auth Methods:")
        for meth, cnt in auth_methods.most_common():
            print(f"    {meth:<12s}  {cnt:>4d}")

    # --- Compliance coverage ---
    compliance_mapper = ComplianceMapper(frameworks=ALL_FRAMEWORKS)
    coverage = compliance_mapper.get_coverage_matrix()
    print(f"\n  {'─' * 60}")
    print(f"  Compliance Coverage Matrix:")
    print(f"  {'─' * 60}")
    print(f"  {'Event Type':<20s}  {'Frameworks Mapped':>17s}  {'Controls':>8s}")
    print(f"  {'─' * 60}")
    for evt_type, frameworks_map in sorted(coverage.items()):
        fw_count = len(frameworks_map)
        ctrl_count = sum(len(ctrls) for ctrls in frameworks_map.values())
        print(f"  {evt_type:<20s}  {fw_count:>17d}  {ctrl_count:>8d}")

    # --- Supply chain (Vulnerability Finding 2002) ---
    sc_events = [e for e in all_events if classify_event_type(e) == "supply_chain"]
    if sc_events:
        verification_results = Counter(e.get("verification_result", "unknown") for e in sc_events)
        signed_count = sum(1 for e in sc_events if e.get("model_signed"))

        print(f"\n  {'─' * 50}")
        print(f"  Supply Chain:")
        print(f"  {'─' * 50}")
        print(f"  Total events:    {len(sc_events)}")
        print(f"  Models signed:   {signed_count} ({signed_count/len(sc_events)*100:.0f}%)")
        print(f"\n  Verification Results:")
        for res, cnt in verification_results.most_common():
            print(f"    {res:<12s}  {cnt:>4d}")

    print(f"\n{'═' * W}")
    print(f"  Pipeline complete.")
    print(f"{'═' * W}\n")


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AITF Demo Pipeline — Process 1000 synthetic events through the Python SDK",
    )
    parser.add_argument(
        "--input", "-i",
        help="Load events from JSONL file instead of generating",
    )
    parser.add_argument(
        "--output", "-o",
        default="aitf_ocsf_export.jsonl",
        help="OCSF export output file (default: aitf_ocsf_export.jsonl)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for event generation (default: 42)",
    )
    args = parser.parse_args()

    # ── Step 1: Load or generate events ──
    print("\n[1/4] Generating synthetic events...")
    if args.input:
        with open(args.input) as f:
            all_events = [json.loads(line) for line in f if line.strip()]
        print(f"  Loaded {len(all_events)} events from {args.input}")
    else:
        all_events = [strip_none(e) for e in generate_events(seed=args.seed)]
        print(f"  Generated {len(all_events)} events (seed={args.seed})")

    # Group by AITF event type (class_uid is not unique per type under reuse)
    events_by_type: dict[str, list[dict]] = defaultdict(list)
    for e in all_events:
        events_by_type[classify_event_type(e)].append(e)

    for etype in sorted(events_by_type):
        name = EVENT_TYPE_LABELS.get(etype, etype)
        print(f"    {name}: {len(events_by_type[etype])} events")

    # ── Step 2: Set up pipeline ──
    print(f"\n[2/4] Setting up AITF pipeline...")

    # Clean output file
    output_path = Path(args.output)
    if output_path.exists():
        output_path.unlink()

    provider, ocsf_exporter = setup_pipeline(args.output)
    print(f"  Processors: Security, PII, Cost, Compliance")
    print(f"  Exporter:   OCSF → {args.output}")
    print(f"  Frameworks: {', '.join(ALL_FRAMEWORKS)}")

    # ── Step 3: Replay through instrumentors ──
    print(f"\n[3/4] Replaying events through SDK instrumentors...")
    start_time = time.monotonic()

    # Initialize instrumentors
    llm_inst = LLMInstrumentor(tracer_provider=provider)
    llm_inst.instrument()

    agent_inst = AgentInstrumentor(tracer_provider=provider)
    agent_inst.instrument()

    mcp_inst = MCPInstrumentor(tracer_provider=provider)
    mcp_inst.instrument()

    rag_inst = RAGInstrumentor(tracer_provider=provider)
    rag_inst.instrument()

    skill_inst = SkillInstrumentor(tracer_provider=provider)
    skill_inst.instrument()

    replay_counts: dict[str, int] = {}

    # Model Inference — API Activity 6003
    cnt = replay_inference_events(events_by_type.get("model_inference", []), llm_inst)
    replay_counts["model_inference"] = cnt
    print(f"    Model Inference (6003):  {cnt} events replayed")

    # Agent Activity — agent_activity 9001
    cnt = replay_agent_events(events_by_type.get("agent_activity", []), agent_inst)
    replay_counts["agent_activity"] = cnt
    print(f"    Agent Activity (9001):   {cnt} events replayed")

    # Tool Execution — API Activity 6003
    cnt = replay_tool_events(events_by_type.get("tool_execution", []), mcp_inst, skill_inst)
    replay_counts["tool_execution"] = cnt
    print(f"    Tool Execution (6003):   {cnt} events replayed")

    # Data Retrieval — Datastore Activity 6005
    cnt = replay_rag_events(events_by_type.get("data_retrieval", []), rag_inst)
    replay_counts["data_retrieval"] = cnt
    print(f"    Data Retrieval (6005):   {cnt} events replayed")

    # Finding/identity types — direct OCSF generation (no instrumentor)
    compliance_mapper = ComplianceMapper(frameworks=ALL_FRAMEWORKS)
    ocsf_direct = generate_ocsf_events_direct(events_by_type, compliance_mapper)
    for etype in ("security_finding", "supply_chain", "governance", "identity"):
        cnt = len(events_by_type.get(etype, []))
        replay_counts[etype] = cnt
        print(f"    {EVENT_TYPE_LABELS.get(etype, etype):<44s}  {cnt} events (direct OCSF)")

    # Flush the pipeline
    provider.force_flush()

    # Write direct OCSF events to the same output file
    if ocsf_direct:
        with open(args.output, "a") as f:
            for event in ocsf_direct:
                f.write(json.dumps(event, default=str) + "\n")

    elapsed = time.monotonic() - start_time

    # ── Step 4: Analytics ──
    print(f"\n[4/4] Computing analytics...")
    print_analytics(all_events, ocsf_direct, replay_counts, ocsf_exporter, elapsed)

    # Final output info
    if output_path.exists():
        size_kb = output_path.stat().st_size / 1024
        line_count = sum(1 for _ in open(args.output))
        print(f"  Output: {args.output}")
        print(f"  Size:   {size_kb:,.1f} KB")
        print(f"  Lines:  {line_count:,d} OCSF events\n")

    # Shutdown
    provider.shutdown()


if __name__ == "__main__":
    main()
