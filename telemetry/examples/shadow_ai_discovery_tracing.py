"""AITF Example: Shadow AI Discovery Tracing.

Demonstrates what a shadow AI discovery tool — such as AIDisco
(https://github.com/girdav01/AIDisco) — should emit when its scan results
are translated into AITF telemetry.

AIDisco scans endpoints for local LLM installations (Ollama, LM Studio,
GPT4All, vLLM, Cursor, Copilot, Open WebUI, Docker AI containers, etc.)
and produces a JSON results file.  This example shows how to convert those
results into the correct AITF OpenTelemetry spans **and** OCSF events so
they flow natively into SIEM/XDR pipelines.

Telemetry generated:
  ┌─────────────────────────────────────────────────────────────────────┐
  │  asset.discover (root span)                                        │
  │  ├── asset.register  (per discovered asset — known)                │
  │  ├── asset.register  (per discovered asset — shadow)               │
  │  │   └── asset.classify  (EU AI Act risk classification)           │
  │  └── asset.audit     (integrity / compliance check per asset)      │
  └─────────────────────────────────────────────────────────────────────┘

OCSF events emitted:
  701002  Asset Discovery       – scan summary
  701001  Asset Registration    – per asset
  701007  Shadow Asset Detected – per unregistered asset
  701004  Risk Classification   – when risk is assessed
  701003  Asset Audit           – per asset audit

All spans are exportable as both OTel traces (OTLP → Jaeger/Tempo) and
OCSF security events (→ SIEM/XDR).  See ``dual_pipeline_tracing.py``
for dual-pipeline setup.
"""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

from aitf.instrumentation.asset_inventory import AssetInventoryInstrumentor
from aitf.exporters.ocsf_exporter import OCSFExporter

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
provider.add_span_processor(SimpleSpanProcessor(OCSFExporter(
    output_file="/tmp/aitf_shadow_ai_events.jsonl",
    compliance_frameworks=["nist_ai_rmf", "eu_ai_act", "mitre_atlas"],
)))
trace.set_tracer_provider(provider)

asset_inv = AssetInventoryInstrumentor(tracer_provider=provider)
asset_inv.instrument()

# ---------------------------------------------------------------------------
# Simulated AIDisco scan results
# ---------------------------------------------------------------------------
# In production, this would be read from AIDisco's JSON output file.  The
# structure below mirrors AIDisco's actual detection categories.

AIDISCO_SCAN_RESULTS: list[dict[str, Any]] = [
    # ── Known / sanctioned installations ──────────────────────────────
    {
        "software": "GitHub Copilot",
        "category": "ide_extension",
        "detection_method": "file_scan",
        "version": "1.234.0",
        "install_path": "/home/dev/.vscode/extensions/github.copilot-1.234.0",
        "hostname": "dev-workstation-042",
        "os": "linux",
        "registered": True,          # already in corporate inventory
        "pid": None,
        "port": None,
    },
    {
        "software": "Cursor",
        "category": "ide",
        "detection_method": "process_scan",
        "version": "0.48.7",
        "install_path": "/opt/cursor/cursor",
        "hostname": "dev-workstation-042",
        "os": "linux",
        "registered": True,
        "pid": 12881,
        "port": None,
    },
    # ── Shadow / unregistered installations ───────────────────────────
    {
        "software": "Ollama",
        "category": "local_inference",
        "detection_method": "process_scan",
        "version": "0.5.4",
        "install_path": "/usr/local/bin/ollama",
        "hostname": "dev-workstation-042",
        "os": "linux",
        "registered": False,         # SHADOW AI
        "pid": 4419,
        "port": 11434,
    },
    {
        "software": "Open WebUI",
        "category": "chat_ui",
        "detection_method": "container_scan",
        "version": "0.5.16",
        "install_path": None,
        "hostname": "dev-workstation-042",
        "os": "linux",
        "registered": False,         # SHADOW AI
        "container_id": "a1b2c3d4e5f6",
        "container_image": "ghcr.io/open-webui/open-webui:main",
        "pid": None,
        "port": 3000,
    },
    {
        "software": "LM Studio",
        "category": "local_inference",
        "detection_method": "file_scan",
        "version": "0.3.8",
        "install_path": "/home/dev/.lmstudio",
        "hostname": "dev-workstation-042",
        "os": "linux",
        "registered": False,         # SHADOW AI
        "pid": None,
        "port": None,
    },
    {
        "software": "text-generation-webui",
        "category": "local_inference",
        "detection_method": "container_scan",
        "version": "latest",
        "install_path": None,
        "hostname": "dev-workstation-042",
        "os": "linux",
        "registered": False,         # SHADOW AI
        "container_id": "f6e5d4c3b2a1",
        "container_image": "atinoda/text-generation-webui:latest",
        "pid": None,
        "port": 7860,
    },
    {
        "software": "n8n",
        "category": "workflow_automation",
        "detection_method": "container_scan",
        "version": "1.76.1",
        "install_path": None,
        "hostname": "dev-workstation-042",
        "os": "linux",
        "registered": False,         # SHADOW AI
        "container_id": "1a2b3c4d5e6f",
        "container_image": "n8nio/n8n:1.76.1",
        "pid": None,
        "port": 5678,
    },
]


# ---------------------------------------------------------------------------
# Helper: map AIDisco category → AITF asset type
# ---------------------------------------------------------------------------

_CATEGORY_TO_ASSET_TYPE = {
    "local_inference": "model",
    "ide_extension": "agent",
    "ide": "agent",
    "chat_ui": "pipeline",
    "workflow_automation": "pipeline",
    "discord_bot": "agent",
    "container": "pipeline",
}

_CATEGORY_TO_RISK = {
    # Local inference can process data outside corporate controls
    "local_inference": "high_risk",
    # IDE assistants see source code — moderate risk
    "ide_extension": "limited_risk",
    "ide": "limited_risk",
    # Chat UIs may expose data to local models
    "chat_ui": "high_risk",
    # Workflow automation can trigger actions
    "workflow_automation": "high_risk",
}


def _asset_id(result: dict[str, Any]) -> str:
    """Deterministic asset ID from hostname + software + version."""
    key = f"{result['hostname']}:{result['software']}:{result.get('version', 'unknown')}"
    return f"aidisco-{hashlib.sha256(key.encode()).hexdigest()[:16]}"


def _discovery_method_to_aitf(method: str) -> str:
    """Map AIDisco detection method to AITF discovery method."""
    return {
        "file_scan": "api_scan",
        "process_scan": "api_scan",
        "container_scan": "api_scan",
        "registry_scan": "registry_sync",
        "network_scan": "network_scan",
        "sigma_rule": "log_analysis",
        "env_var": "api_scan",
    }.get(method, "api_scan")


# ---------------------------------------------------------------------------
# Step 1 — Discovery scan span (the root operation)
# ---------------------------------------------------------------------------

print("=" * 72)
print("Shadow AI Discovery → AITF Telemetry")
print("=" * 72)

shadow_results = [r for r in AIDISCO_SCAN_RESULTS if not r["registered"]]
known_results  = [r for r in AIDISCO_SCAN_RESULTS if r["registered"]]

with asset_inv.trace_discover(
    scope="environment",
    method="api_scan",           # AIDisco uses file/process/container scans
) as discovery:

    # Populate discovery summary
    discovery.set_results(
        assets_found=len(AIDISCO_SCAN_RESULTS),
        new_assets=len(shadow_results),
        shadow_assets=len(shadow_results),
    )
    discovery.set_status("completed")

    # ------------------------------------------------------------------
    # Step 2 — Register each discovered asset
    # ------------------------------------------------------------------

    for result in AIDISCO_SCAN_RESULTS:
        aid    = _asset_id(result)
        atype  = _CATEGORY_TO_ASSET_TYPE.get(result["category"], "pipeline")
        env    = "shadow" if not result["registered"] else "production"
        risk   = _CATEGORY_TO_RISK.get(result["category"], "not_classified")

        tags = [
            f"aidisco:{result['category']}",
            f"hostname:{result['hostname']}",
            f"os:{result['os']}",
        ]
        if result.get("port"):
            tags.append(f"port:{result['port']}")
        if result.get("container_id"):
            tags.append(f"container:{result['container_id'][:12]}")

        with asset_inv.trace_register(
            asset_id=aid,
            asset_name=result["software"],
            asset_type=atype,
            version=result.get("version"),
            owner="unassigned" if not result["registered"] else "it-approved",
            deployment_environment=env,
            risk_classification=risk if not result["registered"] else None,
            source_repository=result.get("install_path"),
            tags=tags,
        ) as reg:
            # Add content hash if we have an install path
            if result.get("install_path"):
                reg.set_hash(f"sha256:{hashlib.sha256(result['install_path'].encode()).hexdigest()[:40]}")

            label = "SHADOW" if not result["registered"] else "KNOWN "
            print(f"  [{label}]  {result['software']:30s}  "
                  f"env={env:12s}  type={atype:10s}  risk={risk}")

        # --------------------------------------------------------------
        # Step 3 — Classify shadow assets under EU AI Act
        # --------------------------------------------------------------

        if not result["registered"]:
            with asset_inv.trace_classify(
                asset_id=aid,
                risk_classification=risk,
                framework="eu_ai_act",
                assessor="aidisco-auto-classifier",
                use_case=f"shadow {result['category']} on endpoint",
            ) as cls:
                cls.set_reason(
                    f"Unregistered {result['category']} software "
                    f"({result['software']} v{result.get('version', 'unknown')}) "
                    f"discovered on {result['hostname']} — outside corporate "
                    f"AI governance controls"
                )
                if result["category"] in ("local_inference", "chat_ui"):
                    cls.set_autonomous_decision(False)
                elif result["category"] == "workflow_automation":
                    cls.set_autonomous_decision(True)

        # --------------------------------------------------------------
        # Step 4 — Audit each asset (integrity + compliance check)
        # --------------------------------------------------------------

        with asset_inv.trace_audit(
            asset_id=aid,
            audit_type="security" if not result["registered"] else "compliance",
            framework="nist_ai_rmf",
            auditor="aidisco-scanner",
        ) as audit:
            if not result["registered"]:
                audit.set_result("fail")
                audit.set_compliance_status("non_compliant")
                audit.set_risk_score(85.0 if result["category"] == "local_inference" else 70.0)
                findings = [{
                    "finding": f"Unregistered {result['software']} not in approved AI inventory",
                    "severity": "high",
                    "category": "shadow_ai",
                    "remediation": "Register asset or remove installation",
                }]
                if result.get("port"):
                    findings.append({
                        "finding": f"Active listener on port {result['port']}",
                        "severity": "medium",
                        "category": "network_exposure",
                        "remediation": "Block port or restrict to localhost",
                    })
                audit.set_findings(json.dumps(findings))
            else:
                audit.set_result("pass")
                audit.set_compliance_status("compliant")
                audit.set_risk_score(15.0)
                audit.set_integrity_verified(True)
                audit.set_findings("[]")

            audit.set_next_audit_due("2026-03-16T00:00:00Z")

print()
print(f"  Total assets found   : {len(AIDISCO_SCAN_RESULTS)}")
print(f"  Known / sanctioned   : {len(known_results)}")
print(f"  Shadow (unregistered): {len(shadow_results)}")

# ---------------------------------------------------------------------------
# What the OCSF exporter emits for the above telemetry
# ---------------------------------------------------------------------------
#
# Below is the OCSF event structure the OCSFExporter produces for each span.
# These events land in SIEM/XDR via AWS Security Lake, Splunk HEC, or
# Trend Vision One — ready for SOC analysts.
#
# ┌──────────────────────────────────────────────────────────────────────────┐
# │ OCSF 701002 — Asset Discovery                                          │
# │                                                                         │
# │  {                                                                      │
# │    "class_uid": 7010,                                                   │
# │    "category_uid": 7,                                                   │
# │    "type_uid": 701002,                                                  │
# │    "activity_id": 2,                                                    │
# │    "activity_name": "Asset Discovery",                                  │
# │    "severity_id": 4,           // High — shadow assets found            │
# │    "time": "2026-02-16T...",                                            │
# │    "message": "AIDisco scan: 7 assets found, 5 shadow",                │
# │    "metadata": {                                                        │
# │      "product": { "name": "AITF", "vendor_name": "OpenTelemetry" },    │
# │      "version": "1.0.0"                                                │
# │    },                                                                   │
# │    "asset_info": {                                                      │
# │      "discovery_scope": "environment",                                  │
# │      "discovery_method": "api_scan",                                    │
# │      "assets_found": 7,                                                 │
# │      "new_assets": 5,                                                   │
# │      "shadow_assets": 5                                                 │
# │    },                                                                   │
# │    "compliance": {                                                      │
# │      "nist_ai_rmf": ["GOVERN-1.2", "MAP-1.5"],                         │
# │      "eu_ai_act": ["Article 9", "Article 12"],                         │
# │      "mitre_atlas": ["AML.T0040"]                                      │
# │    }                                                                    │
# │  }                                                                      │
# │                                                                         │
# ├──────────────────────────────────────────────────────────────────────────┤
# │ OCSF 701007 — Shadow Asset Detected  (one per shadow asset)            │
# │                                                                         │
# │  {                                                                      │
# │    "class_uid": 7010,                                                   │
# │    "type_uid": 701007,                                                  │
# │    "activity_id": 7,                                                    │
# │    "activity_name": "Shadow Asset Detected",                            │
# │    "severity_id": 4,                                                    │
# │    "message": "Unregistered AI asset: Ollama v0.5.4 on                 │
# │                dev-workstation-042 (port 11434)",                       │
# │    "asset_info": {                                                      │
# │      "asset_id": "aidisco-<hash>",                                     │
# │      "name": "Ollama",                                                  │
# │      "type": "model",                                                   │
# │      "version": "0.5.4",                                                │
# │      "deployment_environment": "shadow",                                │
# │      "risk_classification": "high_risk",                                │
# │      "owner": "unassigned",                                             │
# │      "tags": ["aidisco:local_inference", "hostname:dev-workstation-042",│
# │               "os:linux", "port:11434"]                                 │
# │    },                                                                   │
# │    "compliance": {                                                      │
# │      "nist_ai_rmf": ["GOVERN-1.2"],                                    │
# │      "eu_ai_act": ["Article 6", "Article 9"],                          │
# │      "mitre_atlas": ["AML.T0040"]                                      │
# │    }                                                                    │
# │  }                                                                      │
# │                                                                         │
# ├──────────────────────────────────────────────────────────────────────────┤
# │ OCSF 701001 — Asset Registration  (one per asset)                      │
# │                                                                         │
# │  {                                                                      │
# │    "class_uid": 7010,                                                   │
# │    "type_uid": 701001,                                                  │
# │    "activity_id": 1,                                                    │
# │    "activity_name": "Asset Registration",                               │
# │    "severity_id": 1,                                                    │
# │    "asset_info": {                                                      │
# │      "asset_id": "aidisco-<hash>",                                     │
# │      "name": "Ollama",                                                  │
# │      "type": "model",                                                   │
# │      "version": "0.5.4",                                                │
# │      "hash": "sha256:...",                                              │
# │      "owner": "unassigned",                                             │
# │      "deployment_environment": "shadow",                                │
# │      "risk_classification": "high_risk",                                │
# │      "source_repository": "/usr/local/bin/ollama"                       │
# │    }                                                                    │
# │  }                                                                      │
# │                                                                         │
# ├──────────────────────────────────────────────────────────────────────────┤
# │ OCSF 701004 — Risk Classification  (shadow assets only)                │
# │                                                                         │
# │  {                                                                      │
# │    "class_uid": 7010,                                                   │
# │    "type_uid": 701004,                                                  │
# │    "activity_id": 4,                                                    │
# │    "activity_name": "Risk Classification",                              │
# │    "severity_id": 3,                                                    │
# │    "asset_info": { "asset_id": "aidisco-<hash>" },                     │
# │    "classification_info": {                                             │
# │      "framework": "eu_ai_act",                                          │
# │      "risk_classification": "high_risk",                                │
# │      "assessor": "aidisco-auto-classifier",                             │
# │      "use_case": "shadow local_inference on endpoint",                  │
# │      "reason": "Unregistered local_inference software (Ollama v0.5.4)  │
# │                 discovered on dev-workstation-042 — outside corporate   │
# │                 AI governance controls",                                │
# │      "autonomous_decision": false                                       │
# │    },                                                                   │
# │    "compliance": {                                                      │
# │      "eu_ai_act": ["Article 6", "Article 9"]                           │
# │    }                                                                    │
# │  }                                                                      │
# │                                                                         │
# ├──────────────────────────────────────────────────────────────────────────┤
# │ OCSF 701003 — Asset Audit  (one per asset)                             │
# │                                                                         │
# │  {                                                                      │
# │    "class_uid": 7010,                                                   │
# │    "type_uid": 701003,                                                  │
# │    "activity_id": 3,                                                    │
# │    "activity_name": "Asset Audit",                                      │
# │    "severity_id": 4,                                                    │
# │    "asset_info": { "asset_id": "aidisco-<hash>" },                     │
# │    "audit_info": {                                                      │
# │      "audit_type": "security",                                          │
# │      "result": "fail",                                                  │
# │      "framework": "nist_ai_rmf",                                        │
# │      "auditor": "aidisco-scanner",                                      │
# │      "risk_score": 85.0,                                                │
# │      "compliance_status": "non_compliant",                              │
# │      "findings": [                                                      │
# │        {                                                                │
# │          "finding": "Unregistered Ollama not in approved AI inventory", │
# │          "severity": "high",                                            │
# │          "category": "shadow_ai",                                       │
# │          "remediation": "Register asset or remove installation"         │
# │        },                                                               │
# │        {                                                                │
# │          "finding": "Active listener on port 11434",                    │
# │          "severity": "medium",                                          │
# │          "category": "network_exposure",                                │
# │          "remediation": "Block port or restrict to localhost"           │
# │        }                                                                │
# │      ],                                                                 │
# │      "next_audit_due": "2026-03-16T00:00:00Z"                          │
# │    },                                                                   │
# │    "compliance": {                                                      │
# │      "nist_ai_rmf": ["GOVERN-1.2", "MEASURE-2.5"],                     │
# │      "eu_ai_act": ["Article 9"]                                        │
# │    }                                                                    │
# │  }                                                                      │
# └──────────────────────────────────────────────────────────────────────────┘
#
# ---------------------------------------------------------------------------
# Span hierarchy (as seen in Jaeger / Grafana Tempo / Honeycomb)
# ---------------------------------------------------------------------------
#
# ┌─ asset.discover environment ──────────────────────── 3.2s ─────────────┐
# │                                                                         │
# │  ├─ asset.register agent GitHub Copilot ──────────── 0.1s             │
# │  │  └─ asset.audit aidisco-<hash> ────────────────── 0.1s  [PASS]     │
# │  │                                                                     │
# │  ├─ asset.register agent Cursor ──────────────────── 0.1s             │
# │  │  └─ asset.audit aidisco-<hash> ────────────────── 0.1s  [PASS]     │
# │  │                                                                     │
# │  ├─ asset.register model Ollama ──────────────────── 0.2s  [SHADOW]   │
# │  │  ├─ asset.classify aidisco-<hash> ─────────────── 0.1s  [high_risk]│
# │  │  └─ asset.audit aidisco-<hash> ────────────────── 0.1s  [FAIL]     │
# │  │                                                                     │
# │  ├─ asset.register pipeline Open WebUI ───────────── 0.2s  [SHADOW]   │
# │  │  ├─ asset.classify aidisco-<hash> ─────────────── 0.1s  [high_risk]│
# │  │  └─ asset.audit aidisco-<hash> ────────────────── 0.1s  [FAIL]     │
# │  │                                                                     │
# │  ├─ asset.register model LM Studio ──────────────── 0.2s  [SHADOW]   │
# │  │  ├─ asset.classify aidisco-<hash> ─────────────── 0.1s  [high_risk]│
# │  │  └─ asset.audit aidisco-<hash> ────────────────── 0.1s  [FAIL]     │
# │  │                                                                     │
# │  ├─ asset.register model text-generation-webui ──── 0.2s  [SHADOW]   │
# │  │  ├─ asset.classify aidisco-<hash> ─────────────── 0.1s  [high_risk]│
# │  │  └─ asset.audit aidisco-<hash> ────────────────── 0.1s  [FAIL]     │
# │  │                                                                     │
# │  └─ asset.register pipeline n8n ──────────────────── 0.2s  [SHADOW]   │
# │     ├─ asset.classify aidisco-<hash> ─────────────── 0.1s  [high_risk]│
# │     └─ asset.audit aidisco-<hash> ────────────────── 0.1s  [FAIL]     │
# └─────────────────────────────────────────────────────────────────────────┘
#
# ---------------------------------------------------------------------------
# Splunk SPL query to find shadow AI from AIDisco scans
# ---------------------------------------------------------------------------
#
# index=ocsf sourcetype=aitf:ocsf type_uid=701007
# | stats count by asset_info.name, asset_info.type,
#              asset_info.deployment_environment,
#              asset_info.risk_classification,
#              asset_info.tags{}
# | where 'asset_info.deployment_environment'="shadow"
# | sort - count
# | rename asset_info.name AS "Software",
#          asset_info.type AS "Asset Type",
#          asset_info.risk_classification AS "Risk",
#          count AS "Endpoints"
#
# ---------------------------------------------------------------------------
# Sigma rule for shadow AI detection (compatible with aitf_detection_rules)
# ---------------------------------------------------------------------------
#
# title: Shadow AI Installation Detected via AIDisco
# id: aitf-sigma-010
# status: experimental
# description: Detects unregistered AI software installations reported by AIDisco
# references:
#   - https://github.com/girdav01/AIDisco
#   - https://github.com/girdav01/AITF
# author: AITF Project
# date: 2026/02/16
# tags:
#   - asset.shadow
#   - owasp.llm03
#   - mitre.atlas.AML.T0040
# logsource:
#   category: ai_asset_inventory
#   product: aitf
# detection:
#   selection:
#     type_uid: 701007
#     asset_info.deployment_environment: "shadow"
#   condition: selection
# falsepositives:
#   - Development/testing environments with approved local LLM usage
#   - AI research teams with explicit exemptions
# level: high
