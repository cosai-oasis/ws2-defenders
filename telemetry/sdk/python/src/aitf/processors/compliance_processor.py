"""AITF Compliance Processor.

OTel SpanProcessor that maps AI telemetry events to compliance framework controls.
Supports NIST AI RMF, MITRE ATLAS, ISO 42001, EU AI Act, SOC 2, GDPR, CCPA,
and CSA AI Controls Matrix (AICM).

Based on compliance mapping from AITelemetry project.
"""

from __future__ import annotations

from typing import Any

from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor

from aitf.semantic_conventions.attributes import ComplianceAttributes

# Compliance mappings by AI event type
COMPLIANCE_MAPPINGS: dict[str, dict[str, Any]] = {
    "model_inference": {
        "nist_ai_rmf": {"controls": ["MAP-1.1", "MEASURE-2.5"], "function": "MAP"},
        "mitre_atlas": {"techniques": ["AML.T0040"], "tactic": "ML Attack Staging"},
        "iso_42001": {"controls": ["6.1.4", "8.4"], "clause": "Operation"},
        "eu_ai_act": {"articles": ["Article 13", "Article 15"], "risk_level": "high"},
        "soc2": {"controls": ["CC6.1"], "criteria": "Common Criteria"},
        "gdpr": {"articles": ["Article 5", "Article 22"], "lawful_basis": "legitimate_interest"},
        "ccpa": {"sections": ["1798.100"], "category": "personal_information"},
        "csa_aicm": {
            "controls": [
                "MDS-01", "MDS-02", "MDS-03", "MDS-04", "MDS-05", "MDS-06",
                "MDS-07", "MDS-08", "MDS-09", "MDS-10", "MDS-11", "MDS-13",
                "AIS-03", "AIS-04", "AIS-05", "AIS-06", "AIS-07", "AIS-08",
                "AIS-09", "AIS-12", "AIS-14", "AIS-15", "LOG-07", "LOG-08",
                "LOG-13", "LOG-14", "LOG-15", "GRC-13", "GRC-14", "GRC-15",
                "TVM-11", "DSP-07",
            ],
            "domain": "Model Security",
        },
    },
    "agent_activity": {
        "nist_ai_rmf": {"controls": ["GOVERN-1.2", "MANAGE-3.1"], "function": "GOVERN"},
        "mitre_atlas": {"techniques": ["AML.T0048"], "tactic": "ML Attack Staging"},
        "iso_42001": {"controls": ["8.2", "A.6.2.5"], "clause": "Operation"},
        "eu_ai_act": {"articles": ["Article 14", "Article 52"], "risk_level": "high"},
        "soc2": {"controls": ["CC7.2"], "criteria": "Common Criteria"},
        "gdpr": {"articles": ["Article 22"], "lawful_basis": "legitimate_interest"},
        "csa_aicm": {
            "controls": [
                "AIS-02", "AIS-11", "AIS-13", "IAM-04", "IAM-05", "IAM-16",
                "IAM-19", "GRC-09", "GRC-10", "GRC-15", "LOG-05", "LOG-11",
                "MDS-10",
            ],
            "domain": "Application & Interface Security",
        },
    },
    "tool_execution": {
        "nist_ai_rmf": {"controls": ["MAP-3.5", "MANAGE-4.2"], "function": "MANAGE"},
        "mitre_atlas": {"techniques": ["AML.T0043"], "tactic": "ML Attack Staging"},
        "iso_42001": {"controls": ["A.6.2.7"], "clause": "Annex A"},
        "eu_ai_act": {"articles": ["Article 9"], "risk_level": "high"},
        "soc2": {"controls": ["CC6.3"], "criteria": "Common Criteria"},
        "gdpr": {"articles": ["Article 25"], "lawful_basis": "legitimate_interest"},
        "csa_aicm": {
            "controls": [
                "AIS-01", "AIS-04", "AIS-08", "AIS-09", "AIS-10", "AIS-13",
                "IAM-05", "IAM-16", "LOG-05", "LOG-11", "TVM-05", "TVM-11",
            ],
            "domain": "Application & Interface Security",
        },
    },
    "data_retrieval": {
        "nist_ai_rmf": {"controls": ["MAP-1.5", "MEASURE-2.7"], "function": "MAP"},
        "mitre_atlas": {"techniques": ["AML.T0025"], "tactic": "Exfiltration"},
        "iso_42001": {"controls": ["A.7.4"], "clause": "Annex A"},
        "eu_ai_act": {"articles": ["Article 10"], "risk_level": "high"},
        "soc2": {"controls": ["CC6.1"], "criteria": "Common Criteria"},
        "gdpr": {"articles": ["Article 5", "Article 6"], "lawful_basis": "legitimate_interest"},
        "ccpa": {"sections": ["1798.100"], "category": "personal_information"},
        "csa_aicm": {
            "controls": [
                "DSP-01", "DSP-02", "DSP-03", "DSP-04", "DSP-05", "DSP-06",
                "DSP-07", "DSP-08", "DSP-09", "DSP-10", "DSP-11", "DSP-12",
                "DSP-13", "DSP-14", "DSP-15", "DSP-16", "DSP-17", "DSP-18",
                "DSP-19", "DSP-20", "DSP-21", "DSP-22", "DSP-23", "DSP-24",
                "CEK-03", "LOG-07", "LOG-10",
            ],
            "domain": "Data Security & Privacy",
        },
    },
    "security_finding": {
        "nist_ai_rmf": {"controls": ["MANAGE-2.4", "MANAGE-4.1"], "function": "MANAGE"},
        "mitre_atlas": {"techniques": ["AML.T0051"], "tactic": "Initial Access"},
        "iso_42001": {"controls": ["6.1.2", "A.6.2.4"], "clause": "Planning"},
        "eu_ai_act": {"articles": ["Article 9", "Article 62"], "risk_level": "high"},
        "soc2": {"controls": ["CC7.2", "CC7.3"], "criteria": "Common Criteria"},
        "gdpr": {"articles": ["Article 32", "Article 33"], "lawful_basis": "legal_obligation"},
        "ccpa": {"sections": ["1798.150"], "category": "breach"},
        "csa_aicm": {
            "controls": [
                "SEF-01", "SEF-02", "SEF-03", "SEF-04", "SEF-05", "SEF-06",
                "SEF-07", "SEF-08", "SEF-09", "TVM-01", "TVM-02", "TVM-03",
                "TVM-04", "TVM-06", "TVM-07", "TVM-08", "TVM-09", "TVM-10",
                "TVM-11", "TVM-12", "TVM-13", "LOG-02", "LOG-03", "LOG-04",
                "LOG-12", "MDS-06", "MDS-07",
            ],
            "domain": "Security Incident Management",
        },
    },
    "supply_chain": {
        "nist_ai_rmf": {"controls": ["MAP-5.2", "GOVERN-6.1"], "function": "GOVERN"},
        "mitre_atlas": {"techniques": ["AML.T0010"], "tactic": "Resource Development"},
        "iso_42001": {"controls": ["A.6.2.3"], "clause": "Annex A"},
        "eu_ai_act": {"articles": ["Article 15", "Article 28"], "risk_level": "high"},
        "soc2": {"controls": ["CC9.2"], "criteria": "Common Criteria"},
        "gdpr": {"articles": ["Article 28"], "lawful_basis": "contractual"},
        "csa_aicm": {
            "controls": [
                "STA-01", "STA-02", "STA-03", "STA-04", "STA-05", "STA-06",
                "STA-07", "STA-08", "STA-09", "STA-10", "STA-11", "STA-12",
                "STA-13", "STA-14", "STA-15", "STA-16", "CCC-01", "CCC-02",
                "CCC-03", "CCC-04", "CCC-05", "CCC-06", "CCC-07", "CCC-08",
                "CCC-09", "MDS-08", "MDS-09", "MDS-12", "MDS-13",
                "DCS-01", "DCS-02", "DCS-03", "DCS-04", "DCS-05", "DCS-06",
                "DCS-07", "DCS-08", "DCS-09", "DCS-10", "DCS-11", "DCS-12",
                "DCS-13", "DCS-14", "DCS-15",
                "IPY-01", "IPY-02", "IPY-03", "IPY-04",
                "I&S-01", "I&S-02", "I&S-03", "I&S-04", "I&S-05",
                "I&S-06", "I&S-07", "I&S-08", "I&S-09",
            ],
            "domain": "Supply Chain Management",
        },
    },
    "governance": {
        "nist_ai_rmf": {"controls": ["GOVERN-1.1", "MANAGE-1.3"], "function": "GOVERN"},
        "iso_42001": {"controls": ["5.1", "9.1"], "clause": "Leadership"},
        "eu_ai_act": {"articles": ["Article 9", "Article 61"], "risk_level": "high"},
        "soc2": {"controls": ["CC1.2"], "criteria": "Common Criteria"},
        "gdpr": {"articles": ["Article 5"], "lawful_basis": "legal_obligation"},
        "ccpa": {"sections": ["1798.185"], "category": "rulemaking"},
        "csa_aicm": {
            "controls": [
                "GRC-01", "GRC-02", "GRC-03", "GRC-04", "GRC-05", "GRC-06",
                "GRC-07", "GRC-08", "GRC-09", "GRC-10", "GRC-11", "GRC-12",
                "GRC-13", "GRC-14", "GRC-15", "A&A-01", "A&A-02", "A&A-03",
                "A&A-04", "A&A-05", "A&A-06", "BCR-01", "BCR-02", "BCR-03",
                "BCR-04", "BCR-05", "BCR-06", "BCR-07", "BCR-08", "BCR-09",
                "BCR-10", "BCR-11", "HRS-01", "HRS-02", "HRS-03", "HRS-04",
                "HRS-05", "HRS-06", "HRS-07", "HRS-08", "HRS-09", "HRS-10",
                "HRS-11", "HRS-12", "HRS-13", "HRS-14", "HRS-15",
                "LOG-01", "LOG-06", "DSP-01",
            ],
            "domain": "Governance, Risk & Compliance",
        },
    },
    "identity": {
        "nist_ai_rmf": {"controls": ["GOVERN-1.5", "MANAGE-2.1"], "function": "GOVERN"},
        "mitre_atlas": {"techniques": ["AML.T0052"], "tactic": "Initial Access"},
        "iso_42001": {"controls": ["A.6.2.6"], "clause": "Annex A"},
        "eu_ai_act": {"articles": ["Article 9"], "risk_level": "high"},
        "soc2": {"controls": ["CC6.1", "CC6.2"], "criteria": "Common Criteria"},
        "gdpr": {"articles": ["Article 32"], "lawful_basis": "legal_obligation"},
        "ccpa": {"sections": ["1798.140"], "category": "personal_information"},
        "csa_aicm": {
            "controls": [
                "IAM-01", "IAM-02", "IAM-03", "IAM-04", "IAM-05", "IAM-06",
                "IAM-07", "IAM-08", "IAM-09", "IAM-10", "IAM-11", "IAM-12",
                "IAM-13", "IAM-14", "IAM-15", "IAM-16", "IAM-17", "IAM-18",
                "IAM-19", "CEK-01", "CEK-02", "CEK-03", "CEK-04", "CEK-05",
                "CEK-06", "CEK-07", "CEK-08", "CEK-09", "CEK-10", "CEK-11",
                "CEK-12", "CEK-13", "CEK-14", "CEK-15", "CEK-16", "CEK-17",
                "CEK-18", "CEK-19", "CEK-20", "CEK-21", "LOG-04", "LOG-09",
                "UEM-01", "UEM-02", "UEM-03", "UEM-04", "UEM-05", "UEM-06",
                "UEM-07", "UEM-08", "UEM-09", "UEM-10", "UEM-11", "UEM-12",
                "UEM-13", "UEM-14",
            ],
            "domain": "Identity & Access Management",
        },
    },
}


class ComplianceProcessor(SpanProcessor):
    """OTel SpanProcessor that adds compliance framework mappings to AI spans.

    Usage:
        provider.add_span_processor(ComplianceProcessor(
            frameworks=["nist_ai_rmf", "mitre_atlas", "eu_ai_act"],
        ))
    """

    def __init__(
        self,
        frameworks: list[str] | None = None,
    ):
        all_frameworks = [
            "nist_ai_rmf", "mitre_atlas", "iso_42001",
            "eu_ai_act", "soc2", "gdpr", "ccpa", "csa_aicm",
        ]
        self._frameworks = frameworks or all_frameworks

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        pass

    def on_end(self, span: ReadableSpan) -> None:
        """Map span to compliance controls based on span type."""
        attrs = span.attributes or {}

        # Determine event type from span name and attributes
        event_type = self._classify_event(span)
        if not event_type:
            return

        # Get compliance mapping
        mapping = self.get_compliance_mapping(event_type)
        if mapping:
            # In practice, compliance data would be attached during on_start
            # or via a wrapping mechanism. ReadableSpan is immutable.
            pass

    def get_compliance_mapping(self, event_type: str) -> dict[str, Any]:
        """Get compliance mapping for a given event type.

        Returns dict of framework -> controls.
        """
        full_mapping = COMPLIANCE_MAPPINGS.get(event_type, {})
        if not full_mapping:
            return {}

        result: dict[str, Any] = {}
        active_frameworks: list[str] = []

        for framework in self._frameworks:
            if framework in full_mapping:
                result[framework] = full_mapping[framework]
                active_frameworks.append(framework)

        if active_frameworks:
            result["_frameworks"] = active_frameworks

        return result

    def get_compliance_attributes(self, event_type: str) -> dict[str, Any]:
        """Get compliance attributes suitable for span attributes."""
        mapping = self.get_compliance_mapping(event_type)
        if not mapping:
            return {}

        attributes: dict[str, Any] = {}
        frameworks = mapping.pop("_frameworks", [])
        if frameworks:
            attributes[ComplianceAttributes.FRAMEWORKS] = frameworks

        for framework, controls in mapping.items():
            if framework == "nist_ai_rmf" and "controls" in controls:
                attributes[ComplianceAttributes.NIST_AI_RMF_CONTROLS] = controls["controls"]
            elif framework == "mitre_atlas" and "techniques" in controls:
                attributes[ComplianceAttributes.MITRE_ATLAS_TECHNIQUES] = controls["techniques"]
            elif framework == "iso_42001" and "controls" in controls:
                attributes[ComplianceAttributes.ISO_42001_CONTROLS] = controls["controls"]
            elif framework == "eu_ai_act" and "articles" in controls:
                attributes[ComplianceAttributes.EU_AI_ACT_ARTICLES] = controls["articles"]
            elif framework == "soc2" and "controls" in controls:
                attributes[ComplianceAttributes.SOC2_CONTROLS] = controls["controls"]
            elif framework == "gdpr" and "articles" in controls:
                attributes[ComplianceAttributes.GDPR_ARTICLES] = controls["articles"]
            elif framework == "ccpa" and "sections" in controls:
                attributes[ComplianceAttributes.CCPA_SECTIONS] = controls["sections"]
            elif framework == "csa_aicm" and "controls" in controls:
                attributes[ComplianceAttributes.CSA_AICM_CONTROLS] = controls["controls"]

        return attributes

    def get_coverage_matrix(self) -> dict[str, dict[str, list[str]]]:
        """Generate a coverage matrix showing which controls are mapped per event type."""
        matrix: dict[str, dict[str, list[str]]] = {}
        for event_type, mapping in COMPLIANCE_MAPPINGS.items():
            matrix[event_type] = {}
            for framework in self._frameworks:
                if framework in mapping:
                    controls = mapping[framework]
                    key = "controls" if "controls" in controls else "techniques" if "techniques" in controls else "articles" if "articles" in controls else "sections"
                    matrix[event_type][framework] = controls.get(key, [])
        return matrix

    def _classify_event(self, span: ReadableSpan) -> str | None:
        """Classify a span into an AI event type."""
        name = span.name or ""
        attrs = span.attributes or {}

        if name.startswith("chat ") or name.startswith("embeddings "):
            return "model_inference"
        if "gen_ai.provider.name" in attrs:
            return "model_inference"
        if name.startswith("agent."):
            return "agent_activity"
        if name.startswith("mcp.tool.") or name.startswith("skill.invoke"):
            return "tool_execution"
        if name.startswith("rag.") or name.startswith("mcp.resource."):
            return "data_retrieval"
        if "security." in " ".join(str(k) for k in attrs.keys()):
            return "security_finding"

        return None

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
