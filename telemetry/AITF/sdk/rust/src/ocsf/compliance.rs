//! AITF compliance-framework mapper.
//!
//! Maps AITF/OCSF event types to controls across eight regulatory frameworks
//! (NIST AI RMF, MITRE ATLAS, ISO/IEC 42001, EU AI Act, SOC 2, GDPR, CCPA, and
//! CSA AICM). Ported from the Go `ocsf/compliance.go` and cross-checked against
//! the Python `compliance_mapper.py`; the control identifiers are identical to
//! those SDKs.

use serde::{Deserialize, Serialize};

use crate::ocsf::schema::AIBaseEvent;

/// A single framework's mapping for one event type.
///
/// `controls` is the unified primary list (the Go/Python tables call this
/// `controls`, `techniques`, `articles`, or `sections` depending on the
/// framework — all are surfaced here under `controls`). The optional label
/// fields carry the framework-specific descriptor (function / tactic / clause /
/// risk_level / criteria / lawful_basis / category / domain).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FrameworkControls {
    pub controls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clause: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub criteria: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lawful_basis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// Compliance metadata attached to an [`AIBaseEvent`], one entry per framework.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ComplianceMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nist_ai_rmf: Option<FrameworkControls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_atlas: Option<FrameworkControls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iso_42001: Option<FrameworkControls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eu_ai_act: Option<FrameworkControls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soc2: Option<FrameworkControls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gdpr: Option<FrameworkControls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ccpa: Option<FrameworkControls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csa_aicm: Option<FrameworkControls>,
}

/// All supported compliance frameworks, in canonical order.
pub const ALL_FRAMEWORKS: &[&str] = &[
    "nist_ai_rmf",
    "mitre_atlas",
    "iso_42001",
    "eu_ai_act",
    "soc2",
    "gdpr",
    "ccpa",
    "csa_aicm",
];

/// The eight event types covered by the coverage matrix.
pub const EVENT_TYPES: &[&str] = &[
    "model_inference",
    "agent_activity",
    "tool_execution",
    "data_retrieval",
    "security_finding",
    "supply_chain",
    "governance",
    "identity",
];

fn ctrls(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

// --- framework tables (ported verbatim from Go compliance.go) --------------

fn nist_ai_rmf(event_type: &str) -> Option<FrameworkControls> {
    let (controls, function) = match event_type {
        "model_inference" => (vec!["MAP-1.1", "MEASURE-2.5"], "MAP"),
        "agent_activity" => (vec!["GOVERN-1.2", "MANAGE-3.1"], "GOVERN"),
        "tool_execution" => (vec!["MAP-3.5", "MANAGE-4.2"], "MANAGE"),
        "data_retrieval" => (vec!["MAP-1.5", "MEASURE-2.7"], "MAP"),
        "security_finding" => (vec!["MANAGE-2.4", "MANAGE-4.1"], "MANAGE"),
        "supply_chain" => (vec!["MAP-5.2", "GOVERN-6.1"], "GOVERN"),
        "governance" => (vec!["GOVERN-1.1", "MANAGE-1.3"], "GOVERN"),
        "identity" => (vec!["GOVERN-1.5", "MANAGE-2.1"], "GOVERN"),
        _ => return None,
    };
    Some(FrameworkControls {
        controls: ctrls(&controls),
        function: Some(function.to_string()),
        ..Default::default()
    })
}

fn mitre_atlas(event_type: &str) -> Option<FrameworkControls> {
    let (controls, tactic) = match event_type {
        "model_inference" => (vec!["AML.T0040"], "ML Attack Staging"),
        "agent_activity" => (vec!["AML.T0048"], "ML Attack Staging"),
        "tool_execution" => (vec!["AML.T0043"], "ML Attack Staging"),
        "data_retrieval" => (vec!["AML.T0025"], "Exfiltration"),
        "security_finding" => (vec!["AML.T0051"], "Initial Access"),
        "supply_chain" => (vec!["AML.T0010"], "Resource Development"),
        "identity" => (vec!["AML.T0052"], "Initial Access"),
        _ => return None,
    };
    Some(FrameworkControls {
        controls: ctrls(&controls),
        tactic: Some(tactic.to_string()),
        ..Default::default()
    })
}

fn iso_42001(event_type: &str) -> Option<FrameworkControls> {
    let (controls, clause) = match event_type {
        "model_inference" => (vec!["6.1.4", "8.4"], "Operation"),
        "agent_activity" => (vec!["8.2", "A.6.2.5"], "Operation"),
        "tool_execution" => (vec!["A.6.2.7"], "Annex A"),
        "data_retrieval" => (vec!["A.7.4"], "Annex A"),
        "security_finding" => (vec!["6.1.2", "A.6.2.4"], "Planning"),
        "supply_chain" => (vec!["A.6.2.3"], "Annex A"),
        "governance" => (vec!["5.1", "9.1"], "Leadership"),
        "identity" => (vec!["A.6.2.6"], "Annex A"),
        _ => return None,
    };
    Some(FrameworkControls {
        controls: ctrls(&controls),
        clause: Some(clause.to_string()),
        ..Default::default()
    })
}

fn eu_ai_act(event_type: &str) -> Option<FrameworkControls> {
    let controls = match event_type {
        "model_inference" => vec!["Article 13", "Article 15"],
        "agent_activity" => vec!["Article 14", "Article 52"],
        "tool_execution" => vec!["Article 9"],
        "data_retrieval" => vec!["Article 10"],
        "security_finding" => vec!["Article 9", "Article 62"],
        "supply_chain" => vec!["Article 15", "Article 28"],
        "governance" => vec!["Article 9", "Article 61"],
        "identity" => vec!["Article 9"],
        _ => return None,
    };
    Some(FrameworkControls {
        controls: ctrls(&controls),
        risk_level: Some("high".to_string()),
        ..Default::default()
    })
}

fn soc2(event_type: &str) -> Option<FrameworkControls> {
    let controls = match event_type {
        "model_inference" => vec!["CC6.1"],
        "agent_activity" => vec!["CC7.2"],
        "tool_execution" => vec!["CC6.3"],
        "data_retrieval" => vec!["CC6.1"],
        "security_finding" => vec!["CC7.2", "CC7.3"],
        "supply_chain" => vec!["CC9.2"],
        "governance" => vec!["CC1.2"],
        "identity" => vec!["CC6.1", "CC6.2"],
        _ => return None,
    };
    Some(FrameworkControls {
        controls: ctrls(&controls),
        criteria: Some("Common Criteria".to_string()),
        ..Default::default()
    })
}

fn gdpr(event_type: &str) -> Option<FrameworkControls> {
    let (controls, lawful_basis) = match event_type {
        "model_inference" => (vec!["Article 5", "Article 22"], "legitimate_interest"),
        "agent_activity" => (vec!["Article 22"], "legitimate_interest"),
        "tool_execution" => (vec!["Article 25"], "legitimate_interest"),
        "data_retrieval" => (vec!["Article 5", "Article 6"], "legitimate_interest"),
        "security_finding" => (vec!["Article 32", "Article 33"], "legal_obligation"),
        "supply_chain" => (vec!["Article 28"], "contractual"),
        "governance" => (vec!["Article 5"], "legal_obligation"),
        "identity" => (vec!["Article 32"], "legal_obligation"),
        _ => return None,
    };
    Some(FrameworkControls {
        controls: ctrls(&controls),
        lawful_basis: Some(lawful_basis.to_string()),
        ..Default::default()
    })
}

fn ccpa(event_type: &str) -> Option<FrameworkControls> {
    let (controls, category) = match event_type {
        "model_inference" => (vec!["1798.100"], "personal_information"),
        "data_retrieval" => (vec!["1798.100"], "personal_information"),
        "security_finding" => (vec!["1798.150"], "breach"),
        "governance" => (vec!["1798.185"], "rulemaking"),
        "identity" => (vec!["1798.140"], "personal_information"),
        _ => return None,
    };
    Some(FrameworkControls {
        controls: ctrls(&controls),
        category: Some(category.to_string()),
        ..Default::default()
    })
}

fn csa_aicm(event_type: &str) -> Option<FrameworkControls> {
    let (controls, domain): (Vec<&str>, &str) = match event_type {
        "model_inference" => (
            vec![
                "MDS-01", "MDS-02", "MDS-03", "MDS-04", "MDS-05", "MDS-06", "MDS-07", "MDS-08",
                "MDS-09", "MDS-10", "MDS-11", "MDS-13", "AIS-03", "AIS-04", "AIS-05", "AIS-06",
                "AIS-07", "AIS-08", "AIS-09", "AIS-12", "AIS-14", "AIS-15", "LOG-07", "LOG-08",
                "LOG-13", "LOG-14", "LOG-15", "GRC-13", "GRC-14", "GRC-15", "TVM-11", "DSP-07",
            ],
            "Model Security",
        ),
        "agent_activity" => (
            vec![
                "AIS-02", "AIS-11", "AIS-13", "IAM-04", "IAM-05", "IAM-16", "IAM-19", "GRC-09",
                "GRC-10", "GRC-15", "LOG-05", "LOG-11", "MDS-10",
            ],
            "Application & Interface Security",
        ),
        "tool_execution" => (
            vec![
                "AIS-01", "AIS-04", "AIS-08", "AIS-09", "AIS-10", "AIS-13", "IAM-05", "IAM-16",
                "LOG-05", "LOG-11", "TVM-05", "TVM-11",
            ],
            "Application & Interface Security",
        ),
        "data_retrieval" => (
            vec![
                "DSP-01", "DSP-02", "DSP-03", "DSP-04", "DSP-05", "DSP-06", "DSP-07", "DSP-08",
                "DSP-09", "DSP-10", "DSP-11", "DSP-12", "DSP-13", "DSP-14", "DSP-15", "DSP-16",
                "DSP-17", "DSP-18", "DSP-19", "DSP-20", "DSP-21", "DSP-22", "DSP-23", "DSP-24",
                "CEK-03", "LOG-07", "LOG-10",
            ],
            "Data Security & Privacy",
        ),
        "security_finding" => (
            vec![
                "SEF-01", "SEF-02", "SEF-03", "SEF-04", "SEF-05", "SEF-06", "SEF-07", "SEF-08",
                "SEF-09", "TVM-01", "TVM-02", "TVM-03", "TVM-04", "TVM-06", "TVM-07", "TVM-08",
                "TVM-09", "TVM-10", "TVM-11", "TVM-12", "TVM-13", "LOG-02", "LOG-03", "LOG-04",
                "LOG-12", "MDS-06", "MDS-07",
            ],
            "Security Incident Management",
        ),
        "supply_chain" => (
            vec![
                "STA-01", "STA-02", "STA-03", "STA-04", "STA-05", "STA-06", "STA-07", "STA-08",
                "STA-09", "STA-10", "STA-11", "STA-12", "STA-13", "STA-14", "STA-15", "STA-16",
                "CCC-01", "CCC-02", "CCC-03", "CCC-04", "CCC-05", "CCC-06", "CCC-07", "CCC-08",
                "CCC-09", "MDS-08", "MDS-09", "MDS-12", "MDS-13", "DCS-01", "DCS-02", "DCS-03",
                "DCS-04", "DCS-05", "DCS-06", "DCS-07", "DCS-08", "DCS-09", "DCS-10", "DCS-11",
                "DCS-12", "DCS-13", "DCS-14", "DCS-15", "IPY-01", "IPY-02", "IPY-03", "IPY-04",
                "I&S-01", "I&S-02", "I&S-03", "I&S-04", "I&S-05", "I&S-06", "I&S-07", "I&S-08",
                "I&S-09",
            ],
            "Supply Chain Management",
        ),
        "governance" => (
            vec![
                "GRC-01", "GRC-02", "GRC-03", "GRC-04", "GRC-05", "GRC-06", "GRC-07", "GRC-08",
                "GRC-09", "GRC-10", "GRC-11", "GRC-12", "GRC-13", "GRC-14", "GRC-15", "A&A-01",
                "A&A-02", "A&A-03", "A&A-04", "A&A-05", "A&A-06", "BCR-01", "BCR-02", "BCR-03",
                "BCR-04", "BCR-05", "BCR-06", "BCR-07", "BCR-08", "BCR-09", "BCR-10", "BCR-11",
                "HRS-01", "HRS-02", "HRS-03", "HRS-04", "HRS-05", "HRS-06", "HRS-07", "HRS-08",
                "HRS-09", "HRS-10", "HRS-11", "HRS-12", "HRS-13", "HRS-14", "HRS-15", "LOG-01",
                "LOG-06", "DSP-01",
            ],
            "Governance, Risk & Compliance",
        ),
        "identity" => (
            vec![
                "IAM-01", "IAM-02", "IAM-03", "IAM-04", "IAM-05", "IAM-06", "IAM-07", "IAM-08",
                "IAM-09", "IAM-10", "IAM-11", "IAM-12", "IAM-13", "IAM-14", "IAM-15", "IAM-16",
                "IAM-17", "IAM-18", "IAM-19", "CEK-01", "CEK-02", "CEK-03", "CEK-04", "CEK-05",
                "CEK-06", "CEK-07", "CEK-08", "CEK-09", "CEK-10", "CEK-11", "CEK-12", "CEK-13",
                "CEK-14", "CEK-15", "CEK-16", "CEK-17", "CEK-18", "CEK-19", "CEK-20", "CEK-21",
                "LOG-04", "LOG-09", "UEM-01", "UEM-02", "UEM-03", "UEM-04", "UEM-05", "UEM-06",
                "UEM-07", "UEM-08", "UEM-09", "UEM-10", "UEM-11", "UEM-12", "UEM-13", "UEM-14",
            ],
            "Identity & Access Management",
        ),
        _ => return None,
    };
    Some(FrameworkControls {
        controls: ctrls(&controls),
        domain: Some(domain.to_string()),
        ..Default::default()
    })
}

// --- mapper ----------------------------------------------------------------

/// Maps AI events to compliance-framework controls.
#[derive(Debug, Clone)]
pub struct ComplianceMapper {
    frameworks: Vec<String>,
}

impl Default for ComplianceMapper {
    fn default() -> Self {
        Self::new(None)
    }
}

impl ComplianceMapper {
    /// Creates a mapper. If `frameworks` is `None` or empty, all eight
    /// frameworks are enabled.
    pub fn new(frameworks: Option<&[&str]>) -> Self {
        let frameworks = match frameworks {
            Some(f) if !f.is_empty() => f.iter().map(|s| s.to_string()).collect(),
            _ => ALL_FRAMEWORKS.iter().map(|s| s.to_string()).collect(),
        };
        ComplianceMapper { frameworks }
    }

    fn enabled(&self, framework: &str) -> bool {
        self.frameworks.iter().any(|f| f == framework)
    }

    /// Maps an event type to its compliance metadata across the configured
    /// frameworks.
    pub fn map_event(&self, event_type: &str) -> ComplianceMetadata {
        let mut meta = ComplianceMetadata::default();
        if self.enabled("nist_ai_rmf") {
            meta.nist_ai_rmf = nist_ai_rmf(event_type);
        }
        if self.enabled("mitre_atlas") {
            meta.mitre_atlas = mitre_atlas(event_type);
        }
        if self.enabled("iso_42001") {
            meta.iso_42001 = iso_42001(event_type);
        }
        if self.enabled("eu_ai_act") {
            meta.eu_ai_act = eu_ai_act(event_type);
        }
        if self.enabled("soc2") {
            meta.soc2 = soc2(event_type);
        }
        if self.enabled("gdpr") {
            meta.gdpr = gdpr(event_type);
        }
        if self.enabled("ccpa") {
            meta.ccpa = ccpa(event_type);
        }
        if self.enabled("csa_aicm") {
            meta.csa_aicm = csa_aicm(event_type);
        }
        meta
    }

    /// Adds compliance metadata to an event in place.
    pub fn enrich_event(&self, event: &mut AIBaseEvent, event_type: &str) {
        event.compliance = Some(self.map_event(event_type));
    }

    /// Builds a coverage matrix: event type -> framework -> primary control list.
    pub fn get_coverage_matrix(
        &self,
    ) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<String>>> {
        use std::collections::BTreeMap;
        let mut matrix: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        for &event_type in EVENT_TYPES {
            let meta = self.map_event(event_type);
            let mut row: BTreeMap<String, Vec<String>> = BTreeMap::new();
            let entries: [(&str, &Option<FrameworkControls>); 8] = [
                ("nist_ai_rmf", &meta.nist_ai_rmf),
                ("mitre_atlas", &meta.mitre_atlas),
                ("iso_42001", &meta.iso_42001),
                ("eu_ai_act", &meta.eu_ai_act),
                ("soc2", &meta.soc2),
                ("gdpr", &meta.gdpr),
                ("ccpa", &meta.ccpa),
                ("csa_aicm", &meta.csa_aicm),
            ];
            for (name, entry) in entries {
                if let Some(fc) = entry {
                    row.insert(name.to_string(), fc.controls.clone());
                }
            }
            matrix.insert(event_type.to_string(), row);
        }
        matrix
    }
}
