//! Tests for the AITF compliance-framework mapper (mirrors Python
//! TestComplianceMapper).

use aitf::ocsf::compliance::{ComplianceMapper, EVENT_TYPES};
use aitf::ocsf::AIBaseEvent;

#[test]
fn test_map_model_inference() {
    let mapper = ComplianceMapper::default();
    let c = mapper.map_event("model_inference");
    assert!(c.nist_ai_rmf.is_some());
    assert!(c.eu_ai_act.is_some());
    assert!(c.mitre_atlas.is_some());
    assert!(c.csa_aicm.is_some());
}

#[test]
fn test_map_security_finding() {
    let mapper = ComplianceMapper::default();
    let c = mapper.map_event("security_finding");
    let nist = c.nist_ai_rmf.unwrap();
    assert!(nist.controls.contains(&"MANAGE-2.4".to_string()));
}

#[test]
fn test_map_csa_aicm() {
    let mapper = ComplianceMapper::default();
    let c = mapper.map_event("model_inference");
    let aicm = c.csa_aicm.unwrap();
    for ctrl in ["MDS-01", "AIS-04", "AIS-08", "LOG-14", "GRC-13", "TVM-11"] {
        assert!(aicm.controls.contains(&ctrl.to_string()), "missing {ctrl}");
    }
    assert_eq!(aicm.domain.as_deref(), Some("Model Security"));
    assert_eq!(aicm.controls.len(), 32);
}

#[test]
fn test_map_csa_aicm_all_event_types() {
    let mapper = ComplianceMapper::default();
    for &event_type in EVENT_TYPES {
        let c = mapper.map_event(event_type);
        let aicm = c.csa_aicm.expect("csa_aicm present");
        assert!(aicm.domain.is_some());
        assert!(
            aicm.controls.len() >= 12,
            "expected >= 12 AICM controls for {event_type}, got {}",
            aicm.controls.len()
        );
    }
}

#[test]
fn test_map_csa_aicm_comprehensive_coverage() {
    let mapper = ComplianceMapper::default();
    let mut all: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for &event_type in EVENT_TYPES {
        let c = mapper.map_event(event_type);
        for ctrl in c.csa_aicm.unwrap().controls {
            all.insert(ctrl);
        }
    }
    let domains: std::collections::BTreeSet<String> = all
        .iter()
        .map(|c| c.split('-').next().unwrap_or("").to_string())
        .collect();
    let expected = [
        "MDS", "AIS", "LOG", "GRC", "TVM", "DSP", "IAM", "CEK", "SEF", "STA", "CCC", "DCS", "IPY",
        "BCR", "HRS", "A&A", "UEM", "I&S",
    ];
    for d in expected {
        assert!(domains.contains(d), "missing domain {d}");
    }
    assert!(all.len() >= 230, "expected >= 230 unique controls, got {}", all.len());
}

#[test]
fn test_coverage_matrix() {
    let mapper = ComplianceMapper::default();
    let matrix = mapper.get_coverage_matrix();
    assert_eq!(matrix.len(), 8);
    let mi = matrix.get("model_inference").expect("model_inference row");
    assert!(mi.contains_key("nist_ai_rmf"));
    assert!(mi.contains_key("csa_aicm"));
}

#[test]
fn test_filtered_frameworks() {
    let mapper = ComplianceMapper::new(Some(&["eu_ai_act"]));
    let c = mapper.map_event("model_inference");
    assert!(c.eu_ai_act.is_some());
    assert!(c.nist_ai_rmf.is_none());
    assert!(c.csa_aicm.is_none());
}

#[test]
fn test_filtered_csa_aicm_only() {
    let mapper = ComplianceMapper::new(Some(&["csa_aicm"]));
    let c = mapper.map_event("model_inference");
    let aicm = c.csa_aicm.unwrap();
    assert!(c.nist_ai_rmf.is_none());
    assert!(aicm.controls.contains(&"MDS-01".to_string()));
    assert!(aicm.controls.contains(&"AIS-04".to_string()));
}

#[test]
fn test_enrich_event() {
    let mapper = ComplianceMapper::default();
    let mut event = AIBaseEvent::new(6, 6003, 1);
    mapper.enrich_event(&mut event, "model_inference");
    assert!(event.compliance.as_ref().unwrap().nist_ai_rmf.is_some());
    // Round-trips through serde and skips empty frameworks.
    let json = event.to_json().unwrap();
    assert!(json.contains("\"compliance\""));
    assert!(json.contains("nist_ai_rmf"));
}
