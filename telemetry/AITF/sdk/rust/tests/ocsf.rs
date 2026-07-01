//! Tests for the AITF OCSF schema, crosswalk, and mapper (reuse model).

use std::collections::HashMap;

use aitf::ocsf::crosswalk::{
    build_ai_agent, build_delegation, build_delegation_lineage, ocsf_agent_activity_crosswalk,
    ocsf_class_crosswalk, ocsf_delegation_activity_crosswalk,
};
use aitf::ocsf::mapper::{AttrValue, OcsfMapper, SpanData};
use aitf::ocsf::schema::*;
use aitf::semconv;

fn attrs(pairs: &[(&str, AttrValue)]) -> HashMap<String, AttrValue> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

fn span(name: &str, pairs: &[(&str, AttrValue)]) -> SpanData {
    SpanData {
        name: name.to_string(),
        attributes: attrs(pairs),
        start_time_unix_nano: Some(1_700_000_000_000_000_000),
    }
}

#[test]
fn test_class_uids() {
    assert_eq!(CLASS_UID_API_ACTIVITY, 6003);
    assert_eq!(CLASS_UID_DATASTORE_ACTIVITY, 6005);
    assert_eq!(CLASS_UID_APPLICATION_LIFECYCLE, 6002);
    assert_eq!(CLASS_UID_DETECTION_FINDING, 2004);
    assert_eq!(CLASS_UID_VULNERABILITY_FINDING, 2002);
    assert_eq!(CLASS_UID_COMPLIANCE_FINDING, 2003);
    assert_eq!(CLASS_UID_AUTHENTICATION, 3002);
    assert_eq!(CLASS_UID_INVENTORY_INFO, 5001);
    assert_eq!(CLASS_UID_AGENT_ACTIVITY, 9001);
    assert_eq!(CLASS_UID_DELEGATION_ACTIVITY, 9002);
    assert_eq!(CLASS_UID_AGENT_COMMUNICATION, 9003);
}

#[test]
fn test_token_usage_total() {
    let mut usage = AITokenUsage {
        input_tokens: 100,
        output_tokens: 50,
        ..Default::default()
    };
    usage.compute_total();
    assert_eq!(usage.total_tokens, 150);
}

#[test]
fn test_metadata_defaults() {
    let meta = OCSFMetadata::new();
    assert_eq!(meta.version, "1.1.0");
    assert_eq!(meta.product["name"], "AITF");
    assert!(!meta.uid.is_empty());
}

#[test]
fn test_reuse_model_event_uids() {
    // A reuse-model event carries the right category/class/type uids.
    let event = AIBaseEvent::new(CATEGORY_UID_APPLICATION, CLASS_UID_API_ACTIVITY, 1);
    assert_eq!(event.category_uid, 6);
    assert_eq!(event.class_uid, 6003);
    assert_eq!(event.type_uid, 600301);
    assert_eq!(event.compute_type_uid(), 600301);
}

#[test]
fn test_normalize_agent_type_id() {
    assert_eq!(normalize_agent_type_id("native"), 1);
    assert_eq!(normalize_agent_type_id("langchain"), 2);
    assert_eq!(normalize_agent_type_id("langgraph"), 2);
    assert_eq!(normalize_agent_type_id("autogen"), 3);
    assert_eq!(normalize_agent_type_id("crewai"), 4);
    assert_eq!(normalize_agent_type_id("semantic_kernel"), 99);
    assert_eq!(normalize_agent_type_id(""), 0);
}

#[test]
fn test_inference_span_maps_to_6003_with_agent() {
    let mapper = OcsfMapper::new();
    let event = mapper
        .map_span(&span(
            "chat gpt-4o",
            &[
                (semconv::gen_ai::SYSTEM, "openai".into()),
                (semconv::gen_ai::REQUEST_MODEL, "gpt-4o".into()),
                (semconv::gen_ai::OPERATION_NAME, "chat".into()),
                (semconv::gen_ai::USAGE_INPUT_TOKENS, 100i64.into()),
                (semconv::gen_ai::USAGE_OUTPUT_TOKENS, 50i64.into()),
                // agent identity -> ai_operation profile attached
                (semconv::agent::ID, "agent-001".into()),
                (semconv::agent::NAME, "orchestrator".into()),
                (semconv::agent::FRAMEWORK, "crewai".into()),
            ],
        ))
        .unwrap();
    assert_eq!(event.class_uid, 6003);
    assert_eq!(event.activity_id, 1);
    let agent = event.ai_agent.as_ref().expect("ai_agent attached");
    assert_eq!(agent.uid, "agent-001");
    assert_eq!(agent.type_id, Some(4)); // CrewAI
    assert_eq!(agent.agent_type.as_deref(), Some("CrewAI"));
}

#[test]
fn test_build_ai_agent_object() {
    let agent = build_ai_agent(&attrs(&[
        (semconv::agent::ID, "agt-1".into()),
        (semconv::agent::NAME, "planner".into()),
        (semconv::agent::VERSION, "1.2.0".into()),
        (semconv::gen_ai::REQUEST_MODEL, "gpt-4o".into()),
        (semconv::agent::FRAMEWORK, "langchain".into()),
    ]))
    .unwrap();
    assert_eq!(agent.uid, "agt-1");
    assert_eq!(agent.name.as_deref(), Some("planner"));
    assert_eq!(agent.type_id, Some(2));
    assert_eq!(agent.agent_type.as_deref(), Some("LangChain"));
    assert_eq!(agent.ai_model.as_deref(), Some("gpt-4o"));
    assert_eq!(agent.version.as_deref(), Some("1.2.0"));
}

#[test]
fn test_build_ai_agent_none_when_no_identity() {
    assert!(build_ai_agent(&attrs(&[("http.method", "GET".into())])).is_none());
}

#[test]
fn test_build_delegation_object() {
    let deleg = build_delegation(&attrs(&[
        (semconv::identity::DELEGATION_DELEGATEE_ID, "agt-2".into()),
        (semconv::identity::DELEGATION_DELEGATOR_ID, "agt-1".into()),
        (semconv::identity::DELEGATION_TYPE, "on_behalf_of".into()),
        (
            semconv::identity::DELEGATION_SCOPE_DELEGATED,
            AttrValue::StrList(vec!["read".into(), "write".into()]),
        ),
        (semconv::identity::DELEGATION_TTL_SECONDS, 3600i64.into()),
    ]))
    .unwrap();
    assert_eq!(deleg.uid, "agt-2");
    assert_eq!(deleg.parent_uid.as_deref(), Some("agt-1"));
    assert_eq!(deleg.delegation_type.as_deref(), Some("on_behalf_of"));
    assert_eq!(deleg.scope, Some(vec!["read".to_string(), "write".to_string()]));
    assert_eq!(deleg.ttl_seconds, Some(3600));
}

#[test]
fn test_build_delegation_lineage_graph() {
    let lineage = build_delegation_lineage(&attrs(&[(
        semconv::identity::DELEGATION_CHAIN,
        AttrValue::StrList(vec!["root".into(), "agt-1".into(), "agt-2".into()]),
    )]))
    .unwrap();
    let nodes = lineage.nodes.unwrap();
    assert_eq!(nodes.len(), 3);
    assert_eq!(nodes[0].parent_uid, None);
    assert_eq!(nodes[0].depth, 0);
    assert_eq!(nodes[2].parent_uid.as_deref(), Some("agt-1"));
    assert_eq!(nodes[2].depth, 2);
}

#[test]
fn test_identity_span_carries_delegation() {
    let mapper = OcsfMapper::new();
    let event = mapper
        .map_span(&span(
            "identity.delegate orchestrator",
            &[
                (semconv::identity::AGENT_ID, "agt-1".into()),
                (semconv::identity::AGENT_NAME, "orchestrator".into()),
                (semconv::identity::AUTH_METHOD, "mtls".into()),
                (semconv::identity::AUTH_RESULT, "success".into()),
                (semconv::identity::DELEGATION_DELEGATEE_ID, "agt-2".into()),
                (semconv::identity::DELEGATION_DELEGATOR_ID, "agt-1".into()),
                (semconv::identity::DELEGATION_TYPE, "token_exchange".into()),
            ],
        ))
        .unwrap();
    assert_eq!(event.class_uid, 3002);
    let deleg = event.delegation.as_ref().unwrap();
    assert_eq!(deleg.uid, "agt-2");
    assert_eq!(deleg.delegation_type.as_deref(), Some("token_exchange"));
}

#[test]
fn test_all_event_types_map_to_reused_ocsf_classes() {
    let mapper = OcsfMapper::new();
    let cases: Vec<(&str, Vec<(&str, AttrValue)>)> = vec![
        (
            "chat gpt-4o",
            vec![
                (semconv::gen_ai::SYSTEM, "openai".into()),
                (semconv::gen_ai::REQUEST_MODEL, "gpt-4o".into()),
            ],
        ),
        (
            "agent.step research",
            vec![
                (semconv::agent::NAME, "r".into()),
                (semconv::agent::ID, "1".into()),
                (semconv::agent::SESSION_ID, "s1".into()),
            ],
        ),
        ("mcp.tool.invoke read", vec![(semconv::gen_ai::TOOL_NAME, "read".into())]),
        (
            "rag.retrieve db",
            vec![
                (semconv::rag::RETRIEVE_DATABASE, "db".into()),
                (semconv::rag::RETRIEVE_RESULTS_COUNT, 1i64.into()),
            ],
        ),
        (
            "security.threat",
            vec![
                (semconv::security::THREAT_DETECTED, true.into()),
                (semconv::security::RISK_LEVEL, "high".into()),
            ],
        ),
        ("supply_chain.verify m", vec![(semconv::supply_chain::MODEL_SOURCE, "hf".into())]),
        (
            "governance.audit x",
            vec![(
                semconv::compliance::FRAMEWORKS,
                AttrValue::StrList(vec!["eu_ai_act".into()]),
            )],
        ),
        (
            "identity.auth a",
            vec![
                (semconv::identity::AGENT_ID, "1".into()),
                (semconv::identity::AGENT_NAME, "a".into()),
            ],
        ),
        ("model_ops.training r", vec![(semconv::model_ops::TRAINING_RUN_ID, "r1".into())]),
        ("asset.register model m", vec![(semconv::asset_inventory::ID, "a1".into())]),
    ];

    let mut class_uids = std::collections::HashSet::new();
    for (name, pairs) in cases {
        let event = mapper.map_span(&span(name, &pairs)).unwrap_or_else(|| panic!("unmapped: {name}"));
        class_uids.insert(event.class_uid);
    }
    let expected: std::collections::HashSet<i32> =
        [6003, 9001, 6005, 2004, 2002, 2003, 3002, 6002, 5001].into_iter().collect();
    assert_eq!(class_uids, expected);
}

#[test]
fn test_unrelated_span_returns_none() {
    let mapper = OcsfMapper::new();
    let event = mapper.map_span(&span(
        "http.request GET /api/users",
        &[("http.method", "GET".into()), ("http.url", "/api/users".into())],
    ));
    assert!(event.is_none());
}

#[test]
fn test_control_plane_crosswalk_tables() {
    assert_eq!(ocsf_agent_activity_crosswalk(1), Some("Spawn"));
    assert_eq!(ocsf_agent_activity_crosswalk(2), Some("Terminate"));
    assert_eq!(ocsf_delegation_activity_crosswalk("revoke"), Some("Revoke"));

    assert_eq!(ocsf_class_crosswalk("model_inference").unwrap().ocsf_class_uid, 6003);
    assert_eq!(ocsf_class_crosswalk("security_finding").unwrap().ocsf_class_uid, 2004);
    assert_eq!(ocsf_class_crosswalk("identity").unwrap().ocsf_class_uid, 3002);
    let aa = ocsf_class_crosswalk("agent_activity").unwrap();
    assert_eq!(aa.ocsf_category_uid, 9);
    assert_eq!(aa.ocsf_class, "agent_activity");
    assert_eq!(ocsf_class_crosswalk("delegation_activity").unwrap().ocsf_class, "delegation_activity");
}
