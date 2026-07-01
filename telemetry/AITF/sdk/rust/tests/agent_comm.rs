//! Tests for unified A2A / ACP / ANP agent-communication -> OCSF mapping.

use std::collections::HashMap;

use aitf::ocsf::crosswalk::{build_agent_message, canonical_comm_status};
use aitf::ocsf::mapper::{AttrValue, OcsfMapper, SpanData};
use aitf::ocsf::schema::{
    normalize_agent_protocol_id, AGENT_PROTOCOL_ID_A2A, AGENT_PROTOCOL_ID_ACP,
    AGENT_PROTOCOL_ID_ANP, AGENT_PROTOCOL_ID_MCP, AGENT_PROTOCOL_ID_OTHER,
    AGENT_PROTOCOL_ID_UNKNOWN,
};
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
fn test_protocol_normalization() {
    assert_eq!(normalize_agent_protocol_id("a2a"), AGENT_PROTOCOL_ID_A2A);
    assert_eq!(normalize_agent_protocol_id("ACP"), AGENT_PROTOCOL_ID_ACP);
    assert_eq!(normalize_agent_protocol_id("anp"), AGENT_PROTOCOL_ID_ANP);
    assert_eq!(normalize_agent_protocol_id("mcp"), AGENT_PROTOCOL_ID_MCP);
    assert_eq!(normalize_agent_protocol_id("something"), AGENT_PROTOCOL_ID_OTHER);
    assert_eq!(normalize_agent_protocol_id(""), AGENT_PROTOCOL_ID_UNKNOWN);
}

#[test]
fn test_canonical_status() {
    assert_eq!(
        canonical_comm_status(AGENT_PROTOCOL_ID_A2A, "input-required"),
        "input_required"
    );
    assert_eq!(canonical_comm_status(AGENT_PROTOCOL_ID_A2A, "rejected"), "failed");
    assert_eq!(canonical_comm_status(AGENT_PROTOCOL_ID_ACP, "in-progress"), "working");
    assert_eq!(canonical_comm_status(AGENT_PROTOCOL_ID_ACP, "cancelled"), "canceled");
}

#[test]
fn test_build_agent_message_a2a() {
    let msg = build_agent_message(&attrs(&[
        (semconv::a2a::PROTOCOL_VERSION, "0.2".into()),
        (semconv::a2a::TRANSPORT, "jsonrpc".into()),
        (semconv::a2a::METHOD, "message/send".into()),
        (semconv::a2a::TASK_ID, "task_1".into()),
        (semconv::a2a::TASK_STATE, "working".into()),
        (semconv::a2a::MESSAGE_PARTS_COUNT, 2i64.into()),
        (semconv::a2a::INTERACTION_MODE, "stream".into()),
        (semconv::a2a::AGENT_NAME, "planner".into()),
        (semconv::a2a::AGENT_URL, "https://p.example/a2a".into()),
    ]))
    .expect("a2a message");

    assert_eq!(msg.protocol_id, AGENT_PROTOCOL_ID_A2A);
    assert_eq!(msg.unit_type.as_deref(), Some("task"));
    assert_eq!(msg.unit_uid.as_deref(), Some("task_1"));
    assert_eq!(msg.status.as_deref(), Some("working"));
    assert_eq!(msg.direction.as_deref(), Some("stream"));
    assert_eq!(msg.transport.as_deref(), Some("jsonrpc"));
    assert_eq!(msg.dst_agent.as_ref().unwrap().name.as_deref(), Some("planner"));
    assert_eq!(msg.peer_endpoint.as_deref(), Some("https://p.example/a2a"));
}

#[test]
fn test_build_agent_message_acp() {
    let msg = build_agent_message(&attrs(&[
        (semconv::acp::RUN_ID, "run_9".into()),
        (semconv::acp::RUN_STATUS, "in-progress".into()),
        (semconv::acp::RUN_MODE, "async".into()),
        (semconv::acp::OPERATION, "runs.create".into()),
        (semconv::acp::HTTP_URL, "https://acp.example/runs".into()),
    ]))
    .expect("acp message");

    assert_eq!(msg.protocol_id, AGENT_PROTOCOL_ID_ACP);
    assert_eq!(msg.unit_type.as_deref(), Some("run"));
    assert_eq!(msg.unit_uid.as_deref(), Some("run_9"));
    assert_eq!(msg.status.as_deref(), Some("working")); // in-progress -> working
    assert_eq!(msg.transport.as_deref(), Some("http"));
    assert_eq!(msg.endpoint.as_deref(), Some("https://acp.example/runs"));
}

#[test]
fn test_build_agent_message_anp() {
    let msg = build_agent_message(&attrs(&[
        (semconv::anp::PROTOCOL_VERSION, "1.0".into()),
        (semconv::anp::TRANSPORT, "ws".into()),
        (semconv::anp::PEER_DID, "did:wba:peer".into()),
        (semconv::anp::META_PROTOCOL_NAME, "negotiate".into()),
        (semconv::anp::MESSAGE_ID, "m1".into()),
        (semconv::anp::CROSS_DOMAIN, true.into()),
    ]))
    .expect("anp message");

    assert_eq!(msg.protocol_id, AGENT_PROTOCOL_ID_ANP);
    assert_eq!(msg.peer_did.as_deref(), Some("did:wba:peer"));
    assert_eq!(msg.operation.as_deref(), Some("negotiate"));
    assert_eq!(msg.cross_domain, Some(true));
}

#[test]
fn test_canonical_overrides() {
    let msg = build_agent_message(&attrs(&[
        (semconv::agent_comm::PROTOCOL, "custom".into()),
        (semconv::agent_comm::UNIT_ID, "u1".into()),
        (semconv::agent_comm::STATUS, "completed".into()),
        (semconv::agent_comm::PEER_AGENT_NAME, "peer-x".into()),
    ]))
    .expect("canonical message");

    assert_eq!(msg.protocol_id, AGENT_PROTOCOL_ID_OTHER);
    assert_eq!(msg.status.as_deref(), Some("completed"));
    assert_eq!(msg.dst_agent.as_ref().unwrap().name.as_deref(), Some("peer-x"));
}

#[test]
fn test_none_when_no_comm() {
    assert!(build_agent_message(&attrs(&[("http.method", "GET".into())])).is_none());
}

#[test]
fn test_all_protocols_map_to_one_class() {
    let mapper = OcsfMapper::new();
    let cases: Vec<(&str, Vec<(&str, AttrValue)>)> = vec![
        (
            "a2a.message.send",
            vec![
                (semconv::a2a::TASK_ID, "t1".into()),
                (semconv::a2a::TASK_STATE, "working".into()),
            ],
        ),
        (
            "acp.run.create",
            vec![
                (semconv::acp::RUN_ID, "r1".into()),
                (semconv::acp::RUN_STATUS, "completed".into()),
            ],
        ),
        ("anp.message", vec![(semconv::anp::MESSAGE_ID, "m1".into())]),
    ];
    for (name, pairs) in cases {
        let event = mapper.map_span(&span(name, &pairs)).expect(name);
        assert_eq!(event.category_uid, 9, "{name}");
        assert_eq!(event.class_uid, 9003, "{name}");
    }
}

#[test]
fn test_failure_status() {
    let mapper = OcsfMapper::new();
    let event = mapper
        .map_span(&span(
            "a2a.message.send",
            &[
                (semconv::a2a::TASK_ID, "t1".into()),
                (semconv::a2a::TASK_STATE, "failed".into()),
                (semconv::a2a::JSONRPC_ERROR_CODE, "-32000".into()),
            ],
        ))
        .unwrap();
    assert_eq!(event.status_id, 2); // Failure
    assert_eq!(
        event.agent_message.as_ref().unwrap().error_code.as_deref(),
        Some("-32000")
    );
}
