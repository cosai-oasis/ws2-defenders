//! Tests for the Claude Compliance Activity Feed poller (feature `client`).

#![cfg(feature = "client")]

use aitf::ocsf::claude_compliance_client::{
    build_base_params, resolve_limit, ActivityFeedOptions, CLAUDE_COMPLIANCE_MAX_LIMIT,
};

#[test]
fn test_resolve_limit_defaults_and_bounds() {
    assert_eq!(resolve_limit(None).unwrap(), 100);
    assert_eq!(resolve_limit(Some(1)).unwrap(), 1);
    assert_eq!(resolve_limit(Some(5000)).unwrap(), 5000);
    assert!(resolve_limit(Some(0)).is_err());
    assert!(resolve_limit(Some(-5)).is_err());
    assert!(resolve_limit(Some(CLAUDE_COMPLIANCE_MAX_LIMIT + 1)).is_err());
}

#[test]
fn test_build_base_params_array_brackets() {
    let opts = ActivityFeedOptions {
        activity_types: vec!["chat_created".to_string(), "file_uploaded".to_string()],
        organization_ids: vec!["org_1".to_string()],
        actor_ids: vec!["actor_1".to_string()],
        created_at_gte: Some("2026-01-01T00:00:00Z".to_string()),
        created_at_lt: Some("2026-02-01T00:00:00Z".to_string()),
        ..Default::default()
    };
    let params = build_base_params(&opts, 100);

    let has = |k: &str, v: &str| params.iter().any(|(pk, pv)| pk == k && pv == v);
    assert!(has("limit", "100"));
    assert!(has("activity_types[]", "chat_created"));
    assert!(has("activity_types[]", "file_uploaded"));
    assert!(has("organization_ids[]", "org_1"));
    assert!(has("actor_ids[]", "actor_1"));
    assert!(has("created_at.gte", "2026-01-01T00:00:00Z"));
    assert!(has("created_at.lt", "2026-02-01T00:00:00Z"));

    // Two activity_types entries must both be present (repeatable filter).
    let count = params.iter().filter(|(k, _)| k == "activity_types[]").count();
    assert_eq!(count, 2);
}
