//! Tests for the Anthropic Claude Compliance API integration mapper.

use aitf::ocsf::claude_compliance::{classify, ClaudeComplianceMapper};
use serde_json::json;

#[test]
fn test_classify_authentication() {
    assert_eq!(classify("sso_login_initiated"), (3, 3002, 1, "authentication".to_string()));
    assert_eq!(classify("user_sign_out"), (3, 3002, 2, "authentication".to_string()));
}

#[test]
fn test_classify_account_change() {
    let (cat, cls, _, _) = classify("user_added");
    assert_eq!((cat, cls), (3, 3001));
    assert_eq!(classify("user_removed"), (3, 3001, 4, "account_change".to_string()));
}

#[test]
fn test_classify_access_management() {
    assert_eq!(
        classify("role_permission_granted"),
        (3, 3005, 1, "access_management".to_string())
    );
    let (cat, cls, _, _) = classify("group_member_added");
    assert_eq!((cat, cls), (3, 3005));
}

#[test]
fn test_classify_content() {
    assert_eq!(classify("claude_chat_created"), (6, 6001, 1, "content".to_string()));
    assert_eq!(classify("claude_file_uploaded"), (6, 6001, 1, "content".to_string()));
    assert_eq!(classify("chat_message_viewed"), (6, 6001, 2, "content".to_string()));
}

#[test]
fn test_classify_unknown_is_forward_compatible() {
    assert_eq!(
        classify("some_brand_new_future_event"),
        (6, 6003, 99, "other".to_string())
    );
}

#[test]
fn test_chat_created_maps_to_web_resources() {
    let mapper = ClaudeComplianceMapper::new();
    let event = mapper.map_activity(&json!({
        "id": "activity_1",
        "created_at": "2026-04-10T08:09:10Z",
        "organization_id": "org_1",
        "actor": {
            "type": "user_actor",
            "email_address": "u@example.com",
            "user_id": "user_1",
            "ip_address": "192.0.2.34",
            "user_agent": "Mozilla/5.0",
        },
        "type": "claude_chat_created",
        "claude_chat_id": "chat_1",
        "claude_project_id": "proj_1",
    }));

    assert_eq!(event.category_uid, 6);
    assert_eq!(event.class_uid, 6001);
    assert_eq!(event.type_uid, 600101);
    assert_eq!(event.time, "2026-04-10T08:09:10Z");

    let user = event.actor.as_ref().unwrap().user.as_ref().unwrap();
    assert_eq!(user["uid"], "user_1");
    assert_eq!(user["email_addr"], "u@example.com");
    assert_eq!(event.device.as_ref().unwrap().ip.as_deref(), Some("192.0.2.34"));

    let names: std::collections::HashMap<_, _> =
        event.enrichments.iter().map(|e| (e.name.as_str(), e.value.as_str())).collect();
    assert_eq!(names["claude.compliance.chat.id"], "chat_1");
    assert_eq!(names["claude.compliance.activity.type"], "claude_chat_created");

    let obs: std::collections::HashSet<_> =
        event.observables.iter().map(|o| o.value.as_str()).collect();
    assert!(obs.contains("192.0.2.34"));
    assert!(obs.contains("u@example.com"));
}

#[test]
fn test_login_maps_to_authentication() {
    let mapper = ClaudeComplianceMapper::new();
    let event = mapper.map_activity(&json!({
        "id": "a2",
        "created_at": "2026-04-10T09:00:00Z",
        "actor": {
            "type": "unauthenticated_user_actor",
            "unauthenticated_email_address": "x@example.com",
            "ip_address": "10.0.0.1",
        },
        "type": "sso_login_initiated",
    }));
    assert_eq!(
        (event.category_uid, event.class_uid, event.activity_id),
        (3, 3002, 1)
    );
    assert_eq!(event.metadata.product["vendor_name"], "Anthropic");
}

#[test]
fn test_scim_user_added_maps_to_account_change() {
    let mapper = ClaudeComplianceMapper::new();
    let event = mapper.map_activity(&json!({
        "id": "a3",
        "actor": {"type": "scim_directory_sync_actor", "directory_id": "dir_1"},
        "type": "user_added",
    }));
    assert_eq!((event.category_uid, event.class_uid), (3, 3001));
    let user = event.actor.as_ref().unwrap().user.as_ref().unwrap();
    assert_eq!(user["uid"], "dir_1");
    assert!(!event.time.is_empty());
}

#[test]
fn test_failure_status_detected() {
    let mapper = ClaudeComplianceMapper::new();
    let event = mapper.map_activity(&json!({
        "id": "a4",
        "actor": {"type": "api_actor"},
        "type": "sso_login_failed",
    }));
    assert_eq!(event.status_id, 2); // Failure
}

#[test]
fn test_map_activities_batch() {
    let mapper = ClaudeComplianceMapper::new();
    let events = mapper.map_activities(&[
        json!({"id": "x1", "actor": {"type": "api_actor"}, "type": "claude_file_uploaded"}),
        json!({"id": "x2", "actor": {"type": "api_actor"}, "type": "compliance_export_created"}),
    ]);
    let class_uids: Vec<i32> = events.iter().map(|e| e.class_uid).collect();
    assert_eq!(class_uids, vec![6001, 6003]);
}
