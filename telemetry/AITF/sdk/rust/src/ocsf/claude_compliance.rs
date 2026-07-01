//! AITF integration for the Anthropic Claude Compliance API.
//!
//! Normalizes records from the Compliance API Activity Feed
//! (`GET /v1/compliance/activities`) into AITF / OCSF telemetry, classifying
//! each activity by keyword into the existing OCSF class it reuses (OCSF's
//! "reuse objects and profiles" model). Logic mirrors the Python authoritative
//! mapper and the Go port exactly.
//!
//! Docs: <https://platform.claude.com/docs/en/manage-claude/compliance-api>
//!
//! The Activity Feed HTTP poller lives in
//! [`crate::ocsf::claude_compliance_client`] behind the `client` feature; this
//! module maps the records the poller (or any caller) supplies.

use std::collections::HashMap;

use serde_json::Value;

use crate::ocsf::schema::*;
use crate::semconv::claude_compliance as cc;

// --- classification --------------------------------------------------------

struct KeywordClass {
    keywords: &'static [&'static str],
    category_uid: i32,
    class_uid: i32,
    category: &'static str,
}

const KEYWORD_CLASSES: &[KeywordClass] = &[
    KeywordClass {
        keywords: &[
            "login",
            "logout",
            "signin",
            "sign_in",
            "sign_out",
            "sso",
            "mfa",
            "session",
            "authenticat",
            "password",
        ],
        category_uid: 3,
        class_uid: CLASS_UID_AUTHENTICATION,
        category: "authentication",
    },
    KeywordClass {
        keywords: &["role", "permission", "privilege", "group", "access_grant"],
        category_uid: 3,
        class_uid: CLASS_UID_USER_ACCESS_MANAGEMENT,
        category: "access_management",
    },
    KeywordClass {
        keywords: &["user", "member", "invite", "scim", "directory", "provision", "seat"],
        category_uid: 3,
        class_uid: CLASS_UID_ACCOUNT_CHANGE,
        category: "account_change",
    },
    KeywordClass {
        keywords: &[
            "chat",
            "file",
            "project",
            "attachment",
            "message",
            "document",
            "artifact",
            "content",
            "setting",
            "policy",
        ],
        category_uid: 6,
        class_uid: CLASS_UID_WEB_RESOURCES_ACTIVITY,
        category: "content",
    },
    KeywordClass {
        keywords: &["compliance", "api_key", "export", "workspace"],
        category_uid: 6,
        class_uid: CLASS_UID_API_ACTIVITY,
        category: "administration",
    },
];

struct VerbActivity {
    verbs: &'static [&'static str],
    activity_id: i32,
}

const VERB_ACTIVITIES: &[VerbActivity] = &[
    VerbActivity {
        verbs: &[
            "created", "added", "uploaded", "invited", "granted", "enabled", "started",
            "initiated",
        ],
        activity_id: 1,
    },
    VerbActivity {
        verbs: &["deleted", "removed", "revoked", "disabled", "ended", "completed"],
        activity_id: 4,
    },
    VerbActivity {
        verbs: &["updated", "edited", "changed", "renamed", "modified"],
        activity_id: 3,
    },
    VerbActivity {
        verbs: &["viewed", "read", "downloaded", "exported", "listed", "accessed"],
        activity_id: 2,
    },
];

fn any_contains(s: &str, keywords: &[&str]) -> bool {
    keywords.iter().any(|k| s.contains(k))
}

/// Maps a Compliance activity type to `(category_uid, class_uid, activity_id,
/// category)`. First-matching keyword group wins; order matters.
pub fn classify(activity_type: &str) -> (i32, i32, i32, String) {
    let t = activity_type.to_lowercase();

    let (mut category_uid, mut class_uid, mut category) = (6, CLASS_UID_API_ACTIVITY, "other");
    for kc in KEYWORD_CLASSES {
        if any_contains(&t, kc.keywords) {
            category_uid = kc.category_uid;
            class_uid = kc.class_uid;
            category = kc.category;
            break;
        }
    }

    // Authentication uses Logon(1) / Logoff(2) semantics.
    if class_uid == CLASS_UID_AUTHENTICATION {
        let activity_id = if any_contains(&t, &["logout", "sign_out", "signout"]) {
            2
        } else if any_contains(&t, &["login", "sign_in", "signin", "sso"]) {
            1
        } else {
            99
        };
        return (category_uid, class_uid, activity_id, category.to_string());
    }

    let mut activity_id = 99;
    for va in VERB_ACTIVITIES {
        if any_contains(&t, va.verbs) {
            activity_id = va.activity_id;
            break;
        }
    }
    (category_uid, class_uid, activity_id, category.to_string())
}

// --- helpers ---------------------------------------------------------------

fn str_from_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Returns the string form of a JSON object field, or `""` when absent/null.
fn as_string(m: &Value, key: &str) -> String {
    match m.get(key) {
        Some(Value::Null) | None => String::new(),
        Some(v) => str_from_value(v),
    }
}

fn first_non_empty(values: &[String]) -> String {
    values.iter().find(|s| !s.is_empty()).cloned().unwrap_or_default()
}

/// Translates the Compliance actor union into an OCSF actor.
fn build_actor(actor: &Value) -> OCSFActor {
    let uid = first_non_empty(&[
        as_string(actor, "user_id"),
        as_string(actor, "api_key_id"),
        as_string(actor, "admin_api_key_id"),
        as_string(actor, "directory_id"),
    ]);

    let mut user: HashMap<String, Value> = HashMap::new();
    user.insert(
        "type".to_string(),
        actor.get("type").cloned().unwrap_or(Value::Null),
    );
    if !uid.is_empty() {
        user.insert("uid".to_string(), Value::String(uid));
    }
    let email = first_non_empty(&[
        as_string(actor, "email_address"),
        as_string(actor, "unauthenticated_email_address"),
    ]);
    if !email.is_empty() {
        user.insert("email_addr".to_string(), Value::String(email.clone()));
        user.insert("name".to_string(), Value::String(email));
    }

    OCSFActor {
        user: Some(user),
        ..Default::default()
    }
}

// --- mapper ----------------------------------------------------------------

/// Maps Claude Compliance Activity records to OCSF events (reuse model).
#[derive(Default)]
pub struct ClaudeComplianceMapper;

fn claude_compliance_product() -> HashMap<String, String> {
    let mut p = HashMap::new();
    p.insert("name".to_string(), "Anthropic Claude Compliance API".to_string());
    p.insert("vendor_name".to_string(), "Anthropic".to_string());
    p.insert("version".to_string(), "v1".to_string());
    p
}

impl ClaudeComplianceMapper {
    pub fn new() -> Self {
        ClaudeComplianceMapper
    }

    /// Maps a single Activity Feed record (a JSON object) to an OCSF event.
    pub fn map_activity(&self, activity: &Value) -> AIBaseEvent {
        let activity_type = {
            let v = as_string(activity, "type");
            if v.is_empty() {
                "unknown".to_string()
            } else {
                v
            }
        };
        let (category_uid, class_uid, activity_id, category) = classify(&activity_type);

        let empty = Value::Object(Default::default());
        let actor_raw = activity.get("actor").unwrap_or(&empty);

        let ip = as_string(actor_raw, "ip_address");
        let user_agent = as_string(actor_raw, "user_agent");
        let device = if ip.is_empty() {
            None
        } else {
            Some(OCSFDevice {
                ip: Some(ip.clone()),
                ..Default::default()
            })
        };

        let mut enrichments = vec![
            OCSFEnrichment {
                name: cc::ACTIVITY_TYPE.to_string(),
                value: activity_type.clone(),
                provider: Some("claude_compliance".to_string()),
                ..Default::default()
            },
            OCSFEnrichment {
                name: cc::ACTIVITY_CATEGORY.to_string(),
                value: category.clone(),
                provider: Some("claude_compliance".to_string()),
                ..Default::default()
            },
        ];

        let field_attrs: &[(&str, &str)] = &[
            ("id", cc::ACTIVITY_ID),
            ("organization_id", cc::ORGANIZATION_ID),
            ("organization_uuid", cc::ORGANIZATION_UUID),
            ("claude_chat_id", cc::CHAT_ID),
            ("claude_project_id", cc::PROJECT_ID),
            ("claude_file_id", cc::FILE_ID),
            ("filename", cc::FILENAME),
        ];
        for (key, attr) in field_attrs {
            if let Some(v) = activity.get(*key) {
                if !v.is_null() {
                    enrichments.push(OCSFEnrichment {
                        name: attr.to_string(),
                        value: str_from_value(v),
                        ..Default::default()
                    });
                }
            }
        }

        let actor_type = as_string(actor_raw, "type");
        if !actor_type.is_empty() {
            enrichments.push(OCSFEnrichment {
                name: cc::ACTOR_TYPE.to_string(),
                value: actor_type,
                ..Default::default()
            });
        }
        if !user_agent.is_empty() {
            enrichments.push(OCSFEnrichment {
                name: cc::ACTOR_USER_AGENT.to_string(),
                value: user_agent,
                ..Default::default()
            });
        }

        let mut observables = Vec::new();
        let email = first_non_empty(&[
            as_string(actor_raw, "email_address"),
            as_string(actor_raw, "unauthenticated_email_address"),
        ]);
        if !email.is_empty() {
            observables.push(OCSFObservable {
                name: cc::ACTOR_EMAIL.to_string(),
                observable_type: "Email Address".to_string(),
                value: email,
            });
        }
        if !ip.is_empty() {
            observables.push(OCSFObservable {
                name: cc::ACTOR_IP.to_string(),
                observable_type: "IP Address".to_string(),
                value: ip,
            });
        }
        let user_id = as_string(actor_raw, "user_id");
        if !user_id.is_empty() {
            observables.push(OCSFObservable {
                name: cc::ACTOR_USER_ID.to_string(),
                observable_type: "User".to_string(),
                value: user_id,
            });
        }

        let status_id = if any_contains(
            &activity_type.to_lowercase(),
            &["failed", "denied", "rejected", "error"],
        ) {
            STATUS_FAILURE
        } else {
            STATUS_SUCCESS
        };

        let mut event = AIBaseEvent::new(category_uid, class_uid, activity_id);
        event.severity_id = SEVERITY_INFORMATIONAL;
        event.status_id = status_id;
        event.message = activity_type;
        event.metadata.product = claude_compliance_product();
        event.actor = Some(build_actor(actor_raw));
        event.device = device;
        event.enrichments = enrichments;
        event.observables = observables;

        let created_at = as_string(activity, "created_at");
        if !created_at.is_empty() {
            event.time = created_at;
        }
        event
    }

    /// Maps a page of Activity records to OCSF events.
    pub fn map_activities(&self, activities: &[Value]) -> Vec<AIBaseEvent> {
        activities.iter().map(|a| self.map_activity(a)).collect()
    }
}
