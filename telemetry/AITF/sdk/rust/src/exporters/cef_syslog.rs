//! CEF (Common Event Format) syslog exporter.
//!
//! Renders [`AIBaseEvent`] values as CEF syslog message strings for SIEMs that
//! do not support OCSF natively (ArcSight, QRadar, LogRhythm, Elastic Security,
//! etc.). Ported from the Go `exporters/cef_syslog.go`; the class-UID name map,
//! the OCSF-severity -> CEF-severity map, header/extension layout, and value
//! sanitization match that implementation.

use serde_json::Value;

use crate::ocsf::AIBaseEvent;

/// Maps OCSF `severity_id` to a CEF severity (0..10).
fn ocsf_to_cef_severity(severity_id: i64) -> i64 {
    match severity_id {
        0 => 0,  // Unknown
        1 => 1,  // Informational
        2 => 3,  // Low
        3 => 5,  // Medium
        4 => 7,  // High
        5 => 9,  // Critical
        6 => 10, // Fatal
        _ => 0,
    }
}

/// Returns the display name for a reused OCSF class UID, or `None` if unknown.
pub fn class_uid_to_name(class_uid: i64) -> Option<&'static str> {
    let name = match class_uid {
        2002 => "Vulnerability Finding",
        2003 => "Compliance Finding",
        2004 => "Detection Finding",
        3001 => "Account Change",
        3002 => "Authentication",
        3004 => "Entity Management",
        3005 => "User Access Management",
        5001 => "Inventory Info",
        6001 => "Web Resources Activity",
        6002 => "Application Lifecycle",
        6003 => "API Activity",
        6005 => "Datastore Activity",
        9001 => "Agent Activity",
        9002 => "Delegation Activity",
        9003 => "Agent Communication",
        _ => return None,
    };
    Some(name)
}

/// Escapes special characters in a CEF extension value (`\ | = \n \r`).
pub fn sanitize_cef_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Escapes special characters in a CEF header field (`\ |`).
pub fn sanitize_cef_header(value: &str) -> String {
    value.replace('\\', "\\\\").replace('|', "\\|")
}

fn get_int(m: &Value, key: &str, default: i64) -> i64 {
    match m.get(key) {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(default),
        _ => default,
    }
}

fn get_string(m: &Value, key: &str, default: &str) -> String {
    match m.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => default.to_string(),
        Some(other) => other.to_string(),
    }
}

/// Renders an OCSF event (as a JSON object) to a CEF syslog message string.
fn ocsf_value_to_cef(event: &Value, vendor: &str, product: &str, version: &str) -> String {
    let class_uid = get_int(event, "class_uid", 0);
    let activity_id = get_int(event, "activity_id", 0);
    let type_uid = get_int(event, "type_uid", class_uid * 100 + activity_id);
    let severity_id = get_int(event, "severity_id", 1);

    let signature_id = type_uid.to_string();
    let name = class_uid_to_name(class_uid)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("OCSF-{class_uid}"));
    let cef_severity = ocsf_to_cef_severity(severity_id);

    let mut ext: Vec<String> = Vec::new();

    // Timestamp
    let event_time = get_string(event, "time", "");
    ext.push(format!("rt={}", sanitize_cef_value(&event_time)));

    // Message
    let msg = get_string(event, "message", "");
    if !msg.is_empty() {
        ext.push(format!("msg={}", sanitize_cef_value(&msg)));
    }

    // OCSF identifiers
    ext.push(format!("cs1={class_uid}"));
    ext.push("cs1Label=ocsf_class_uid".to_string());
    ext.push(format!("cs2={activity_id}"));
    ext.push("cs2Label=ocsf_activity_id".to_string());
    ext.push(format!("cs3={}", get_int(event, "category_uid", 6)));
    ext.push("cs3Label=ocsf_category_uid".to_string());

    // Model information
    if let Some(model_info) = event.get("model").filter(|v| v.is_object()) {
        let model_id = get_string(model_info, "model_id", "");
        if !model_id.is_empty() {
            ext.push(format!("cs4={}", sanitize_cef_value(&model_id)));
            ext.push("cs4Label=ai_model_id".to_string());
        }
        let provider = get_string(model_info, "provider", "");
        if !provider.is_empty() {
            ext.push(format!("cs5={}", sanitize_cef_value(&provider)));
            ext.push("cs5Label=ai_provider".to_string());
        }
    }

    // Agent name
    let agent_name = get_string(event, "agent_name", "");
    if !agent_name.is_empty() {
        ext.push(format!("suser={}", sanitize_cef_value(&agent_name)));
    }

    // Tool name
    let tool_name = get_string(event, "tool_name", "");
    if !tool_name.is_empty() {
        ext.push(format!("cs6={}", sanitize_cef_value(&tool_name)));
        ext.push("cs6Label=ai_tool_name".to_string());
    }

    // Security finding
    if let Some(finding) = event.get("finding").filter(|v| v.is_object()) {
        let ft = get_string(finding, "finding_type", "");
        if !ft.is_empty() {
            ext.push(format!("cat={}", sanitize_cef_value(&ft)));
        }
        if let Some(rs) = finding.get("risk_score") {
            ext.push(format!("cn1={}", json_scalar(rs)));
            ext.push("cn1Label=risk_score".to_string());
        }
        let owasp = get_string(finding, "owasp_category", "");
        if !owasp.is_empty() {
            ext.push(format!("flexString1={}", sanitize_cef_value(&owasp)));
            ext.push("flexString1Label=owasp_category".to_string());
        }
    }

    // Token usage
    if let Some(usage) = event.get("usage").filter(|v| v.is_object()) {
        if let Some(it) = usage.get("input_tokens") {
            ext.push(format!("cn2={}", json_scalar(it)));
            ext.push("cn2Label=input_tokens".to_string());
        }
        if let Some(ot) = usage.get("output_tokens") {
            ext.push(format!("cn3={}", json_scalar(ot)));
            ext.push("cn3Label=output_tokens".to_string());
        }
    }

    // Cost
    if let Some(cost) = event.get("cost").filter(|v| v.is_object()) {
        if let Some(tc) = cost.get("total_cost_usd") {
            ext.push(format!("cfp1={}", json_scalar(tc)));
            ext.push("cfp1Label=total_cost_usd".to_string());
        }
    }

    let extension_str = ext.join(" ");

    format!(
        "CEF:0|{}|{}|{}|{}|{}|{}|{}",
        sanitize_cef_header(vendor),
        sanitize_cef_header(product),
        sanitize_cef_header(version),
        signature_id,
        sanitize_cef_header(&name),
        cef_severity,
        extension_str,
    )
}

/// Renders a JSON scalar the way Go's `fmt.Sprintf("%v")` would (no quotes).
fn json_scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "<nil>".to_string(),
        other => other.to_string(),
    }
}

/// Exports [`AIBaseEvent`] values as CEF syslog message strings.
#[derive(Debug, Clone)]
pub struct CefSyslogExporter {
    vendor: String,
    product: String,
    version: String,
}

impl Default for CefSyslogExporter {
    fn default() -> Self {
        CefSyslogExporter {
            vendor: "AITF".to_string(),
            product: "AI-Telemetry-Framework".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

impl CefSyslogExporter {
    /// Creates an exporter with AITF default header fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the CEF DeviceVendor / DeviceProduct / DeviceVersion header fields.
    pub fn with_device(
        vendor: impl Into<String>,
        product: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        CefSyslogExporter {
            vendor: vendor.into(),
            product: product.into(),
            version: version.into(),
        }
    }

    /// Converts a single event to a CEF syslog message string.
    pub fn to_cef(&self, event: &AIBaseEvent) -> String {
        let value = serde_json::to_value(event).unwrap_or(Value::Null);
        ocsf_value_to_cef(&value, &self.vendor, &self.product, &self.version)
    }

    /// Converts a batch of events to CEF syslog message strings.
    pub fn to_cef_batch(&self, events: &[AIBaseEvent]) -> Vec<String> {
        events.iter().map(|e| self.to_cef(e)).collect()
    }
}
