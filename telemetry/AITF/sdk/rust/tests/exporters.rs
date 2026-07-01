//! Tests for the AITF exporters (OCSF JSONL, CEF syslog, immutable log).

use aitf::exporters::cef_syslog::{class_uid_to_name, sanitize_cef_value, CefSyslogExporter};
use aitf::exporters::immutable_log::{verify_immutable_log, ImmutableLogExporter};
use aitf::exporters::OcsfExporter;
use aitf::ocsf::AIBaseEvent;

fn sample_event() -> AIBaseEvent {
    let mut e = AIBaseEvent::new(6, 6003, 1);
    e.message = "chat gpt-4o".to_string();
    e.ai_model = Some("gpt-4o".to_string());
    e
}

#[test]
fn test_ocsf_jsonl_round_trips() {
    let exporter = OcsfExporter::new();
    let events = vec![sample_event(), sample_event()];
    let jsonl = exporter.to_jsonl(&events).unwrap();
    let lines: Vec<&str> = jsonl.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let parsed: AIBaseEvent = serde_json::from_str(line).unwrap();
        assert_eq!(parsed.class_uid, 6003);
        assert_eq!(parsed.activity_id, 1);
    }
}

#[test]
fn test_ocsf_append_to_file() {
    let dir = std::env::temp_dir().join(format!("aitf_ocsf_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.jsonl");
    let _ = std::fs::remove_file(&path);

    let exporter = OcsfExporter::new();
    exporter.append_to_file(&path, &[sample_event()]).unwrap();
    exporter.append_to_file(&path, &[sample_event()]).unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents.lines().count(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_cef_contains_name_and_cs1() {
    let exporter = CefSyslogExporter::new();
    // class 6003 -> "API Activity"
    let line = exporter.to_cef(&sample_event());
    assert!(line.starts_with("CEF:0|AITF|AI-Telemetry-Framework|1.0.0|"));
    assert!(line.contains("|API Activity|"), "line: {line}");
    assert!(line.contains("cs1=6003"), "line: {line}");
    assert!(line.contains("cs1Label=ocsf_class_uid"));
    assert!(line.contains("cs2=1"));

    // A detection finding maps to a different name.
    let mut finding = AIBaseEvent::new(2, 2004, 1);
    finding.message = "security.prompt_injection".to_string();
    let line = exporter.to_cef(&finding);
    assert!(line.contains("|Detection Finding|"), "line: {line}");
    assert!(line.contains("cs1=2004"));
}

#[test]
fn test_class_uid_to_name_and_sanitize() {
    assert_eq!(class_uid_to_name(9003), Some("Agent Communication"));
    assert_eq!(class_uid_to_name(6001), Some("Web Resources Activity"));
    assert_eq!(class_uid_to_name(12345), None);
    assert_eq!(sanitize_cef_value("a|b=c\\d"), "a\\|b\\=c\\\\d");
}

#[test]
fn test_immutable_log_verifies() {
    let dir = std::env::temp_dir().join(format!("aitf_imm_{}_{}", std::process::id(), 1));
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_dir_all(&dir);

    let mut exporter = ImmutableLogExporter::new(&path).unwrap();
    exporter.export(&[sample_event(), sample_event()]).unwrap();
    exporter.export(&[sample_event()]).unwrap();
    assert_eq!(exporter.event_count(), 3);
    assert_eq!(exporter.current_seq(), 3);

    let result = verify_immutable_log(&path);
    assert!(result.valid, "verify failed: {:?}", result.error);
    assert_eq!(result.entries_checked, 3);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_immutable_log_detects_tampering() {
    let dir = std::env::temp_dir().join(format!("aitf_imm_{}_{}", std::process::id(), 2));
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_dir_all(&dir);

    let mut exporter = ImmutableLogExporter::new(&path).unwrap();
    exporter.export(&[sample_event(), sample_event(), sample_event()]).unwrap();

    // Tamper with the second entry's event payload.
    let contents = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
    lines[1] = lines[1].replace("chat gpt-4o", "tampered message");
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let result = verify_immutable_log(&path);
    assert!(!result.valid);
    assert!(result.first_invalid_seq.is_some());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_immutable_log_resumes_chain() {
    let dir = std::env::temp_dir().join(format!("aitf_imm_{}_{}", std::process::id(), 3));
    let path = dir.join("audit.jsonl");
    let _ = std::fs::remove_dir_all(&dir);

    {
        let mut e = ImmutableLogExporter::new(&path).unwrap();
        e.export(&[sample_event()]).unwrap();
    }
    {
        let mut e = ImmutableLogExporter::new(&path).unwrap();
        assert_eq!(e.current_seq(), 1);
        e.export(&[sample_event()]).unwrap();
    }
    let result = verify_immutable_log(&path);
    assert!(result.valid);
    assert_eq!(result.entries_checked, 2);

    let _ = std::fs::remove_dir_all(&dir);
}
