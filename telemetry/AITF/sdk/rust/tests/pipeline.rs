//! Tests for the dual-pipeline helper.

use std::time::{SystemTime, UNIX_EPOCH};

use aitf::ocsf::mapper::SpanData;
use aitf::pipeline::DualPipeline;

fn temp_dir() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aitf_pipeline_test_{nanos}_{:?}", std::thread::current().id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn inference_span() -> SpanData {
    SpanData::new("chat gpt-4o")
        .with_attr("gen_ai.provider.name", "openai")
        .with_attr("gen_ai.request.model", "gpt-4o")
        .with_attr("gen_ai.operation.name", "chat")
}

#[test]
fn fans_out_to_all_sinks() {
    let dir = temp_dir();
    let ocsf = dir.join("events.jsonl");
    let cef = dir.join("events.cef");
    let imm = dir.join("audit.log");

    let mut pipeline = DualPipeline::builder()
        .with_ocsf_output_file(&ocsf)
        .with_cef_output_file(&cef)
        .with_immutable_log_file(&imm)
        .with_service_name("svc")
        .build()
        .unwrap();

    let event = pipeline.process_span(&inference_span()).unwrap();
    assert!(event.is_some());
    let event = event.unwrap();
    assert_eq!(event.class_uid, 6003); // reused API Activity

    // OCSF JSONL written and round-trips.
    let ocsf_txt = std::fs::read_to_string(&ocsf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(ocsf_txt.lines().next().unwrap()).unwrap();
    assert_eq!(parsed["class_uid"], 6003);

    // CEF line written with the OCSF class name.
    let cef_txt = std::fs::read_to_string(&cef).unwrap();
    assert!(cef_txt.contains("API Activity"), "cef: {cef_txt}");
    assert!(cef_txt.starts_with("CEF:"));

    // Immutable log written and verifies.
    let result = aitf::exporters::verify_immutable_log(&imm);
    assert!(result.valid, "chain should verify");
    assert_eq!(result.entries_checked, 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compliance_enrichment_applied() {
    let mut pipeline = DualPipeline::builder().with_compliance().build().unwrap();
    let event = pipeline.process_span(&inference_span()).unwrap().unwrap();
    let compliance = event.compliance.expect("compliance enrichment");
    assert!(compliance.nist_ai_rmf.is_some());
    assert!(compliance.csa_aicm.is_some());
}

#[test]
fn non_ai_span_returns_none() {
    let mut pipeline = DualPipeline::builder().build().unwrap();
    let span = SpanData::new("http.request GET /").with_attr("http.method", "GET");
    assert!(pipeline.process_span(&span).unwrap().is_none());
}

#[test]
fn process_spans_batch() {
    let dir = temp_dir();
    let mut pipeline = DualPipeline::builder()
        .with_ocsf_output_file(dir.join("e.jsonl"))
        .build()
        .unwrap();
    let spans = [inference_span(), inference_span()];
    let events = pipeline.process_spans(spans.iter()).unwrap();
    assert_eq!(events.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}
