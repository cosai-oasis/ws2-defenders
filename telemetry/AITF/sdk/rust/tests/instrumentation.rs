//! Integration tests for the OTel-backed instrumentation helpers (feature `otel`).

#![cfg(feature = "otel")]

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{Key, Value};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};

use aitf::instrumentation::{
    AgentInstrumentor, InferenceConfig, LlmInstrumentor, SessionConfig,
};
use aitf::semconv::{agent, gen_ai};

fn attr<'a>(
    span: &'a opentelemetry_sdk::trace::SpanData,
    key: &str,
) -> Option<&'a Value> {
    span.attributes
        .iter()
        .find(|kv| kv.key == Key::from(key.to_string()))
        .map(|kv| &kv.value)
}

#[test]
fn inference_span_records_model_and_usage() {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let tracer = provider.tracer("test");

    let llm = LlmInstrumentor::with_tracer(tracer);
    let mut span = llm.trace_inference(InferenceConfig {
        model: "gpt-4o".into(),
        provider: "openai".into(),
        operation: "chat".into(),
        ..Default::default()
    });
    span.set_prompt("hello");
    span.set_usage(100, 50);
    span.set_response("resp-1", "gpt-4o", &["stop".to_string()]);
    span.set_completion("hi");
    span.end(Ok::<_, std::io::Error>(()));

    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let s = &spans[0];

    assert_eq!(s.name, "chat gpt-4o");
    assert_eq!(
        attr(s, gen_ai::REQUEST_MODEL),
        Some(&Value::String("gpt-4o".into()))
    );
    assert_eq!(
        attr(s, gen_ai::USAGE_INPUT_TOKENS),
        Some(&Value::I64(100))
    );
    assert_eq!(
        attr(s, gen_ai::USAGE_OUTPUT_TOKENS),
        Some(&Value::I64(50))
    );
}

#[test]
fn agent_session_and_step_record_attributes() {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let tracer = provider.tracer("test");

    let instr = AgentInstrumentor::with_tracer(tracer);
    let mut session = instr.trace_session(SessionConfig {
        agent_name: "orchestrator".into(),
        agent_id: "agent-1".into(),
        session_id: "sess-1".into(),
        ..Default::default()
    });

    let mut step = session.step("reason");
    step.set_thought("think about it");
    step.set_action("call_tool");
    step.end(Ok::<_, std::io::Error>(()));

    session.end(Ok::<_, std::io::Error>(()));

    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 2);

    let session_span = spans
        .iter()
        .find(|s| s.name == "agent.session orchestrator")
        .expect("session span");
    assert_eq!(
        attr(session_span, agent::NAME),
        Some(&Value::String("orchestrator".into()))
    );
    assert_eq!(
        attr(session_span, agent::SESSION_TURN_COUNT),
        Some(&Value::I64(1))
    );

    let step_span = spans
        .iter()
        .find(|s| s.name == "agent.step.reason orchestrator")
        .expect("step span");
    assert_eq!(
        attr(step_span, agent::STEP_THOUGHT),
        Some(&Value::String("think about it".into()))
    );
    assert_eq!(
        attr(step_span, agent::STEP_ACTION),
        Some(&Value::String("call_tool".into()))
    );
}
