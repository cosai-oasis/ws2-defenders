//! Interop with the official AITF Rust SDK (the `aitf` crate).
//!
//! **Feature-gated (`aitf-sdk`), off by default.** The `aitf` crate is the AITF
//! 0.2 reference *instrumentation* SDK — what an instrumented application uses
//! to emit AITF telemetry. AgentDR sits on the other side: it *ingests* that
//! telemetry. We do not adopt the SDK's types internally (AgentDR carries a much
//! richer endpoint-detection model); instead this module uses the SDK's
//! `OcsfMapper` as a **conformance oracle** so AgentDR's own OTLP→OCSF class
//! mapping (see [`crate::models::AiOperation::ocsf_class_uid`]) is guaranteed to
//! stay in lock-step with upstream as AITF evolves.
//!
//! NOTE: the API calls below follow the AITF 0.2 SDK docs (`SpanData::new`,
//! `.with_attr`, `OcsfMapper::new().map_span`). Because the crate is beta and
//! not yet on crates.io, this module is only compiled under the opt-in feature;
//! adjust the calls here if the upstream API shifts. The reused `class_uid` is
//! read out of the serialized event so we don't depend on the exact field
//! accessor shape.
//!
//! To enable: uncomment the `aitf` dependency and set `aitf-sdk = ["dep:aitf"]`
//! in `Cargo.toml`, then `cargo build --features aitf-sdk`. This path is not
//! exercised by the default offline/CI build.

use aitf::{OcsfMapper, SpanData};

/// Map a set of `gen_ai.*` span attributes to a reused OCSF `class_uid` using
/// the official AITF SDK. Returns `None` if the SDK could not map the span.
pub fn sdk_ocsf_class_uid(span_name: &str, attrs: &[(&str, &str)]) -> Option<u32> {
    let mut span = SpanData::new(span_name);
    for (k, v) in attrs {
        span = span.with_attr(*k, *v);
    }
    let event = OcsfMapper::new().map_span(&span).ok()?;
    let value = serde_json::to_value(&event).ok()?;
    value
        .get("class_uid")
        .and_then(|c| c.as_u64())
        .map(|n| n as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AiOperation;

    /// AgentDR's own mapping for an LLM-inference span must agree with the
    /// SDK's OcsfMapper. If AITF re-numbers a class upstream, this test fails
    /// and tells us exactly where AgentDR has drifted.
    #[test]
    fn inference_class_matches_sdk() {
        let sdk = sdk_ocsf_class_uid(
            "chat gpt-4o",
            &[("gen_ai.system", "openai"), ("gen_ai.request.model", "gpt-4o")],
        );
        assert_eq!(sdk, Some(AiOperation::Inference.ocsf_class_uid()));
    }
}
