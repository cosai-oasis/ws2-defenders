//! Dual-pipeline helper.
//!
//! [`DualPipeline`] wires AITF's OCSF/SIEM side of the dual-pipeline pattern:
//! it maps a [`SpanData`] to a reused-OCSF [`AIBaseEvent`], optionally enriches
//! it with compliance-control mappings, and fans the event out to the
//! configured exporters (OCSF JSONL/HTTP, CEF, immutable hash-chained log) —
//! all from a single instrumentation pass.
//!
//! Unlike the Go/Python SDKs, the Rust crate does not depend on the
//! OpenTelemetry SDK, so the **OTLP** side of the dual pipeline stays the
//! application's own OTel setup; the same span attributes feed both. This type
//! owns the OCSF/SIEM half.
//!
//! ```
//! use aitf::pipeline::DualPipeline;
//! use aitf::ocsf::mapper::SpanData;
//!
//! let mut pipeline = DualPipeline::builder()
//!     .with_compliance()                       // enrich with all frameworks
//!     .build()
//!     .unwrap();
//!
//! let span = SpanData::new("chat gpt-4o")
//!     .with_attr("gen_ai.provider.name", "openai")
//!     .with_attr("gen_ai.request.model", "gpt-4o");
//! let event = pipeline.process_span(&span).unwrap();
//! assert!(event.is_some());
//! ```

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::exporters::{CefSyslogExporter, ImmutableLogExporter, OcsfExporter};
use crate::ocsf::compliance::ComplianceMapper;
use crate::ocsf::mapper::{OcsfMapper, SpanData};
use crate::ocsf::schema::AIBaseEvent;

/// Builder for [`DualPipeline`].
#[derive(Default)]
pub struct DualPipelineBuilder {
    ocsf_output_file: Option<PathBuf>,
    ocsf_endpoint: Option<String>,
    ocsf_api_key: Option<String>,
    cef_output_file: Option<PathBuf>,
    immutable_log_file: Option<PathBuf>,
    enable_compliance: bool,
    compliance_frameworks: Option<Vec<String>>,
    service_name: Option<String>,
}

impl DualPipelineBuilder {
    /// Append OCSF events as JSONL to a file.
    pub fn with_ocsf_output_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.ocsf_output_file = Some(path.into());
        self
    }

    /// POST OCSF events to an HTTP endpoint (requires the `client` feature at
    /// run time; the setting is accepted regardless so config is portable).
    pub fn with_ocsf_endpoint(
        mut self,
        endpoint: impl Into<String>,
        api_key: Option<String>,
    ) -> Self {
        self.ocsf_endpoint = Some(endpoint.into());
        self.ocsf_api_key = api_key;
        self
    }

    /// Append CEF lines to a syslog/file sink.
    pub fn with_cef_output_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.cef_output_file = Some(path.into());
        self
    }

    /// Append events to an immutable, SHA-256 hash-chained audit log.
    pub fn with_immutable_log_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.immutable_log_file = Some(path.into());
        self
    }

    /// Enrich events with compliance-control mappings for the given frameworks
    /// (e.g. `["nist_ai_rmf", "eu_ai_act"]`).
    pub fn with_compliance_frameworks(mut self, frameworks: Vec<String>) -> Self {
        self.enable_compliance = true;
        self.compliance_frameworks = Some(frameworks);
        self
    }

    /// Enrich events with all compliance frameworks.
    pub fn with_compliance(mut self) -> Self {
        self.enable_compliance = true;
        self.compliance_frameworks = None;
        self
    }

    /// Set the logical service name (recorded on the pipeline for reference).
    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = Some(name.into());
        self
    }

    /// Build the pipeline. Fails only if the immutable log file cannot be opened.
    pub fn build(self) -> io::Result<DualPipeline> {
        let compliance = if self.enable_compliance {
            match &self.compliance_frameworks {
                Some(fw) => {
                    let refs: Vec<&str> = fw.iter().map(String::as_str).collect();
                    Some(ComplianceMapper::new(Some(&refs)))
                }
                None => Some(ComplianceMapper::new(None)),
            }
        } else {
            None
        };

        let immutable = match self.immutable_log_file {
            Some(path) => Some(ImmutableLogExporter::new(path)?),
            None => None,
        };

        let cef = self
            .cef_output_file
            .map(|path| (CefSyslogExporter::new(), path));

        Ok(DualPipeline {
            mapper: OcsfMapper::new(),
            compliance,
            ocsf_exporter: OcsfExporter::new(),
            ocsf_output_file: self.ocsf_output_file,
            ocsf_endpoint: self.ocsf_endpoint,
            ocsf_api_key: self.ocsf_api_key,
            cef,
            immutable,
            service_name: self.service_name,
        })
    }
}

/// Maps spans to OCSF events and fans them out to the configured exporters.
pub struct DualPipeline {
    mapper: OcsfMapper,
    compliance: Option<ComplianceMapper>,
    ocsf_exporter: OcsfExporter,
    ocsf_output_file: Option<PathBuf>,
    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    ocsf_endpoint: Option<String>,
    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    ocsf_api_key: Option<String>,
    cef: Option<(CefSyslogExporter, PathBuf)>,
    immutable: Option<ImmutableLogExporter>,
    service_name: Option<String>,
}

impl DualPipeline {
    /// Start building a pipeline.
    pub fn builder() -> DualPipelineBuilder {
        DualPipelineBuilder::default()
    }

    /// The configured service name, if any.
    pub fn service_name(&self) -> Option<&str> {
        self.service_name.as_deref()
    }

    /// Map a span to an OCSF event, enrich it, export it, and return it.
    ///
    /// Returns `Ok(None)` for spans that are not AI-related.
    pub fn process_span(&mut self, span: &SpanData) -> io::Result<Option<AIBaseEvent>> {
        let Some(mut event) = self.mapper.map_span(span) else {
            return Ok(None);
        };
        if let Some(cm) = &self.compliance {
            if let Some(event_type) = self.mapper.classify_span(span) {
                cm.enrich_event(&mut event, event_type);
            }
        }
        self.export(&event)?;
        Ok(Some(event))
    }

    /// Process many spans, returning the events that were produced.
    pub fn process_spans<'a, I>(&mut self, spans: I) -> io::Result<Vec<AIBaseEvent>>
    where
        I: IntoIterator<Item = &'a SpanData>,
    {
        let mut out = Vec::new();
        for span in spans {
            if let Some(event) = self.process_span(span)? {
                out.push(event);
            }
        }
        Ok(out)
    }

    /// Export an already-built event to all configured sinks.
    pub fn process_event(&mut self, event: &AIBaseEvent) -> io::Result<()> {
        self.export(event)
    }

    fn export(&mut self, event: &AIBaseEvent) -> io::Result<()> {
        let batch = std::slice::from_ref(event);

        if let Some(path) = &self.ocsf_output_file {
            self.ocsf_exporter.append_to_file(path, batch)?;
        }

        if let Some((cef, path)) = &self.cef {
            let line = cef.to_cef(event);
            append_line(path, &line)?;
        }

        if let Some(imm) = &mut self.immutable {
            imm.export(batch)?;
        }

        #[cfg(feature = "client")]
        if let Some(endpoint) = &self.ocsf_endpoint {
            self.ocsf_exporter
                .post_to_endpoint(endpoint, batch, self.ocsf_api_key.as_deref(), &[])
                .map_err(io::Error::other)?;
        }

        Ok(())
    }
}

fn append_line(path: &Path, line: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")
}
