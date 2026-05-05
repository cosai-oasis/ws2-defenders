"""AITF Exporters.

Provides OTel SpanExporters for both OCSF-formatted security output (SIEM,
XDR, data lakes) and standard OpenTelemetry export (OTLP to Jaeger, Grafana
Tempo, Datadog, etc.).

AITF supports dual-pipeline export where the same spans flow to both:
- **OTLP** → OTLP-compatible backends for observability and security analytics
- **OCSF** → OCSF-native SIEM/XDR for normalized security events

See :mod:`aitf.pipeline` for the recommended ``DualPipelineProvider``.
"""

from aitf.exporters.ocsf_exporter import OCSFExporter

__all__ = ["OCSFExporter"]
