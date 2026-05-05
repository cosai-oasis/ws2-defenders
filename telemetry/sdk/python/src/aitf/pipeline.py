"""AITF Dual Pipeline Provider.

Configures an OpenTelemetry ``TracerProvider`` with both OTLP and OCSF
export pipelines, enabling the same security-enriched spans to be sent to
OTLP-compatible backends (Jaeger, Grafana Tempo, Datadog, Elastic Security,
etc.) for observability and security analytics **and** OCSF-native SIEM/XDR
endpoints simultaneously.

Architecture::

    ┌──────────────────────────────────────────────────┐
    │              Your AI Application                  │
    │        (AITF Instrumentors create spans)          │
    └────────────────────┬─────────────────────────────┘
                         │ OTel Spans (with aitf.security.* attributes)
                         ▼
    ┌──────────────────────────────────────────────────┐
    │           DualPipelineProvider                     │
    │           (TracerProvider)                         │
    │                                                   │
    │  ┌─────────────┐          ┌──────────────────┐   │
    │  │ OTLP Export  │          │   OCSF Export    │   │
    │  │ (BatchSpan   │          │  (BatchSpan      │   │
    │  │  Processor)  │          │   Processor)     │   │
    │  └──────┬──────┘          └────────┬─────────┘   │
    └─────────┼──────────────────────────┼─────────────┘
              │                          │
              ▼                          ▼
    ┌──────────────────┐      ┌──────────────────────┐
    │  Observability & │      │  OCSF-Native SIEM /  │
    │  Security        │      │  Compliance           │
    │  (Jaeger, Tempo, │      │  (Splunk, Security   │
    │   Datadog, etc.) │      │   Lake, QRadar, etc.)│
    └──────────────────┘      └──────────────────────┘

Usage::

    from aitf.pipeline import DualPipelineProvider
    from aitf import AITFInstrumentor

    # One-liner: enable both OTLP + OCSF export
    provider = DualPipelineProvider(
        otlp_endpoint="http://localhost:4317",
        ocsf_output_file="/var/log/aitf/events.jsonl",
    )

    instrumentor = AITFInstrumentor(tracer_provider=provider.tracer_provider)
    instrumentor.instrument_all()

    # Spans flow to OTLP (observability & security) AND OCSF (SIEM) simultaneously.
"""

from __future__ import annotations

import logging
from typing import Any, Sequence

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)

from aitf.exporters.ocsf_exporter import OCSFExporter

logger = logging.getLogger(__name__)


class DualPipelineProvider:
    """Configures a TracerProvider with dual OTLP + OCSF export.

    This is the recommended entry point for production AITF deployments.
    OTLP carries security-enriched spans (including ``aitf.security.*``
    attributes) to OTLP-compatible backends for both observability and
    security analytics. OCSF provides additional schema normalization for
    SIEMs that require OCSF-native ingestion.

    Parameters
    ----------
    otlp_endpoint : str, optional
        OTLP gRPC endpoint (e.g., ``"http://localhost:4317"``).
        Requires ``opentelemetry-exporter-otlp-proto-grpc``.
    otlp_http_endpoint : str, optional
        OTLP HTTP/protobuf endpoint (e.g., ``"http://localhost:4318"``).
        Requires ``opentelemetry-exporter-otlp-proto-http``.
    otlp_headers : dict[str, str], optional
        Headers for OTLP export (e.g., auth tokens for Grafana Cloud).
    ocsf_output_file : str, optional
        Path to write OCSF JSONL events.
    ocsf_endpoint : str, optional
        HTTP endpoint for OCSF event delivery.
    ocsf_api_key : str, optional
        API key for OCSF HTTP endpoint.
    compliance_frameworks : list[str], optional
        Compliance frameworks for OCSF enrichment
        (e.g., ``["nist_ai_rmf", "eu_ai_act"]``).
    console : bool
        If ``True``, also print spans to the console (for development).
    additional_exporters : list[SpanExporter], optional
        Extra exporters (CEF syslog, immutable log, etc.).
    resource_attributes : dict[str, str], optional
        OpenTelemetry resource attributes.
    service_name : str
        Service name for OTel resource identification.
    batch_ocsf : bool
        If ``True`` (default), use ``BatchSpanProcessor`` for OCSF.
        Set ``False`` for ``SimpleSpanProcessor`` (useful for debugging).
    batch_otlp : bool
        If ``True`` (default), use ``BatchSpanProcessor`` for OTLP.
    """

    def __init__(
        self,
        *,
        otlp_endpoint: str | None = None,
        otlp_http_endpoint: str | None = None,
        otlp_headers: dict[str, str] | None = None,
        ocsf_output_file: str | None = None,
        ocsf_endpoint: str | None = None,
        ocsf_api_key: str | None = None,
        compliance_frameworks: list[str] | None = None,
        console: bool = False,
        additional_exporters: list[SpanExporter] | None = None,
        resource_attributes: dict[str, str] | None = None,
        service_name: str = "aitf-service",
        batch_ocsf: bool = True,
        batch_otlp: bool = True,
    ) -> None:
        # Build OTel Resource
        attrs = {"service.name": service_name}
        if resource_attributes:
            attrs.update(resource_attributes)
        resource = Resource.create(attrs)

        self._provider = TracerProvider(resource=resource)
        self._exporters: list[SpanExporter] = []

        # ── OTLP pipeline (observability & security analytics) ─────
        otlp_exporter = self._create_otlp_exporter(
            otlp_endpoint, otlp_http_endpoint, otlp_headers,
        )
        if otlp_exporter:
            processor_cls = BatchSpanProcessor if batch_otlp else SimpleSpanProcessor
            self._provider.add_span_processor(processor_cls(otlp_exporter))
            self._exporters.append(otlp_exporter)
            logger.info(
                "OTLP pipeline enabled: %s",
                otlp_endpoint or otlp_http_endpoint,
            )

        # ── OCSF pipeline (OCSF-native SIEM / compliance) ──────────
        if ocsf_output_file or ocsf_endpoint:
            ocsf_exporter = OCSFExporter(
                output_file=ocsf_output_file,
                endpoint=ocsf_endpoint,
                api_key=ocsf_api_key,
                compliance_frameworks=compliance_frameworks,
            )
            processor_cls = BatchSpanProcessor if batch_ocsf else SimpleSpanProcessor
            self._provider.add_span_processor(processor_cls(ocsf_exporter))
            self._exporters.append(ocsf_exporter)
            logger.info(
                "OCSF pipeline enabled: %s",
                ocsf_output_file or ocsf_endpoint,
            )

        # ── Console (development) ─────────────────────────────────
        if console:
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter
            self._provider.add_span_processor(
                SimpleSpanProcessor(ConsoleSpanExporter())
            )
            logger.info("Console span output enabled")

        # ── Additional exporters (CEF, immutable log, etc.) ───────
        if additional_exporters:
            for exporter in additional_exporters:
                self._provider.add_span_processor(
                    BatchSpanProcessor(exporter)
                )
                self._exporters.append(exporter)
                logger.info("Additional exporter enabled: %s", type(exporter).__name__)

        # Warn if no exporters configured
        if not self._exporters and not console:
            logger.warning(
                "DualPipelineProvider created with no exporters. "
                "Spans will be created but not exported. "
                "Set otlp_endpoint and/or ocsf_output_file."
            )

    @property
    def tracer_provider(self) -> TracerProvider:
        """The configured ``TracerProvider`` for use with AITF instrumentors."""
        return self._provider

    def set_as_global(self) -> None:
        """Register this provider as the global OTel ``TracerProvider``."""
        trace.set_tracer_provider(self._provider)

    def shutdown(self) -> None:
        """Flush and shut down all exporters."""
        self._provider.shutdown()

    @property
    def exporters(self) -> list[SpanExporter]:
        """List of active exporters (read-only)."""
        return list(self._exporters)

    @staticmethod
    def _create_otlp_exporter(
        grpc_endpoint: str | None,
        http_endpoint: str | None,
        headers: dict[str, str] | None,
    ) -> SpanExporter | None:
        """Create an OTLP exporter, preferring gRPC over HTTP.

        Returns None if no endpoint is configured or if the required
        package is not installed.
        """
        if grpc_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                    OTLPSpanExporter,
                )
                return OTLPSpanExporter(
                    endpoint=grpc_endpoint,
                    headers=headers or {},
                )
            except ImportError:
                logger.warning(
                    "opentelemetry-exporter-otlp-proto-grpc not installed. "
                    "Install with: pip install opentelemetry-exporter-otlp-proto-grpc"
                )
                return None

        if http_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter,
                )
                return OTLPSpanExporter(
                    endpoint=http_endpoint,
                    headers=headers or {},
                )
            except ImportError:
                logger.warning(
                    "opentelemetry-exporter-otlp-proto-http not installed. "
                    "Install with: pip install opentelemetry-exporter-otlp-proto-http"
                )
                return None

        return None


# ── Convenience constructors ──────────────────────────────────────────

def create_otel_only_provider(
    endpoint: str = "http://localhost:4317",
    *,
    service_name: str = "aitf-service",
    headers: dict[str, str] | None = None,
    resource_attributes: dict[str, str] | None = None,
) -> DualPipelineProvider:
    """Create a provider that exports only to an OTel backend (OTLP).

    Use when your backend consumes OTLP natively for both observability and
    security analytics, and you do not need OCSF-formatted output.
    """
    return DualPipelineProvider(
        otlp_endpoint=endpoint,
        otlp_headers=headers,
        service_name=service_name,
        resource_attributes=resource_attributes,
    )


def create_ocsf_only_provider(
    output_file: str = "/var/log/aitf/ocsf_events.jsonl",
    *,
    endpoint: str | None = None,
    api_key: str | None = None,
    compliance_frameworks: list[str] | None = None,
    service_name: str = "aitf-service",
    resource_attributes: dict[str, str] | None = None,
) -> DualPipelineProvider:
    """Create a provider that exports only to OCSF (SIEM/XDR).

    Use when your SIEM requires OCSF-native ingestion and you already
    have separate OTLP infrastructure for observability and security.
    """
    return DualPipelineProvider(
        ocsf_output_file=output_file,
        ocsf_endpoint=endpoint,
        ocsf_api_key=api_key,
        compliance_frameworks=compliance_frameworks,
        service_name=service_name,
        resource_attributes=resource_attributes,
    )


def create_dual_pipeline_provider(
    otlp_endpoint: str = "http://localhost:4317",
    ocsf_output_file: str = "/var/log/aitf/ocsf_events.jsonl",
    *,
    ocsf_endpoint: str | None = None,
    ocsf_api_key: str | None = None,
    otlp_headers: dict[str, str] | None = None,
    compliance_frameworks: list[str] | None = None,
    service_name: str = "aitf-service",
    resource_attributes: dict[str, str] | None = None,
) -> DualPipelineProvider:
    """Create a provider with both OTel and OCSF export pipelines.

    This is the recommended setup for production deployments.
    """
    return DualPipelineProvider(
        otlp_endpoint=otlp_endpoint,
        otlp_headers=otlp_headers,
        ocsf_output_file=ocsf_output_file,
        ocsf_endpoint=ocsf_endpoint,
        ocsf_api_key=ocsf_api_key,
        compliance_frameworks=compliance_frameworks,
        service_name=service_name,
        resource_attributes=resource_attributes,
    )
