"""AITF OCSF Exporter.

OTel SpanExporter that converts AI spans to OCSF Category 7 events
and exports them to SIEM/XDR endpoints, S3, or local files.

Based on forwarder architecture from the AITelemetry project.
"""

from __future__ import annotations

import json
import logging
import ssl
import threading
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from aitf.ocsf.compliance_mapper import ComplianceMapper
from aitf.ocsf.mapper import OCSFMapper
from aitf.ocsf.schema import AIBaseEvent

logger = logging.getLogger(__name__)

# Maximum output file size (500MB) to prevent unbounded growth
_MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024

# Localhost hosts allowed for HTTP (development only)
_DEV_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _validate_endpoint(endpoint: str, api_key: str | None = None) -> str:
    """Validate and sanitize an endpoint URL.

    Enforces HTTPS for non-localhost endpoints, especially when API keys
    are used. Prevents SSRF by restricting to http(s) schemes.
    """
    parsed = urlparse(endpoint)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed."
        )

    is_dev_host = parsed.hostname in _DEV_HOSTS if parsed.hostname else False

    # Enforce HTTPS when API key is present and not localhost
    if api_key and parsed.scheme != "https" and not is_dev_host:
        raise ValueError(
            "HTTPS is required when using API key authentication. "
            "Use https:// or connect to localhost for development."
        )

    # Warn if using HTTP even without API key (non-localhost)
    if parsed.scheme == "http" and not is_dev_host:
        logger.warning(
            "Using insecure HTTP endpoint. Consider using HTTPS for production."
        )

    return endpoint


def _validate_output_path(output_file: str) -> Path:
    """Validate output file path to prevent path traversal.

    Rejects any path containing '..' components, which could be used
    to escape the intended directory.
    """
    raw_path = Path(output_file)

    # Reject paths with '..' components to prevent traversal
    if ".." in raw_path.parts:
        raise ValueError(
            f"Path traversal detected in output path: {output_file!r} "
            f"contains '..' component"
        )

    return raw_path.resolve()


class OCSFExporter(SpanExporter):
    """Exports OTel spans as OCSF Category 7 AI events.

    Converts AI-related spans to OCSF events using OCSFMapper,
    enriches with compliance metadata, and exports to configured
    destinations.

    Usage:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        exporter = OCSFExporter(
            output_file="/var/log/aitf/ocsf_events.jsonl",
            compliance_frameworks=["nist_ai_rmf", "eu_ai_act", "mitre_atlas"],
        )
        provider = TracerProvider()
        provider.add_span_processor(BatchSpanProcessor(exporter))
    """

    def __init__(
        self,
        endpoint: str | None = None,
        output_file: str | None = None,
        compliance_frameworks: list[str] | None = None,
        include_raw_span: bool = False,
        api_key: str | None = None,
    ):
        # Validate endpoint URL
        if endpoint:
            self._endpoint = _validate_endpoint(endpoint, api_key)
        else:
            self._endpoint = None

        self._include_raw_span = include_raw_span
        self._api_key = api_key
        self._mapper = OCSFMapper()
        self._compliance_mapper = ComplianceMapper(frameworks=compliance_frameworks)
        self._event_count = 0
        self._lock = threading.Lock()
        self._file_lock = threading.Lock()

        # Validate and create output file path
        if output_file:
            resolved = _validate_output_path(output_file)
            self._output_file = str(resolved)
            resolved.parent.mkdir(parents=True, exist_ok=True)
        else:
            self._output_file = None

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        """Export spans as OCSF events."""
        events: list[dict[str, Any]] = []

        for span in spans:
            ocsf_event = self._mapper.map_span(span)
            if ocsf_event is None:
                continue

            # Enrich with compliance metadata
            event_type = self._classify_event(ocsf_event)
            if event_type:
                self._compliance_mapper.enrich_event(ocsf_event, event_type)

            event_dict = ocsf_event.model_dump(exclude_none=True)
            events.append(event_dict)
            with self._lock:
                self._event_count += 1

        if not events:
            return SpanExportResult.SUCCESS

        # Export to configured destinations
        try:
            if self._output_file:
                self._export_to_file(events)
            if self._endpoint:
                self._export_to_endpoint(events)
            return SpanExportResult.SUCCESS
        except Exception as exc:
            logger.error("OCSF export failed: %s", exc)
            return SpanExportResult.FAILURE

    def _export_to_file(self, events: list[dict[str, Any]]) -> None:
        """Write OCSF events to JSONL file with size limit enforcement."""
        with self._file_lock:
            output_path = Path(self._output_file)

            # Check file size to prevent unbounded growth
            if output_path.exists() and output_path.stat().st_size > _MAX_FILE_SIZE_BYTES:
                logger.warning(
                    "OCSF output file exceeds %d bytes, rotating",
                    _MAX_FILE_SIZE_BYTES,
                )
                rotated = output_path.with_suffix(".jsonl.old")
                output_path.rename(rotated)

            with open(self._output_file, "a") as f:
                for event in events:
                    f.write(json.dumps(event, default=str) + "\n")

    def _export_to_endpoint(self, events: list[dict[str, Any]]) -> None:
        """Send OCSF events to HTTP endpoint with TLS enforcement."""
        try:
            import urllib.request

            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"

            payload = json.dumps(events, default=str).encode("utf-8")
            req = urllib.request.Request(
                self._endpoint,
                data=payload,
                headers=headers,
                method="POST",
            )

            # Create SSL context for HTTPS connections with strict verification
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED

            with urllib.request.urlopen(req, timeout=30, context=ssl_context) as resp:
                if resp.status >= 400:
                    logger.error("OCSF endpoint returned %d", resp.status)
        except Exception as exc:
            logger.error("Failed to send to OCSF endpoint: %s", exc)
            raise

    def _classify_event(self, event: AIBaseEvent) -> str | None:
        """Classify an OCSF event for compliance mapping."""
        class_uid = event.class_uid
        mapping = {
            7001: "model_inference",
            7002: "agent_activity",
            7003: "tool_execution",
            7004: "data_retrieval",
            7005: "security_finding",
            7006: "supply_chain",
            7007: "governance",
            7008: "identity",
        }
        return mapping.get(class_uid)

    @property
    def event_count(self) -> int:
        with self._lock:
            return self._event_count

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
