"""AITF CEF Syslog Exporter.

OTel SpanExporter that converts AI spans to CEF (Common Event Format) syslog
messages and sends them to any SIEM that supports CEF ingestion -- including
vendors that do not support OCSF natively.

Supported destinations:
    - ArcSight (Micro Focus / OpenText)
    - QRadar (IBM)
    - LogRhythm
    - Trend Vision One (Service Gateway)
    - Splunk (via syslog input)
    - Elastic Security (via Filebeat CEF module)
    - Any syslog-compatible receiver (RFC 5424 / RFC 3164)

CEF format:
    CEF:0|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension

Transport:
    - TCP with TLS (recommended for production)
    - TCP without TLS (development only)
    - UDP (lossy, use only for high-throughput non-critical events)

Usage:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from aitf.exporters.cef_syslog_exporter import CEFSyslogExporter

    exporter = CEFSyslogExporter(
        host="siem.example.com",
        port=6514,
        protocol="tcp",
        tls=True,
    )
    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(exporter))
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from typing import Any, Sequence

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from aitf.ocsf.mapper import OCSFMapper
from aitf.ocsf.schema import AIBaseEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CEF severity mapping from OCSF severity_id
# ---------------------------------------------------------------------------

_OCSF_TO_CEF_SEVERITY: dict[int, int] = {
    0: 0,   # Unknown -> 0
    1: 1,   # Informational -> 1
    2: 3,   # Low -> 3
    3: 5,   # Medium -> 5
    4: 7,   # High -> 7
    5: 9,   # Critical -> 9
    6: 10,  # Fatal -> 10
}

_CLASS_UID_TO_NAME: dict[int, str] = {
    7001: "AI Model Inference",
    7002: "AI Agent Activity",
    7003: "AI Tool Execution",
    7004: "AI Data Retrieval",
    7005: "AI Security Finding",
    7006: "AI Supply Chain Event",
    7007: "AI Governance Event",
    7008: "AI Identity Event",
    7009: "AI Model Operations Event",
    7010: "AI Asset Inventory Event",
}


def _sanitize_cef_value(value: str) -> str:
    """Escape characters that have special meaning in CEF extension values."""
    value = value.replace("\\", "\\\\")
    value = value.replace("|", "\\|")
    value = value.replace("=", "\\=")
    value = value.replace("\n", "\\n")
    value = value.replace("\r", "\\r")
    return value


def _sanitize_cef_header(value: str) -> str:
    """Escape characters in CEF header fields (only backslash and pipe)."""
    value = value.replace("\\", "\\\\")
    value = value.replace("|", "\\|")
    return value


def ocsf_event_to_cef(
    event: dict[str, Any],
    vendor: str = "AITF",
    product: str = "AI-Telemetry-Framework",
    version: str = "1.0.0",
) -> str:
    """Convert an OCSF event dict to a CEF syslog message.

    CEF format:
        CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

    Args:
        event: OCSF event dictionary.
        vendor: CEF DeviceVendor field.
        product: CEF DeviceProduct field.
        version: CEF DeviceVersion field.

    Returns:
        Formatted CEF string.
    """
    class_uid = event.get("class_uid", 0)
    activity_id = event.get("activity_id", 0)
    type_uid = event.get("type_uid", class_uid * 100 + activity_id)
    severity_id = event.get("severity_id", 1)

    signature_id = str(type_uid)
    name = _sanitize_cef_header(
        _CLASS_UID_TO_NAME.get(class_uid, f"OCSF-{class_uid}")
    )
    cef_severity = _OCSF_TO_CEF_SEVERITY.get(severity_id, 1)

    # Build extension key=value pairs
    extensions: list[str] = []

    # Timestamp
    event_time = event.get("time", datetime.now(timezone.utc).isoformat())
    extensions.append(f"rt={_sanitize_cef_value(str(event_time))}")

    # Message
    message = event.get("message", "")
    if message:
        extensions.append(f"msg={_sanitize_cef_value(str(message))}")

    # OCSF class identifiers
    extensions.append(f"cs1={class_uid}")
    extensions.append("cs1Label=ocsf_class_uid")
    extensions.append(f"cs2={activity_id}")
    extensions.append("cs2Label=ocsf_activity_id")
    extensions.append(f"cs3={event.get('category_uid', 7)}")
    extensions.append("cs3Label=ocsf_category_uid")

    # Model information
    model_info = event.get("model", {})
    if isinstance(model_info, dict):
        if model_info.get("model_id"):
            extensions.append(
                f"cs4={_sanitize_cef_value(str(model_info['model_id']))}"
            )
            extensions.append("cs4Label=ai_model_id")
        if model_info.get("provider"):
            extensions.append(
                f"cs5={_sanitize_cef_value(str(model_info['provider']))}"
            )
            extensions.append("cs5Label=ai_provider")

    # Agent name
    agent_name = event.get("agent_name", "")
    if agent_name:
        extensions.append(f"suser={_sanitize_cef_value(str(agent_name))}")

    # Tool / MCP server
    tool_name = event.get("tool_name", "")
    if tool_name:
        extensions.append(f"cs6={_sanitize_cef_value(str(tool_name))}")
        extensions.append("cs6Label=ai_tool_name")

    # Security finding details
    finding = event.get("finding", {})
    if isinstance(finding, dict):
        if finding.get("finding_type"):
            extensions.append(
                f"cat={_sanitize_cef_value(str(finding['finding_type']))}"
            )
        if finding.get("risk_score") is not None:
            extensions.append(f"cn1={finding['risk_score']}")
            extensions.append("cn1Label=risk_score")
        if finding.get("owasp_category"):
            extensions.append(
                f"flexString1={_sanitize_cef_value(str(finding['owasp_category']))}"
            )
            extensions.append("flexString1Label=owasp_category")
        if finding.get("mitre_technique"):
            extensions.append(
                f"flexString2={_sanitize_cef_value(str(finding['mitre_technique']))}"
            )
            extensions.append("flexString2Label=mitre_technique")

    # Token usage
    usage = event.get("usage", {})
    if isinstance(usage, dict):
        if usage.get("input_tokens") is not None:
            extensions.append(f"cn2={usage['input_tokens']}")
            extensions.append("cn2Label=input_tokens")
        if usage.get("output_tokens") is not None:
            extensions.append(f"cn3={usage['output_tokens']}")
            extensions.append("cn3Label=output_tokens")

    # Cost
    cost = event.get("cost", {})
    if isinstance(cost, dict) and cost.get("total_cost_usd") is not None:
        extensions.append(f"cfp1={cost['total_cost_usd']}")
        extensions.append("cfp1Label=total_cost_usd")

    # Compliance frameworks (use deviceCustomString7 to avoid
    # overwriting flexString2 which may hold mitre_technique)
    compliance = event.get("compliance", {})
    if isinstance(compliance, dict):
        comp_parts = []
        for framework, details in compliance.items():
            comp_parts.append(f"{framework}:{details}")
        if comp_parts:
            extensions.append(
                f"cs7={_sanitize_cef_value('; '.join(comp_parts[:5]))}"
            )
            extensions.append("cs7Label=compliance_frameworks")

    extension_str = " ".join(extensions)
    vendor_h = _sanitize_cef_header(vendor)
    product_h = _sanitize_cef_header(product)
    version_h = _sanitize_cef_header(version)

    return (
        f"CEF:0|{vendor_h}|{product_h}|{version_h}|{signature_id}"
        f"|{name}|{cef_severity}|{extension_str}"
    )


# ---------------------------------------------------------------------------
# Syslog Transport
# ---------------------------------------------------------------------------

class SyslogTransport:
    """Sends CEF messages to a syslog receiver via TCP/TLS or UDP.

    Supports:
        - TCP with TLS (RFC 5425 octet-counting framing)
        - TCP without TLS (development only)
        - UDP (RFC 3164 datagram framing)
    """

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "tcp",
        tls: bool = True,
        tls_ca_cert: str | None = None,
        tls_verify: bool = True,
        connect_timeout: float = 10.0,
    ) -> None:
        self._host = host
        self._port = port
        self._protocol = protocol.lower()
        self._use_tls = tls
        self._tls_ca_cert = tls_ca_cert
        self._tls_verify = tls_verify
        self._connect_timeout = connect_timeout
        self._sock: socket.socket | None = None
        self._connected = False
        self._lock = threading.Lock()

    def connect(self) -> None:
        """Establish connection to the syslog receiver."""
        with self._lock:
            if self._connected:
                return

            if self._protocol == "tcp":
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(self._connect_timeout)

                if self._use_tls:
                    ssl_ctx = ssl.create_default_context()
                    if self._tls_ca_cert:
                        ssl_ctx.load_verify_locations(self._tls_ca_cert)
                    if not self._tls_verify:
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = ssl.CERT_NONE
                        logger.warning(
                            "TLS verification disabled for syslog transport. "
                            "Do not use in production."
                        )
                    else:
                        ssl_ctx.check_hostname = True
                        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
                    self._sock = ssl_ctx.wrap_socket(
                        raw_sock, server_hostname=self._host
                    )
                else:
                    logger.warning(
                        "TLS disabled for syslog. Use TLS in production."
                    )
                    self._sock = raw_sock

                self._sock.connect((self._host, self._port))
                self._connected = True
                logger.info(
                    "Connected to syslog %s:%d via TCP%s",
                    self._host, self._port,
                    "+TLS" if self._use_tls else "",
                )

            elif self._protocol == "udp":
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._connected = True
                logger.info(
                    "Configured UDP syslog to %s:%d",
                    self._host, self._port,
                )
            else:
                raise ValueError(
                    f"Unsupported protocol: {self._protocol!r}. "
                    f"Use 'tcp' or 'udp'."
                )

    def send(self, cef_message: str) -> None:
        """Send a single CEF syslog message."""
        if not self._connected or self._sock is None:
            self.connect()

        encoded = cef_message.encode("utf-8")

        with self._lock:
            if self._protocol == "tcp":
                # RFC 5425 octet-counting framing
                framed = f"{len(encoded)} ".encode("utf-8") + encoded
                self._sock.sendall(framed)
            else:
                self._sock.sendto(encoded, (self._host, self._port))

    def send_batch(self, messages: list[str]) -> int:
        """Send a batch of CEF messages. Returns count sent."""
        sent = 0
        for msg in messages:
            try:
                self.send(msg)
                sent += 1
            except (OSError, ConnectionError) as exc:
                logger.warning(
                    "Syslog send failed after %d/%d: %s",
                    sent, len(messages), exc,
                )
                self._connected = False
                try:
                    self.connect()
                    self.send(msg)
                    sent += 1
                except Exception:
                    logger.error(
                        "Reconnect failed, dropping remaining %d messages",
                        len(messages) - sent,
                    )
                    break
        return sent

    def close(self) -> None:
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
                self._connected = False


# ---------------------------------------------------------------------------
# CEF Syslog SpanExporter
# ---------------------------------------------------------------------------

class CEFSyslogExporter(SpanExporter):
    """Exports AITF telemetry as CEF syslog messages to any SIEM.

    Converts OTel spans to OCSF events, formats as CEF, and sends via
    syslog to any CEF-compatible receiver. Works with SIEMs that do not
    support OCSF natively.

    Args:
        host: Syslog receiver hostname or IP.
        port: Syslog receiver port (default 514, or 6514 for TLS).
        protocol: Transport protocol (``tcp`` or ``udp``).
        tls: Enable TLS for TCP connections.
        tls_ca_cert: Path to CA certificate for TLS verification.
        tls_verify: Verify TLS certificates (disable only for dev).
        vendor: CEF DeviceVendor header field.
        product: CEF DeviceProduct header field.
        version: CEF DeviceVersion header field.
        batch_size: Max messages per flush batch.

    Usage:
        exporter = CEFSyslogExporter(
            host="qradar.example.com",
            port=514,
            protocol="tcp",
            tls=True,
        )
    """

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "tcp",
        tls: bool = True,
        tls_ca_cert: str | None = None,
        tls_verify: bool = True,
        vendor: str = "AITF",
        product: str = "AI-Telemetry-Framework",
        version: str = "1.0.0",
        batch_size: int = 100,
    ) -> None:
        self._transport = SyslogTransport(
            host=host,
            port=port,
            protocol=protocol,
            tls=tls,
            tls_ca_cert=tls_ca_cert,
            tls_verify=tls_verify,
        )
        self._vendor = vendor
        self._product = product
        self._version = version
        self._batch_size = batch_size
        self._mapper = OCSFMapper()
        self._total_exported = 0
        self._lock = threading.Lock()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        """Convert spans to CEF and send via syslog."""
        cef_messages: list[str] = []

        for span in spans:
            ocsf_event = self._mapper.map_span(span)
            if ocsf_event is None:
                continue

            event_dict = ocsf_event.model_dump(exclude_none=True)
            cef_msg = ocsf_event_to_cef(
                event_dict,
                vendor=self._vendor,
                product=self._product,
                version=self._version,
            )
            cef_messages.append(cef_msg)

        if not cef_messages:
            return SpanExportResult.SUCCESS

        try:
            for i in range(0, len(cef_messages), self._batch_size):
                batch = cef_messages[i : i + self._batch_size]
                sent = self._transport.send_batch(batch)
                with self._lock:
                    self._total_exported += sent

            return SpanExportResult.SUCCESS
        except Exception as exc:
            logger.error("CEF syslog export failed: %s", exc)
            return SpanExportResult.FAILURE

    @property
    def total_exported(self) -> int:
        with self._lock:
            return self._total_exported

    def shutdown(self) -> None:
        self._transport.close()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
