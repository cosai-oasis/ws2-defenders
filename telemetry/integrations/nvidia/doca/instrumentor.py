"""AITF Instrumentor for NVIDIA DOCA (BlueField DPU).

NVIDIA DOCA (Data Center Infrastructure on a Chip Architecture) provides
hardware-accelerated infrastructure services on BlueField DPUs. This module
instruments DOCA operations with AITF telemetry, producing OpenTelemetry
spans for:

- **DPU lifecycle** -- BlueField initialization, mode configuration, and
  health monitoring via gRPC orchestrator.
- **DOCA Telemetry Service (DTS)** -- Configuring and routing AI telemetry
  through DTS with native OTLP export to correlate AITF spans with hardware
  counters (NIC, PCIe, GPU, power/thermal).
- **DOCA Flow** -- Hardware-offloaded packet classification for AI inference
  traffic (gRPC/HTTP model endpoints, MCP server ports) with per-flow
  telemetry counters at line rate.
- **DOCA App Shield** -- Host memory introspection from the DPU's isolated
  trust domain to detect tampering of AI inference processes (Triton, NIM,
  vLLM containers).
- **DOCA DPI** -- Deep Packet Inspection with hardware RegEx acceleration
  for detecting prompt injection, data exfiltration, and anomalous AI API
  patterns in network traffic at line rate.

All spans carry ``gen_ai.system = "nvidia_doca"`` and use AITF semantic
convention attributes from ``aitf.semantic_conventions.attributes``.

Architecture::

    +-----------------+     +-------------------+     +------------------+
    | AI Application  |     | AITF SDK          |     | BlueField DPU    |
    | (Host x86)      |---->| (OTel Spans)      |---->| (Arm cores)      |
    +-----------------+     +-------------------+     +------------------+
                                                       |  DOCA Services  |
                                                       |  +-- DTS ----+  |
                                                       |  | HW telem  |  |
                                                       |  | OTLP out  |  |
                                                       |  +----------+   |
                                                       |  +-- Flow ---+  |
                                                       |  | AI traffic|  |
                                                       |  | classify  |  |
                                                       |  +----------+   |
                                                       |  +- AppShield+  |
                                                       |  | Memory    |  |
                                                       |  | integrity |  |
                                                       |  +----------+   |
                                                       |  +-- DPI ----+  |
                                                       |  | RegEx HW  |  |
                                                       |  | inspection|  |
                                                       |  +----------+   |
                                                       +------------------+
                                                               |
                                                          OTLP / syslog
                                                               |
                                                               v
                                                       +------------------+
                                                       | OTel Collector / |
                                                       | SIEM / XDR      |
                                                       +------------------+

Usage::

    from integrations.nvidia.doca.instrumentor import DOCAInstrumentor

    doca = DOCAInstrumentor(
        dpu_address="192.168.100.1",
        dts_otlp_target="otel-collector:4317",
    )
    doca.instrument()

    # Trace DPU initialization
    with doca.trace_dpu_init(
        bf_version="BlueField-3",
        mode="dpu",
        firmware="24.40.1000",
    ) as init_op:
        init_op.set_arm_cores(16)
        init_op.set_network_speed_gbps(400)
        init_op.set_pcie_gen("5.0")

    # Configure AI traffic flow monitoring
    with doca.trace_flow_create(
        pipe_name="ai_inference_traffic",
        match_protocol="tcp",
        match_dst_ports=[8000, 8001, 8080, 50051],
        description="Classify NIM/Triton/vLLM/gRPC inference traffic",
    ) as flow:
        flow.set_action("monitor_and_forward")
        flow.set_hw_offload(True)

    # Monitor AI process integrity from DPU trust domain
    with doca.trace_appshield_scan(
        target_process="triton-server",
        scan_type="memory_integrity",
    ) as scan:
        scan.set_result(
            integrity_valid=True,
            pages_scanned=4096,
            pages_modified=0,
        )

    # DPI inspection for AI API traffic
    with doca.trace_dpi_inspection(
        signature_set="aitf_ai_threats",
        flow_count=15000,
    ) as dpi:
        dpi.set_result(
            packets_inspected=1_200_000,
            matches=3,
            match_signatures=["prompt_injection_http", "exfil_base64_body"],
        )

    doca.uninstrument()
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import (
    GenAIAttributes,
    SecurityAttributes,
    SupplyChainAttributes,
)

_TRACER_NAME = "integrations.nvidia.doca"
_GEN_AI_SYSTEM = "nvidia_doca"


class DOCAInstrumentor:
    """Instrumentor for NVIDIA DOCA services on BlueField DPUs.

    Provides telemetry for DPU lifecycle, DOCA Flow traffic classification,
    App Shield memory integrity, DPI pattern matching, and DTS telemetry
    routing -- all correlated with AITF AI telemetry spans.

    Args:
        tracer_provider: Optional custom ``TracerProvider``. Falls back to
            the globally registered provider.
        dpu_address: Management IP of the BlueField DPU Arm subsystem.
        dts_otlp_target: OTLP endpoint that DTS should export to
            (e.g. ``otel-collector:4317``).
        bf_version: BlueField hardware version (``BlueField-2``,
            ``BlueField-3``, ``BlueField-4``).
    """

    def __init__(
        self,
        tracer_provider: TracerProvider | None = None,
        dpu_address: str | None = None,
        dts_otlp_target: str | None = None,
        bf_version: str | None = None,
    ) -> None:
        self._tracer_provider = tracer_provider
        self._dpu_address = dpu_address
        self._dts_otlp_target = dts_otlp_target
        self._bf_version = bf_version
        self._tracer: trace.Tracer | None = None
        self._instrumented = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Enable DOCA instrumentation."""
        if self._instrumented:
            return
        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)
        self._instrumented = True

    def uninstrument(self) -> None:
        """Disable DOCA instrumentation."""
        self._tracer = None
        self._instrumented = False

    @property
    def is_instrumented(self) -> bool:
        return self._instrumented

    def get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    def _base_attributes(self) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            GenAIAttributes.SYSTEM: _GEN_AI_SYSTEM,
        }
        if self._dpu_address:
            attrs["nvidia.doca.dpu.address"] = self._dpu_address
        if self._bf_version:
            attrs["nvidia.doca.dpu.version"] = self._bf_version
        return attrs

    # ------------------------------------------------------------------
    # DPU Initialization
    # ------------------------------------------------------------------

    @contextmanager
    def trace_dpu_init(
        self,
        bf_version: str | None = None,
        mode: str = "dpu",
        firmware: str | None = None,
        serial_number: str | None = None,
    ) -> Generator[DPUInitSpan, None, None]:
        """Trace BlueField DPU initialization and configuration.

        Args:
            bf_version: Hardware version (BlueField-2/3/4).
            mode: DPU operation mode (``dpu``, ``nic``, ``restricted``).
            firmware: DPU firmware version string.
            serial_number: DPU serial number for asset tracking.
        """
        tracer = self.get_tracer()
        attributes = self._base_attributes()
        attributes["nvidia.doca.operation"] = "dpu_init"
        attributes["nvidia.doca.dpu.mode"] = mode
        if bf_version:
            attributes["nvidia.doca.dpu.version"] = bf_version
        if firmware:
            attributes[SupplyChainAttributes.MODEL_VERSION] = firmware
        if serial_number:
            attributes["nvidia.doca.dpu.serial"] = serial_number

        start = time.monotonic()
        with tracer.start_as_current_span(
            name="doca.dpu_init",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            init_span = DPUInitSpan(span, start)
            try:
                yield init_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # DOCA Telemetry Service (DTS) Configuration
    # ------------------------------------------------------------------

    @contextmanager
    def trace_dts_config(
        self,
        providers: list[str] | None = None,
        exporters: list[str] | None = None,
        sampling_interval_ms: int | None = None,
    ) -> Generator[DTSConfigSpan, None, None]:
        """Trace DTS configuration and telemetry routing setup.

        Args:
            providers: DTS data providers (``sysfs``, ``ethtool``, ``tc``,
                ``bfperf``, ``prometheus_aggr``).
            exporters: DTS export destinations (``otlp``, ``prometheus``,
                ``kafka``, ``fluent``).
            sampling_interval_ms: Telemetry sampling interval.
        """
        tracer = self.get_tracer()
        attributes = self._base_attributes()
        attributes["nvidia.doca.operation"] = "dts_config"
        if providers:
            attributes["nvidia.doca.dts.providers"] = providers
        if exporters:
            attributes["nvidia.doca.dts.exporters"] = exporters
        if self._dts_otlp_target:
            attributes["nvidia.doca.dts.otlp_target"] = (
                self._dts_otlp_target
            )
        if sampling_interval_ms is not None:
            attributes["nvidia.doca.dts.sampling_interval_ms"] = (
                sampling_interval_ms
            )

        with tracer.start_as_current_span(
            name="doca.dts_config",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            config_span = DTSConfigSpan(span)
            try:
                yield config_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # DOCA Flow -- AI Traffic Classification
    # ------------------------------------------------------------------

    @contextmanager
    def trace_flow_create(
        self,
        pipe_name: str,
        match_protocol: str | None = None,
        match_dst_ports: list[int] | None = None,
        match_src_ip: str | None = None,
        match_dst_ip: str | None = None,
        description: str | None = None,
    ) -> Generator[FlowPipeSpan, None, None]:
        """Trace creation of a DOCA Flow pipe for AI traffic classification.

        DOCA Flow pipes run on the BlueField NIC hardware, classifying
        packets at line rate (up to 400 Gb/s) without consuming host CPU.

        Args:
            pipe_name: Logical name for the flow pipe.
            match_protocol: L4 protocol to match (``tcp``, ``udp``).
            match_dst_ports: Destination ports to match (e.g. model endpoints).
            match_src_ip: Source IP CIDR to match.
            match_dst_ip: Destination IP CIDR to match.
            description: Human-readable description of the pipe's purpose.
        """
        tracer = self.get_tracer()
        attributes = self._base_attributes()
        attributes["nvidia.doca.operation"] = "flow_create"
        attributes["nvidia.doca.flow.pipe_name"] = pipe_name
        if match_protocol:
            attributes["nvidia.doca.flow.match_protocol"] = match_protocol
        if match_dst_ports:
            attributes["nvidia.doca.flow.match_dst_ports"] = (
                match_dst_ports
            )
        if match_src_ip:
            attributes["nvidia.doca.flow.match_src_ip"] = match_src_ip
        if match_dst_ip:
            attributes["nvidia.doca.flow.match_dst_ip"] = match_dst_ip
        if description:
            attributes["nvidia.doca.flow.description"] = description

        with tracer.start_as_current_span(
            name=f"doca.flow.create {pipe_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            pipe_span = FlowPipeSpan(span)
            try:
                yield pipe_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_flow_stats(
        self,
        pipe_name: str,
    ) -> Generator[FlowStatsSpan, None, None]:
        """Trace a DOCA Flow statistics query for AI traffic counters.

        Args:
            pipe_name: The flow pipe to query statistics for.
        """
        tracer = self.get_tracer()
        attributes = self._base_attributes()
        attributes["nvidia.doca.operation"] = "flow_stats"
        attributes["nvidia.doca.flow.pipe_name"] = pipe_name

        with tracer.start_as_current_span(
            name=f"doca.flow.stats {pipe_name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            stats_span = FlowStatsSpan(span)
            try:
                yield stats_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # DOCA App Shield -- AI Workload Integrity
    # ------------------------------------------------------------------

    @contextmanager
    def trace_appshield_scan(
        self,
        target_process: str,
        scan_type: str = "memory_integrity",
        system_layer: str = "bare_metal",
    ) -> Generator[AppShieldScanSpan, None, None]:
        """Trace an App Shield memory integrity scan of an AI process.

        App Shield runs on the DPU's Arm cores and reads host memory via
        DMA over PCIe, providing introspection from an independent trust
        domain that malware on the host cannot subvert.

        Args:
            target_process: Name of the AI process to scan (e.g.
                ``triton-server``, ``nim-container``, ``vllm-worker``).
            scan_type: Type of scan (``memory_integrity``,
                ``process_list``, ``module_list``, ``yara``).
            system_layer: Host layer (``bare_metal``, ``vm``, ``container``).
        """
        tracer = self.get_tracer()
        attributes = self._base_attributes()
        attributes["nvidia.doca.operation"] = "appshield_scan"
        attributes["nvidia.doca.appshield.target_process"] = (
            target_process
        )
        attributes["nvidia.doca.appshield.scan_type"] = scan_type
        attributes["nvidia.doca.appshield.system_layer"] = system_layer

        start = time.monotonic()
        with tracer.start_as_current_span(
            name=f"doca.appshield.scan {target_process}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            scan_span = AppShieldScanSpan(span, start)
            try:
                yield scan_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # DOCA DPI -- Deep Packet Inspection for AI Traffic
    # ------------------------------------------------------------------

    @contextmanager
    def trace_dpi_inspection(
        self,
        signature_set: str = "aitf_ai_threats",
        flow_count: int | None = None,
    ) -> Generator[DPIInspectionSpan, None, None]:
        """Trace a DOCA DPI inspection cycle for AI API traffic.

        DOCA DPI uses the BlueField hardware RegEx accelerator (RXP) for
        line-rate pattern matching against compiled signature sets. Custom
        AITF signatures can detect prompt injection patterns, base64-encoded
        exfiltration, and anomalous AI API request structures in-flight.

        Args:
            signature_set: Name of the loaded signature set.
            flow_count: Number of active flows being inspected.
        """
        tracer = self.get_tracer()
        attributes = self._base_attributes()
        attributes["nvidia.doca.operation"] = "dpi_inspection"
        attributes["nvidia.doca.dpi.signature_set"] = signature_set
        if flow_count is not None:
            attributes["nvidia.doca.dpi.flow_count"] = flow_count

        start = time.monotonic()
        with tracer.start_as_current_span(
            name=f"doca.dpi.inspect {signature_set}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            dpi_span = DPIInspectionSpan(span, start)
            try:
                yield dpi_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ------------------------------------------------------------------
    # gRPC Control Plane
    # ------------------------------------------------------------------

    @contextmanager
    def trace_grpc_call(
        self,
        service: str,
        method: str,
    ) -> Generator[GRPCCallSpan, None, None]:
        """Trace a gRPC control-plane call from host to DPU.

        DOCA's gRPC infrastructure allows managing DPU programs
        (Flow pipes, DPI engines, telemetry config) from the host.

        Args:
            service: DOCA gRPC service name (e.g. ``doca_flow``,
                ``doca_dpi``, ``doca_telemetry``).
            method: RPC method name.
        """
        tracer = self.get_tracer()
        attributes = self._base_attributes()
        attributes["nvidia.doca.operation"] = "grpc_call"
        attributes["nvidia.doca.grpc.service"] = service
        attributes["nvidia.doca.grpc.method"] = method

        start = time.monotonic()
        with tracer.start_as_current_span(
            name=f"doca.grpc/{service}/{method}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            grpc_span = GRPCCallSpan(span, start)
            try:
                yield grpc_span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


# ======================================================================
# Span helper classes
# ======================================================================


class DPUInitSpan:
    """Helper for recording DPU initialization attributes."""

    def __init__(self, span: trace.Span, start_time: float) -> None:
        self._span = span
        self._start_time = start_time

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_arm_cores(self, count: int) -> None:
        self._span.set_attribute("nvidia.doca.dpu.arm_cores", count)

    def set_network_speed_gbps(self, gbps: int) -> None:
        self._span.set_attribute(
            "nvidia.doca.dpu.network_speed_gbps", gbps
        )

    def set_pcie_gen(self, gen: str) -> None:
        self._span.set_attribute("nvidia.doca.dpu.pcie_gen", gen)

    def set_memory_gb(self, gb: int) -> None:
        self._span.set_attribute("nvidia.doca.dpu.memory_gb", gb)

    def set_crypto_engines(self, engines: list[str]) -> None:
        self._span.set_attribute(
            "nvidia.doca.dpu.crypto_engines", engines
        )

    def set_init_time_ms(self, ms: float | None = None) -> None:
        if ms is None:
            ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute("nvidia.doca.dpu.init_time_ms", ms)

    def set_secure_boot(self, enabled: bool) -> None:
        self._span.set_attribute(
            "nvidia.doca.dpu.secure_boot", enabled
        )


class DTSConfigSpan:
    """Helper for recording DTS configuration attributes."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_counter_sets(self, counter_sets: list[str]) -> None:
        self._span.set_attribute(
            "nvidia.doca.dts.counter_sets", counter_sets
        )

    def set_hft_enabled(self, enabled: bool) -> None:
        """Set whether High Frequency Telemetry is enabled."""
        self._span.set_attribute("nvidia.doca.dts.hft_enabled", enabled)

    def set_ipc_socket(self, path: str) -> None:
        self._span.set_attribute("nvidia.doca.dts.ipc_socket", path)

    def set_labels(self, labels: dict[str, str]) -> None:
        for key, value in labels.items():
            self._span.set_attribute(
                f"nvidia.doca.dts.label.{key}", value
            )


class FlowPipeSpan:
    """Helper for recording DOCA Flow pipe attributes."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_action(self, action: str) -> None:
        """Set pipe action (``monitor_and_forward``, ``drop``, ``hairpin``,
        ``mirror``)."""
        self._span.set_attribute("nvidia.doca.flow.action", action)

    def set_hw_offload(self, offloaded: bool) -> None:
        self._span.set_attribute(
            "nvidia.doca.flow.hw_offload", offloaded
        )

    def set_pipe_type(self, pipe_type: str) -> None:
        """Set pipe type (``basic``, ``control``)."""
        self._span.set_attribute("nvidia.doca.flow.pipe_type", pipe_type)

    def set_entry_count(self, count: int) -> None:
        self._span.set_attribute(
            "nvidia.doca.flow.entry_count", count
        )

    def set_meter(
        self,
        cir_bytes_per_sec: int | None = None,
        cbs_bytes: int | None = None,
    ) -> None:
        if cir_bytes_per_sec is not None:
            self._span.set_attribute(
                "nvidia.doca.flow.meter_cir", cir_bytes_per_sec
            )
        if cbs_bytes is not None:
            self._span.set_attribute(
                "nvidia.doca.flow.meter_cbs", cbs_bytes
            )


class FlowStatsSpan:
    """Helper for recording DOCA Flow statistics."""

    def __init__(self, span: trace.Span) -> None:
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_counters(
        self,
        total_packets: int | None = None,
        total_bytes: int | None = None,
        active_flows: int | None = None,
        hw_offloaded_flows: int | None = None,
    ) -> None:
        if total_packets is not None:
            self._span.set_attribute(
                "nvidia.doca.flow.stats.total_packets", total_packets
            )
        if total_bytes is not None:
            self._span.set_attribute(
                "nvidia.doca.flow.stats.total_bytes", total_bytes
            )
        if active_flows is not None:
            self._span.set_attribute(
                "nvidia.doca.flow.stats.active_flows", active_flows
            )
        if hw_offloaded_flows is not None:
            self._span.set_attribute(
                "nvidia.doca.flow.stats.hw_offloaded_flows",
                hw_offloaded_flows,
            )

    def set_ai_traffic_stats(
        self,
        inference_requests: int | None = None,
        inference_bytes: int | None = None,
        mcp_requests: int | None = None,
        model_download_bytes: int | None = None,
    ) -> None:
        if inference_requests is not None:
            self._span.set_attribute(
                "nvidia.doca.flow.stats.inference_requests",
                inference_requests,
            )
        if inference_bytes is not None:
            self._span.set_attribute(
                "nvidia.doca.flow.stats.inference_bytes",
                inference_bytes,
            )
        if mcp_requests is not None:
            self._span.set_attribute(
                "nvidia.doca.flow.stats.mcp_requests", mcp_requests
            )
        if model_download_bytes is not None:
            self._span.set_attribute(
                "nvidia.doca.flow.stats.model_download_bytes",
                model_download_bytes,
            )


class AppShieldScanSpan:
    """Helper for recording App Shield scan results."""

    def __init__(self, span: trace.Span, start_time: float) -> None:
        self._span = span
        self._start_time = start_time

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_result(
        self,
        integrity_valid: bool,
        pages_scanned: int | None = None,
        pages_modified: int | None = None,
        modules_loaded: int | None = None,
        suspicious_modules: list[str] | None = None,
    ) -> None:
        self._span.set_attribute(
            "nvidia.doca.appshield.integrity_valid", integrity_valid
        )
        if pages_scanned is not None:
            self._span.set_attribute(
                "nvidia.doca.appshield.pages_scanned", pages_scanned
            )
        if pages_modified is not None:
            self._span.set_attribute(
                "nvidia.doca.appshield.pages_modified", pages_modified
            )
        if modules_loaded is not None:
            self._span.set_attribute(
                "nvidia.doca.appshield.modules_loaded", modules_loaded
            )
        if suspicious_modules:
            self._span.set_attribute(
                "nvidia.doca.appshield.suspicious_modules",
                suspicious_modules,
            )
            # Also flag as security finding
            self._span.set_attribute(
                SecurityAttributes.THREAT_TYPE, "ai_process_tampering"
            )

    def set_yara_matches(self, rule_names: list[str]) -> None:
        """Record YARA rule matches found in process memory."""
        self._span.set_attribute(
            "nvidia.doca.appshield.yara_matches", rule_names
        )
        if rule_names:
            self._span.set_attribute(
                SecurityAttributes.THREAT_TYPE, "malware_in_ai_process"
            )

    def set_scan_time_ms(self, ms: float | None = None) -> None:
        if ms is None:
            ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute(
            "nvidia.doca.appshield.scan_time_ms", ms
        )

    def set_network_connections(
        self,
        total: int | None = None,
        suspicious: list[str] | None = None,
    ) -> None:
        """Record network connections observed for the AI process."""
        if total is not None:
            self._span.set_attribute(
                "nvidia.doca.appshield.connections_total", total
            )
        if suspicious:
            self._span.set_attribute(
                "nvidia.doca.appshield.connections_suspicious",
                suspicious,
            )


class DPIInspectionSpan:
    """Helper for recording DPI inspection results."""

    def __init__(self, span: trace.Span, start_time: float) -> None:
        self._span = span
        self._start_time = start_time

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_result(
        self,
        packets_inspected: int | None = None,
        matches: int | None = None,
        match_signatures: list[str] | None = None,
        bytes_inspected: int | None = None,
    ) -> None:
        if packets_inspected is not None:
            self._span.set_attribute(
                "nvidia.doca.dpi.packets_inspected", packets_inspected
            )
        if matches is not None:
            self._span.set_attribute(
                "nvidia.doca.dpi.matches", matches
            )
        if match_signatures:
            self._span.set_attribute(
                "nvidia.doca.dpi.match_signatures", match_signatures
            )
            self._span.set_attribute(
                SecurityAttributes.THREAT_TYPE, "dpi_pattern_match"
            )
        if bytes_inspected is not None:
            self._span.set_attribute(
                "nvidia.doca.dpi.bytes_inspected", bytes_inspected
            )

    def set_throughput(
        self,
        gbps: float | None = None,
        packets_per_second: int | None = None,
    ) -> None:
        if gbps is not None:
            self._span.set_attribute(
                "nvidia.doca.dpi.throughput_gbps", gbps
            )
        if packets_per_second is not None:
            self._span.set_attribute(
                "nvidia.doca.dpi.packets_per_second", packets_per_second
            )

    def set_inspection_time_ms(self, ms: float | None = None) -> None:
        if ms is None:
            ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute(
            "nvidia.doca.dpi.inspection_time_ms", ms
        )

    def set_actions_taken(
        self,
        dropped: int = 0,
        forwarded: int = 0,
        mirrored: int = 0,
        alerted: int = 0,
    ) -> None:
        self._span.set_attribute(
            "nvidia.doca.dpi.actions_dropped", dropped
        )
        self._span.set_attribute(
            "nvidia.doca.dpi.actions_forwarded", forwarded
        )
        self._span.set_attribute(
            "nvidia.doca.dpi.actions_mirrored", mirrored
        )
        self._span.set_attribute(
            "nvidia.doca.dpi.actions_alerted", alerted
        )


class GRPCCallSpan:
    """Helper for recording gRPC control-plane call results."""

    def __init__(self, span: trace.Span, start_time: float) -> None:
        self._span = span
        self._start_time = start_time

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_response_status(self, status: str) -> None:
        self._span.set_attribute(
            "nvidia.doca.grpc.status", status
        )

    def set_latency_ms(self, ms: float | None = None) -> None:
        if ms is None:
            ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute("nvidia.doca.grpc.latency_ms", ms)
