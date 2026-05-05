"""AITF Integration for NVIDIA DOCA (BlueField DPU).

Provides hardware-accelerated AI telemetry processing on NVIDIA BlueField
Data Processing Units via the DOCA SDK.

Components:
    - DOCAInstrumentor: Traces DOCA service lifecycle and DPU operations
    - DTSExporter: Exports AITF telemetry via DOCA Telemetry Service (OTLP)
    - FlowMonitor: Hardware-accelerated AI traffic classification via DOCA Flow
    - AppShieldMonitor: AI workload memory integrity from DPU trust domain
"""

from integrations.nvidia.doca.instrumentor import DOCAInstrumentor

__all__ = ["DOCAInstrumentor"]
