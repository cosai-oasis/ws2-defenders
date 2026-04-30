"""AITF AI Asset Inventory Instrumentation.

Provides tracing for AI asset lifecycle management: registration, discovery,
audit, risk classification, dependency mapping, and decommissioning. Aligned
with CoSAI AI Incident Response preparation requirements.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import AssetInventoryAttributes

_TRACER_NAME = "aitf.instrumentation.asset_inventory"


class AssetInventoryInstrumentor:
    """Instrumentor for AI asset inventory operations."""

    def __init__(self, tracer_provider: TracerProvider | None = None):
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False

    def instrument(self) -> None:
        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)
        self._instrumented = True

    def uninstrument(self) -> None:
        self._tracer = None
        self._instrumented = False

    def get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    # ── Registration ──────────────────────────────────────────────────

    @contextmanager
    def trace_register(
        self,
        asset_id: str | None = None,
        asset_name: str = "",
        asset_type: str = "model",
        version: str | None = None,
        asset_hash: str | None = None,
        owner: str | None = None,
        owner_type: str | None = None,
        deployment_environment: str | None = None,
        risk_classification: str | None = None,
        source_repository: str | None = None,
        tags: list[str] | None = None,
    ) -> Generator[AssetRegistration, None, None]:
        """Context manager for tracing asset registration.

        Usage:
            with asset_inv.trace_register(
                asset_name="customer-support-llama-70b",
                asset_type="model",
                owner="ml-platform-team",
                risk_classification="high_risk",
            ) as reg:
                # ... register asset ...
                reg.set_hash("sha256:abc123")
        """
        tracer = self.get_tracer()
        asset_id = asset_id or str(uuid.uuid4())

        attributes: dict[str, Any] = {
            AssetInventoryAttributes.ID: asset_id,
            AssetInventoryAttributes.NAME: asset_name,
            AssetInventoryAttributes.TYPE: asset_type,
        }
        if version:
            attributes[AssetInventoryAttributes.VERSION] = version
        if asset_hash:
            attributes[AssetInventoryAttributes.HASH] = asset_hash
        if owner:
            attributes[AssetInventoryAttributes.OWNER] = owner
        if owner_type:
            attributes[AssetInventoryAttributes.OWNER_TYPE] = owner_type
        if deployment_environment:
            attributes[AssetInventoryAttributes.DEPLOYMENT_ENVIRONMENT] = deployment_environment
        if risk_classification:
            attributes[AssetInventoryAttributes.RISK_CLASSIFICATION] = risk_classification
        if source_repository:
            attributes[AssetInventoryAttributes.SOURCE_REPOSITORY] = source_repository
        if tags:
            attributes[AssetInventoryAttributes.TAGS] = tags

        with tracer.start_as_current_span(
            f"asset.register {asset_type} {asset_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            reg = AssetRegistration(span, asset_id)
            try:
                yield reg
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Discovery ─────────────────────────────────────────────────────

    @contextmanager
    def trace_discover(
        self,
        scope: str = "organization",
        method: str = "api_scan",
    ) -> Generator[AssetDiscovery, None, None]:
        """Context manager for tracing asset discovery scans."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            AssetInventoryAttributes.DISCOVERY_SCOPE: scope,
            AssetInventoryAttributes.DISCOVERY_METHOD: method,
        }

        with tracer.start_as_current_span(
            f"asset.discover {scope}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            disc = AssetDiscovery(span)
            try:
                yield disc
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Audit ─────────────────────────────────────────────────────────

    @contextmanager
    def trace_audit(
        self,
        asset_id: str,
        audit_type: str = "compliance",
        framework: str | None = None,
        auditor: str | None = None,
    ) -> Generator[AssetAudit, None, None]:
        """Context manager for tracing asset audits."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            AssetInventoryAttributes.ID: asset_id,
            AssetInventoryAttributes.AUDIT_TYPE: audit_type,
        }
        if framework:
            attributes[AssetInventoryAttributes.AUDIT_FRAMEWORK] = framework
        if auditor:
            attributes[AssetInventoryAttributes.AUDIT_AUDITOR] = auditor

        with tracer.start_as_current_span(
            f"asset.audit {asset_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            audit = AssetAudit(span)
            try:
                yield audit
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Classification ────────────────────────────────────────────────

    @contextmanager
    def trace_classify(
        self,
        asset_id: str,
        risk_classification: str,
        framework: str = "eu_ai_act",
        assessor: str | None = None,
        use_case: str | None = None,
    ) -> Generator[AssetClassification, None, None]:
        """Context manager for tracing risk classification."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            AssetInventoryAttributes.ID: asset_id,
            AssetInventoryAttributes.RISK_CLASSIFICATION: risk_classification,
            AssetInventoryAttributes.CLASSIFICATION_FRAMEWORK: framework,
        }
        if assessor:
            attributes[AssetInventoryAttributes.CLASSIFICATION_ASSESSOR] = assessor
        if use_case:
            attributes[AssetInventoryAttributes.CLASSIFICATION_USE_CASE] = use_case

        with tracer.start_as_current_span(
            f"asset.classify {asset_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            cls = AssetClassification(span)
            try:
                yield cls
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Decommission ──────────────────────────────────────────────────

    @contextmanager
    def trace_decommission(
        self,
        asset_id: str,
        asset_type: str,
        reason: str,
        replacement_id: str | None = None,
        approved_by: str | None = None,
    ) -> Generator[trace.Span, None, None]:
        """Context manager for tracing asset decommissioning."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            AssetInventoryAttributes.ID: asset_id,
            AssetInventoryAttributes.TYPE: asset_type,
            AssetInventoryAttributes.DECOMMISSION_REASON: reason,
        }
        if replacement_id:
            attributes[AssetInventoryAttributes.DECOMMISSION_REPLACEMENT_ID] = replacement_id
        if approved_by:
            attributes[AssetInventoryAttributes.DECOMMISSION_APPROVED_BY] = approved_by

        with tracer.start_as_current_span(
            f"asset.decommission {asset_type} {asset_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


# ── Helper classes ────────────────────────────────────────────────────


class AssetRegistration:
    """Helper for enriching an asset registration span."""

    def __init__(self, span: trace.Span, asset_id: str):
        self._span = span
        self.asset_id = asset_id

    def set_hash(self, hash_value: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.HASH, hash_value)

    def set_version(self, version: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.VERSION, version)

    def set_risk_classification(self, classification: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.RISK_CLASSIFICATION, classification)

    def set_deployment_environment(self, env: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.DEPLOYMENT_ENVIRONMENT, env)


class AssetDiscovery:
    """Helper for enriching an asset discovery span."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_results(
        self,
        assets_found: int,
        new_assets: int = 0,
        shadow_assets: int = 0,
    ) -> None:
        self._span.set_attribute(AssetInventoryAttributes.DISCOVERY_ASSETS_FOUND, assets_found)
        self._span.set_attribute(AssetInventoryAttributes.DISCOVERY_NEW_ASSETS, new_assets)
        self._span.set_attribute(AssetInventoryAttributes.DISCOVERY_SHADOW_ASSETS, shadow_assets)

    def set_status(self, status: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.DISCOVERY_STATUS, status)


class AssetAudit:
    """Helper for enriching an asset audit span."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_result(self, result: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.AUDIT_RESULT, result)

    def set_risk_score(self, score: float) -> None:
        self._span.set_attribute(AssetInventoryAttributes.AUDIT_RISK_SCORE, score)

    def set_integrity_verified(self, verified: bool) -> None:
        self._span.set_attribute(AssetInventoryAttributes.AUDIT_INTEGRITY_VERIFIED, verified)

    def set_compliance_status(self, status: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.AUDIT_COMPLIANCE_STATUS, status)

    def set_findings(self, findings: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.AUDIT_FINDINGS, findings)

    def set_next_audit_due(self, timestamp: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.AUDIT_NEXT_AUDIT_DUE, timestamp)


class AssetClassification:
    """Helper for enriching a risk classification span."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_previous(self, previous: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.CLASSIFICATION_PREVIOUS, previous)

    def set_reason(self, reason: str) -> None:
        self._span.set_attribute(AssetInventoryAttributes.CLASSIFICATION_REASON, reason)

    def set_autonomous_decision(self, autonomous: bool) -> None:
        self._span.set_attribute(AssetInventoryAttributes.CLASSIFICATION_AUTONOMOUS_DECISION, autonomous)
