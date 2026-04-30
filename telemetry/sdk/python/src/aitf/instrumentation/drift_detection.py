"""AITF Model Drift Detection Instrumentation.

Provides structured tracing for model drift detection, baseline management,
drift investigation, and remediation. Aligned with CoSAI's identification of
model drift as a top-level AI incident category.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import DriftDetectionAttributes

_TRACER_NAME = "aitf.instrumentation.drift_detection"


class DriftDetectionInstrumentor:
    """Instrumentor for model drift detection operations."""

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

    # ── Detection ─────────────────────────────────────────────────────

    @contextmanager
    def trace_detect(
        self,
        model_id: str,
        drift_type: str,
        detection_method: str | None = None,
        reference_dataset: str | None = None,
        reference_period: str | None = None,
        threshold: float | None = None,
    ) -> Generator[DriftDetection, None, None]:
        """Context manager for tracing a drift detection analysis.

        Usage:
            with drift.trace_detect(
                model_id="customer-support-llama-70b",
                drift_type="data_distribution",
                detection_method="psi",
            ) as det:
                score = run_psi_analysis(current_data, baseline_data)
                det.set_score(score)
                det.set_result("alert" if score > 0.25 else "normal")
                det.set_affected_segments(["enterprise", "apac"])
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            DriftDetectionAttributes.MODEL_ID: model_id,
            DriftDetectionAttributes.TYPE: drift_type,
        }
        if detection_method:
            attributes[DriftDetectionAttributes.DETECTION_METHOD] = detection_method
        if reference_dataset:
            attributes[DriftDetectionAttributes.REFERENCE_DATASET] = reference_dataset
        if reference_period:
            attributes[DriftDetectionAttributes.REFERENCE_PERIOD] = reference_period
        if threshold is not None:
            attributes[DriftDetectionAttributes.THRESHOLD] = threshold

        with tracer.start_as_current_span(
            f"drift.detect {drift_type} {model_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            det = DriftDetection(span)
            try:
                yield det
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Baseline ──────────────────────────────────────────────────────

    @contextmanager
    def trace_baseline(
        self,
        model_id: str,
        operation: str = "create",
        dataset: str | None = None,
        sample_size: int | None = None,
        period: str | None = None,
    ) -> Generator[DriftBaseline, None, None]:
        """Context manager for tracing baseline establishment or refresh."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            DriftDetectionAttributes.MODEL_ID: model_id,
            DriftDetectionAttributes.BASELINE_OPERATION: operation,
        }
        if dataset:
            attributes[DriftDetectionAttributes.BASELINE_DATASET] = dataset
        if sample_size is not None:
            attributes[DriftDetectionAttributes.BASELINE_SAMPLE_SIZE] = sample_size
        if period:
            attributes[DriftDetectionAttributes.BASELINE_PERIOD] = period

        with tracer.start_as_current_span(
            f"drift.baseline {operation} {model_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            baseline = DriftBaseline(span)
            try:
                yield baseline
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Investigation ─────────────────────────────────────────────────

    @contextmanager
    def trace_investigate(
        self,
        model_id: str,
        trigger_id: str,
    ) -> Generator[DriftInvestigation, None, None]:
        """Context manager for tracing a drift investigation."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            DriftDetectionAttributes.MODEL_ID: model_id,
            DriftDetectionAttributes.INVESTIGATION_TRIGGER_ID: trigger_id,
        }

        with tracer.start_as_current_span(
            f"drift.investigate {model_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            inv = DriftInvestigation(span)
            try:
                yield inv
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Remediation ───────────────────────────────────────────────────

    @contextmanager
    def trace_remediate(
        self,
        model_id: str,
        action: str,
        trigger_id: str | None = None,
        automated: bool = False,
        initiated_by: str | None = None,
    ) -> Generator[DriftRemediation, None, None]:
        """Context manager for tracing a drift remediation action."""
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            DriftDetectionAttributes.MODEL_ID: model_id,
            DriftDetectionAttributes.REMEDIATION_ACTION: action,
            DriftDetectionAttributes.REMEDIATION_AUTOMATED: automated,
        }
        if trigger_id:
            attributes[DriftDetectionAttributes.REMEDIATION_TRIGGER_ID] = trigger_id
        if initiated_by:
            attributes[DriftDetectionAttributes.REMEDIATION_INITIATED_BY] = initiated_by

        with tracer.start_as_current_span(
            f"drift.remediate {action} {model_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            rem = DriftRemediation(span)
            try:
                yield rem
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


# ── Helper classes ────────────────────────────────────────────────────


class DriftDetection:
    """Helper for enriching a drift detection span."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_score(self, score: float) -> None:
        self._span.set_attribute(DriftDetectionAttributes.SCORE, score)

    def set_result(self, result: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.RESULT, result)

    def set_metrics(self, baseline: float, current: float, metric_name: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.BASELINE_METRIC, baseline)
        self._span.set_attribute(DriftDetectionAttributes.CURRENT_METRIC, current)
        self._span.set_attribute(DriftDetectionAttributes.METRIC_NAME, metric_name)

    def set_p_value(self, p_value: float) -> None:
        self._span.set_attribute(DriftDetectionAttributes.P_VALUE, p_value)

    def set_sample_size(self, size: int) -> None:
        self._span.set_attribute(DriftDetectionAttributes.SAMPLE_SIZE, size)

    def set_affected_segments(self, segments: list[str]) -> None:
        self._span.set_attribute(DriftDetectionAttributes.AFFECTED_SEGMENTS, segments)

    def set_feature(self, name: str, importance: float | None = None) -> None:
        self._span.set_attribute(DriftDetectionAttributes.FEATURE_NAME, name)
        if importance is not None:
            self._span.set_attribute(DriftDetectionAttributes.FEATURE_IMPORTANCE, importance)

    def set_action_triggered(self, action: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.ACTION_TRIGGERED, action)


class DriftBaseline:
    """Helper for enriching a drift baseline span."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_id(self, baseline_id: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.BASELINE_ID, baseline_id)

    def set_metrics(self, metrics_json: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.BASELINE_METRICS, metrics_json)

    def set_features(self, features: list[str]) -> None:
        self._span.set_attribute(DriftDetectionAttributes.BASELINE_FEATURES, features)

    def set_previous_id(self, previous_id: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.BASELINE_PREVIOUS_ID, previous_id)


class DriftInvestigation:
    """Helper for enriching a drift investigation span."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_root_cause(self, cause: str, category: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.INVESTIGATION_ROOT_CAUSE, cause)
        self._span.set_attribute(DriftDetectionAttributes.INVESTIGATION_ROOT_CAUSE_CATEGORY, category)

    def set_impact(
        self,
        affected_segments: list[str],
        affected_users_estimate: int | None = None,
        blast_radius: str | None = None,
    ) -> None:
        self._span.set_attribute(DriftDetectionAttributes.INVESTIGATION_AFFECTED_SEGMENTS, affected_segments)
        if affected_users_estimate is not None:
            self._span.set_attribute(DriftDetectionAttributes.INVESTIGATION_AFFECTED_USERS, affected_users_estimate)
        if blast_radius:
            self._span.set_attribute(DriftDetectionAttributes.INVESTIGATION_BLAST_RADIUS, blast_radius)

    def set_severity(self, severity: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.INVESTIGATION_SEVERITY, severity)

    def set_recommendation(self, recommendation: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.INVESTIGATION_RECOMMENDATION, recommendation)


class DriftRemediation:
    """Helper for enriching a drift remediation span."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_status(self, status: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.REMEDIATION_STATUS, status)

    def set_rollback_to(self, model_version: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.REMEDIATION_ROLLBACK_TO, model_version)

    def set_retrain_dataset(self, dataset: str) -> None:
        self._span.set_attribute(DriftDetectionAttributes.REMEDIATION_RETRAIN_DATASET, dataset)

    def set_validation_passed(self, passed: bool) -> None:
        self._span.set_attribute(DriftDetectionAttributes.REMEDIATION_VALIDATION_PASSED, passed)
