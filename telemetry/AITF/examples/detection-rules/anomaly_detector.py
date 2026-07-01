"""AITF Statistical Anomaly Detection Engine.

Provides time-series and behavioral anomaly detection on top of AITF
telemetry metrics. Designed to feed the detection rules in
``aitf_detection_rules.py`` with statistical baselines, and to produce
data points suitable for Grafana/Prometheus dashboards or matplotlib
visualizations.

Key components:
  - BaselineTracker: Maintains rolling statistics (EMA, variance, percentiles)
    for any named metric series.
  - AnomalyDetector: Applies z-score, IQR, and adaptive threshold methods.
  - TimeSeriesAnomalyDetector: Detects anomalies in token usage, latency,
    and cost over time with windowed seasonality awareness.
  - BehavioralAnomalyDetector: Detects anomalous agent/session patterns
    using Markov-chain transition probabilities.

Usage:
    from anomaly_detector import AnomalyDetector, BaselineTracker

    tracker = BaselineTracker(window_size=1000)
    detector = AnomalyDetector(tracker)

    for event in aitf_events:
        tokens = event.get("gen_ai.usage.input_tokens", 0)
        result = detector.check("input_tokens", tokens)
        if result.is_anomaly:
            print(f"Anomaly: {result}")
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aitf.semantic_conventions.attributes import (
    AgentAttributes,
    CostAttributes,
    GenAIAttributes,
    LatencyAttributes,
    MCPAttributes,
    SkillAttributes,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class AnomalyMethod(str, Enum):
    """Statistical method used for anomaly detection."""

    Z_SCORE = "z_score"
    IQR = "iqr"
    ADAPTIVE = "adaptive"
    PERCENTILE = "percentile"


class AnomalySeverity(str, Enum):
    """Severity of detected anomaly."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AnomalyResult:
    """Result from a single anomaly check."""

    metric_name: str
    value: float
    is_anomaly: bool
    method: AnomalyMethod
    severity: AnomalySeverity = AnomalySeverity.INFO
    score: float = 0.0
    threshold: float = 0.0
    baseline_mean: float = 0.0
    baseline_std: float = 0.0
    details: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "value": self.value,
            "is_anomaly": self.is_anomaly,
            "method": self.method.value,
            "severity": self.severity.value,
            "score": round(self.score, 4),
            "threshold": round(self.threshold, 4),
            "baseline_mean": round(self.baseline_mean, 4),
            "baseline_std": round(self.baseline_std, 4),
            "details": self.details,
            "timestamp": self.timestamp,
        }


@dataclass
class VisualizationPoint:
    """A single data point for time-series visualization.

    Can be exported to Grafana annotations, Prometheus metrics, or
    matplotlib scatter plots.
    """

    timestamp: float
    metric_name: str
    value: float
    baseline_mean: float
    upper_bound: float
    lower_bound: float
    is_anomaly: bool
    anomaly_score: float = 0.0
    labels: dict[str, str] = field(default_factory=dict)

    def to_grafana_annotation(self) -> dict[str, Any]:
        """Format as a Grafana annotation payload."""
        return {
            "time": int(self.timestamp * 1000),
            "timeEnd": int(self.timestamp * 1000),
            "tags": [
                self.metric_name,
                "anomaly" if self.is_anomaly else "normal",
            ],
            "text": (
                f"{self.metric_name}={self.value:.2f} "
                f"(baseline={self.baseline_mean:.2f}, "
                f"score={self.anomaly_score:.2f})"
            ),
        }

    def to_prometheus_metric(self) -> dict[str, Any]:
        """Format as a Prometheus-style metric for push gateway."""
        return {
            "metric_name": f"aitf_anomaly_{self.metric_name.replace('.', '_')}",
            "value": self.anomaly_score,
            "timestamp_ms": int(self.timestamp * 1000),
            "labels": {
                "is_anomaly": str(self.is_anomaly).lower(),
                **self.labels,
            },
        }


# ---------------------------------------------------------------------------
# BaselineTracker
# ---------------------------------------------------------------------------


class BaselineTracker:
    """Maintains rolling statistics for named metric series.

    Tracks exponential moving average (EMA), variance, min/max, and
    approximate percentiles using a reservoir-sampled window.

    Args:
        window_size: Maximum number of observations to keep in the
            sliding window for percentile calculations.
        ema_alpha: Smoothing factor for the exponential moving average
            (0 < alpha <= 1). Smaller values give more weight to
            historical data.
    """

    def __init__(
        self,
        window_size: int = 1000,
        ema_alpha: float = 0.05,
    ) -> None:
        self._window_size = window_size
        self._alpha = ema_alpha
        # {metric_name: deque([values...])}
        self._windows: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        # EMA state: {metric: {"mean": float, "var": float, "n": int,
        #             "min": float, "max": float}}
        self._ema: dict[str, dict[str, float]] = defaultdict(
            lambda: {"mean": 0.0, "var": 0.0, "n": 0, "min": float("inf"), "max": float("-inf")}
        )

    def update(self, metric_name: str, value: float) -> None:
        """Record a new observation for the metric.

        Args:
            metric_name: Identifier for the metric (e.g. "input_tokens").
            value: The observed numeric value.
        """
        self._windows[metric_name].append(value)
        s = self._ema[metric_name]
        s["n"] += 1
        s["min"] = min(s["min"], value)
        s["max"] = max(s["max"], value)

        if s["n"] == 1:
            s["mean"] = value
            s["var"] = 0.0
        else:
            diff = value - s["mean"]
            s["mean"] += self._alpha * diff
            s["var"] = (1 - self._alpha) * (s["var"] + self._alpha * diff * diff)

    def get_mean(self, metric_name: str) -> float:
        """Return the EMA mean for a metric."""
        return self._ema[metric_name]["mean"]

    def get_std(self, metric_name: str) -> float:
        """Return the EMA standard deviation for a metric."""
        v = self._ema[metric_name]["var"]
        return math.sqrt(v) if v > 0 else 0.0

    def get_count(self, metric_name: str) -> int:
        """Return the total number of observations recorded."""
        return int(self._ema[metric_name]["n"])

    def get_min(self, metric_name: str) -> float:
        """Return the minimum observed value."""
        return self._ema[metric_name]["min"]

    def get_max(self, metric_name: str) -> float:
        """Return the maximum observed value."""
        return self._ema[metric_name]["max"]

    def get_percentile(self, metric_name: str, p: float) -> float:
        """Return the approximate p-th percentile from the window.

        Args:
            metric_name: Metric identifier.
            p: Percentile (0-100).

        Returns:
            Approximate percentile value, or 0.0 if no data.
        """
        window = self._windows.get(metric_name)
        if not window:
            return 0.0
        sorted_vals = sorted(window)
        idx = max(0, min(len(sorted_vals) - 1, int(len(sorted_vals) * p / 100)))
        return sorted_vals[idx]

    def get_iqr(self, metric_name: str) -> tuple[float, float, float]:
        """Return (Q1, Q3, IQR) from the current window.

        Returns:
            Tuple of (q1, q3, iqr). All zeros if insufficient data.
        """
        window = self._windows.get(metric_name)
        if not window or len(window) < 4:
            return 0.0, 0.0, 0.0
        sorted_vals = sorted(window)
        n = len(sorted_vals)
        q1 = sorted_vals[n // 4]
        q3 = sorted_vals[3 * n // 4]
        return q1, q3, q3 - q1

    def get_stats(self, metric_name: str) -> dict[str, float]:
        """Return a dictionary of all statistics for a metric."""
        q1, q3, iqr = self.get_iqr(metric_name)
        return {
            "mean": self.get_mean(metric_name),
            "std": self.get_std(metric_name),
            "count": float(self.get_count(metric_name)),
            "min": self.get_min(metric_name),
            "max": self.get_max(metric_name),
            "q1": q1,
            "q3": q3,
            "iqr": iqr,
            "p50": self.get_percentile(metric_name, 50),
            "p90": self.get_percentile(metric_name, 90),
            "p95": self.get_percentile(metric_name, 95),
            "p99": self.get_percentile(metric_name, 99),
        }

    def has_baseline(self, metric_name: str, min_samples: int = 20) -> bool:
        """Check whether sufficient data exists for a reliable baseline."""
        return self.get_count(metric_name) >= min_samples


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------


class AnomalyDetector:
    """General-purpose anomaly detector using z-score and IQR methods.

    Operates on a shared ``BaselineTracker`` to maintain rolling baselines
    and detect anomalies in real time.

    Args:
        tracker: BaselineTracker instance for maintaining statistics.
        z_score_threshold: Number of standard deviations for z-score method.
        iqr_multiplier: IQR multiplier for the IQR method (typically 1.5).
        min_samples: Minimum observations before anomaly detection activates.
        sensitivity: Global sensitivity multiplier (0.1=very lenient, 2.0=strict).
    """

    def __init__(
        self,
        tracker: BaselineTracker | None = None,
        z_score_threshold: float = 3.0,
        iqr_multiplier: float = 1.5,
        min_samples: int = 20,
        sensitivity: float = 1.0,
    ) -> None:
        self._tracker = tracker or BaselineTracker()
        self._z_threshold = z_score_threshold
        self._iqr_multiplier = iqr_multiplier
        self._min_samples = min_samples
        self._sensitivity = sensitivity
        self._viz_points: list[VisualizationPoint] = []

    @property
    def tracker(self) -> BaselineTracker:
        """Access the underlying baseline tracker."""
        return self._tracker

    @property
    def visualization_points(self) -> list[VisualizationPoint]:
        """Access recorded visualization data points."""
        return self._viz_points

    def check(
        self,
        metric_name: str,
        value: float,
        method: AnomalyMethod = AnomalyMethod.Z_SCORE,
        labels: dict[str, str] | None = None,
    ) -> AnomalyResult:
        """Check a single value for anomalies and update the baseline.

        Args:
            metric_name: Identifier for the metric.
            value: Observed value.
            method: Detection method to use.
            labels: Optional labels for visualization.

        Returns:
            AnomalyResult with detection outcome.
        """
        ts = time.time()

        # Update baseline first
        self._tracker.update(metric_name, value)

        if not self._tracker.has_baseline(metric_name, self._min_samples):
            return AnomalyResult(
                metric_name=metric_name,
                value=value,
                is_anomaly=False,
                method=method,
                details=f"Insufficient data ({self._tracker.get_count(metric_name)}/{self._min_samples})",
                timestamp=ts,
            )

        if method == AnomalyMethod.Z_SCORE:
            result = self._check_zscore(metric_name, value, ts)
        elif method == AnomalyMethod.IQR:
            result = self._check_iqr(metric_name, value, ts)
        elif method == AnomalyMethod.ADAPTIVE:
            result = self._check_adaptive(metric_name, value, ts)
        elif method == AnomalyMethod.PERCENTILE:
            result = self._check_percentile(metric_name, value, ts)
        else:
            result = self._check_zscore(metric_name, value, ts)

        # Record visualization point
        mean = self._tracker.get_mean(metric_name)
        std = self._tracker.get_std(metric_name)
        threshold = self._z_threshold * self._sensitivity
        self._viz_points.append(VisualizationPoint(
            timestamp=ts,
            metric_name=metric_name,
            value=value,
            baseline_mean=mean,
            upper_bound=mean + threshold * std,
            lower_bound=max(0, mean - threshold * std),
            is_anomaly=result.is_anomaly,
            anomaly_score=result.score,
            labels=labels or {},
        ))

        return result

    def _check_zscore(
        self, metric_name: str, value: float, ts: float
    ) -> AnomalyResult:
        """Z-score based anomaly detection."""
        mean = self._tracker.get_mean(metric_name)
        std = self._tracker.get_std(metric_name)
        if std == 0:
            std = 1.0

        z_score = abs(value - mean) / std
        threshold = self._z_threshold * self._sensitivity
        is_anomaly = z_score > threshold

        severity = AnomalySeverity.INFO
        if is_anomaly:
            if z_score > threshold * 2:
                severity = AnomalySeverity.CRITICAL
            elif z_score > threshold * 1.5:
                severity = AnomalySeverity.WARNING

        return AnomalyResult(
            metric_name=metric_name,
            value=value,
            is_anomaly=is_anomaly,
            method=AnomalyMethod.Z_SCORE,
            severity=severity,
            score=z_score,
            threshold=threshold,
            baseline_mean=mean,
            baseline_std=std,
            details=(
                f"z-score={z_score:.2f} (threshold={threshold:.2f}, "
                f"mean={mean:.2f}, std={std:.2f})"
            ),
            timestamp=ts,
        )

    def _check_iqr(
        self, metric_name: str, value: float, ts: float
    ) -> AnomalyResult:
        """IQR (Interquartile Range) based anomaly detection."""
        q1, q3, iqr = self._tracker.get_iqr(metric_name)
        if iqr == 0:
            return AnomalyResult(
                metric_name=metric_name,
                value=value,
                is_anomaly=False,
                method=AnomalyMethod.IQR,
                details="IQR is zero, cannot detect anomalies",
                timestamp=ts,
            )

        multiplier = self._iqr_multiplier * self._sensitivity
        lower_fence = q1 - multiplier * iqr
        upper_fence = q3 + multiplier * iqr
        is_anomaly = value < lower_fence or value > upper_fence

        # Distance from nearest fence
        if value > upper_fence:
            score = (value - upper_fence) / iqr
        elif value < lower_fence:
            score = (lower_fence - value) / iqr
        else:
            score = 0.0

        severity = AnomalySeverity.INFO
        if is_anomaly:
            severity = AnomalySeverity.CRITICAL if score > 3.0 else AnomalySeverity.WARNING

        return AnomalyResult(
            metric_name=metric_name,
            value=value,
            is_anomaly=is_anomaly,
            method=AnomalyMethod.IQR,
            severity=severity,
            score=score,
            threshold=multiplier,
            baseline_mean=self._tracker.get_mean(metric_name),
            baseline_std=self._tracker.get_std(metric_name),
            details=(
                f"value={value:.2f}, Q1={q1:.2f}, Q3={q3:.2f}, IQR={iqr:.2f}, "
                f"fences=[{lower_fence:.2f}, {upper_fence:.2f}]"
            ),
            timestamp=ts,
        )

    def _check_adaptive(
        self, metric_name: str, value: float, ts: float
    ) -> AnomalyResult:
        """Adaptive method: uses z-score but adjusts threshold dynamically.

        Tightens the threshold when variance is low (stable metric) and
        loosens it when variance is high (noisy metric).
        """
        mean = self._tracker.get_mean(metric_name)
        std = self._tracker.get_std(metric_name)
        if std == 0:
            std = 1.0

        # Coefficient of variation -- ratio of std to mean
        cv = std / abs(mean) if mean != 0 else 1.0

        # Adaptive threshold: tighter when CV is low, looser when CV is high
        base_threshold = self._z_threshold * self._sensitivity
        adaptive_threshold = base_threshold * (1 + cv)
        # Clamp to reasonable range
        adaptive_threshold = max(2.0, min(adaptive_threshold, 8.0))

        z_score = abs(value - mean) / std
        is_anomaly = z_score > adaptive_threshold

        severity = AnomalySeverity.INFO
        if is_anomaly:
            severity = AnomalySeverity.CRITICAL if z_score > adaptive_threshold * 2 else AnomalySeverity.WARNING

        return AnomalyResult(
            metric_name=metric_name,
            value=value,
            is_anomaly=is_anomaly,
            method=AnomalyMethod.ADAPTIVE,
            severity=severity,
            score=z_score,
            threshold=adaptive_threshold,
            baseline_mean=mean,
            baseline_std=std,
            details=(
                f"z-score={z_score:.2f}, adaptive_threshold={adaptive_threshold:.2f} "
                f"(CV={cv:.3f}, base={base_threshold:.2f})"
            ),
            timestamp=ts,
        )

    def _check_percentile(
        self, metric_name: str, value: float, ts: float
    ) -> AnomalyResult:
        """Percentile-based anomaly detection.

        Flags values above the 99th percentile or below the 1st percentile.
        """
        p1 = self._tracker.get_percentile(metric_name, 1)
        p99 = self._tracker.get_percentile(metric_name, 99)
        p50 = self._tracker.get_percentile(metric_name, 50)
        is_anomaly = value > p99 or value < p1

        # Score: how far beyond the percentile boundary
        if value > p99:
            score = (value - p99) / max(p99 - p50, 1.0)
        elif value < p1:
            score = (p1 - value) / max(p50 - p1, 1.0)
        else:
            score = 0.0

        severity = AnomalySeverity.INFO
        if is_anomaly:
            severity = AnomalySeverity.CRITICAL if score > 2.0 else AnomalySeverity.WARNING

        return AnomalyResult(
            metric_name=metric_name,
            value=value,
            is_anomaly=is_anomaly,
            method=AnomalyMethod.PERCENTILE,
            severity=severity,
            score=score,
            threshold=0.0,
            baseline_mean=self._tracker.get_mean(metric_name),
            baseline_std=self._tracker.get_std(metric_name),
            details=(
                f"value={value:.2f}, P1={p1:.2f}, P50={p50:.2f}, "
                f"P99={p99:.2f}, distance_score={score:.2f}"
            ),
            timestamp=ts,
        )


# ---------------------------------------------------------------------------
# TimeSeriesAnomalyDetector
# ---------------------------------------------------------------------------


class TimeSeriesAnomalyDetector:
    """Time-series anomaly detection for AITF telemetry metrics.

    Specialized detector that processes AITF events and automatically
    extracts and monitors token usage, latency, and cost metrics.

    Maintains separate baselines per model and per metric, producing
    visualization-ready data points.

    Args:
        detector: Underlying AnomalyDetector instance.
        default_method: Default detection method for all metrics.
    """

    def __init__(
        self,
        detector: AnomalyDetector | None = None,
        default_method: AnomalyMethod = AnomalyMethod.Z_SCORE,
    ) -> None:
        self._detector = detector or AnomalyDetector()
        self._default_method = default_method
        # Metric-specific method overrides
        self._method_overrides: dict[str, AnomalyMethod] = {}

    @property
    def detector(self) -> AnomalyDetector:
        return self._detector

    def set_method(self, metric_name: str, method: AnomalyMethod) -> None:
        """Override the detection method for a specific metric."""
        self._method_overrides[metric_name] = method

    def process_event(self, event: dict[str, Any]) -> list[AnomalyResult]:
        """Process an AITF telemetry event and check all applicable metrics.

        Extracts token counts, latency, and cost values from the event and
        runs anomaly detection on each.

        Args:
            event: AITF telemetry event dictionary.

        Returns:
            List of AnomalyResult objects (one per checked metric).
        """
        model = event.get(GenAIAttributes.REQUEST_MODEL, "unknown")
        results: list[AnomalyResult] = []

        # Define metrics to extract from the event
        metrics = {
            "input_tokens": event.get(GenAIAttributes.USAGE_INPUT_TOKENS),
            "output_tokens": event.get(GenAIAttributes.USAGE_OUTPUT_TOKENS),
            "total_tokens": None,  # computed below
            "latency_ms": event.get(LatencyAttributes.TOTAL_MS),
            "ttft_ms": event.get(LatencyAttributes.TIME_TO_FIRST_TOKEN_MS),
            "tokens_per_second": event.get(LatencyAttributes.TOKENS_PER_SECOND),
            "input_cost": event.get(CostAttributes.INPUT_COST),
            "output_cost": event.get(CostAttributes.OUTPUT_COST),
            "total_cost": event.get(CostAttributes.TOTAL_COST),
        }

        # Compute total tokens if components are present
        input_t = metrics["input_tokens"]
        output_t = metrics["output_tokens"]
        if input_t is not None and output_t is not None:
            metrics["total_tokens"] = input_t + output_t

        # Compute total cost if components are present
        if metrics["total_cost"] is None:
            ic = metrics["input_cost"]
            oc = metrics["output_cost"]
            if ic is not None and oc is not None:
                metrics["total_cost"] = ic + oc

        labels = {"model": model}
        for metric_name, value in metrics.items():
            if value is None or value == 0:
                continue
            # Use per-model metric keys for isolation
            full_name = f"{model}.{metric_name}"
            method = self._method_overrides.get(
                metric_name, self._default_method
            )
            result = self._detector.check(full_name, float(value), method, labels)
            results.append(result)

        return results

    def get_model_summary(self, model: str) -> dict[str, dict[str, float]]:
        """Get statistical summary for all metrics of a specific model.

        Args:
            model: Model name (e.g. "gpt-4o").

        Returns:
            Dictionary of metric_name -> stats dict.
        """
        summary = {}
        metric_names = [
            "input_tokens", "output_tokens", "total_tokens",
            "latency_ms", "ttft_ms", "tokens_per_second",
            "input_cost", "output_cost", "total_cost",
        ]
        for mn in metric_names:
            full_name = f"{model}.{mn}"
            if self._detector.tracker.get_count(full_name) > 0:
                summary[mn] = self._detector.tracker.get_stats(full_name)
        return summary


# ---------------------------------------------------------------------------
# BehavioralAnomalyDetector
# ---------------------------------------------------------------------------


class BehavioralAnomalyDetector:
    """Behavioral anomaly detection for AI agent sessions.

    Builds Markov-chain transition models for agent action sequences and
    detects deviations from learned patterns. Also tracks session-level
    metrics like tool diversity and delegation frequency.

    Args:
        min_sessions: Minimum sessions observed before flagging anomalies.
        transition_anomaly_threshold: Minimum transition probability below
            which a transition is considered anomalous (0-1).
    """

    def __init__(
        self,
        min_sessions: int = 10,
        transition_anomaly_threshold: float = 0.01,
    ) -> None:
        self._min_sessions = min_sessions
        self._transition_threshold = transition_anomaly_threshold
        self._sessions_observed = 0

        # Transition counts: {(from_state, to_state): count}
        self._transitions: dict[tuple[str, str], int] = defaultdict(int)
        # Outgoing counts per state: {state: total_outgoing}
        self._state_counts: dict[str, int] = defaultdict(int)

        # Per-session action history
        self._current_sessions: dict[str, list[str]] = defaultdict(list)

        # Session-level stats tracker
        self._session_tracker = BaselineTracker(window_size=500)

    @property
    def sessions_observed(self) -> int:
        return self._sessions_observed

    def record_action(self, session_id: str, action: str) -> list[AnomalyResult]:
        """Record an agent action and check for behavioral anomalies.

        Args:
            session_id: Agent session identifier.
            action: Action label (tool name, step type, etc.).

        Returns:
            List of anomaly results detected for this action.
        """
        results: list[AnomalyResult] = []
        ts = time.time()
        history = self._current_sessions[session_id]

        # Record transition
        if history:
            prev = history[-1]
            self._transitions[(prev, action)] += 1
            self._state_counts[prev] += 1

            # Check transition probability
            if self._sessions_observed >= self._min_sessions:
                total = self._state_counts.get(prev, 0)
                if total > 0:
                    prob = self._transitions[(prev, action)] / total
                    if prob < self._transition_threshold:
                        results.append(AnomalyResult(
                            metric_name=f"transition.{prev}->{action}",
                            value=prob,
                            is_anomaly=True,
                            method=AnomalyMethod.ADAPTIVE,
                            severity=AnomalySeverity.WARNING,
                            score=1.0 / max(prob, 1e-6),
                            threshold=self._transition_threshold,
                            details=(
                                f"Unusual transition: '{prev}' -> '{action}' "
                                f"(probability={prob:.4f}, "
                                f"threshold={self._transition_threshold})"
                            ),
                            timestamp=ts,
                        ))

        history.append(action)
        return results

    def end_session(self, session_id: str) -> list[AnomalyResult]:
        """Finalize a session and check session-level behavioral metrics.

        Args:
            session_id: Session to finalize.

        Returns:
            List of session-level anomaly results.
        """
        results: list[AnomalyResult] = []
        ts = time.time()
        history = self._current_sessions.pop(session_id, [])
        if not history:
            return results

        self._sessions_observed += 1

        # Compute session metrics
        total_actions = len(history)
        unique_actions = len(set(history))
        diversity_ratio = unique_actions / total_actions if total_actions > 0 else 0

        # Update session-level baselines
        self._session_tracker.update("session_length", total_actions)
        self._session_tracker.update("action_diversity", diversity_ratio)

        if self._session_tracker.has_baseline("session_length", self._min_sessions):
            # Check session length anomaly
            mean = self._session_tracker.get_mean("session_length")
            std = self._session_tracker.get_std("session_length")
            if std > 0:
                z = abs(total_actions - mean) / std
                if z > 3.0:
                    results.append(AnomalyResult(
                        metric_name="session_length",
                        value=float(total_actions),
                        is_anomaly=True,
                        method=AnomalyMethod.Z_SCORE,
                        severity=AnomalySeverity.WARNING,
                        score=z,
                        threshold=3.0,
                        baseline_mean=mean,
                        baseline_std=std,
                        details=(
                            f"Session length {total_actions} is {z:.1f} "
                            f"std devs from mean {mean:.0f}"
                        ),
                        timestamp=ts,
                    ))

            # Check diversity anomaly (very low diversity suggests looping)
            d_mean = self._session_tracker.get_mean("action_diversity")
            d_std = self._session_tracker.get_std("action_diversity")
            if d_std > 0:
                z_div = (d_mean - diversity_ratio) / d_std  # lower is anomalous
                if z_div > 3.0:
                    results.append(AnomalyResult(
                        metric_name="action_diversity",
                        value=diversity_ratio,
                        is_anomaly=True,
                        method=AnomalyMethod.Z_SCORE,
                        severity=AnomalySeverity.WARNING,
                        score=z_div,
                        threshold=3.0,
                        baseline_mean=d_mean,
                        baseline_std=d_std,
                        details=(
                            f"Action diversity {diversity_ratio:.2f} is unusually low "
                            f"(mean={d_mean:.2f}, z={z_div:.1f})"
                        ),
                        timestamp=ts,
                    ))

        return results

    def get_transition_probabilities(self) -> dict[str, dict[str, float]]:
        """Return the learned Markov transition probability matrix.

        Returns:
            {from_state: {to_state: probability}}
        """
        probs: dict[str, dict[str, float]] = defaultdict(dict)
        for (from_s, to_s), count in self._transitions.items():
            total = self._state_counts.get(from_s, 1)
            probs[from_s][to_s] = count / total
        return dict(probs)

    def get_session_stats(self) -> dict[str, dict[str, float]]:
        """Return session-level baseline statistics."""
        return {
            "session_length": self._session_tracker.get_stats("session_length"),
            "action_diversity": self._session_tracker.get_stats("action_diversity"),
        }


# ---------------------------------------------------------------------------
# Convenience: demonstration with synthetic data
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import random

    print("=== AITF Anomaly Detection Engine ===\n")

    # --- Time-series anomaly detection ---
    print("--- Time-Series Anomaly Detection ---\n")

    ts_detector = TimeSeriesAnomalyDetector(
        detector=AnomalyDetector(
            tracker=BaselineTracker(window_size=200),
            z_score_threshold=3.0,
            sensitivity=1.0,
        ),
    )

    # Generate 50 normal events then inject anomalies
    events: list[dict[str, Any]] = []
    for i in range(50):
        events.append({
            GenAIAttributes.REQUEST_MODEL: "gpt-4o",
            GenAIAttributes.USAGE_INPUT_TOKENS: random.gauss(200, 30),
            GenAIAttributes.USAGE_OUTPUT_TOKENS: random.gauss(400, 60),
            LatencyAttributes.TOTAL_MS: random.gauss(800, 100),
            CostAttributes.INPUT_COST: random.gauss(0.001, 0.0002),
            CostAttributes.OUTPUT_COST: random.gauss(0.004, 0.0008),
        })

    # Anomalous events
    events.append({
        GenAIAttributes.REQUEST_MODEL: "gpt-4o",
        GenAIAttributes.USAGE_INPUT_TOKENS: 5000,  # 10x normal
        GenAIAttributes.USAGE_OUTPUT_TOKENS: 8000,  # 13x normal
        LatencyAttributes.TOTAL_MS: 15000,
        CostAttributes.INPUT_COST: 0.05,
        CostAttributes.OUTPUT_COST: 0.08,
    })
    events.append({
        GenAIAttributes.REQUEST_MODEL: "gpt-4o",
        GenAIAttributes.USAGE_INPUT_TOKENS: 200,
        GenAIAttributes.USAGE_OUTPUT_TOKENS: 400,
        LatencyAttributes.TOTAL_MS: 800,
        CostAttributes.INPUT_COST: 0.001,
        CostAttributes.OUTPUT_COST: 0.004,
    })

    anomaly_count = 0
    for i, evt in enumerate(events):
        results = ts_detector.process_event(evt)
        anomalies = [r for r in results if r.is_anomaly]
        if anomalies:
            anomaly_count += 1
            print(f"  Event {i}: {len(anomalies)} anomaly(ies) detected")
            for a in anomalies:
                print(f"    [{a.severity.value.upper()}] {a.metric_name}: {a.details}")

    print(f"\n  Processed {len(events)} events, found anomalies in {anomaly_count} event(s)")

    # Print model summary
    print("\n  Model summary (gpt-4o):")
    summary = ts_detector.get_model_summary("gpt-4o")
    for metric, stats in summary.items():
        print(f"    {metric}: mean={stats['mean']:.2f}, std={stats['std']:.2f}, "
              f"p95={stats['p95']:.2f}")

    # --- Behavioral anomaly detection ---
    print("\n--- Behavioral Anomaly Detection ---\n")

    behavioral = BehavioralAnomalyDetector(
        min_sessions=5,
        transition_anomaly_threshold=0.02,
    )

    # Train on normal sessions
    normal_patterns = [
        ["planning", "search", "reasoning", "response"],
        ["planning", "search", "search", "reasoning", "response"],
        ["planning", "reasoning", "response"],
        ["planning", "search", "reasoning", "search", "reasoning", "response"],
    ]

    for i in range(20):
        session_id = f"train-session-{i}"
        pattern = random.choice(normal_patterns)
        for action in pattern:
            behavioral.record_action(session_id, action)
        behavioral.end_session(session_id)

    print(f"  Trained on {behavioral.sessions_observed} sessions")

    # Check an anomalous session
    anomalous_session = "anomaly-session-1"
    print(f"\n  Checking anomalous session: {anomalous_session}")
    anomalous_actions = ["planning", "delete_files", "execute_command",
                          "search", "delete_files", "response"]
    for action in anomalous_actions:
        results = behavioral.record_action(anomalous_session, action)
        for r in results:
            if r.is_anomaly:
                print(f"    ANOMALY: {r.details}")

    end_results = behavioral.end_session(anomalous_session)
    for r in end_results:
        if r.is_anomaly:
            print(f"    SESSION ANOMALY: {r.details}")

    # Print transition probabilities
    print("\n  Learned transition probabilities:")
    probs = behavioral.get_transition_probabilities()
    for from_state in sorted(probs.keys()):
        transitions = probs[from_state]
        top = sorted(transitions.items(), key=lambda x: x[1], reverse=True)[:3]
        trans_str = ", ".join(f"{t}={p:.2f}" for t, p in top)
        print(f"    {from_state} -> {trans_str}")

    # --- Visualization data ---
    print(f"\n  Visualization data points collected: "
          f"{len(ts_detector.detector.visualization_points)}")
    if ts_detector.detector.visualization_points:
        sample = ts_detector.detector.visualization_points[-1]
        print(f"  Sample Grafana annotation: {sample.to_grafana_annotation()}")
