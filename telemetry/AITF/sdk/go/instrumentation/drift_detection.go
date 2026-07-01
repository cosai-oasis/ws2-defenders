// Package instrumentation provides AITF instrumentation for AI operations.
package instrumentation

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

const driftTracerName = "instrumentation.drift_detection"

// DriftDetectionInstrumentor traces model drift detection, baseline management,
// investigation, and remediation operations. Aligned with CoSAI's identification
// of model drift as a top-level AI incident category.
type DriftDetectionInstrumentor struct {
	tracer trace.Tracer
}

// NewDriftDetectionInstrumentor creates a new drift detection instrumentor.
func NewDriftDetectionInstrumentor(tp trace.TracerProvider) *DriftDetectionInstrumentor {
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return &DriftDetectionInstrumentor{
		tracer: tp.Tracer(driftTracerName),
	}
}

// ── Detection ───────────────────────────────────────────────────────────────

// DetectConfig holds configuration for a drift detection span.
type DetectConfig struct {
	ModelID          string
	DriftType        string // e.g. "data_distribution", "concept", "performance"
	DetectionMethod  string // e.g. "psi", "ks_test", "js_divergence"
	ReferenceDataset string
	ReferencePeriod  string
	Threshold        *float64
}

// DriftDetection provides methods for enriching a drift detection span.
type DriftDetection struct {
	span trace.Span
}

// TraceDetect starts a span for a drift detection analysis. The caller must call
// End() when done.
func (d *DriftDetectionInstrumentor) TraceDetect(ctx context.Context, cfg DetectConfig) (context.Context, *DriftDetection) {
	spanName := fmt.Sprintf("drift.detect %s %s", cfg.DriftType, cfg.ModelID)
	attrs := []attribute.KeyValue{
		semconv.DriftModelIDKey.String(cfg.ModelID),
		semconv.DriftTypeKey.String(cfg.DriftType),
	}
	if cfg.DetectionMethod != "" {
		attrs = append(attrs, semconv.DriftDetectionMethodKey.String(cfg.DetectionMethod))
	}
	if cfg.ReferenceDataset != "" {
		attrs = append(attrs, semconv.DriftRefDatasetKey.String(cfg.ReferenceDataset))
	}
	if cfg.ReferencePeriod != "" {
		attrs = append(attrs, semconv.DriftRefPeriodKey.String(cfg.ReferencePeriod))
	}
	if cfg.Threshold != nil {
		attrs = append(attrs, semconv.DriftThresholdKey.Float64(*cfg.Threshold))
	}

	ctx, span := d.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &DriftDetection{span: span}
}

// SetScore records the drift score.
func (det *DriftDetection) SetScore(score float64) {
	det.span.SetAttributes(semconv.DriftScoreKey.Float64(score))
}

// SetResult records the detection result (e.g. "normal", "alert", "critical").
func (det *DriftDetection) SetResult(result string) {
	det.span.SetAttributes(semconv.DriftResultKey.String(result))
}

// SetMetrics records baseline vs current metric values.
func (det *DriftDetection) SetMetrics(baseline, current float64, metricName string) {
	det.span.SetAttributes(
		semconv.DriftBaselineMetricKey.Float64(baseline),
		semconv.DriftCurrentMetricKey.Float64(current),
		semconv.DriftMetricNameKey.String(metricName),
	)
}

// SetPValue records the statistical p-value.
func (det *DriftDetection) SetPValue(pValue float64) {
	det.span.SetAttributes(semconv.DriftPValueKey.Float64(pValue))
}

// SetSampleSize records the number of samples analyzed.
func (det *DriftDetection) SetSampleSize(size int) {
	det.span.SetAttributes(semconv.DriftSampleSizeKey.Int(size))
}

// SetAffectedSegments records the data segments affected by drift.
func (det *DriftDetection) SetAffectedSegments(segments []string) {
	det.span.SetAttributes(semconv.DriftAffectedSegmentsKey.StringSlice(segments))
}

// SetFeature records a feature name and its optional importance score.
func (det *DriftDetection) SetFeature(name string, importance *float64) {
	det.span.SetAttributes(semconv.DriftFeatureNameKey.String(name))
	if importance != nil {
		det.span.SetAttributes(semconv.DriftFeatureImportanceKey.Float64(*importance))
	}
}

// SetActionTriggered records the action triggered by drift detection.
func (det *DriftDetection) SetActionTriggered(action string) {
	det.span.SetAttributes(semconv.DriftActionTriggeredKey.String(action))
}

// End completes the drift detection span.
func (det *DriftDetection) End(err error) {
	if err != nil {
		det.span.SetStatus(codes.Error, err.Error())
		det.span.RecordError(err)
	} else {
		det.span.SetStatus(codes.Ok, "")
	}
	det.span.End()
}

// Span returns the underlying OTel span.
func (det *DriftDetection) Span() trace.Span { return det.span }

// ── Baseline ────────────────────────────────────────────────────────────────

// BaselineConfig holds configuration for a baseline management span.
type BaselineConfig struct {
	ModelID    string
	Operation  string // e.g. "create", "refresh"
	Dataset    string
	SampleSize *int
	Period     string
}

// DriftBaseline provides methods for enriching a drift baseline span.
type DriftBaseline struct {
	span trace.Span
}

// TraceBaseline starts a span for baseline establishment or refresh. The caller
// must call End() when done.
func (d *DriftDetectionInstrumentor) TraceBaseline(ctx context.Context, cfg BaselineConfig) (context.Context, *DriftBaseline) {
	if cfg.Operation == "" {
		cfg.Operation = "create"
	}

	spanName := fmt.Sprintf("drift.baseline %s %s", cfg.Operation, cfg.ModelID)
	attrs := []attribute.KeyValue{
		semconv.DriftModelIDKey.String(cfg.ModelID),
		semconv.DriftBaselineOperationKey.String(cfg.Operation),
	}
	if cfg.Dataset != "" {
		attrs = append(attrs, semconv.DriftBaselineDatasetKey.String(cfg.Dataset))
	}
	if cfg.SampleSize != nil {
		attrs = append(attrs, semconv.DriftBaselineSampleSizeKey.Int(*cfg.SampleSize))
	}
	if cfg.Period != "" {
		attrs = append(attrs, semconv.DriftBaselinePeriodKey.String(cfg.Period))
	}

	ctx, span := d.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &DriftBaseline{span: span}
}

// SetID records the baseline identifier.
func (b *DriftBaseline) SetID(baselineID string) {
	b.span.SetAttributes(semconv.DriftBaselineIDKey.String(baselineID))
}

// SetMetrics records baseline metrics as a JSON string.
func (b *DriftBaseline) SetMetrics(metricsJSON string) {
	b.span.SetAttributes(semconv.DriftBaselineMetricsKey.String(metricsJSON))
}

// SetFeatures records the feature names included in the baseline.
func (b *DriftBaseline) SetFeatures(features []string) {
	b.span.SetAttributes(semconv.DriftBaselineFeaturesKey.StringSlice(features))
}

// SetPreviousID records the identifier of the previous baseline.
func (b *DriftBaseline) SetPreviousID(previousID string) {
	b.span.SetAttributes(semconv.DriftBaselinePreviousIDKey.String(previousID))
}

// End completes the baseline span.
func (b *DriftBaseline) End(err error) {
	if err != nil {
		b.span.SetStatus(codes.Error, err.Error())
		b.span.RecordError(err)
	} else {
		b.span.SetStatus(codes.Ok, "")
	}
	b.span.End()
}

// Span returns the underlying OTel span.
func (b *DriftBaseline) Span() trace.Span { return b.span }

// ── Investigation ───────────────────────────────────────────────────────────

// InvestigationConfig holds configuration for a drift investigation span.
type InvestigationConfig struct {
	ModelID   string
	TriggerID string
}

// DriftInvestigation provides methods for enriching a drift investigation span.
type DriftInvestigation struct {
	span trace.Span
}

// TraceInvestigate starts a span for a drift investigation. The caller must call
// End() when done.
func (d *DriftDetectionInstrumentor) TraceInvestigate(ctx context.Context, cfg InvestigationConfig) (context.Context, *DriftInvestigation) {
	spanName := fmt.Sprintf("drift.investigate %s", cfg.ModelID)
	attrs := []attribute.KeyValue{
		semconv.DriftModelIDKey.String(cfg.ModelID),
		semconv.DriftInvestTriggerIDKey.String(cfg.TriggerID),
	}

	ctx, span := d.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &DriftInvestigation{span: span}
}

// SetRootCause records the root cause and its category.
func (inv *DriftInvestigation) SetRootCause(cause, category string) {
	inv.span.SetAttributes(
		semconv.DriftInvestRootCauseKey.String(cause),
		semconv.DriftInvestRootCauseCatKey.String(category),
	)
}

// SetImpact records the impact of the drift event.
func (inv *DriftInvestigation) SetImpact(affectedSegments []string, affectedUsersEstimate *int, blastRadius string) {
	inv.span.SetAttributes(semconv.DriftInvestAffectedSegmentsKey.StringSlice(affectedSegments))
	if affectedUsersEstimate != nil {
		inv.span.SetAttributes(semconv.DriftInvestAffectedUsersKey.Int(*affectedUsersEstimate))
	}
	if blastRadius != "" {
		inv.span.SetAttributes(semconv.DriftInvestBlastRadiusKey.String(blastRadius))
	}
}

// SetSeverity records the severity of the drift investigation.
func (inv *DriftInvestigation) SetSeverity(severity string) {
	inv.span.SetAttributes(semconv.DriftInvestSeverityKey.String(severity))
}

// SetRecommendation records the recommended action.
func (inv *DriftInvestigation) SetRecommendation(recommendation string) {
	inv.span.SetAttributes(semconv.DriftInvestRecommendationKey.String(recommendation))
}

// End completes the investigation span.
func (inv *DriftInvestigation) End(err error) {
	if err != nil {
		inv.span.SetStatus(codes.Error, err.Error())
		inv.span.RecordError(err)
	} else {
		inv.span.SetStatus(codes.Ok, "")
	}
	inv.span.End()
}

// Span returns the underlying OTel span.
func (inv *DriftInvestigation) Span() trace.Span { return inv.span }

// ── Remediation ─────────────────────────────────────────────────────────────

// RemediationConfig holds configuration for a drift remediation span.
type RemediationConfig struct {
	ModelID     string
	Action      string // e.g. "retrain", "rollback", "recalibrate"
	TriggerID   string
	Automated   bool
	InitiatedBy string
}

// DriftRemediation provides methods for enriching a drift remediation span.
type DriftRemediation struct {
	span trace.Span
}

// TraceRemediate starts a span for a drift remediation action. The caller must
// call End() when done.
func (d *DriftDetectionInstrumentor) TraceRemediate(ctx context.Context, cfg RemediationConfig) (context.Context, *DriftRemediation) {
	spanName := fmt.Sprintf("drift.remediate %s %s", cfg.Action, cfg.ModelID)
	attrs := []attribute.KeyValue{
		semconv.DriftModelIDKey.String(cfg.ModelID),
		semconv.DriftRemediationActionKey.String(cfg.Action),
		semconv.DriftRemediationAutomatedKey.Bool(cfg.Automated),
	}
	if cfg.TriggerID != "" {
		attrs = append(attrs, semconv.DriftRemediationTriggerIDKey.String(cfg.TriggerID))
	}
	if cfg.InitiatedBy != "" {
		attrs = append(attrs, semconv.DriftRemediationInitiatedByKey.String(cfg.InitiatedBy))
	}

	ctx, span := d.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &DriftRemediation{span: span}
}

// SetStatus records the remediation status.
func (rem *DriftRemediation) SetStatus(status string) {
	rem.span.SetAttributes(semconv.DriftRemediationStatusKey.String(status))
}

// SetRollbackTo records the model version to roll back to.
func (rem *DriftRemediation) SetRollbackTo(modelVersion string) {
	rem.span.SetAttributes(semconv.DriftRemediationRollbackToKey.String(modelVersion))
}

// SetRetrainDataset records the dataset used for retraining.
func (rem *DriftRemediation) SetRetrainDataset(dataset string) {
	rem.span.SetAttributes(semconv.DriftRemediationRetrainKey.String(dataset))
}

// SetValidationPassed records whether the remediation validation passed.
func (rem *DriftRemediation) SetValidationPassed(passed bool) {
	rem.span.SetAttributes(semconv.DriftRemediationValidPassedKey.Bool(passed))
}

// End completes the remediation span.
func (rem *DriftRemediation) End(err error) {
	if err != nil {
		rem.span.SetStatus(codes.Error, err.Error())
		rem.span.RecordError(err)
	} else {
		rem.span.SetStatus(codes.Ok, "")
	}
	rem.span.End()
}

// Span returns the underlying OTel span.
func (rem *DriftRemediation) Span() trace.Span { return rem.span }
