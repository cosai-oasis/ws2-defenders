// Package instrumentation provides AITF instrumentation for AI operations.
package instrumentation

import (
	"context"
	"encoding/json"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

const modelOpsTracerName = "instrumentation.model_ops"

// ModelOpsInstrumentor traces AI model lifecycle operations including training,
// evaluation, registry, deployment, serving, monitoring, and prompt versioning.
type ModelOpsInstrumentor struct {
	tracer trace.Tracer
}

// NewModelOpsInstrumentor creates a new model operations instrumentor.
func NewModelOpsInstrumentor(tp trace.TracerProvider) *ModelOpsInstrumentor {
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return &ModelOpsInstrumentor{
		tracer: tp.Tracer(modelOpsTracerName),
	}
}

// ── Training ────────────────────────────────────────────────────────────────

// TrainingConfig holds configuration for a training span.
type TrainingConfig struct {
	RunID          string
	TrainingType   string // e.g. "fine_tuning", "lora", "rlhf"
	BaseModel      string
	Framework      string
	DatasetID      string
	DatasetVersion string
	DatasetSize    *int
	Hyperparams    string
	Epochs         *int
	ExperimentID   string
	ExperimentName string
}

// TrainingRun provides methods for recording training run attributes.
type TrainingRun struct {
	span  trace.Span
	RunID string
}

// TraceTraining starts a new training span. The caller must call End() when done.
func (m *ModelOpsInstrumentor) TraceTraining(ctx context.Context, cfg TrainingConfig) (context.Context, *TrainingRun) {
	if cfg.TrainingType == "" {
		cfg.TrainingType = "fine_tuning"
	}

	spanName := fmt.Sprintf("model_ops.training %s", cfg.RunID)
	attrs := []attribute.KeyValue{
		semconv.ModelOpsTrainingRunIDKey.String(cfg.RunID),
		semconv.ModelOpsTrainingTypeKey.String(cfg.TrainingType),
		semconv.ModelOpsTrainingBaseModelKey.String(cfg.BaseModel),
	}
	if cfg.Framework != "" {
		attrs = append(attrs, semconv.ModelOpsTrainingFrameworkKey.String(cfg.Framework))
	}
	if cfg.DatasetID != "" {
		attrs = append(attrs, semconv.ModelOpsTrainingDatasetIDKey.String(cfg.DatasetID))
	}
	if cfg.DatasetVersion != "" {
		attrs = append(attrs, semconv.ModelOpsTrainingDatasetVersionKey.String(cfg.DatasetVersion))
	}
	if cfg.DatasetSize != nil {
		attrs = append(attrs, semconv.ModelOpsTrainingDatasetSizeKey.Int(*cfg.DatasetSize))
	}
	if cfg.Hyperparams != "" {
		attrs = append(attrs, semconv.ModelOpsTrainingHyperparamsKey.String(cfg.Hyperparams))
	}
	if cfg.Epochs != nil {
		attrs = append(attrs, semconv.ModelOpsTrainingEpochsKey.Int(*cfg.Epochs))
	}
	if cfg.ExperimentID != "" {
		attrs = append(attrs, semconv.ModelOpsTrainingExperimentIDKey.String(cfg.ExperimentID))
	}
	if cfg.ExperimentName != "" {
		attrs = append(attrs, semconv.ModelOpsTrainingExperimentNameKey.String(cfg.ExperimentName))
	}

	ctx, span := m.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)

	return ctx, &TrainingRun{span: span, RunID: cfg.RunID}
}

// SetLoss records the final training and validation loss.
func (t *TrainingRun) SetLoss(loss float64, valLoss *float64) {
	t.span.SetAttributes(semconv.ModelOpsTrainingLossFinalKey.Float64(loss))
	if valLoss != nil {
		t.span.SetAttributes(semconv.ModelOpsTrainingValLossFinalKey.Float64(*valLoss))
	}
}

// SetOutputModel records the output model identifier and hash.
func (t *TrainingRun) SetOutputModel(modelID string, modelHash string) {
	t.span.SetAttributes(semconv.ModelOpsTrainingOutputModelIDKey.String(modelID))
	if modelHash != "" {
		t.span.SetAttributes(semconv.ModelOpsTrainingOutputModelHashKey.String(modelHash))
	}
}

// SetCompute records GPU compute details.
func (t *TrainingRun) SetCompute(gpuType string, gpuCount int, gpuHours float64) {
	t.span.SetAttributes(
		semconv.ModelOpsTrainingGPUTypeKey.String(gpuType),
		semconv.ModelOpsTrainingGPUCountKey.Int(gpuCount),
		semconv.ModelOpsTrainingGPUHoursKey.Float64(gpuHours),
	)
}

// SetCodeCommit records the code commit hash used for training.
func (t *TrainingRun) SetCodeCommit(commit string) {
	t.span.SetAttributes(semconv.ModelOpsTrainingCodeCommitKey.String(commit))
}

// End completes the training span.
func (t *TrainingRun) End(err error) {
	if err != nil {
		t.span.SetStatus(codes.Error, err.Error())
		t.span.RecordError(err)
		t.span.SetAttributes(semconv.ModelOpsTrainingStatusKey.String("failed"))
	} else {
		t.span.SetStatus(codes.Ok, "")
		t.span.SetAttributes(semconv.ModelOpsTrainingStatusKey.String("completed"))
	}
	t.span.End()
}

// Span returns the underlying OTel span.
func (t *TrainingRun) Span() trace.Span { return t.span }

// ── Evaluation ──────────────────────────────────────────────────────────────

// EvaluationConfig holds configuration for an evaluation span.
type EvaluationConfig struct {
	ModelID       string
	EvalType      string // e.g. "benchmark", "llm_judge"
	RunID         string
	DatasetID     string
	DatasetSize   *int
	JudgeModel    string
	BaselineModel string
}

// EvaluationRun provides methods for recording evaluation attributes.
type EvaluationRun struct {
	span  trace.Span
	RunID string
}

// TraceEvaluation starts a new evaluation span. The caller must call End() when done.
func (m *ModelOpsInstrumentor) TraceEvaluation(ctx context.Context, cfg EvaluationConfig) (context.Context, *EvaluationRun) {
	if cfg.EvalType == "" {
		cfg.EvalType = "benchmark"
	}

	spanName := fmt.Sprintf("model_ops.evaluation %s", cfg.RunID)
	attrs := []attribute.KeyValue{
		semconv.ModelOpsEvalRunIDKey.String(cfg.RunID),
		semconv.ModelOpsEvalModelIDKey.String(cfg.ModelID),
		semconv.ModelOpsEvalTypeKey.String(cfg.EvalType),
	}
	if cfg.DatasetID != "" {
		attrs = append(attrs, semconv.ModelOpsEvalDatasetIDKey.String(cfg.DatasetID))
	}
	if cfg.DatasetSize != nil {
		attrs = append(attrs, semconv.ModelOpsEvalDatasetSizeKey.Int(*cfg.DatasetSize))
	}
	if cfg.JudgeModel != "" {
		attrs = append(attrs, semconv.ModelOpsEvalJudgeModelKey.String(cfg.JudgeModel))
	}
	if cfg.BaselineModel != "" {
		attrs = append(attrs, semconv.ModelOpsEvalBaselineModelKey.String(cfg.BaselineModel))
	}

	ctx, span := m.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)

	return ctx, &EvaluationRun{span: span, RunID: cfg.RunID}
}

// SetMetrics records evaluation metrics as a JSON string.
func (e *EvaluationRun) SetMetrics(metrics map[string]interface{}) {
	data, err := json.Marshal(metrics)
	if err == nil {
		e.span.SetAttributes(semconv.ModelOpsEvalMetricsKey.String(string(data)))
	}
}

// SetPass records whether the evaluation passed and if regression was detected.
func (e *EvaluationRun) SetPass(passed bool, regressionDetected bool) {
	e.span.SetAttributes(
		semconv.ModelOpsEvalPassKey.Bool(passed),
		semconv.ModelOpsEvalRegressionDetectedKey.Bool(regressionDetected),
	)
}

// End completes the evaluation span.
func (e *EvaluationRun) End(err error) {
	if err != nil {
		e.span.SetStatus(codes.Error, err.Error())
		e.span.RecordError(err)
	} else {
		e.span.SetStatus(codes.Ok, "")
	}
	e.span.End()
}

// Span returns the underlying OTel span.
func (e *EvaluationRun) Span() trace.Span { return e.span }

// ── Registry ────────────────────────────────────────────────────────────────

// RegistryConfig holds configuration for a registry span.
type RegistryConfig struct {
	ModelID        string
	Operation      string // e.g. "register", "promote", "archive"
	ModelVersion   string
	Stage          string
	ModelAlias     string
	Owner          string
	TrainingRunID  string
	ParentModelID  string
}

// TraceRegistry starts a new registry operation span. The caller must call
// End() on the returned span when done.
func (m *ModelOpsInstrumentor) TraceRegistry(ctx context.Context, cfg RegistryConfig) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("model_ops.registry.%s %s", cfg.Operation, cfg.ModelID)
	attrs := []attribute.KeyValue{
		semconv.ModelOpsRegistryOperationKey.String(cfg.Operation),
		semconv.ModelOpsRegistryModelIDKey.String(cfg.ModelID),
	}
	if cfg.ModelVersion != "" {
		attrs = append(attrs, semconv.ModelOpsRegistryModelVersionKey.String(cfg.ModelVersion))
	}
	if cfg.Stage != "" {
		attrs = append(attrs, semconv.ModelOpsRegistryStageKey.String(cfg.Stage))
	}
	if cfg.ModelAlias != "" {
		attrs = append(attrs, semconv.ModelOpsRegistryModelAliasKey.String(cfg.ModelAlias))
	}
	if cfg.Owner != "" {
		attrs = append(attrs, semconv.ModelOpsRegistryOwnerKey.String(cfg.Owner))
	}
	if cfg.TrainingRunID != "" {
		attrs = append(attrs, semconv.ModelOpsRegistryTrainingRunIDKey.String(cfg.TrainingRunID))
	}
	if cfg.ParentModelID != "" {
		attrs = append(attrs, semconv.ModelOpsRegistryParentModelIDKey.String(cfg.ParentModelID))
	}

	ctx, span := m.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, span
}

// ── Deployment ──────────────────────────────────────────────────────────────

// DeploymentConfig holds configuration for a deployment span.
type DeploymentConfig struct {
	ModelID        string
	Strategy       string // e.g. "rolling", "canary", "blue_green"
	DeploymentID   string
	Environment    string
	Endpoint       string
	CanaryPercent  *float64
	InfraProvider  string
}

// DeploymentOperation provides methods for recording deployment attributes.
type DeploymentOperation struct {
	span         trace.Span
	DeploymentID string
}

// TraceDeployment starts a new deployment span. The caller must call End() when done.
func (m *ModelOpsInstrumentor) TraceDeployment(ctx context.Context, cfg DeploymentConfig) (context.Context, *DeploymentOperation) {
	if cfg.Strategy == "" {
		cfg.Strategy = "rolling"
	}
	if cfg.Environment == "" {
		cfg.Environment = "production"
	}

	spanName := fmt.Sprintf("model_ops.deployment %s", cfg.DeploymentID)
	attrs := []attribute.KeyValue{
		semconv.ModelOpsDeploymentIDKey.String(cfg.DeploymentID),
		semconv.ModelOpsDeploymentModelIDKey.String(cfg.ModelID),
		semconv.ModelOpsDeploymentStrategyKey.String(cfg.Strategy),
		semconv.ModelOpsDeploymentEnvironmentKey.String(cfg.Environment),
	}
	if cfg.Endpoint != "" {
		attrs = append(attrs, semconv.ModelOpsDeploymentEndpointKey.String(cfg.Endpoint))
	}
	if cfg.CanaryPercent != nil {
		attrs = append(attrs, semconv.ModelOpsDeploymentCanaryPctKey.Float64(*cfg.CanaryPercent))
	}
	if cfg.InfraProvider != "" {
		attrs = append(attrs, semconv.ModelOpsDeploymentInfraProviderKey.String(cfg.InfraProvider))
	}

	ctx, span := m.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)

	return ctx, &DeploymentOperation{span: span, DeploymentID: cfg.DeploymentID}
}

// SetHealth records deployment health check results.
func (d *DeploymentOperation) SetHealth(status string, latencyMs *float64) {
	d.span.SetAttributes(semconv.ModelOpsDeploymentHealthStatusKey.String(status))
	if latencyMs != nil {
		d.span.SetAttributes(semconv.ModelOpsDeploymentHealthLatencyKey.Float64(*latencyMs))
	}
}

// SetInfrastructure records deployment infrastructure details.
func (d *DeploymentOperation) SetInfrastructure(gpuType string, replicas *int) {
	if gpuType != "" {
		d.span.SetAttributes(semconv.ModelOpsDeploymentInfraGPUTypeKey.String(gpuType))
	}
	if replicas != nil {
		d.span.SetAttributes(semconv.ModelOpsDeploymentInfraReplicasKey.Int(*replicas))
	}
}

// End completes the deployment span.
func (d *DeploymentOperation) End(err error) {
	if err != nil {
		d.span.SetStatus(codes.Error, err.Error())
		d.span.RecordError(err)
		d.span.SetAttributes(semconv.ModelOpsDeploymentStatusKey.String("failed"))
	} else {
		d.span.SetStatus(codes.Ok, "")
		d.span.SetAttributes(semconv.ModelOpsDeploymentStatusKey.String("completed"))
	}
	d.span.End()
}

// Span returns the underlying OTel span.
func (d *DeploymentOperation) Span() trace.Span { return d.span }

// ── Serving: Route ──────────────────────────────────────────────────────────

// RouteConfig holds configuration for a routing span.
type RouteConfig struct {
	SelectedModel string
	Reason        string
	Candidates    []string
}

// TraceRoute starts a span for a model routing decision. The caller must call
// End() on the returned span when done.
func (m *ModelOpsInstrumentor) TraceRoute(ctx context.Context, cfg RouteConfig) (context.Context, trace.Span) {
	if cfg.Reason == "" {
		cfg.Reason = "capability"
	}

	attrs := []attribute.KeyValue{
		semconv.ModelOpsServingOperationKey.String("route"),
		semconv.ModelOpsServingRouteSelectedKey.String(cfg.SelectedModel),
		semconv.ModelOpsServingRouteReasonKey.String(cfg.Reason),
	}
	if len(cfg.Candidates) > 0 {
		attrs = append(attrs, semconv.ModelOpsServingRouteCandidatesKey.StringSlice(cfg.Candidates))
	}

	ctx, span := m.tracer.Start(ctx, "model_ops.serving.route",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, span
}

// ── Serving: Fallback ───────────────────────────────────────────────────────

// FallbackConfig holds configuration for a fallback span.
type FallbackConfig struct {
	OriginalModel string
	FinalModel    string
	Trigger       string // e.g. "error", "timeout", "rate_limit"
	Chain         []string
	Depth         int
}

// TraceFallback starts a span for a model serving fallback. The caller must call
// End() on the returned span when done.
func (m *ModelOpsInstrumentor) TraceFallback(ctx context.Context, cfg FallbackConfig) (context.Context, trace.Span) {
	if cfg.Trigger == "" {
		cfg.Trigger = "error"
	}
	if cfg.Depth == 0 {
		cfg.Depth = 1
	}

	attrs := []attribute.KeyValue{
		semconv.ModelOpsServingOperationKey.String("fallback"),
		semconv.ModelOpsServingFallbackTriggerKey.String(cfg.Trigger),
		semconv.ModelOpsServingFallbackOriginalKey.String(cfg.OriginalModel),
		semconv.ModelOpsServingFallbackFinalKey.String(cfg.FinalModel),
		semconv.ModelOpsServingFallbackDepthKey.Int(cfg.Depth),
	}
	if len(cfg.Chain) > 0 {
		attrs = append(attrs, semconv.ModelOpsServingFallbackChainKey.StringSlice(cfg.Chain))
	}

	ctx, span := m.tracer.Start(ctx, "model_ops.serving.fallback",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, span
}

// ── Serving: Cache Lookup ───────────────────────────────────────────────────

// CacheLookupConfig holds configuration for a cache lookup span.
type CacheLookupConfig struct {
	CacheType string // e.g. "semantic", "exact"
}

// CacheLookup provides methods for recording cache lookup results.
type CacheLookup struct {
	span trace.Span
}

// TraceCacheLookup starts a span for a cache lookup operation. The caller must
// call End() when done.
func (m *ModelOpsInstrumentor) TraceCacheLookup(ctx context.Context, cfg CacheLookupConfig) (context.Context, *CacheLookup) {
	if cfg.CacheType == "" {
		cfg.CacheType = "semantic"
	}

	attrs := []attribute.KeyValue{
		semconv.ModelOpsServingOperationKey.String("cache_lookup"),
		semconv.ModelOpsServingCacheTypeKey.String(cfg.CacheType),
	}

	ctx, span := m.tracer.Start(ctx, "model_ops.serving.cache_lookup",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &CacheLookup{span: span}
}

// SetHit records whether the cache was hit and optional similarity/cost data.
func (c *CacheLookup) SetHit(hit bool, similarityScore *float64, costSavedUSD *float64) {
	c.span.SetAttributes(semconv.ModelOpsServingCacheHitKey.Bool(hit))
	if similarityScore != nil {
		c.span.SetAttributes(semconv.ModelOpsServingCacheSimilarityKey.Float64(*similarityScore))
	}
	if costSavedUSD != nil {
		c.span.SetAttributes(semconv.ModelOpsServingCacheCostSavedKey.Float64(*costSavedUSD))
	}
}

// End completes the cache lookup span.
func (c *CacheLookup) End(err error) {
	if err != nil {
		c.span.SetStatus(codes.Error, err.Error())
		c.span.RecordError(err)
	} else {
		c.span.SetStatus(codes.Ok, "")
	}
	c.span.End()
}

// Span returns the underlying OTel span.
func (c *CacheLookup) Span() trace.Span { return c.span }

// ── Monitoring ──────────────────────────────────────────────────────────────

// MonitoringCheckConfig holds configuration for a monitoring check span.
type MonitoringCheckConfig struct {
	ModelID    string
	CheckType  string // e.g. "drift", "performance", "sla"
	MetricName string
}

// MonitoringCheck provides methods for recording monitoring check results.
type MonitoringCheck struct {
	span trace.Span
}

// TraceMonitoringCheck starts a span for a model monitoring check. The caller must
// call End() when done.
func (m *ModelOpsInstrumentor) TraceMonitoringCheck(ctx context.Context, cfg MonitoringCheckConfig) (context.Context, *MonitoringCheck) {
	spanName := fmt.Sprintf("model_ops.monitoring.%s", cfg.CheckType)
	attrs := []attribute.KeyValue{
		semconv.ModelOpsMonitorCheckTypeKey.String(cfg.CheckType),
		semconv.ModelOpsMonitorModelIDKey.String(cfg.ModelID),
	}
	if cfg.MetricName != "" {
		attrs = append(attrs, semconv.ModelOpsMonitorMetricNameKey.String(cfg.MetricName))
	}

	ctx, span := m.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &MonitoringCheck{span: span}
}

// SetResult records the monitoring check result.
func (mc *MonitoringCheck) SetResult(result string, metricValue *float64, baselineValue *float64, driftScore *float64, driftType string, actionTriggered string) {
	mc.span.SetAttributes(semconv.ModelOpsMonitorResultKey.String(result))
	if metricValue != nil {
		mc.span.SetAttributes(semconv.ModelOpsMonitorMetricValueKey.Float64(*metricValue))
	}
	if baselineValue != nil {
		mc.span.SetAttributes(semconv.ModelOpsMonitorBaselineValueKey.Float64(*baselineValue))
	}
	if driftScore != nil {
		mc.span.SetAttributes(semconv.ModelOpsMonitorDriftScoreKey.Float64(*driftScore))
	}
	if driftType != "" {
		mc.span.SetAttributes(semconv.ModelOpsMonitorDriftTypeKey.String(driftType))
	}
	if actionTriggered != "" {
		mc.span.SetAttributes(semconv.ModelOpsMonitorActionTriggeredKey.String(actionTriggered))
	}
}

// End completes the monitoring check span.
func (mc *MonitoringCheck) End(err error) {
	if err != nil {
		mc.span.SetStatus(codes.Error, err.Error())
		mc.span.RecordError(err)
	} else {
		mc.span.SetStatus(codes.Ok, "")
	}
	mc.span.End()
}

// Span returns the underlying OTel span.
func (mc *MonitoringCheck) Span() trace.Span { return mc.span }

// ── Prompt Lifecycle ────────────────────────────────────────────────────────

// PromptConfig holds configuration for a prompt lifecycle span.
type PromptConfig struct {
	Name        string
	Operation   string // e.g. "create", "update", "deploy", "rollback"
	Version     string
	Label       string
	ModelTarget string
}

// PromptOperation provides methods for recording prompt lifecycle attributes.
type PromptOperation struct {
	span trace.Span
}

// TracePrompt starts a span for a prompt lifecycle operation. The caller must
// call End() when done.
func (m *ModelOpsInstrumentor) TracePrompt(ctx context.Context, cfg PromptConfig) (context.Context, *PromptOperation) {
	spanName := fmt.Sprintf("model_ops.prompt.%s %s", cfg.Operation, cfg.Name)
	attrs := []attribute.KeyValue{
		semconv.ModelOpsPromptNameKey.String(cfg.Name),
		semconv.ModelOpsPromptOperationKey.String(cfg.Operation),
	}
	if cfg.Version != "" {
		attrs = append(attrs, semconv.ModelOpsPromptVersionKey.String(cfg.Version))
	}
	if cfg.Label != "" {
		attrs = append(attrs, semconv.ModelOpsPromptLabelKey.String(cfg.Label))
	}
	if cfg.ModelTarget != "" {
		attrs = append(attrs, semconv.ModelOpsPromptModelTargetKey.String(cfg.ModelTarget))
	}

	ctx, span := m.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &PromptOperation{span: span}
}

// SetEvaluation records prompt evaluation results.
func (p *PromptOperation) SetEvaluation(score float64, passed bool) {
	p.span.SetAttributes(
		semconv.ModelOpsPromptEvalScoreKey.Float64(score),
		semconv.ModelOpsPromptEvalPassKey.Bool(passed),
	)
}

// SetContentHash records the prompt content hash.
func (p *PromptOperation) SetContentHash(hash string) {
	p.span.SetAttributes(semconv.ModelOpsPromptContentHashKey.String(hash))
}

// SetABTest records A/B test information for the prompt.
func (p *PromptOperation) SetABTest(testID, variant string) {
	p.span.SetAttributes(
		semconv.ModelOpsPromptABTestIDKey.String(testID),
		semconv.ModelOpsPromptABTestVariantKey.String(variant),
	)
}

// End completes the prompt lifecycle span.
func (p *PromptOperation) End(err error) {
	if err != nil {
		p.span.SetStatus(codes.Error, err.Error())
		p.span.RecordError(err)
	} else {
		p.span.SetStatus(codes.Ok, "")
	}
	p.span.End()
}

// Span returns the underlying OTel span.
func (p *PromptOperation) Span() trace.Span { return p.span }
