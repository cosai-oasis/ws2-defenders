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

const assetInventoryTracerName = "instrumentation.asset_inventory"

// AssetInventoryInstrumentor traces AI asset lifecycle management including
// registration, discovery, audit, risk classification, and decommissioning.
// Aligned with CoSAI AI Incident Response preparation requirements.
type AssetInventoryInstrumentor struct {
	tracer trace.Tracer
}

// NewAssetInventoryInstrumentor creates a new asset inventory instrumentor.
func NewAssetInventoryInstrumentor(tp trace.TracerProvider) *AssetInventoryInstrumentor {
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return &AssetInventoryInstrumentor{
		tracer: tp.Tracer(assetInventoryTracerName),
	}
}

// ── Registration ────────────────────────────────────────────────────────────

// RegisterConfig holds configuration for an asset registration span.
type RegisterConfig struct {
	AssetID              string
	AssetName            string
	AssetType            string // e.g. "model", "dataset", "agent", "pipeline"
	Version              string
	AssetHash            string
	Owner                string
	OwnerType            string
	DeploymentEnvironment string
	RiskClassification   string
	SourceRepository     string
	Tags                 []string
}

// AssetRegistration provides methods for enriching an asset registration span.
type AssetRegistration struct {
	span    trace.Span
	AssetID string
}

// TraceRegister starts a span for asset registration. The caller must call
// End() when done.
func (ai *AssetInventoryInstrumentor) TraceRegister(ctx context.Context, cfg RegisterConfig) (context.Context, *AssetRegistration) {
	if cfg.AssetType == "" {
		cfg.AssetType = "model"
	}

	spanName := fmt.Sprintf("asset.register %s %s", cfg.AssetType, cfg.AssetName)
	attrs := []attribute.KeyValue{
		semconv.AssetIDKey.String(cfg.AssetID),
		semconv.AssetNameKey.String(cfg.AssetName),
		semconv.AssetTypeKey.String(cfg.AssetType),
	}
	if cfg.Version != "" {
		attrs = append(attrs, semconv.AssetVersionKey.String(cfg.Version))
	}
	if cfg.AssetHash != "" {
		attrs = append(attrs, semconv.AssetHashKey.String(cfg.AssetHash))
	}
	if cfg.Owner != "" {
		attrs = append(attrs, semconv.AssetOwnerKey.String(cfg.Owner))
	}
	if cfg.OwnerType != "" {
		attrs = append(attrs, semconv.AssetOwnerTypeKey.String(cfg.OwnerType))
	}
	if cfg.DeploymentEnvironment != "" {
		attrs = append(attrs, semconv.AssetDeployEnvKey.String(cfg.DeploymentEnvironment))
	}
	if cfg.RiskClassification != "" {
		attrs = append(attrs, semconv.AssetRiskClassificationKey.String(cfg.RiskClassification))
	}
	if cfg.SourceRepository != "" {
		attrs = append(attrs, semconv.AssetSourceRepoKey.String(cfg.SourceRepository))
	}
	if len(cfg.Tags) > 0 {
		attrs = append(attrs, semconv.AssetTagsKey.StringSlice(cfg.Tags))
	}

	ctx, span := ai.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &AssetRegistration{span: span, AssetID: cfg.AssetID}
}

// SetHash records the asset hash after registration.
func (r *AssetRegistration) SetHash(hash string) {
	r.span.SetAttributes(semconv.AssetHashKey.String(hash))
}

// SetVersion records the asset version.
func (r *AssetRegistration) SetVersion(version string) {
	r.span.SetAttributes(semconv.AssetVersionKey.String(version))
}

// SetRiskClassification records or updates the risk classification.
func (r *AssetRegistration) SetRiskClassification(classification string) {
	r.span.SetAttributes(semconv.AssetRiskClassificationKey.String(classification))
}

// SetDeploymentEnvironment records the deployment environment.
func (r *AssetRegistration) SetDeploymentEnvironment(env string) {
	r.span.SetAttributes(semconv.AssetDeployEnvKey.String(env))
}

// End completes the registration span.
func (r *AssetRegistration) End(err error) {
	if err != nil {
		r.span.SetStatus(codes.Error, err.Error())
		r.span.RecordError(err)
	} else {
		r.span.SetStatus(codes.Ok, "")
	}
	r.span.End()
}

// Span returns the underlying OTel span.
func (r *AssetRegistration) Span() trace.Span { return r.span }

// ── Discovery ───────────────────────────────────────────────────────────────

// DiscoveryConfig holds configuration for an asset discovery span.
type DiscoveryConfig struct {
	Scope  string // e.g. "organization", "team", "project"
	Method string // e.g. "api_scan", "network_scan", "registry_sync"
}

// AssetDiscovery provides methods for enriching an asset discovery span.
type AssetDiscovery struct {
	span trace.Span
}

// TraceDiscover starts a span for an asset discovery scan. The caller must call
// End() when done.
func (ai *AssetInventoryInstrumentor) TraceDiscover(ctx context.Context, cfg DiscoveryConfig) (context.Context, *AssetDiscovery) {
	if cfg.Scope == "" {
		cfg.Scope = "organization"
	}
	if cfg.Method == "" {
		cfg.Method = "api_scan"
	}

	spanName := fmt.Sprintf("asset.discover %s", cfg.Scope)
	attrs := []attribute.KeyValue{
		semconv.AssetDiscoveryScopeKey.String(cfg.Scope),
		semconv.AssetDiscoveryMethodKey.String(cfg.Method),
	}

	ctx, span := ai.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &AssetDiscovery{span: span}
}

// SetResults records discovery scan results.
func (d *AssetDiscovery) SetResults(assetsFound, newAssets, shadowAssets int) {
	d.span.SetAttributes(
		semconv.AssetDiscoveryAssetsFoundKey.Int(assetsFound),
		semconv.AssetDiscoveryNewAssetsKey.Int(newAssets),
		semconv.AssetDiscoveryShadowKey.Int(shadowAssets),
	)
}

// SetStatus records the discovery status.
func (d *AssetDiscovery) SetStatus(status string) {
	d.span.SetAttributes(semconv.AssetDiscoveryStatusKey.String(status))
}

// End completes the discovery span.
func (d *AssetDiscovery) End(err error) {
	if err != nil {
		d.span.SetStatus(codes.Error, err.Error())
		d.span.RecordError(err)
	} else {
		d.span.SetStatus(codes.Ok, "")
	}
	d.span.End()
}

// Span returns the underlying OTel span.
func (d *AssetDiscovery) Span() trace.Span { return d.span }

// ── Audit ───────────────────────────────────────────────────────────────────

// AuditConfig holds configuration for an asset audit span.
type AuditConfig struct {
	AssetID   string
	AuditType string // e.g. "compliance", "security", "integrity"
	Framework string
	Auditor   string
}

// AssetAudit provides methods for enriching an asset audit span.
type AssetAudit struct {
	span trace.Span
}

// TraceAudit starts a span for an asset audit. The caller must call End() when done.
func (ai *AssetInventoryInstrumentor) TraceAudit(ctx context.Context, cfg AuditConfig) (context.Context, *AssetAudit) {
	if cfg.AuditType == "" {
		cfg.AuditType = "compliance"
	}

	spanName := fmt.Sprintf("asset.audit %s", cfg.AssetID)
	attrs := []attribute.KeyValue{
		semconv.AssetIDKey.String(cfg.AssetID),
		semconv.AssetAuditTypeKey.String(cfg.AuditType),
	}
	if cfg.Framework != "" {
		attrs = append(attrs, semconv.AssetAuditFrameworkKey.String(cfg.Framework))
	}
	if cfg.Auditor != "" {
		attrs = append(attrs, semconv.AssetAuditAuditorKey.String(cfg.Auditor))
	}

	ctx, span := ai.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &AssetAudit{span: span}
}

// SetResult records the audit result.
func (a *AssetAudit) SetResult(result string) {
	a.span.SetAttributes(semconv.AssetAuditResultKey.String(result))
}

// SetRiskScore records the audit risk score.
func (a *AssetAudit) SetRiskScore(score float64) {
	a.span.SetAttributes(semconv.AssetAuditRiskScoreKey.Float64(score))
}

// SetIntegrityVerified records whether integrity was verified.
func (a *AssetAudit) SetIntegrityVerified(verified bool) {
	a.span.SetAttributes(semconv.AssetAuditIntegrityKey.Bool(verified))
}

// SetComplianceStatus records the compliance status.
func (a *AssetAudit) SetComplianceStatus(status string) {
	a.span.SetAttributes(semconv.AssetAuditComplianceKey.String(status))
}

// SetFindings records audit findings as a string.
func (a *AssetAudit) SetFindings(findings string) {
	a.span.SetAttributes(semconv.AssetAuditFindingsKey.String(findings))
}

// SetNextAuditDue records when the next audit is due.
func (a *AssetAudit) SetNextAuditDue(timestamp string) {
	a.span.SetAttributes(semconv.AssetAuditNextDueKey.String(timestamp))
}

// End completes the audit span.
func (a *AssetAudit) End(err error) {
	if err != nil {
		a.span.SetStatus(codes.Error, err.Error())
		a.span.RecordError(err)
	} else {
		a.span.SetStatus(codes.Ok, "")
	}
	a.span.End()
}

// Span returns the underlying OTel span.
func (a *AssetAudit) Span() trace.Span { return a.span }

// ── Classification ──────────────────────────────────────────────────────────

// ClassifyConfig holds configuration for a risk classification span.
type ClassifyConfig struct {
	AssetID            string
	RiskClassification string // e.g. "high_risk", "minimal_risk"
	Framework          string // e.g. "eu_ai_act"
	Assessor           string
	UseCase            string
}

// AssetClassification provides methods for enriching a risk classification span.
type AssetClassification struct {
	span trace.Span
}

// TraceClassify starts a span for risk classification. The caller must call
// End() when done.
func (ai *AssetInventoryInstrumentor) TraceClassify(ctx context.Context, cfg ClassifyConfig) (context.Context, *AssetClassification) {
	if cfg.Framework == "" {
		cfg.Framework = "eu_ai_act"
	}

	spanName := fmt.Sprintf("asset.classify %s", cfg.AssetID)
	attrs := []attribute.KeyValue{
		semconv.AssetIDKey.String(cfg.AssetID),
		semconv.AssetRiskClassificationKey.String(cfg.RiskClassification),
		semconv.AssetClassFrameworkKey.String(cfg.Framework),
	}
	if cfg.Assessor != "" {
		attrs = append(attrs, semconv.AssetClassAssessorKey.String(cfg.Assessor))
	}
	if cfg.UseCase != "" {
		attrs = append(attrs, semconv.AssetClassUseCaseKey.String(cfg.UseCase))
	}

	ctx, span := ai.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &AssetClassification{span: span}
}

// SetPrevious records the previous risk classification.
func (c *AssetClassification) SetPrevious(previous string) {
	c.span.SetAttributes(semconv.AssetClassPreviousKey.String(previous))
}

// SetReason records the reason for classification.
func (c *AssetClassification) SetReason(reason string) {
	c.span.SetAttributes(semconv.AssetClassReasonKey.String(reason))
}

// SetAutonomousDecision records whether the asset makes autonomous decisions.
func (c *AssetClassification) SetAutonomousDecision(autonomous bool) {
	c.span.SetAttributes(semconv.AssetClassAutonomousDecisionKey.Bool(autonomous))
}

// End completes the classification span.
func (c *AssetClassification) End(err error) {
	if err != nil {
		c.span.SetStatus(codes.Error, err.Error())
		c.span.RecordError(err)
	} else {
		c.span.SetStatus(codes.Ok, "")
	}
	c.span.End()
}

// Span returns the underlying OTel span.
func (c *AssetClassification) Span() trace.Span { return c.span }

// ── Decommission ────────────────────────────────────────────────────────────

// DecommissionConfig holds configuration for an asset decommission span.
type DecommissionConfig struct {
	AssetID       string
	AssetType     string
	Reason        string
	ReplacementID string
	ApprovedBy    string
}

// TraceDecommission starts a span for asset decommissioning. The caller must
// call End() on the returned span when done.
func (ai *AssetInventoryInstrumentor) TraceDecommission(ctx context.Context, cfg DecommissionConfig) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("asset.decommission %s %s", cfg.AssetType, cfg.AssetID)
	attrs := []attribute.KeyValue{
		semconv.AssetIDKey.String(cfg.AssetID),
		semconv.AssetTypeKey.String(cfg.AssetType),
		semconv.AssetDecommissionReasonKey.String(cfg.Reason),
	}
	if cfg.ReplacementID != "" {
		attrs = append(attrs, semconv.AssetDecommissionReplacementKey.String(cfg.ReplacementID))
	}
	if cfg.ApprovedBy != "" {
		attrs = append(attrs, semconv.AssetDecommissionApprovedByKey.String(cfg.ApprovedBy))
	}

	ctx, span := ai.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, span
}
