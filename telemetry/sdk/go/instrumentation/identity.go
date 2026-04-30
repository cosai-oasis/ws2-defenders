// Package instrumentation provides AITF instrumentation for AI operations.
package instrumentation

import (
	"context"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

const identityTracerName = "instrumentation.identity"

// IdentityInstrumentor traces AI agent identity operations including lifecycle,
// authentication, authorization, delegation, trust establishment, and session
// management. Supports OAuth 2.1, SPIFFE, mTLS, DID/VC, and other modern
// identity protocols for AI agents.
type IdentityInstrumentor struct {
	tracer trace.Tracer
}

// NewIdentityInstrumentor creates a new identity instrumentor.
func NewIdentityInstrumentor(tp trace.TracerProvider) *IdentityInstrumentor {
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return &IdentityInstrumentor{
		tracer: tp.Tracer(identityTracerName),
	}
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

// LifecycleConfig holds configuration for an identity lifecycle span.
type LifecycleConfig struct {
	AgentID        string
	AgentName      string
	Operation      string // e.g. "create", "rotate", "revoke", "suspend"
	IdentityType   string // e.g. "persistent", "ephemeral", "delegated"
	Provider       string
	Owner          string
	OwnerType      string
	CredentialType string
	Scope          []string
	TTLSeconds     *int
}

// IdentityLifecycle provides methods for recording identity lifecycle attributes.
type IdentityLifecycle struct {
	span trace.Span
}

// TraceLifecycle starts a span for an identity lifecycle operation. The caller
// must call End() when done.
func (id *IdentityInstrumentor) TraceLifecycle(ctx context.Context, cfg LifecycleConfig) (context.Context, *IdentityLifecycle) {
	if cfg.IdentityType == "" {
		cfg.IdentityType = "persistent"
	}

	spanName := fmt.Sprintf("identity.lifecycle.%s %s", cfg.Operation, cfg.AgentID)
	attrs := []attribute.KeyValue{
		semconv.IdentityAgentIDKey.String(cfg.AgentID),
		semconv.IdentityAgentNameKey.String(cfg.AgentName),
		semconv.IdentityLifecycleOpKey.String(cfg.Operation),
		semconv.IdentityTypeKey.String(cfg.IdentityType),
	}
	if cfg.Provider != "" {
		attrs = append(attrs, semconv.IdentityProviderKey.String(cfg.Provider))
	}
	if cfg.Owner != "" {
		attrs = append(attrs, semconv.IdentityOwnerKey.String(cfg.Owner))
	}
	if cfg.OwnerType != "" {
		attrs = append(attrs, semconv.IdentityOwnerTypeKey.String(cfg.OwnerType))
	}
	if cfg.CredentialType != "" {
		attrs = append(attrs, semconv.IdentityCredentialTypeKey.String(cfg.CredentialType))
	}
	if len(cfg.Scope) > 0 {
		attrs = append(attrs, semconv.IdentityScopeKey.StringSlice(cfg.Scope))
	}
	if cfg.TTLSeconds != nil {
		attrs = append(attrs, semconv.IdentityTTLSecondsKey.Int(*cfg.TTLSeconds))
	}

	ctx, span := id.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &IdentityLifecycle{span: span}
}

// SetStatus records the identity status and optional previous status.
func (lc *IdentityLifecycle) SetStatus(status string, previousStatus string) {
	lc.span.SetAttributes(semconv.IdentityStatusKey.String(status))
	if previousStatus != "" {
		lc.span.SetAttributes(semconv.IdentityPreviousStatusKey.String(previousStatus))
	}
}

// SetCredential records credential details.
func (lc *IdentityLifecycle) SetCredential(credentialID string, expiresAt string) {
	lc.span.SetAttributes(semconv.IdentityCredentialIDKey.String(credentialID))
	if expiresAt != "" {
		lc.span.SetAttributes(semconv.IdentityExpiresAtKey.String(expiresAt))
	}
}

// SetAutoRotate records whether automatic credential rotation is enabled.
func (lc *IdentityLifecycle) SetAutoRotate(enabled bool, intervalSeconds *int) {
	lc.span.SetAttributes(semconv.IdentityAutoRotateKey.Bool(enabled))
	if intervalSeconds != nil {
		lc.span.SetAttributes(semconv.IdentityRotationIntervalKey.Int(*intervalSeconds))
	}
}

// End completes the lifecycle span.
func (lc *IdentityLifecycle) End(err error) {
	if err != nil {
		lc.span.SetStatus(codes.Error, err.Error())
		lc.span.RecordError(err)
	} else {
		lc.span.SetStatus(codes.Ok, "")
	}
	lc.span.End()
}

// Span returns the underlying OTel span.
func (lc *IdentityLifecycle) Span() trace.Span { return lc.span }

// ── Authentication ──────────────────────────────────────────────────────────

// AuthenticationConfig holds configuration for an authentication span.
type AuthenticationConfig struct {
	AgentID        string
	AgentName      string
	Method         string // e.g. "spiffe_svid", "oauth2", "mtls"
	TargetService  string
	Provider       string
	ScopeRequested []string
}

// AuthenticationAttempt provides methods for recording authentication results.
type AuthenticationAttempt struct {
	span trace.Span
}

// TraceAuthentication starts a span for an agent authentication attempt. The
// caller must call End() when done.
func (id *IdentityInstrumentor) TraceAuthentication(ctx context.Context, cfg AuthenticationConfig) (context.Context, *AuthenticationAttempt) {
	spanName := fmt.Sprintf("identity.auth %s", cfg.AgentName)
	attrs := []attribute.KeyValue{
		semconv.IdentityAgentIDKey.String(cfg.AgentID),
		semconv.IdentityAgentNameKey.String(cfg.AgentName),
		semconv.IdentityAuthMethodKey.String(cfg.Method),
	}
	if cfg.TargetService != "" {
		attrs = append(attrs, semconv.IdentityAuthTargetServiceKey.String(cfg.TargetService))
	}
	if cfg.Provider != "" {
		attrs = append(attrs, semconv.IdentityAuthProviderKey.String(cfg.Provider))
	}
	if len(cfg.ScopeRequested) > 0 {
		attrs = append(attrs, semconv.IdentityAuthScopeRequestedKey.StringSlice(cfg.ScopeRequested))
	}

	ctx, span := id.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
	return ctx, &AuthenticationAttempt{span: span}
}

// SetResult records the authentication result.
func (a *AuthenticationAttempt) SetResult(result string, scopeGranted []string, tokenType string, failureReason string) {
	a.span.SetAttributes(semconv.IdentityAuthResultKey.String(result))
	if len(scopeGranted) > 0 {
		a.span.SetAttributes(semconv.IdentityAuthScopeGrantedKey.StringSlice(scopeGranted))
	}
	if tokenType != "" {
		a.span.SetAttributes(semconv.IdentityAuthTokenTypeKey.String(tokenType))
	}
	if failureReason != "" {
		a.span.SetAttributes(semconv.IdentityAuthFailureReasonKey.String(failureReason))
	}
}

// SetPKCE records whether PKCE was used.
func (a *AuthenticationAttempt) SetPKCE(used bool) {
	a.span.SetAttributes(semconv.IdentityAuthPKCEUsedKey.Bool(used))
}

// SetDPoP records whether DPoP was used.
func (a *AuthenticationAttempt) SetDPoP(used bool) {
	a.span.SetAttributes(semconv.IdentityAuthDPoPUsedKey.Bool(used))
}

// SetContinuous records whether continuous authentication is enabled.
func (a *AuthenticationAttempt) SetContinuous(continuous bool) {
	a.span.SetAttributes(semconv.IdentityAuthContinuousKey.Bool(continuous))
}

// End completes the authentication span.
func (a *AuthenticationAttempt) End(err error) {
	if err != nil {
		a.span.SetStatus(codes.Error, err.Error())
		a.span.RecordError(err)
	} else {
		a.span.SetStatus(codes.Ok, "")
	}
	a.span.End()
}

// Span returns the underlying OTel span.
func (a *AuthenticationAttempt) Span() trace.Span { return a.span }

// ── Authorization ───────────────────────────────────────────────────────────

// AuthorizationConfig holds configuration for an authorization span.
type AuthorizationConfig struct {
	AgentID      string
	AgentName    string
	Resource     string
	Action       string // e.g. "read", "write", "execute"
	PolicyEngine string // e.g. "opa", "cedar"
}

// AuthorizationCheck provides methods for recording authorization decisions.
type AuthorizationCheck struct {
	span trace.Span
}

// TraceAuthorization starts a span for an authorization decision. The caller
// must call End() when done.
func (id *IdentityInstrumentor) TraceAuthorization(ctx context.Context, cfg AuthorizationConfig) (context.Context, *AuthorizationCheck) {
	if cfg.Action == "" {
		cfg.Action = "read"
	}

	spanName := fmt.Sprintf("identity.authz %s -> %s", cfg.AgentName, cfg.Resource)
	attrs := []attribute.KeyValue{
		semconv.IdentityAgentIDKey.String(cfg.AgentID),
		semconv.IdentityAgentNameKey.String(cfg.AgentName),
		semconv.IdentityAuthzResourceKey.String(cfg.Resource),
		semconv.IdentityAuthzActionKey.String(cfg.Action),
	}
	if cfg.PolicyEngine != "" {
		attrs = append(attrs, semconv.IdentityAuthzPolicyEngineKey.String(cfg.PolicyEngine))
	}

	ctx, span := id.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &AuthorizationCheck{span: span}
}

// SetDecision records the authorization decision.
func (az *AuthorizationCheck) SetDecision(decision string, policyID string, denyReason string, riskScore *float64) {
	az.span.SetAttributes(semconv.IdentityAuthzDecisionKey.String(decision))
	if policyID != "" {
		az.span.SetAttributes(semconv.IdentityAuthzPolicyIDKey.String(policyID))
	}
	if denyReason != "" {
		az.span.SetAttributes(semconv.IdentityAuthzDenyReasonKey.String(denyReason))
	}
	if riskScore != nil {
		az.span.SetAttributes(semconv.IdentityAuthzRiskScoreKey.Float64(*riskScore))
	}
}

// SetJEA records Just-Enough-Access authorization details.
func (az *AuthorizationCheck) SetJEA(enabled bool, timeLimited bool, expiresAt string) {
	az.span.SetAttributes(
		semconv.IdentityAuthzJEAKey.Bool(enabled),
		semconv.IdentityAuthzTimeLimitedKey.Bool(timeLimited),
	)
	if expiresAt != "" {
		az.span.SetAttributes(semconv.IdentityAuthzExpiresAtKey.String(expiresAt))
	}
}

// End completes the authorization span.
func (az *AuthorizationCheck) End(err error) {
	if err != nil {
		az.span.SetStatus(codes.Error, err.Error())
		az.span.RecordError(err)
	} else {
		az.span.SetStatus(codes.Ok, "")
	}
	az.span.End()
}

// Span returns the underlying OTel span.
func (az *AuthorizationCheck) Span() trace.Span { return az.span }

// ── Delegation ──────────────────────────────────────────────────────────────

// DelegationConfig holds configuration for a delegation span.
type DelegationConfig struct {
	Delegator      string
	DelegatorID    string
	Delegatee      string
	DelegateeID    string
	DelegationType string // e.g. "on_behalf_of", "token_exchange"
	ScopeDelegated []string
	TTLSeconds     *int
}

// DelegationOperation provides methods for recording delegation results.
type DelegationOperation struct {
	span trace.Span
}

// TraceDelegation starts a span for credential delegation. The caller must call
// End() when done.
func (id *IdentityInstrumentor) TraceDelegation(ctx context.Context, cfg DelegationConfig) (context.Context, *DelegationOperation) {
	if cfg.DelegationType == "" {
		cfg.DelegationType = "on_behalf_of"
	}

	spanName := fmt.Sprintf("identity.delegate %s -> %s", cfg.Delegator, cfg.Delegatee)
	attrs := []attribute.KeyValue{
		semconv.IdentityDelegDelegatorKey.String(cfg.Delegator),
		semconv.IdentityDelegDelegatorIDKey.String(cfg.DelegatorID),
		semconv.IdentityDelegDelegateeKey.String(cfg.Delegatee),
		semconv.IdentityDelegDelegateeIDKey.String(cfg.DelegateeID),
		semconv.IdentityDelegTypeKey.String(cfg.DelegationType),
	}
	if len(cfg.ScopeDelegated) > 0 {
		attrs = append(attrs, semconv.IdentityDelegScopeDelegatedKey.StringSlice(cfg.ScopeDelegated))
	}
	if cfg.TTLSeconds != nil {
		attrs = append(attrs, semconv.IdentityDelegTTLSecondsKey.Int(*cfg.TTLSeconds))
	}

	ctx, span := id.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &DelegationOperation{span: span}
}

// SetChain records the delegation chain and its depth.
func (del *DelegationOperation) SetChain(chain []string) {
	del.span.SetAttributes(
		semconv.IdentityDelegChainKey.StringSlice(chain),
		semconv.IdentityDelegChainDepthKey.Int(len(chain)-1),
	)
}

// SetResult records the delegation result.
func (del *DelegationOperation) SetResult(result string) {
	del.span.SetAttributes(semconv.IdentityDelegResultKey.String(result))
}

// SetScopeAttenuated records whether the delegated scope was attenuated.
func (del *DelegationOperation) SetScopeAttenuated(attenuated bool) {
	del.span.SetAttributes(semconv.IdentityDelegScopeAttenuatedKey.Bool(attenuated))
}

// SetProof records the proof type used for delegation.
func (del *DelegationOperation) SetProof(proofType string) {
	del.span.SetAttributes(semconv.IdentityDelegProofTypeKey.String(proofType))
}

// End completes the delegation span.
func (del *DelegationOperation) End(err error) {
	if err != nil {
		del.span.SetStatus(codes.Error, err.Error())
		del.span.RecordError(err)
	} else {
		del.span.SetStatus(codes.Ok, "")
	}
	del.span.End()
}

// Span returns the underlying OTel span.
func (del *DelegationOperation) Span() trace.Span { return del.span }

// ── Trust ───────────────────────────────────────────────────────────────────

// TrustConfig holds configuration for a trust establishment span.
type TrustConfig struct {
	AgentID     string
	AgentName   string
	Operation   string // e.g. "establish", "verify", "revoke"
	PeerAgent   string
	PeerAgentID string
	Method      string // e.g. "mtls", "spiffe", "did"
}

// TrustOperation provides methods for recording trust establishment results.
type TrustOperation struct {
	span trace.Span
}

// TraceTrust starts a span for trust establishment between agents. The caller
// must call End() when done.
func (id *IdentityInstrumentor) TraceTrust(ctx context.Context, cfg TrustConfig) (context.Context, *TrustOperation) {
	if cfg.Method == "" {
		cfg.Method = "mtls"
	}

	spanName := fmt.Sprintf("identity.trust.%s %s", cfg.Operation, cfg.PeerAgent)
	attrs := []attribute.KeyValue{
		semconv.IdentityAgentIDKey.String(cfg.AgentID),
		semconv.IdentityAgentNameKey.String(cfg.AgentName),
		semconv.IdentityTrustOperationKey.String(cfg.Operation),
		semconv.IdentityTrustPeerAgentKey.String(cfg.PeerAgent),
		semconv.IdentityTrustPeerAgentIDKey.String(cfg.PeerAgentID),
		semconv.IdentityTrustMethodKey.String(cfg.Method),
	}

	ctx, span := id.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
	return ctx, &TrustOperation{span: span}
}

// SetResult records the trust establishment result.
func (t *TrustOperation) SetResult(result string, trustLevel string, crossDomain bool) {
	t.span.SetAttributes(semconv.IdentityTrustResultKey.String(result))
	if trustLevel != "" {
		t.span.SetAttributes(semconv.IdentityTrustLevelKey.String(trustLevel))
	}
	t.span.SetAttributes(semconv.IdentityTrustCrossDomainKey.Bool(crossDomain))
}

// SetTrustDomain records the trust domain and optional peer domain.
func (t *TrustOperation) SetTrustDomain(domain string, peerDomain string) {
	t.span.SetAttributes(semconv.IdentityTrustDomainKey.String(domain))
	if peerDomain != "" {
		t.span.SetAttributes(semconv.IdentityTrustPeerDomainKey.String(peerDomain))
	}
}

// SetProtocol records the trust protocol used.
func (t *TrustOperation) SetProtocol(protocol string) {
	t.span.SetAttributes(semconv.IdentityTrustProtocolKey.String(protocol))
}

// End completes the trust span.
func (t *TrustOperation) End(err error) {
	if err != nil {
		t.span.SetStatus(codes.Error, err.Error())
		t.span.RecordError(err)
	} else {
		t.span.SetStatus(codes.Ok, "")
	}
	t.span.End()
}

// Span returns the underlying OTel span.
func (t *TrustOperation) Span() trace.Span { return t.span }

// ── Session ─────────────────────────────────────────────────────────────────

// SessionConfig holds configuration for an identity session span. Note: this
// type is named IdentitySessionConfig to avoid collision with the agent
// SessionConfig in the same package.
type IdentitySessionConfig struct {
	AgentID   string
	AgentName string
	Operation string // e.g. "create", "refresh", "terminate"
	SessionID string
	Scope     []string
	ExpiresAt string
}

// IdentitySession provides methods for recording identity session attributes.
type IdentitySession struct {
	span         trace.Span
	SessionID    string
	actionsCount int
	mu           sync.Mutex
}

// TraceSession starts a span for an identity session operation. The caller must
// call End() when done.
func (id *IdentityInstrumentor) TraceSession(ctx context.Context, cfg IdentitySessionConfig) (context.Context, *IdentitySession) {
	if cfg.Operation == "" {
		cfg.Operation = "create"
	}

	spanName := fmt.Sprintf("identity.session %s", cfg.AgentName)
	attrs := []attribute.KeyValue{
		semconv.IdentityAgentIDKey.String(cfg.AgentID),
		semconv.IdentityAgentNameKey.String(cfg.AgentName),
		semconv.IdentitySessionIDKey.String(cfg.SessionID),
		semconv.IdentitySessionOperationKey.String(cfg.Operation),
	}
	if len(cfg.Scope) > 0 {
		attrs = append(attrs, semconv.IdentitySessionScopeKey.StringSlice(cfg.Scope))
	}
	if cfg.ExpiresAt != "" {
		attrs = append(attrs, semconv.IdentitySessionExpiresAtKey.String(cfg.ExpiresAt))
	}

	ctx, span := id.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, &IdentitySession{span: span, SessionID: cfg.SessionID}
}

// RecordAction increments the session action counter.
func (s *IdentitySession) RecordAction() {
	s.mu.Lock()
	s.actionsCount++
	count := s.actionsCount
	s.mu.Unlock()
	s.span.SetAttributes(semconv.IdentitySessionActionsCountKey.Int(count))
}

// SetTermination records the reason for session termination.
func (s *IdentitySession) SetTermination(reason string) {
	s.span.SetAttributes(semconv.IdentitySessionTerminationReasonKey.String(reason))
}

// End completes the session span.
func (s *IdentitySession) End(err error) {
	if err != nil {
		s.span.SetStatus(codes.Error, err.Error())
		s.span.RecordError(err)
	} else {
		s.span.SetStatus(codes.Ok, "")
	}
	s.span.End()
}

// Span returns the underlying OTel span.
func (s *IdentitySession) Span() trace.Span { return s.span }
