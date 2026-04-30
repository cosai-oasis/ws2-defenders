/**
 * AITF Agentic Identity Instrumentation.
 *
 * Provides tracing for the complete agent identity lifecycle: identity creation,
 * authentication, authorization, delegation, trust establishment, and session
 * management. Supports OAuth 2.1, SPIFFE, mTLS, DID/VC, and other modern
 * identity protocols for AI agents.
 */

import {
  trace,
  Span,
  SpanKind,
  SpanStatusCode,
  Tracer,
  TracerProvider,
} from "@opentelemetry/api";
import { IdentityAttributes } from "../semantic-conventions/attributes";

const TRACER_NAME = "instrumentation.identity";

// ---------------------------------------------------------------------------
// Option interfaces
// ---------------------------------------------------------------------------

/** Options for tracing an identity lifecycle operation. */
export interface TraceLifecycleOptions {
  agentId: string;
  agentName: string;
  operation: string;
  identityType?: string;
  provider?: string;
  owner?: string;
  ownerType?: string;
  credentialType?: string;
  scope?: string[];
  ttlSeconds?: number;
}

/** Options for tracing an agent authentication attempt. */
export interface TraceAuthenticationOptions {
  agentId: string;
  agentName: string;
  method: string;
  targetService?: string;
  provider?: string;
  scopeRequested?: string[];
}

/** Options for tracing an authorization decision. */
export interface TraceAuthorizationOptions {
  agentId: string;
  agentName: string;
  resource: string;
  action?: string;
  policyEngine?: string;
}

/** Options for tracing credential delegation. */
export interface TraceDelegationOptions {
  delegator: string;
  delegatorId: string;
  delegatee: string;
  delegateeId: string;
  delegationType?: string;
  scopeDelegated?: string[];
  ttlSeconds?: number;
}

/** Options for tracing trust establishment between agents. */
export interface TraceTrustOptions {
  agentId: string;
  agentName: string;
  operation: string;
  peerAgent: string;
  peerAgentId: string;
  method?: string;
}

/** Options for tracing identity session operations. */
export interface TraceSessionOptions {
  agentId: string;
  agentName: string;
  operation?: string;
  sessionId?: string;
  scope?: string[];
  expiresAt?: string;
}

// ---------------------------------------------------------------------------
// Helper classes
// ---------------------------------------------------------------------------

/** Helper for recording identity lifecycle attributes on a span. */
export class IdentityLifecycle {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the identity status, optionally with previous status. */
  setStatus(status: string, previousStatus?: string): void {
    this._span.setAttribute(IdentityAttributes.STATUS, status);
    if (previousStatus !== undefined) {
      this._span.setAttribute(IdentityAttributes.PREVIOUS_STATUS, previousStatus);
    }
  }

  /** Record credential information. */
  setCredential(credentialId: string, expiresAt?: string): void {
    this._span.setAttribute(IdentityAttributes.CREDENTIAL_ID, credentialId);
    if (expiresAt !== undefined) {
      this._span.setAttribute(IdentityAttributes.EXPIRES_AT, expiresAt);
    }
  }

  /** Record auto-rotation configuration. */
  setAutoRotate(enabled: boolean, intervalSeconds?: number): void {
    this._span.setAttribute(IdentityAttributes.AUTO_ROTATE, enabled);
    if (intervalSeconds !== undefined) {
      this._span.setAttribute(IdentityAttributes.ROTATION_INTERVAL, intervalSeconds);
    }
  }
}

/** Helper for recording authentication attempt results on a span. */
export class AuthenticationAttempt {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the authentication result. */
  setResult(options: {
    result: string;
    scopeGranted?: string[];
    tokenType?: string;
    failureReason?: string;
  }): void {
    this._span.setAttribute(IdentityAttributes.AUTH_RESULT, options.result);
    if (options.scopeGranted !== undefined) {
      this._span.setAttribute(IdentityAttributes.AUTH_SCOPE_GRANTED, options.scopeGranted);
    }
    if (options.tokenType !== undefined) {
      this._span.setAttribute(IdentityAttributes.AUTH_TOKEN_TYPE, options.tokenType);
    }
    if (options.failureReason !== undefined) {
      this._span.setAttribute(IdentityAttributes.AUTH_FAILURE_REASON, options.failureReason);
    }
  }

  /** Record whether PKCE was used. */
  setPkce(used: boolean): void {
    this._span.setAttribute(IdentityAttributes.AUTH_PKCE_USED, used);
  }

  /** Record whether DPoP was used. */
  setDpop(used: boolean): void {
    this._span.setAttribute(IdentityAttributes.AUTH_DPOP_USED, used);
  }

  /** Record whether continuous authentication is enabled. */
  setContinuous(continuous: boolean): void {
    this._span.setAttribute(IdentityAttributes.AUTH_CONTINUOUS, continuous);
  }
}

/** Helper for recording authorization check results on a span. */
export class AuthorizationCheck {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the authorization decision. */
  setDecision(options: {
    decision: string;
    policyId?: string;
    denyReason?: string;
    riskScore?: number;
  }): void {
    this._span.setAttribute(IdentityAttributes.AUTHZ_DECISION, options.decision);
    if (options.policyId !== undefined) {
      this._span.setAttribute(IdentityAttributes.AUTHZ_POLICY_ID, options.policyId);
    }
    if (options.denyReason !== undefined) {
      this._span.setAttribute(IdentityAttributes.AUTHZ_DENY_REASON, options.denyReason);
    }
    if (options.riskScore !== undefined) {
      this._span.setAttribute(IdentityAttributes.AUTHZ_RISK_SCORE, options.riskScore);
    }
  }

  /** Record Just-Enough-Access (JEA) configuration. */
  setJea(enabled: boolean, timeLimited: boolean = false, expiresAt?: string): void {
    this._span.setAttribute(IdentityAttributes.AUTHZ_JEA, enabled);
    this._span.setAttribute(IdentityAttributes.AUTHZ_TIME_LIMITED, timeLimited);
    if (expiresAt !== undefined) {
      this._span.setAttribute(IdentityAttributes.AUTHZ_EXPIRES_AT, expiresAt);
    }
  }
}

/** Helper for recording delegation operation results on a span. */
export class DelegationOperation {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the delegation chain (list of identities in the chain). */
  setChain(chain: string[]): void {
    this._span.setAttribute(IdentityAttributes.DELEGATION_CHAIN, chain);
    this._span.setAttribute(IdentityAttributes.DELEGATION_CHAIN_DEPTH, chain.length - 1);
  }

  /** Record the delegation result. */
  setResult(result: string): void {
    this._span.setAttribute(IdentityAttributes.DELEGATION_RESULT, result);
  }

  /** Record whether the scope was attenuated during delegation. */
  setScopeAttenuated(attenuated: boolean): void {
    this._span.setAttribute(IdentityAttributes.DELEGATION_SCOPE_ATTENUATED, attenuated);
  }

  /** Record the proof type used for delegation. */
  setProof(proofType: string): void {
    this._span.setAttribute(IdentityAttributes.DELEGATION_PROOF_TYPE, proofType);
  }
}

/** Helper for recording trust establishment results on a span. */
export class TrustOperation {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the trust establishment result. */
  setResult(
    result: string,
    trustLevel?: string,
    crossDomain: boolean = false,
  ): void {
    this._span.setAttribute(IdentityAttributes.TRUST_RESULT, result);
    if (trustLevel !== undefined) {
      this._span.setAttribute(IdentityAttributes.TRUST_LEVEL, trustLevel);
    }
    this._span.setAttribute(IdentityAttributes.TRUST_CROSS_DOMAIN, crossDomain);
  }

  /** Record trust domain information. */
  setTrustDomain(domain: string, peerDomain?: string): void {
    this._span.setAttribute(IdentityAttributes.TRUST_DOMAIN, domain);
    if (peerDomain !== undefined) {
      this._span.setAttribute(IdentityAttributes.TRUST_PEER_DOMAIN, peerDomain);
    }
  }

  /** Record the trust establishment protocol. */
  setProtocol(protocol: string): void {
    this._span.setAttribute(IdentityAttributes.TRUST_PROTOCOL, protocol);
  }
}

/** Helper for recording identity session attributes on a span. */
export class IdentitySession {
  private readonly _span: Span;

  /** The unique identifier for this session. */
  readonly sessionId: string;

  private _actionsCount = 0;

  constructor(span: Span, sessionId: string) {
    this._span = span;
    this.sessionId = sessionId;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Increment the session action counter. */
  recordAction(): void {
    this._actionsCount += 1;
    this._span.setAttribute(IdentityAttributes.SESSION_ACTIONS_COUNT, this._actionsCount);
  }

  /** Record the session termination reason. */
  setTermination(reason: string): void {
    this._span.setAttribute(IdentityAttributes.SESSION_TERMINATION_REASON, reason);
  }
}

// ---------------------------------------------------------------------------
// Instrumentor
// ---------------------------------------------------------------------------

/**
 * Instrumentor for AI agent identity operations.
 *
 * Traces identity lifecycle, authentication, authorization, delegation,
 * trust establishment, and session management with AITF semantic convention
 * attributes.
 */
export class IdentityInstrumentor {
  private _tracerProvider: TracerProvider | null;
  private _tracer: Tracer | null = null;
  private _instrumented = false;

  constructor(tracerProvider?: TracerProvider) {
    this._tracerProvider = tracerProvider ?? null;
  }

  /** Enable identity instrumentation. */
  instrument(): void {
    const tp = this._tracerProvider ?? trace.getTracerProvider();
    this._tracer = tp.getTracer(TRACER_NAME);
    this._instrumented = true;
  }

  /** Disable identity instrumentation. */
  uninstrument(): void {
    this._tracer = null;
    this._instrumented = false;
  }

  /** Get the tracer instance, lazily initializing if needed. */
  getTracer(): Tracer {
    if (!this._tracer) {
      const tp = this._tracerProvider ?? trace.getTracerProvider();
      this._tracer = tp.getTracer(TRACER_NAME);
    }
    return this._tracer;
  }

  // -- Lifecycle ------------------------------------------------------------

  /**
   * Trace an identity lifecycle operation (create, rotate, revoke, etc.).
   *
   * Returns an {@link IdentityLifecycle} for manual span management, or
   * accepts a callback that receives the lifecycle and automatically ends
   * the span.
   */
  traceLifecycle(options: TraceLifecycleOptions): IdentityLifecycle;
  traceLifecycle<T>(
    options: TraceLifecycleOptions,
    fn: (lifecycle: IdentityLifecycle) => T,
  ): T;
  traceLifecycle<T>(
    options: TraceLifecycleOptions,
    fn?: (lifecycle: IdentityLifecycle) => T,
  ): IdentityLifecycle | T {
    const tracer = this.getTracer();
    const identityType = options.identityType ?? "persistent";

    const attributes: Record<string, string | number | boolean | string[]> = {
      [IdentityAttributes.AGENT_ID]: options.agentId,
      [IdentityAttributes.AGENT_NAME]: options.agentName,
      [IdentityAttributes.LIFECYCLE_OPERATION]: options.operation,
      [IdentityAttributes.TYPE]: identityType,
    };
    if (options.provider !== undefined) {
      attributes[IdentityAttributes.PROVIDER] = options.provider;
    }
    if (options.owner !== undefined) {
      attributes[IdentityAttributes.OWNER] = options.owner;
    }
    if (options.ownerType !== undefined) {
      attributes[IdentityAttributes.OWNER_TYPE] = options.ownerType;
    }
    if (options.credentialType !== undefined) {
      attributes[IdentityAttributes.CREDENTIAL_TYPE] = options.credentialType;
    }
    if (options.scope !== undefined) {
      attributes[IdentityAttributes.SCOPE] = options.scope;
    }
    if (options.ttlSeconds !== undefined) {
      attributes[IdentityAttributes.TTL_SECONDS] = options.ttlSeconds;
    }

    const spanName = `identity.lifecycle.${options.operation} ${options.agentId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const lifecycle = new IdentityLifecycle(otelSpan);
          try {
            const result = fn(lifecycle);
            if (result instanceof Promise) {
              return result
                .then((val) => {
                  otelSpan.setStatus({ code: SpanStatusCode.OK });
                  otelSpan.end();
                  return val;
                })
                .catch((err) => {
                  otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
                  otelSpan.recordException(err);
                  otelSpan.end();
                  throw err;
                }) as T;
            }
            otelSpan.setStatus({ code: SpanStatusCode.OK });
            otelSpan.end();
            return result;
          } catch (err) {
            otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
            otelSpan.recordException(err as Error);
            otelSpan.end();
            throw err;
          }
        },
      );
    }

    const otelSpan = tracer.startSpan(spanName, {
      kind: SpanKind.INTERNAL,
      attributes,
    });
    return new IdentityLifecycle(otelSpan);
  }

  // -- Authentication -------------------------------------------------------

  /**
   * Trace an agent authentication attempt.
   *
   * Returns an {@link AuthenticationAttempt} for manual span management, or
   * accepts a callback that receives the attempt and automatically ends
   * the span.
   */
  traceAuthentication(options: TraceAuthenticationOptions): AuthenticationAttempt;
  traceAuthentication<T>(
    options: TraceAuthenticationOptions,
    fn: (auth: AuthenticationAttempt) => T,
  ): T;
  traceAuthentication<T>(
    options: TraceAuthenticationOptions,
    fn?: (auth: AuthenticationAttempt) => T,
  ): AuthenticationAttempt | T {
    const tracer = this.getTracer();

    const attributes: Record<string, string | number | boolean | string[]> = {
      [IdentityAttributes.AGENT_ID]: options.agentId,
      [IdentityAttributes.AGENT_NAME]: options.agentName,
      [IdentityAttributes.AUTH_METHOD]: options.method,
    };
    if (options.targetService !== undefined) {
      attributes[IdentityAttributes.AUTH_TARGET_SERVICE] = options.targetService;
    }
    if (options.provider !== undefined) {
      attributes[IdentityAttributes.AUTH_PROVIDER] = options.provider;
    }
    if (options.scopeRequested !== undefined) {
      attributes[IdentityAttributes.AUTH_SCOPE_REQUESTED] = options.scopeRequested;
    }

    const spanName = `identity.auth ${options.agentName}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.CLIENT, attributes },
        (otelSpan) => {
          const auth = new AuthenticationAttempt(otelSpan);
          try {
            const result = fn(auth);
            if (result instanceof Promise) {
              return result
                .then((val) => {
                  otelSpan.setStatus({ code: SpanStatusCode.OK });
                  otelSpan.end();
                  return val;
                })
                .catch((err) => {
                  otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
                  otelSpan.recordException(err);
                  otelSpan.end();
                  throw err;
                }) as T;
            }
            otelSpan.setStatus({ code: SpanStatusCode.OK });
            otelSpan.end();
            return result;
          } catch (err) {
            otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
            otelSpan.recordException(err as Error);
            otelSpan.end();
            throw err;
          }
        },
      );
    }

    const otelSpan = tracer.startSpan(spanName, {
      kind: SpanKind.CLIENT,
      attributes,
    });
    return new AuthenticationAttempt(otelSpan);
  }

  // -- Authorization --------------------------------------------------------

  /**
   * Trace an authorization decision.
   *
   * Returns an {@link AuthorizationCheck} for manual span management, or
   * accepts a callback that receives the check and automatically ends
   * the span.
   */
  traceAuthorization(options: TraceAuthorizationOptions): AuthorizationCheck;
  traceAuthorization<T>(
    options: TraceAuthorizationOptions,
    fn: (authz: AuthorizationCheck) => T,
  ): T;
  traceAuthorization<T>(
    options: TraceAuthorizationOptions,
    fn?: (authz: AuthorizationCheck) => T,
  ): AuthorizationCheck | T {
    const tracer = this.getTracer();
    const action = options.action ?? "read";

    const attributes: Record<string, string | number | boolean> = {
      [IdentityAttributes.AGENT_ID]: options.agentId,
      [IdentityAttributes.AGENT_NAME]: options.agentName,
      [IdentityAttributes.AUTHZ_RESOURCE]: options.resource,
      [IdentityAttributes.AUTHZ_ACTION]: action,
    };
    if (options.policyEngine !== undefined) {
      attributes[IdentityAttributes.AUTHZ_POLICY_ENGINE] = options.policyEngine;
    }

    const spanName = `identity.authz ${options.agentName} -> ${options.resource}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const authz = new AuthorizationCheck(otelSpan);
          try {
            const result = fn(authz);
            if (result instanceof Promise) {
              return result
                .then((val) => {
                  otelSpan.setStatus({ code: SpanStatusCode.OK });
                  otelSpan.end();
                  return val;
                })
                .catch((err) => {
                  otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
                  otelSpan.recordException(err);
                  otelSpan.end();
                  throw err;
                }) as T;
            }
            otelSpan.setStatus({ code: SpanStatusCode.OK });
            otelSpan.end();
            return result;
          } catch (err) {
            otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
            otelSpan.recordException(err as Error);
            otelSpan.end();
            throw err;
          }
        },
      );
    }

    const otelSpan = tracer.startSpan(spanName, {
      kind: SpanKind.INTERNAL,
      attributes,
    });
    return new AuthorizationCheck(otelSpan);
  }

  // -- Delegation -----------------------------------------------------------

  /**
   * Trace credential delegation between agents.
   *
   * Returns a {@link DelegationOperation} for manual span management, or
   * accepts a callback that receives the operation and automatically ends
   * the span.
   */
  traceDelegation(options: TraceDelegationOptions): DelegationOperation;
  traceDelegation<T>(
    options: TraceDelegationOptions,
    fn: (delegation: DelegationOperation) => T,
  ): T;
  traceDelegation<T>(
    options: TraceDelegationOptions,
    fn?: (delegation: DelegationOperation) => T,
  ): DelegationOperation | T {
    const tracer = this.getTracer();
    const delegationType = options.delegationType ?? "on_behalf_of";

    const attributes: Record<string, string | number | boolean | string[]> = {
      [IdentityAttributes.DELEGATION_DELEGATOR]: options.delegator,
      [IdentityAttributes.DELEGATION_DELEGATOR_ID]: options.delegatorId,
      [IdentityAttributes.DELEGATION_DELEGATEE]: options.delegatee,
      [IdentityAttributes.DELEGATION_DELEGATEE_ID]: options.delegateeId,
      [IdentityAttributes.DELEGATION_TYPE]: delegationType,
    };
    if (options.scopeDelegated !== undefined) {
      attributes[IdentityAttributes.DELEGATION_SCOPE_DELEGATED] = options.scopeDelegated;
    }
    if (options.ttlSeconds !== undefined) {
      attributes[IdentityAttributes.DELEGATION_TTL_SECONDS] = options.ttlSeconds;
    }

    const spanName = `identity.delegate ${options.delegator} -> ${options.delegatee}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const delegation = new DelegationOperation(otelSpan);
          try {
            const result = fn(delegation);
            if (result instanceof Promise) {
              return result
                .then((val) => {
                  otelSpan.setStatus({ code: SpanStatusCode.OK });
                  otelSpan.end();
                  return val;
                })
                .catch((err) => {
                  otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
                  otelSpan.recordException(err);
                  otelSpan.end();
                  throw err;
                }) as T;
            }
            otelSpan.setStatus({ code: SpanStatusCode.OK });
            otelSpan.end();
            return result;
          } catch (err) {
            otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
            otelSpan.recordException(err as Error);
            otelSpan.end();
            throw err;
          }
        },
      );
    }

    const otelSpan = tracer.startSpan(spanName, {
      kind: SpanKind.INTERNAL,
      attributes,
    });
    return new DelegationOperation(otelSpan);
  }

  // -- Trust ----------------------------------------------------------------

  /**
   * Trace trust establishment between agents.
   *
   * Returns a {@link TrustOperation} for manual span management, or accepts
   * a callback that receives the operation and automatically ends the span.
   */
  traceTrust(options: TraceTrustOptions): TrustOperation;
  traceTrust<T>(
    options: TraceTrustOptions,
    fn: (trust: TrustOperation) => T,
  ): T;
  traceTrust<T>(
    options: TraceTrustOptions,
    fn?: (trust: TrustOperation) => T,
  ): TrustOperation | T {
    const tracer = this.getTracer();
    const method = options.method ?? "mtls";

    const attributes: Record<string, string | number | boolean> = {
      [IdentityAttributes.AGENT_ID]: options.agentId,
      [IdentityAttributes.AGENT_NAME]: options.agentName,
      [IdentityAttributes.TRUST_OPERATION]: options.operation,
      [IdentityAttributes.TRUST_PEER_AGENT]: options.peerAgent,
      [IdentityAttributes.TRUST_PEER_AGENT_ID]: options.peerAgentId,
      [IdentityAttributes.TRUST_METHOD]: method,
    };

    const spanName = `identity.trust.${options.operation} ${options.peerAgent}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.CLIENT, attributes },
        (otelSpan) => {
          const trust = new TrustOperation(otelSpan);
          try {
            const result = fn(trust);
            if (result instanceof Promise) {
              return result
                .then((val) => {
                  otelSpan.setStatus({ code: SpanStatusCode.OK });
                  otelSpan.end();
                  return val;
                })
                .catch((err) => {
                  otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
                  otelSpan.recordException(err);
                  otelSpan.end();
                  throw err;
                }) as T;
            }
            otelSpan.setStatus({ code: SpanStatusCode.OK });
            otelSpan.end();
            return result;
          } catch (err) {
            otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
            otelSpan.recordException(err as Error);
            otelSpan.end();
            throw err;
          }
        },
      );
    }

    const otelSpan = tracer.startSpan(spanName, {
      kind: SpanKind.CLIENT,
      attributes,
    });
    return new TrustOperation(otelSpan);
  }

  // -- Session --------------------------------------------------------------

  /**
   * Trace an identity session operation (create, refresh, terminate).
   *
   * Returns an {@link IdentitySession} for manual span management, or
   * accepts a callback that receives the session and automatically ends
   * the span.
   */
  traceSession(options: TraceSessionOptions): IdentitySession;
  traceSession<T>(
    options: TraceSessionOptions,
    fn: (session: IdentitySession) => T,
  ): T;
  traceSession<T>(
    options: TraceSessionOptions,
    fn?: (session: IdentitySession) => T,
  ): IdentitySession | T {
    const tracer = this.getTracer();
    const operation = options.operation ?? "create";
    const sessionId = options.sessionId ?? crypto.randomUUID();

    const attributes: Record<string, string | number | boolean | string[]> = {
      [IdentityAttributes.AGENT_ID]: options.agentId,
      [IdentityAttributes.AGENT_NAME]: options.agentName,
      [IdentityAttributes.SESSION_ID]: sessionId,
      [IdentityAttributes.SESSION_OPERATION]: operation,
    };
    if (options.scope !== undefined) {
      attributes[IdentityAttributes.SESSION_SCOPE] = options.scope;
    }
    if (options.expiresAt !== undefined) {
      attributes[IdentityAttributes.SESSION_EXPIRES_AT] = options.expiresAt;
    }

    const spanName = `identity.session ${options.agentName}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const session = new IdentitySession(otelSpan, sessionId);
          try {
            const result = fn(session);
            if (result instanceof Promise) {
              return result
                .then((val) => {
                  otelSpan.setStatus({ code: SpanStatusCode.OK });
                  otelSpan.end();
                  return val;
                })
                .catch((err) => {
                  otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
                  otelSpan.recordException(err);
                  otelSpan.end();
                  throw err;
                }) as T;
            }
            otelSpan.setStatus({ code: SpanStatusCode.OK });
            otelSpan.end();
            return result;
          } catch (err) {
            otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
            otelSpan.recordException(err as Error);
            otelSpan.end();
            throw err;
          }
        },
      );
    }

    const otelSpan = tracer.startSpan(spanName, {
      kind: SpanKind.INTERNAL,
      attributes,
    });
    return new IdentitySession(otelSpan, sessionId);
  }
}
