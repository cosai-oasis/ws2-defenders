/**
 * AITF AI Asset Inventory Instrumentation.
 *
 * Provides tracing for AI asset lifecycle management: registration, discovery,
 * audit, risk classification, dependency mapping, and decommissioning. Aligned
 * with CoSAI AI Incident Response preparation requirements.
 */

import {
  trace,
  Span,
  SpanKind,
  SpanStatusCode,
  Tracer,
  TracerProvider,
} from "@opentelemetry/api";
import { AssetInventoryAttributes } from "../semantic-conventions/attributes";

const TRACER_NAME = "instrumentation.asset_inventory";

// ---------------------------------------------------------------------------
// Option interfaces
// ---------------------------------------------------------------------------

/** Options for tracing asset registration. */
export interface TraceRegisterOptions {
  assetId?: string;
  assetName?: string;
  assetType?: string;
  version?: string;
  assetHash?: string;
  owner?: string;
  ownerType?: string;
  deploymentEnvironment?: string;
  riskClassification?: string;
  sourceRepository?: string;
  tags?: string[];
}

/** Options for tracing asset discovery scans. */
export interface TraceDiscoverOptions {
  scope?: string;
  method?: string;
}

/** Options for tracing asset audits. */
export interface TraceAuditOptions {
  assetId: string;
  auditType?: string;
  framework?: string;
  auditor?: string;
}

/** Options for tracing risk classification. */
export interface TraceClassifyOptions {
  assetId: string;
  riskClassification: string;
  framework?: string;
  assessor?: string;
  useCase?: string;
}

/** Options for tracing asset decommissioning. */
export interface TraceDecommissionOptions {
  assetId: string;
  assetType: string;
  reason: string;
  replacementId?: string;
  approvedBy?: string;
}

// ---------------------------------------------------------------------------
// Helper classes
// ---------------------------------------------------------------------------

/** Helper for enriching an asset registration span. */
export class AssetRegistration {
  private readonly _span: Span;

  /** The unique identifier for this asset. */
  readonly assetId: string;

  constructor(span: Span, assetId: string) {
    this._span = span;
    this.assetId = assetId;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the asset content hash. */
  setHash(hashValue: string): void {
    this._span.setAttribute(AssetInventoryAttributes.HASH, hashValue);
  }

  /** Record the asset version. */
  setVersion(version: string): void {
    this._span.setAttribute(AssetInventoryAttributes.VERSION, version);
  }

  /** Record the risk classification. */
  setRiskClassification(classification: string): void {
    this._span.setAttribute(AssetInventoryAttributes.RISK_CLASSIFICATION, classification);
  }

  /** Record the deployment environment. */
  setDeploymentEnvironment(env: string): void {
    this._span.setAttribute(AssetInventoryAttributes.DEPLOYMENT_ENVIRONMENT, env);
  }
}

/** Helper for enriching an asset discovery span. */
export class AssetDiscovery {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record discovery results. */
  setResults(options: {
    assetsFound: number;
    newAssets?: number;
    shadowAssets?: number;
  }): void {
    this._span.setAttribute(
      AssetInventoryAttributes.DISCOVERY_ASSETS_FOUND,
      options.assetsFound,
    );
    this._span.setAttribute(
      AssetInventoryAttributes.DISCOVERY_NEW_ASSETS,
      options.newAssets ?? 0,
    );
    this._span.setAttribute(
      AssetInventoryAttributes.DISCOVERY_SHADOW_ASSETS,
      options.shadowAssets ?? 0,
    );
  }

  /** Record the discovery status. */
  setStatus(status: string): void {
    this._span.setAttribute(AssetInventoryAttributes.DISCOVERY_STATUS, status);
  }
}

/** Helper for enriching an asset audit span. */
export class AssetAudit {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the audit result. */
  setResult(result: string): void {
    this._span.setAttribute(AssetInventoryAttributes.AUDIT_RESULT, result);
  }

  /** Record the audit risk score. */
  setRiskScore(score: number): void {
    this._span.setAttribute(AssetInventoryAttributes.AUDIT_RISK_SCORE, score);
  }

  /** Record whether integrity was verified. */
  setIntegrityVerified(verified: boolean): void {
    this._span.setAttribute(AssetInventoryAttributes.AUDIT_INTEGRITY_VERIFIED, verified);
  }

  /** Record the compliance status. */
  setComplianceStatus(status: string): void {
    this._span.setAttribute(AssetInventoryAttributes.AUDIT_COMPLIANCE_STATUS, status);
  }

  /** Record audit findings as a string. */
  setFindings(findings: string): void {
    this._span.setAttribute(AssetInventoryAttributes.AUDIT_FINDINGS, findings);
  }

  /** Record when the next audit is due. */
  setNextAuditDue(timestamp: string): void {
    this._span.setAttribute(AssetInventoryAttributes.AUDIT_NEXT_AUDIT_DUE, timestamp);
  }
}

/** Helper for enriching a risk classification span. */
export class AssetClassification {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the previous risk classification. */
  setPrevious(previous: string): void {
    this._span.setAttribute(AssetInventoryAttributes.CLASSIFICATION_PREVIOUS, previous);
  }

  /** Record the reason for the classification. */
  setReason(reason: string): void {
    this._span.setAttribute(AssetInventoryAttributes.CLASSIFICATION_REASON, reason);
  }

  /** Record whether the asset makes autonomous decisions. */
  setAutonomousDecision(autonomous: boolean): void {
    this._span.setAttribute(AssetInventoryAttributes.CLASSIFICATION_AUTONOMOUS_DECISION, autonomous);
  }
}

// ---------------------------------------------------------------------------
// Instrumentor
// ---------------------------------------------------------------------------

/**
 * Instrumentor for AI asset inventory operations.
 *
 * Traces asset registration, discovery, audit, risk classification, and
 * decommissioning with AITF semantic convention attributes.
 */
export class AssetInventoryInstrumentor {
  private _tracerProvider: TracerProvider | null;
  private _tracer: Tracer | null = null;
  private _instrumented = false;

  constructor(tracerProvider?: TracerProvider) {
    this._tracerProvider = tracerProvider ?? null;
  }

  /** Enable asset inventory instrumentation. */
  instrument(): void {
    const tp = this._tracerProvider ?? trace.getTracerProvider();
    this._tracer = tp.getTracer(TRACER_NAME);
    this._instrumented = true;
  }

  /** Disable asset inventory instrumentation. */
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

  // -- Registration ---------------------------------------------------------

  /**
   * Trace asset registration.
   *
   * Returns an {@link AssetRegistration} for manual span management, or
   * accepts a callback that receives the registration and automatically
   * ends the span.
   */
  traceRegister(options?: TraceRegisterOptions): AssetRegistration;
  traceRegister<T>(
    options: TraceRegisterOptions | undefined,
    fn: (reg: AssetRegistration) => T,
  ): T;
  traceRegister<T>(
    options?: TraceRegisterOptions,
    fn?: (reg: AssetRegistration) => T,
  ): AssetRegistration | T {
    const tracer = this.getTracer();
    const assetId = options?.assetId ?? crypto.randomUUID();
    const assetName = options?.assetName ?? "";
    const assetType = options?.assetType ?? "model";

    const attributes: Record<string, string | number | boolean | string[]> = {
      [AssetInventoryAttributes.ID]: assetId,
      [AssetInventoryAttributes.NAME]: assetName,
      [AssetInventoryAttributes.TYPE]: assetType,
    };
    if (options?.version !== undefined) {
      attributes[AssetInventoryAttributes.VERSION] = options.version;
    }
    if (options?.assetHash !== undefined) {
      attributes[AssetInventoryAttributes.HASH] = options.assetHash;
    }
    if (options?.owner !== undefined) {
      attributes[AssetInventoryAttributes.OWNER] = options.owner;
    }
    if (options?.ownerType !== undefined) {
      attributes[AssetInventoryAttributes.OWNER_TYPE] = options.ownerType;
    }
    if (options?.deploymentEnvironment !== undefined) {
      attributes[AssetInventoryAttributes.DEPLOYMENT_ENVIRONMENT] = options.deploymentEnvironment;
    }
    if (options?.riskClassification !== undefined) {
      attributes[AssetInventoryAttributes.RISK_CLASSIFICATION] = options.riskClassification;
    }
    if (options?.sourceRepository !== undefined) {
      attributes[AssetInventoryAttributes.SOURCE_REPOSITORY] = options.sourceRepository;
    }
    if (options?.tags !== undefined) {
      attributes[AssetInventoryAttributes.TAGS] = options.tags;
    }

    const spanName = `asset.register ${assetType} ${assetName}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const reg = new AssetRegistration(otelSpan, assetId);
          try {
            const result = fn(reg);
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
    return new AssetRegistration(otelSpan, assetId);
  }

  // -- Discovery ------------------------------------------------------------

  /**
   * Trace asset discovery scans.
   *
   * Returns an {@link AssetDiscovery} for manual span management, or
   * accepts a callback that receives the discovery and automatically
   * ends the span.
   */
  traceDiscover(options?: TraceDiscoverOptions): AssetDiscovery;
  traceDiscover<T>(
    options: TraceDiscoverOptions | undefined,
    fn: (disc: AssetDiscovery) => T,
  ): T;
  traceDiscover<T>(
    options?: TraceDiscoverOptions,
    fn?: (disc: AssetDiscovery) => T,
  ): AssetDiscovery | T {
    const tracer = this.getTracer();
    const scope = options?.scope ?? "organization";
    const method = options?.method ?? "api_scan";

    const attributes: Record<string, string | number | boolean> = {
      [AssetInventoryAttributes.DISCOVERY_SCOPE]: scope,
      [AssetInventoryAttributes.DISCOVERY_METHOD]: method,
    };

    const spanName = `asset.discover ${scope}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const disc = new AssetDiscovery(otelSpan);
          try {
            const result = fn(disc);
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
    return new AssetDiscovery(otelSpan);
  }

  // -- Audit ----------------------------------------------------------------

  /**
   * Trace asset audits.
   *
   * Returns an {@link AssetAudit} for manual span management, or accepts
   * a callback that receives the audit and automatically ends the span.
   */
  traceAudit(options: TraceAuditOptions): AssetAudit;
  traceAudit<T>(
    options: TraceAuditOptions,
    fn: (audit: AssetAudit) => T,
  ): T;
  traceAudit<T>(
    options: TraceAuditOptions,
    fn?: (audit: AssetAudit) => T,
  ): AssetAudit | T {
    const tracer = this.getTracer();
    const auditType = options.auditType ?? "compliance";

    const attributes: Record<string, string | number | boolean> = {
      [AssetInventoryAttributes.ID]: options.assetId,
      [AssetInventoryAttributes.AUDIT_TYPE]: auditType,
    };
    if (options.framework !== undefined) {
      attributes[AssetInventoryAttributes.AUDIT_FRAMEWORK] = options.framework;
    }
    if (options.auditor !== undefined) {
      attributes[AssetInventoryAttributes.AUDIT_AUDITOR] = options.auditor;
    }

    const spanName = `asset.audit ${options.assetId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const audit = new AssetAudit(otelSpan);
          try {
            const result = fn(audit);
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
    return new AssetAudit(otelSpan);
  }

  // -- Classification -------------------------------------------------------

  /**
   * Trace risk classification of an asset.
   *
   * Returns an {@link AssetClassification} for manual span management, or
   * accepts a callback that receives the classification and automatically
   * ends the span.
   */
  traceClassify(options: TraceClassifyOptions): AssetClassification;
  traceClassify<T>(
    options: TraceClassifyOptions,
    fn: (cls: AssetClassification) => T,
  ): T;
  traceClassify<T>(
    options: TraceClassifyOptions,
    fn?: (cls: AssetClassification) => T,
  ): AssetClassification | T {
    const tracer = this.getTracer();
    const framework = options.framework ?? "eu_ai_act";

    const attributes: Record<string, string | number | boolean> = {
      [AssetInventoryAttributes.ID]: options.assetId,
      [AssetInventoryAttributes.RISK_CLASSIFICATION]: options.riskClassification,
      [AssetInventoryAttributes.CLASSIFICATION_FRAMEWORK]: framework,
    };
    if (options.assessor !== undefined) {
      attributes[AssetInventoryAttributes.CLASSIFICATION_ASSESSOR] = options.assessor;
    }
    if (options.useCase !== undefined) {
      attributes[AssetInventoryAttributes.CLASSIFICATION_USE_CASE] = options.useCase;
    }

    const spanName = `asset.classify ${options.assetId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const cls = new AssetClassification(otelSpan);
          try {
            const result = fn(cls);
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
    return new AssetClassification(otelSpan);
  }

  // -- Decommission ---------------------------------------------------------

  /**
   * Trace asset decommissioning.
   *
   * Returns the underlying {@link Span} for manual management, or accepts
   * a callback that automatically ends the span.
   */
  traceDecommission(options: TraceDecommissionOptions): Span;
  traceDecommission<T>(
    options: TraceDecommissionOptions,
    fn: (span: Span) => T,
  ): T;
  traceDecommission<T>(
    options: TraceDecommissionOptions,
    fn?: (span: Span) => T,
  ): Span | T {
    const tracer = this.getTracer();

    const attributes: Record<string, string | number | boolean> = {
      [AssetInventoryAttributes.ID]: options.assetId,
      [AssetInventoryAttributes.TYPE]: options.assetType,
      [AssetInventoryAttributes.DECOMMISSION_REASON]: options.reason,
    };
    if (options.replacementId !== undefined) {
      attributes[AssetInventoryAttributes.DECOMMISSION_REPLACEMENT_ID] = options.replacementId;
    }
    if (options.approvedBy !== undefined) {
      attributes[AssetInventoryAttributes.DECOMMISSION_APPROVED_BY] = options.approvedBy;
    }

    const spanName = `asset.decommission ${options.assetType} ${options.assetId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          try {
            const result = fn(otelSpan);
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

    return tracer.startSpan(spanName, {
      kind: SpanKind.INTERNAL,
      attributes,
    });
  }
}
