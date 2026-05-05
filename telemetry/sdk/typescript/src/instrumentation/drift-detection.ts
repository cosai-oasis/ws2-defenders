/**
 * AITF Model Drift Detection Instrumentation.
 *
 * Provides structured tracing for model drift detection, baseline management,
 * drift investigation, and remediation. Aligned with CoSAI's identification of
 * model drift as a top-level AI incident category.
 */

import {
  trace,
  Span,
  SpanKind,
  SpanStatusCode,
  Tracer,
  TracerProvider,
} from "@opentelemetry/api";
import { DriftDetectionAttributes } from "../semantic-conventions/attributes";

const TRACER_NAME = "instrumentation.drift_detection";

// ---------------------------------------------------------------------------
// Option interfaces
// ---------------------------------------------------------------------------

/** Options for tracing a drift detection analysis. */
export interface TraceDetectOptions {
  modelId: string;
  driftType: string;
  detectionMethod?: string;
  referenceDataset?: string;
  referencePeriod?: string;
  threshold?: number;
}

/** Options for tracing baseline establishment or refresh. */
export interface TraceBaselineOptions {
  modelId: string;
  operation?: string;
  dataset?: string;
  sampleSize?: number;
  period?: string;
}

/** Options for tracing a drift investigation. */
export interface TraceInvestigateOptions {
  modelId: string;
  triggerId: string;
}

/** Options for tracing a drift remediation action. */
export interface TraceRemediateOptions {
  modelId: string;
  action: string;
  triggerId?: string;
  automated?: boolean;
  initiatedBy?: string;
}

// ---------------------------------------------------------------------------
// Helper classes
// ---------------------------------------------------------------------------

/** Helper for enriching a drift detection span. */
export class DriftDetection {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the drift detection score. */
  setScore(score: number): void {
    this._span.setAttribute(DriftDetectionAttributes.SCORE, score);
  }

  /** Record the detection result (e.g. "alert", "normal", "warning"). */
  setResult(result: string): void {
    this._span.setAttribute(DriftDetectionAttributes.RESULT, result);
  }

  /** Record baseline vs. current metric comparison. */
  setMetrics(baseline: number, current: number, metricName: string): void {
    this._span.setAttribute(DriftDetectionAttributes.BASELINE_METRIC, baseline);
    this._span.setAttribute(DriftDetectionAttributes.CURRENT_METRIC, current);
    this._span.setAttribute(DriftDetectionAttributes.METRIC_NAME, metricName);
  }

  /** Record the statistical p-value from the detection test. */
  setPValue(pValue: number): void {
    this._span.setAttribute(DriftDetectionAttributes.P_VALUE, pValue);
  }

  /** Record the sample size used for detection. */
  setSampleSize(size: number): void {
    this._span.setAttribute(DriftDetectionAttributes.SAMPLE_SIZE, size);
  }

  /** Record the segments affected by the drift. */
  setAffectedSegments(segments: string[]): void {
    this._span.setAttribute(DriftDetectionAttributes.AFFECTED_SEGMENTS, segments);
  }

  /** Record the feature that drifted and optionally its importance. */
  setFeature(name: string, importance?: number): void {
    this._span.setAttribute(DriftDetectionAttributes.FEATURE_NAME, name);
    if (importance !== undefined) {
      this._span.setAttribute(DriftDetectionAttributes.FEATURE_IMPORTANCE, importance);
    }
  }

  /** Record the action triggered in response to the drift. */
  setActionTriggered(action: string): void {
    this._span.setAttribute(DriftDetectionAttributes.ACTION_TRIGGERED, action);
  }
}

/** Helper for enriching a drift baseline span. */
export class DriftBaseline {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the baseline identifier. */
  setId(baselineId: string): void {
    this._span.setAttribute(DriftDetectionAttributes.BASELINE_ID, baselineId);
  }

  /** Record the baseline metrics as a JSON string. */
  setMetrics(metricsJson: string): void {
    this._span.setAttribute(DriftDetectionAttributes.BASELINE_METRICS, metricsJson);
  }

  /** Record the features captured in the baseline. */
  setFeatures(features: string[]): void {
    this._span.setAttribute(DriftDetectionAttributes.BASELINE_FEATURES, features);
  }

  /** Record the previous baseline identifier that this replaces. */
  setPreviousId(previousId: string): void {
    this._span.setAttribute(DriftDetectionAttributes.BASELINE_PREVIOUS_ID, previousId);
  }
}

/** Helper for enriching a drift investigation span. */
export class DriftInvestigation {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the identified root cause and its category. */
  setRootCause(cause: string, category: string): void {
    this._span.setAttribute(DriftDetectionAttributes.INVESTIGATION_ROOT_CAUSE, cause);
    this._span.setAttribute(DriftDetectionAttributes.INVESTIGATION_ROOT_CAUSE_CATEGORY, category);
  }

  /** Record the impact assessment of the drift. */
  setImpact(options: {
    affectedSegments: string[];
    affectedUsersEstimate?: number;
    blastRadius?: string;
  }): void {
    this._span.setAttribute(
      DriftDetectionAttributes.INVESTIGATION_AFFECTED_SEGMENTS,
      options.affectedSegments,
    );
    if (options.affectedUsersEstimate !== undefined) {
      this._span.setAttribute(
        DriftDetectionAttributes.INVESTIGATION_AFFECTED_USERS,
        options.affectedUsersEstimate,
      );
    }
    if (options.blastRadius !== undefined) {
      this._span.setAttribute(
        DriftDetectionAttributes.INVESTIGATION_BLAST_RADIUS,
        options.blastRadius,
      );
    }
  }

  /** Record the severity of the investigation finding. */
  setSeverity(severity: string): void {
    this._span.setAttribute(DriftDetectionAttributes.INVESTIGATION_SEVERITY, severity);
  }

  /** Record the recommended remediation action. */
  setRecommendation(recommendation: string): void {
    this._span.setAttribute(DriftDetectionAttributes.INVESTIGATION_RECOMMENDATION, recommendation);
  }
}

/** Helper for enriching a drift remediation span. */
export class DriftRemediation {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the remediation status. */
  setStatus(status: string): void {
    this._span.setAttribute(DriftDetectionAttributes.REMEDIATION_STATUS, status);
  }

  /** Record the model version to roll back to. */
  setRollbackTo(modelVersion: string): void {
    this._span.setAttribute(DriftDetectionAttributes.REMEDIATION_ROLLBACK_TO, modelVersion);
  }

  /** Record the dataset used for retraining. */
  setRetrainDataset(dataset: string): void {
    this._span.setAttribute(DriftDetectionAttributes.REMEDIATION_RETRAIN_DATASET, dataset);
  }

  /** Record whether the post-remediation validation passed. */
  setValidationPassed(passed: boolean): void {
    this._span.setAttribute(DriftDetectionAttributes.REMEDIATION_VALIDATION_PASSED, passed);
  }
}

// ---------------------------------------------------------------------------
// Instrumentor
// ---------------------------------------------------------------------------

/**
 * Instrumentor for model drift detection operations.
 *
 * Traces drift detection analyses, baseline management, investigations,
 * and remediation actions with AITF semantic convention attributes.
 */
export class DriftDetectionInstrumentor {
  private _tracerProvider: TracerProvider | null;
  private _tracer: Tracer | null = null;
  private _instrumented = false;

  constructor(tracerProvider?: TracerProvider) {
    this._tracerProvider = tracerProvider ?? null;
  }

  /** Enable drift detection instrumentation. */
  instrument(): void {
    const tp = this._tracerProvider ?? trace.getTracerProvider();
    this._tracer = tp.getTracer(TRACER_NAME);
    this._instrumented = true;
  }

  /** Disable drift detection instrumentation. */
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

  // -- Detection ------------------------------------------------------------

  /**
   * Trace a drift detection analysis.
   *
   * Returns a {@link DriftDetection} for manual span management, or accepts
   * a callback that receives the detection and automatically ends the span.
   */
  traceDetect(options: TraceDetectOptions): DriftDetection;
  traceDetect<T>(
    options: TraceDetectOptions,
    fn: (det: DriftDetection) => T,
  ): T;
  traceDetect<T>(
    options: TraceDetectOptions,
    fn?: (det: DriftDetection) => T,
  ): DriftDetection | T {
    const tracer = this.getTracer();

    const attributes: Record<string, string | number | boolean> = {
      [DriftDetectionAttributes.MODEL_ID]: options.modelId,
      [DriftDetectionAttributes.TYPE]: options.driftType,
    };
    if (options.detectionMethod !== undefined) {
      attributes[DriftDetectionAttributes.DETECTION_METHOD] = options.detectionMethod;
    }
    if (options.referenceDataset !== undefined) {
      attributes[DriftDetectionAttributes.REFERENCE_DATASET] = options.referenceDataset;
    }
    if (options.referencePeriod !== undefined) {
      attributes[DriftDetectionAttributes.REFERENCE_PERIOD] = options.referencePeriod;
    }
    if (options.threshold !== undefined) {
      attributes[DriftDetectionAttributes.THRESHOLD] = options.threshold;
    }

    const spanName = `drift.detect ${options.driftType} ${options.modelId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const det = new DriftDetection(otelSpan);
          try {
            const result = fn(det);
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
    return new DriftDetection(otelSpan);
  }

  // -- Baseline -------------------------------------------------------------

  /**
   * Trace baseline establishment or refresh.
   *
   * Returns a {@link DriftBaseline} for manual span management, or accepts
   * a callback that receives the baseline and automatically ends the span.
   */
  traceBaseline(options: TraceBaselineOptions): DriftBaseline;
  traceBaseline<T>(
    options: TraceBaselineOptions,
    fn: (baseline: DriftBaseline) => T,
  ): T;
  traceBaseline<T>(
    options: TraceBaselineOptions,
    fn?: (baseline: DriftBaseline) => T,
  ): DriftBaseline | T {
    const tracer = this.getTracer();
    const operation = options.operation ?? "create";

    const attributes: Record<string, string | number | boolean> = {
      [DriftDetectionAttributes.MODEL_ID]: options.modelId,
      [DriftDetectionAttributes.BASELINE_OPERATION]: operation,
    };
    if (options.dataset !== undefined) {
      attributes[DriftDetectionAttributes.BASELINE_DATASET] = options.dataset;
    }
    if (options.sampleSize !== undefined) {
      attributes[DriftDetectionAttributes.BASELINE_SAMPLE_SIZE] = options.sampleSize;
    }
    if (options.period !== undefined) {
      attributes[DriftDetectionAttributes.BASELINE_PERIOD] = options.period;
    }

    const spanName = `drift.baseline ${operation} ${options.modelId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const baseline = new DriftBaseline(otelSpan);
          try {
            const result = fn(baseline);
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
    return new DriftBaseline(otelSpan);
  }

  // -- Investigation --------------------------------------------------------

  /**
   * Trace a drift investigation.
   *
   * Returns a {@link DriftInvestigation} for manual span management, or
   * accepts a callback that receives the investigation and automatically
   * ends the span.
   */
  traceInvestigate(options: TraceInvestigateOptions): DriftInvestigation;
  traceInvestigate<T>(
    options: TraceInvestigateOptions,
    fn: (inv: DriftInvestigation) => T,
  ): T;
  traceInvestigate<T>(
    options: TraceInvestigateOptions,
    fn?: (inv: DriftInvestigation) => T,
  ): DriftInvestigation | T {
    const tracer = this.getTracer();

    const attributes: Record<string, string | number | boolean> = {
      [DriftDetectionAttributes.MODEL_ID]: options.modelId,
      [DriftDetectionAttributes.INVESTIGATION_TRIGGER_ID]: options.triggerId,
    };

    const spanName = `drift.investigate ${options.modelId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const inv = new DriftInvestigation(otelSpan);
          try {
            const result = fn(inv);
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
    return new DriftInvestigation(otelSpan);
  }

  // -- Remediation ----------------------------------------------------------

  /**
   * Trace a drift remediation action.
   *
   * Returns a {@link DriftRemediation} for manual span management, or
   * accepts a callback that receives the remediation and automatically
   * ends the span.
   */
  traceRemediate(options: TraceRemediateOptions): DriftRemediation;
  traceRemediate<T>(
    options: TraceRemediateOptions,
    fn: (rem: DriftRemediation) => T,
  ): T;
  traceRemediate<T>(
    options: TraceRemediateOptions,
    fn?: (rem: DriftRemediation) => T,
  ): DriftRemediation | T {
    const tracer = this.getTracer();
    const automated = options.automated ?? false;

    const attributes: Record<string, string | number | boolean> = {
      [DriftDetectionAttributes.MODEL_ID]: options.modelId,
      [DriftDetectionAttributes.REMEDIATION_ACTION]: options.action,
      [DriftDetectionAttributes.REMEDIATION_AUTOMATED]: automated,
    };
    if (options.triggerId !== undefined) {
      attributes[DriftDetectionAttributes.REMEDIATION_TRIGGER_ID] = options.triggerId;
    }
    if (options.initiatedBy !== undefined) {
      attributes[DriftDetectionAttributes.REMEDIATION_INITIATED_BY] = options.initiatedBy;
    }

    const spanName = `drift.remediate ${options.action} ${options.modelId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const rem = new DriftRemediation(otelSpan);
          try {
            const result = fn(rem);
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
    return new DriftRemediation(otelSpan);
  }
}
