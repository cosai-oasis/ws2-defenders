/**
 * AITF Model Operations (LLMOps/MLOps) Instrumentation.
 *
 * Provides tracing for the complete AI model lifecycle: training, evaluation,
 * registry, deployment, serving (routing/fallback/caching), monitoring, and
 * prompt versioning.
 */

import {
  trace,
  Span,
  SpanKind,
  SpanStatusCode,
  Tracer,
  TracerProvider,
} from "@opentelemetry/api";
import { ModelOpsAttributes } from "../semantic-conventions/attributes";

const TRACER_NAME = "instrumentation.model_ops";

// ---------------------------------------------------------------------------
// Option interfaces
// ---------------------------------------------------------------------------

/** Options for tracing a training/fine-tuning run. */
export interface TraceTrainingOptions {
  runId?: string;
  trainingType?: string;
  baseModel: string;
  framework?: string;
  datasetId?: string;
  datasetVersion?: string;
  datasetSize?: number;
  hyperparameters?: string;
  epochs?: number;
  experimentId?: string;
  experimentName?: string;
}

/** Options for tracing a model evaluation run. */
export interface TraceEvaluationOptions {
  modelId: string;
  evalType?: string;
  runId?: string;
  datasetId?: string;
  datasetSize?: number;
  judgeModel?: string;
  baselineModel?: string;
}

/** Options for tracing a model registry operation. */
export interface TraceRegistryOptions {
  modelId: string;
  operation: string;
  modelVersion?: string;
  stage?: string;
  modelAlias?: string;
  owner?: string;
  trainingRunId?: string;
  parentModelId?: string;
}

/** Options for tracing a model deployment. */
export interface TraceDeploymentOptions {
  modelId: string;
  strategy?: string;
  deploymentId?: string;
  environment?: string;
  endpoint?: string;
  canaryPercent?: number;
  infrastructureProvider?: string;
}

/** Options for tracing a model routing decision. */
export interface TraceRouteOptions {
  selectedModel: string;
  reason?: string;
  candidates?: string[];
}

/** Options for tracing a model serving fallback. */
export interface TraceFallbackOptions {
  originalModel: string;
  finalModel: string;
  trigger?: string;
  chain?: string[];
  depth?: number;
}

/** Options for tracing a cache lookup operation. */
export interface TraceCacheLookupOptions {
  cacheType?: string;
}

/** Options for tracing a model monitoring check. */
export interface TraceMonitoringCheckOptions {
  modelId: string;
  checkType: string;
  metricName?: string;
}

/** Options for tracing a prompt lifecycle operation. */
export interface TracePromptOptions {
  name: string;
  operation: string;
  version?: string;
  label?: string;
  modelTarget?: string;
}

// ---------------------------------------------------------------------------
// Helper classes
// ---------------------------------------------------------------------------

/** Helper for recording training run attributes on a span. */
export class TrainingRun {
  private readonly _span: Span;

  /** The unique identifier for this training run. */
  readonly runId: string;

  constructor(span: Span, runId: string) {
    this._span = span;
    this.runId = runId;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record final training loss values. */
  setLoss(loss: number, valLoss?: number): void {
    this._span.setAttribute(ModelOpsAttributes.TRAINING_LOSS_FINAL, loss);
    if (valLoss !== undefined) {
      this._span.setAttribute(ModelOpsAttributes.TRAINING_VAL_LOSS_FINAL, valLoss);
    }
  }

  /** Record the output model produced by the training run. */
  setOutputModel(modelId: string, modelHash?: string): void {
    this._span.setAttribute(ModelOpsAttributes.TRAINING_OUTPUT_MODEL_ID, modelId);
    if (modelHash !== undefined) {
      this._span.setAttribute(ModelOpsAttributes.TRAINING_OUTPUT_MODEL_HASH, modelHash);
    }
  }

  /** Record compute resource usage. */
  setCompute(gpuType: string, gpuCount: number, gpuHours: number): void {
    this._span.setAttribute(ModelOpsAttributes.TRAINING_COMPUTE_GPU_TYPE, gpuType);
    this._span.setAttribute(ModelOpsAttributes.TRAINING_COMPUTE_GPU_COUNT, gpuCount);
    this._span.setAttribute(ModelOpsAttributes.TRAINING_COMPUTE_GPU_HOURS, gpuHours);
  }

  /** Record the code commit hash associated with training. */
  setCodeCommit(commit: string): void {
    this._span.setAttribute(ModelOpsAttributes.TRAINING_CODE_COMMIT, commit);
  }
}

/** Helper for recording evaluation run attributes on a span. */
export class EvaluationRun {
  private readonly _span: Span;

  /** The unique identifier for this evaluation run. */
  readonly runId: string;

  constructor(span: Span, runId: string) {
    this._span = span;
    this.runId = runId;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record evaluation metrics as a JSON-serialized string. */
  setMetrics(metrics: Record<string, number>): void {
    this._span.setAttribute(
      ModelOpsAttributes.EVALUATION_METRICS,
      JSON.stringify(metrics),
    );
  }

  /** Record whether the evaluation passed and if regression was detected. */
  setPass(passed: boolean, regressionDetected: boolean = false): void {
    this._span.setAttribute(ModelOpsAttributes.EVALUATION_PASS, passed);
    this._span.setAttribute(
      ModelOpsAttributes.EVALUATION_REGRESSION_DETECTED,
      regressionDetected,
    );
  }
}

/** Helper for recording deployment attributes on a span. */
export class DeploymentOperation {
  private readonly _span: Span;

  /** The unique identifier for this deployment. */
  readonly deploymentId: string;

  constructor(span: Span, deploymentId: string) {
    this._span = span;
    this.deploymentId = deploymentId;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record deployment health check results. */
  setHealth(status: string, latencyMs?: number): void {
    this._span.setAttribute(ModelOpsAttributes.DEPLOYMENT_HEALTH_STATUS, status);
    if (latencyMs !== undefined) {
      this._span.setAttribute(ModelOpsAttributes.DEPLOYMENT_HEALTH_LATENCY, latencyMs);
    }
  }

  /** Record infrastructure details. */
  setInfrastructure(options: { gpuType?: string; replicas?: number }): void {
    if (options.gpuType !== undefined) {
      this._span.setAttribute(ModelOpsAttributes.DEPLOYMENT_INFRA_GPU_TYPE, options.gpuType);
    }
    if (options.replicas !== undefined) {
      this._span.setAttribute(ModelOpsAttributes.DEPLOYMENT_INFRA_REPLICAS, options.replicas);
    }
  }
}

/** Helper for recording cache lookup results on a span. */
export class CacheLookup {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record cache lookup results. */
  setHit(
    hit: boolean,
    similarityScore?: number,
    costSavedUsd?: number,
  ): void {
    this._span.setAttribute(ModelOpsAttributes.SERVING_CACHE_HIT, hit);
    if (similarityScore !== undefined) {
      this._span.setAttribute(
        ModelOpsAttributes.SERVING_CACHE_SIMILARITY_SCORE,
        similarityScore,
      );
    }
    if (costSavedUsd !== undefined) {
      this._span.setAttribute(
        ModelOpsAttributes.SERVING_CACHE_COST_SAVED,
        costSavedUsd,
      );
    }
  }
}

/** Helper for recording monitoring check results on a span. */
export class MonitoringCheck {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record monitoring check results. */
  setResult(options: {
    result: string;
    metricValue?: number;
    baselineValue?: number;
    driftScore?: number;
    driftType?: string;
    actionTriggered?: string;
  }): void {
    this._span.setAttribute(ModelOpsAttributes.MONITORING_RESULT, options.result);
    if (options.metricValue !== undefined) {
      this._span.setAttribute(ModelOpsAttributes.MONITORING_METRIC_VALUE, options.metricValue);
    }
    if (options.baselineValue !== undefined) {
      this._span.setAttribute(ModelOpsAttributes.MONITORING_BASELINE_VALUE, options.baselineValue);
    }
    if (options.driftScore !== undefined) {
      this._span.setAttribute(ModelOpsAttributes.MONITORING_DRIFT_SCORE, options.driftScore);
    }
    if (options.driftType !== undefined) {
      this._span.setAttribute(ModelOpsAttributes.MONITORING_DRIFT_TYPE, options.driftType);
    }
    if (options.actionTriggered !== undefined) {
      this._span.setAttribute(ModelOpsAttributes.MONITORING_ACTION_TRIGGERED, options.actionTriggered);
    }
  }
}

/** Helper for recording prompt lifecycle attributes on a span. */
export class PromptOperation {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record prompt evaluation results. */
  setEvaluation(score: number, passed: boolean): void {
    this._span.setAttribute(ModelOpsAttributes.PROMPT_EVAL_SCORE, score);
    this._span.setAttribute(ModelOpsAttributes.PROMPT_EVAL_PASS, passed);
  }

  /** Record a content hash for the prompt template. */
  setContentHash(hashValue: string): void {
    this._span.setAttribute(ModelOpsAttributes.PROMPT_CONTENT_HASH, hashValue);
  }

  /** Record A/B test metadata. */
  setAbTest(testId: string, variant: string): void {
    this._span.setAttribute(ModelOpsAttributes.PROMPT_AB_TEST_ID, testId);
    this._span.setAttribute(ModelOpsAttributes.PROMPT_AB_TEST_VARIANT, variant);
  }
}

// ---------------------------------------------------------------------------
// Instrumentor
// ---------------------------------------------------------------------------

/**
 * Instrumentor for AI model lifecycle operations.
 *
 * Traces training, evaluation, registry, deployment, serving, monitoring,
 * and prompt versioning operations with AITF semantic convention attributes.
 */
export class ModelOpsInstrumentor {
  private _tracerProvider: TracerProvider | null;
  private _tracer: Tracer | null = null;
  private _instrumented = false;

  constructor(tracerProvider?: TracerProvider) {
    this._tracerProvider = tracerProvider ?? null;
  }

  /** Enable model ops instrumentation. */
  instrument(): void {
    const tp = this._tracerProvider ?? trace.getTracerProvider();
    this._tracer = tp.getTracer(TRACER_NAME);
    this._instrumented = true;
  }

  /** Disable model ops instrumentation. */
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

  // -- Training -------------------------------------------------------------

  /**
   * Trace a training/fine-tuning run.
   *
   * Returns a {@link TrainingRun} for manual span management, or accepts a
   * callback that receives the run and automatically ends the span.
   */
  traceTraining(options: TraceTrainingOptions): TrainingRun;
  traceTraining<T>(
    options: TraceTrainingOptions,
    fn: (run: TrainingRun) => T,
  ): T;
  traceTraining<T>(
    options: TraceTrainingOptions,
    fn?: (run: TrainingRun) => T,
  ): TrainingRun | T {
    const tracer = this.getTracer();
    const runId = options.runId ?? crypto.randomUUID();
    const trainingType = options.trainingType ?? "fine_tuning";

    const attributes: Record<string, string | number | boolean> = {
      [ModelOpsAttributes.TRAINING_RUN_ID]: runId,
      [ModelOpsAttributes.TRAINING_TYPE]: trainingType,
      [ModelOpsAttributes.TRAINING_BASE_MODEL]: options.baseModel,
    };
    if (options.framework !== undefined) {
      attributes[ModelOpsAttributes.TRAINING_FRAMEWORK] = options.framework;
    }
    if (options.datasetId !== undefined) {
      attributes[ModelOpsAttributes.TRAINING_DATASET_ID] = options.datasetId;
    }
    if (options.datasetVersion !== undefined) {
      attributes[ModelOpsAttributes.TRAINING_DATASET_VERSION] = options.datasetVersion;
    }
    if (options.datasetSize !== undefined) {
      attributes[ModelOpsAttributes.TRAINING_DATASET_SIZE] = options.datasetSize;
    }
    if (options.hyperparameters !== undefined) {
      attributes[ModelOpsAttributes.TRAINING_HYPERPARAMETERS] = options.hyperparameters;
    }
    if (options.epochs !== undefined) {
      attributes[ModelOpsAttributes.TRAINING_EPOCHS] = options.epochs;
    }
    if (options.experimentId !== undefined) {
      attributes[ModelOpsAttributes.TRAINING_EXPERIMENT_ID] = options.experimentId;
    }
    if (options.experimentName !== undefined) {
      attributes[ModelOpsAttributes.TRAINING_EXPERIMENT_NAME] = options.experimentName;
    }

    const spanName = `model_ops.training ${runId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const run = new TrainingRun(otelSpan, runId);
          try {
            const result = fn(run);
            if (result instanceof Promise) {
              return result
                .then((val) => {
                  otelSpan.setAttribute(ModelOpsAttributes.TRAINING_STATUS, "completed");
                  otelSpan.setStatus({ code: SpanStatusCode.OK });
                  otelSpan.end();
                  return val;
                })
                .catch((err) => {
                  otelSpan.setAttribute(ModelOpsAttributes.TRAINING_STATUS, "failed");
                  otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
                  otelSpan.recordException(err);
                  otelSpan.end();
                  throw err;
                }) as T;
            }
            otelSpan.setAttribute(ModelOpsAttributes.TRAINING_STATUS, "completed");
            otelSpan.setStatus({ code: SpanStatusCode.OK });
            otelSpan.end();
            return result;
          } catch (err) {
            otelSpan.setAttribute(ModelOpsAttributes.TRAINING_STATUS, "failed");
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
    return new TrainingRun(otelSpan, runId);
  }

  // -- Evaluation -----------------------------------------------------------

  /**
   * Trace a model evaluation run.
   *
   * Returns an {@link EvaluationRun} for manual span management, or accepts
   * a callback that receives the run and automatically ends the span.
   */
  traceEvaluation(options: TraceEvaluationOptions): EvaluationRun;
  traceEvaluation<T>(
    options: TraceEvaluationOptions,
    fn: (run: EvaluationRun) => T,
  ): T;
  traceEvaluation<T>(
    options: TraceEvaluationOptions,
    fn?: (run: EvaluationRun) => T,
  ): EvaluationRun | T {
    const tracer = this.getTracer();
    const runId = options.runId ?? crypto.randomUUID();
    const evalType = options.evalType ?? "benchmark";

    const attributes: Record<string, string | number | boolean> = {
      [ModelOpsAttributes.EVALUATION_RUN_ID]: runId,
      [ModelOpsAttributes.EVALUATION_MODEL_ID]: options.modelId,
      [ModelOpsAttributes.EVALUATION_TYPE]: evalType,
    };
    if (options.datasetId !== undefined) {
      attributes[ModelOpsAttributes.EVALUATION_DATASET_ID] = options.datasetId;
    }
    if (options.datasetSize !== undefined) {
      attributes[ModelOpsAttributes.EVALUATION_DATASET_SIZE] = options.datasetSize;
    }
    if (options.judgeModel !== undefined) {
      attributes[ModelOpsAttributes.EVALUATION_JUDGE_MODEL] = options.judgeModel;
    }
    if (options.baselineModel !== undefined) {
      attributes[ModelOpsAttributes.EVALUATION_BASELINE_MODEL] = options.baselineModel;
    }

    const spanName = `model_ops.evaluation ${runId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const evalRun = new EvaluationRun(otelSpan, runId);
          try {
            const result = fn(evalRun);
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
    return new EvaluationRun(otelSpan, runId);
  }

  // -- Registry -------------------------------------------------------------

  /**
   * Trace a model registry operation (register, promote, tag, etc.).
   *
   * Returns the underlying {@link Span} for manual management, or accepts
   * a callback that automatically ends the span.
   */
  traceRegistry(options: TraceRegistryOptions): Span;
  traceRegistry<T>(
    options: TraceRegistryOptions,
    fn: (span: Span) => T,
  ): T;
  traceRegistry<T>(
    options: TraceRegistryOptions,
    fn?: (span: Span) => T,
  ): Span | T {
    const tracer = this.getTracer();

    const attributes: Record<string, string | number | boolean> = {
      [ModelOpsAttributes.REGISTRY_OPERATION]: options.operation,
      [ModelOpsAttributes.REGISTRY_MODEL_ID]: options.modelId,
    };
    if (options.modelVersion !== undefined) {
      attributes[ModelOpsAttributes.REGISTRY_MODEL_VERSION] = options.modelVersion;
    }
    if (options.stage !== undefined) {
      attributes[ModelOpsAttributes.REGISTRY_STAGE] = options.stage;
    }
    if (options.modelAlias !== undefined) {
      attributes[ModelOpsAttributes.REGISTRY_MODEL_ALIAS] = options.modelAlias;
    }
    if (options.owner !== undefined) {
      attributes[ModelOpsAttributes.REGISTRY_OWNER] = options.owner;
    }
    if (options.trainingRunId !== undefined) {
      attributes[ModelOpsAttributes.REGISTRY_LINEAGE_TRAINING_RUN_ID] = options.trainingRunId;
    }
    if (options.parentModelId !== undefined) {
      attributes[ModelOpsAttributes.REGISTRY_LINEAGE_PARENT_MODEL_ID] = options.parentModelId;
    }

    const spanName = `model_ops.registry.${options.operation} ${options.modelId}`;

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

  // -- Deployment -----------------------------------------------------------

  /**
   * Trace a model deployment.
   *
   * Returns a {@link DeploymentOperation} for manual span management, or
   * accepts a callback that receives the operation and automatically ends
   * the span.
   */
  traceDeployment(options: TraceDeploymentOptions): DeploymentOperation;
  traceDeployment<T>(
    options: TraceDeploymentOptions,
    fn: (op: DeploymentOperation) => T,
  ): T;
  traceDeployment<T>(
    options: TraceDeploymentOptions,
    fn?: (op: DeploymentOperation) => T,
  ): DeploymentOperation | T {
    const tracer = this.getTracer();
    const deploymentId = options.deploymentId ?? crypto.randomUUID();
    const strategy = options.strategy ?? "rolling";
    const environment = options.environment ?? "production";

    const attributes: Record<string, string | number | boolean> = {
      [ModelOpsAttributes.DEPLOYMENT_ID]: deploymentId,
      [ModelOpsAttributes.DEPLOYMENT_MODEL_ID]: options.modelId,
      [ModelOpsAttributes.DEPLOYMENT_STRATEGY]: strategy,
      [ModelOpsAttributes.DEPLOYMENT_ENVIRONMENT]: environment,
    };
    if (options.endpoint !== undefined) {
      attributes[ModelOpsAttributes.DEPLOYMENT_ENDPOINT] = options.endpoint;
    }
    if (options.canaryPercent !== undefined) {
      attributes[ModelOpsAttributes.DEPLOYMENT_CANARY_PERCENT] = options.canaryPercent;
    }
    if (options.infrastructureProvider !== undefined) {
      attributes[ModelOpsAttributes.DEPLOYMENT_INFRA_PROVIDER] = options.infrastructureProvider;
    }

    const spanName = `model_ops.deployment ${deploymentId}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const op = new DeploymentOperation(otelSpan, deploymentId);
          try {
            const result = fn(op);
            if (result instanceof Promise) {
              return result
                .then((val) => {
                  otelSpan.setAttribute(ModelOpsAttributes.DEPLOYMENT_STATUS, "completed");
                  otelSpan.setStatus({ code: SpanStatusCode.OK });
                  otelSpan.end();
                  return val;
                })
                .catch((err) => {
                  otelSpan.setAttribute(ModelOpsAttributes.DEPLOYMENT_STATUS, "failed");
                  otelSpan.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
                  otelSpan.recordException(err);
                  otelSpan.end();
                  throw err;
                }) as T;
            }
            otelSpan.setAttribute(ModelOpsAttributes.DEPLOYMENT_STATUS, "completed");
            otelSpan.setStatus({ code: SpanStatusCode.OK });
            otelSpan.end();
            return result;
          } catch (err) {
            otelSpan.setAttribute(ModelOpsAttributes.DEPLOYMENT_STATUS, "failed");
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
    return new DeploymentOperation(otelSpan, deploymentId);
  }

  // -- Serving: Route -------------------------------------------------------

  /**
   * Trace a model routing decision.
   *
   * Returns the underlying {@link Span} for manual management, or accepts
   * a callback that automatically ends the span.
   */
  traceRoute(options: TraceRouteOptions): Span;
  traceRoute<T>(options: TraceRouteOptions, fn: (span: Span) => T): T;
  traceRoute<T>(
    options: TraceRouteOptions,
    fn?: (span: Span) => T,
  ): Span | T {
    const tracer = this.getTracer();
    const reason = options.reason ?? "capability";

    const attributes: Record<string, string | number | boolean | string[]> = {
      [ModelOpsAttributes.SERVING_OPERATION]: "route",
      [ModelOpsAttributes.SERVING_ROUTE_SELECTED_MODEL]: options.selectedModel,
      [ModelOpsAttributes.SERVING_ROUTE_REASON]: reason,
    };
    if (options.candidates !== undefined) {
      attributes[ModelOpsAttributes.SERVING_ROUTE_CANDIDATES] = options.candidates;
    }

    const spanName = "model_ops.serving.route";

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

  // -- Serving: Fallback ----------------------------------------------------

  /**
   * Trace a model serving fallback.
   *
   * Returns the underlying {@link Span} for manual management, or accepts
   * a callback that automatically ends the span.
   */
  traceFallback(options: TraceFallbackOptions): Span;
  traceFallback<T>(options: TraceFallbackOptions, fn: (span: Span) => T): T;
  traceFallback<T>(
    options: TraceFallbackOptions,
    fn?: (span: Span) => T,
  ): Span | T {
    const tracer = this.getTracer();
    const trigger = options.trigger ?? "error";
    const depth = options.depth ?? 1;

    const attributes: Record<string, string | number | boolean | string[]> = {
      [ModelOpsAttributes.SERVING_OPERATION]: "fallback",
      [ModelOpsAttributes.SERVING_FALLBACK_TRIGGER]: trigger,
      [ModelOpsAttributes.SERVING_FALLBACK_ORIGINAL_MODEL]: options.originalModel,
      [ModelOpsAttributes.SERVING_FALLBACK_FINAL_MODEL]: options.finalModel,
      [ModelOpsAttributes.SERVING_FALLBACK_DEPTH]: depth,
    };
    if (options.chain !== undefined) {
      attributes[ModelOpsAttributes.SERVING_FALLBACK_CHAIN] = options.chain;
    }

    const spanName = "model_ops.serving.fallback";

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

  // -- Serving: Cache Lookup ------------------------------------------------

  /**
   * Trace a cache lookup operation.
   *
   * Returns a {@link CacheLookup} for manual span management, or accepts
   * a callback that receives the lookup and automatically ends the span.
   */
  traceCacheLookup(options?: TraceCacheLookupOptions): CacheLookup;
  traceCacheLookup<T>(
    options: TraceCacheLookupOptions | undefined,
    fn: (lookup: CacheLookup) => T,
  ): T;
  traceCacheLookup<T>(
    options?: TraceCacheLookupOptions,
    fn?: (lookup: CacheLookup) => T,
  ): CacheLookup | T {
    const tracer = this.getTracer();
    const cacheType = options?.cacheType ?? "semantic";

    const attributes: Record<string, string | number | boolean> = {
      [ModelOpsAttributes.SERVING_OPERATION]: "cache_lookup",
      [ModelOpsAttributes.SERVING_CACHE_TYPE]: cacheType,
    };

    const spanName = "model_ops.serving.cache_lookup";

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const lookup = new CacheLookup(otelSpan);
          try {
            const result = fn(lookup);
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
    return new CacheLookup(otelSpan);
  }

  // -- Monitoring -----------------------------------------------------------

  /**
   * Trace a model monitoring check (drift, performance, SLA).
   *
   * Returns a {@link MonitoringCheck} for manual span management, or accepts
   * a callback that receives the check and automatically ends the span.
   */
  traceMonitoringCheck(options: TraceMonitoringCheckOptions): MonitoringCheck;
  traceMonitoringCheck<T>(
    options: TraceMonitoringCheckOptions,
    fn: (check: MonitoringCheck) => T,
  ): T;
  traceMonitoringCheck<T>(
    options: TraceMonitoringCheckOptions,
    fn?: (check: MonitoringCheck) => T,
  ): MonitoringCheck | T {
    const tracer = this.getTracer();

    const attributes: Record<string, string | number | boolean> = {
      [ModelOpsAttributes.MONITORING_CHECK_TYPE]: options.checkType,
      [ModelOpsAttributes.MONITORING_MODEL_ID]: options.modelId,
    };
    if (options.metricName !== undefined) {
      attributes[ModelOpsAttributes.MONITORING_METRIC_NAME] = options.metricName;
    }

    const spanName = `model_ops.monitoring.${options.checkType}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const check = new MonitoringCheck(otelSpan);
          try {
            const result = fn(check);
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
    return new MonitoringCheck(otelSpan);
  }

  // -- Prompt Lifecycle -----------------------------------------------------

  /**
   * Trace a prompt lifecycle operation.
   *
   * Returns a {@link PromptOperation} for manual span management, or accepts
   * a callback that receives the operation and automatically ends the span.
   */
  tracePrompt(options: TracePromptOptions): PromptOperation;
  tracePrompt<T>(
    options: TracePromptOptions,
    fn: (op: PromptOperation) => T,
  ): T;
  tracePrompt<T>(
    options: TracePromptOptions,
    fn?: (op: PromptOperation) => T,
  ): PromptOperation | T {
    const tracer = this.getTracer();

    const attributes: Record<string, string | number | boolean> = {
      [ModelOpsAttributes.PROMPT_NAME]: options.name,
      [ModelOpsAttributes.PROMPT_OPERATION]: options.operation,
    };
    if (options.version !== undefined) {
      attributes[ModelOpsAttributes.PROMPT_VERSION] = options.version;
    }
    if (options.label !== undefined) {
      attributes[ModelOpsAttributes.PROMPT_LABEL] = options.label;
    }
    if (options.modelTarget !== undefined) {
      attributes[ModelOpsAttributes.PROMPT_MODEL_TARGET] = options.modelTarget;
    }

    const spanName = `model_ops.prompt.${options.operation} ${options.name}`;

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const op = new PromptOperation(otelSpan);
          try {
            const result = fn(op);
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
    return new PromptOperation(otelSpan);
  }
}
