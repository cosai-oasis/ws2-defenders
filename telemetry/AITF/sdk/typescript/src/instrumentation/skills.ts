/**
 * AITF Skills Instrumentation.
 *
 * Provides tracing for skill discovery, invocation, composition, and resolution.
 */

import {
  trace,
  Span,
  SpanKind,
  SpanStatusCode,
  Tracer,
  TracerProvider,
} from "@opentelemetry/api";
import { SkillAttributes } from "../semantic-conventions/attributes";

const TRACER_NAME = "instrumentation.skills";

/** Options for tracing a skill invocation. */
export interface TraceInvokeOptions {
  skillName: string;
  version?: string;
  skillId?: string;
  provider?: string;
  category?: string;
  description?: string;
  skillInput?: string;
  source?: string;
  permissions?: string[];
}

/** Options for tracing skill discovery. */
export interface TraceDiscoverOptions {
  source: string;
  filterCategory?: string;
}

/**
 * Helper for skill invocation spans.
 */
export class SkillInvocation {
  private readonly _span: Span;
  private readonly _startTime: number;
  private _statusSet = false;

  constructor(span: Span, startTime: number) {
    this._span = span;
    this._startTime = startTime;
  }

  get span(): Span {
    return this._span;
  }

  setOutput(output: string): void {
    this._span.setAttribute(SkillAttributes.OUTPUT, output);
    this._span.addEvent("skill.output", {
      "skill.output.content": output,
    });
  }

  setStatus(status: string): void {
    this._span.setAttribute(SkillAttributes.STATUS, status);
    this._statusSet = true;
  }

  setError(
    errorType: string,
    message: string,
    retryable: boolean = false
  ): void {
    this._span.setAttribute(
      SkillAttributes.STATUS,
      SkillAttributes.Status.ERROR
    );
    this._statusSet = true;
    this._span.addEvent("skill.error", {
      "skill.error.type": errorType,
      "skill.error.message": message,
      "skill.error.retryable": retryable,
    });
  }

  setRetryCount(count: number): void {
    this._span.setAttribute(SkillAttributes.RETRY_COUNT, count);
  }

  /** End the invocation span with success, recording duration. */
  end(): void {
    const durationMs = performance.now() - this._startTime;
    this._span.setAttribute(SkillAttributes.DURATION_MS, durationMs);
    if (!this._statusSet) {
      this._span.setAttribute(
        SkillAttributes.STATUS,
        SkillAttributes.Status.SUCCESS
      );
    }
    this._span.setStatus({ code: SpanStatusCode.OK });
    this._span.end();
  }

  /** End the invocation span with an error, recording duration. */
  endWithError(err: Error): void {
    const durationMs = performance.now() - this._startTime;
    this._span.setAttribute(SkillAttributes.DURATION_MS, durationMs);
    this._span.setAttribute(
      SkillAttributes.STATUS,
      SkillAttributes.Status.ERROR
    );
    this._span.setStatus({
      code: SpanStatusCode.ERROR,
      message: String(err),
    });
    this._span.recordException(err);
    this._span.end();
  }
}

/**
 * Helper for skill discovery spans.
 */
export class SkillDiscovery {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  setSkills(skillNames: string[]): void {
    this._span.setAttribute(SkillAttributes.COUNT, skillNames.length);
    this._span.setAttribute(SkillAttributes.NAMES, skillNames);
  }
}

/**
 * Helper for skill composition spans.
 */
export class SkillComposition {
  private readonly _span: Span;
  private readonly _tracer: Tracer;
  private _completed = 0;

  constructor(span: Span, tracer: Tracer) {
    this._span = span;
    this._tracer = tracer;
  }

  get completedCount(): number {
    return this._completed;
  }

  markCompleted(): void {
    this._completed++;
  }
}

/**
 * Instrumentor for skill operations.
 */
export class SkillInstrumentor {
  private _tracerProvider: TracerProvider | null;
  private _tracer: Tracer | null = null;
  private _instrumented = false;

  constructor(tracerProvider?: TracerProvider) {
    this._tracerProvider = tracerProvider ?? null;
  }

  instrument(): void {
    const tp = this._tracerProvider ?? trace.getTracerProvider();
    this._tracer = tp.getTracer(TRACER_NAME);
    this._instrumented = true;
  }

  uninstrument(): void {
    this._tracer = null;
    this._instrumented = false;
  }

  getTracer(): Tracer {
    if (!this._tracer) {
      const tp = this._tracerProvider ?? trace.getTracerProvider();
      this._tracer = tp.getTracer(TRACER_NAME);
    }
    return this._tracer;
  }

  /**
   * Trace a skill invocation.
   */
  traceInvoke(options: TraceInvokeOptions): SkillInvocation;
  traceInvoke<T>(
    options: TraceInvokeOptions,
    fn: (invocation: SkillInvocation) => T
  ): T;
  traceInvoke<T>(
    options: TraceInvokeOptions,
    fn?: (invocation: SkillInvocation) => T
  ): SkillInvocation | T {
    const tracer = this.getTracer();
    const startTime = performance.now();
    const attributes: Record<string, string | number | boolean | string[]> = {
      [SkillAttributes.NAME]: options.skillName,
      [SkillAttributes.VERSION]: options.version ?? "1.0.0",
      [SkillAttributes.PROVIDER]: options.provider ?? "custom",
    };
    if (options.skillId) {
      attributes[SkillAttributes.ID] = options.skillId;
    }
    if (options.category) {
      attributes[SkillAttributes.CATEGORY] = options.category;
    }
    if (options.description) {
      attributes[SkillAttributes.DESCRIPTION] = options.description;
    }
    if (options.skillInput !== undefined) {
      attributes[SkillAttributes.INPUT] = options.skillInput;
    }
    if (options.source) {
      attributes[SkillAttributes.SOURCE] = options.source;
    }
    if (options.permissions) {
      attributes[SkillAttributes.PERMISSIONS] = options.permissions;
    }

    if (fn) {
      return tracer.startActiveSpan(
        `skill.invoke ${options.skillName}`,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const invocation = new SkillInvocation(otelSpan, startTime);
          try {
            const result = fn(invocation);
            if (result instanceof Promise) {
              return (result as Promise<unknown>)
                .then((val) => {
                  invocation.end();
                  return val;
                })
                .catch((err) => {
                  invocation.endWithError(err);
                  throw err;
                }) as T;
            }
            invocation.end();
            return result;
          } catch (err) {
            invocation.endWithError(err as Error);
            throw err;
          }
        }
      );
    }

    const otelSpan = tracer.startSpan(
      `skill.invoke ${options.skillName}`,
      { kind: SpanKind.INTERNAL, attributes }
    );
    return new SkillInvocation(otelSpan, startTime);
  }

  /**
   * Trace skill discovery from a source.
   */
  traceDiscover<T>(
    options: TraceDiscoverOptions,
    fn: (discovery: SkillDiscovery) => T
  ): T {
    const tracer = this.getTracer();
    const attributes: Record<string, string | number | boolean> = {
      [SkillAttributes.SOURCE]: options.source,
    };
    if (options.filterCategory) {
      attributes["skill.filter.category"] = options.filterCategory;
    }

    return tracer.startActiveSpan(
      `skill.discover ${options.source}`,
      { kind: SpanKind.CLIENT, attributes },
      (otelSpan) => {
        const discovery = new SkillDiscovery(otelSpan);
        try {
          const result = fn(discovery);
          if (result instanceof Promise) {
            return (result as Promise<unknown>)
              .then((val) => {
                otelSpan.setStatus({ code: SpanStatusCode.OK });
                otelSpan.end();
                return val;
              })
              .catch((err) => {
                otelSpan.setStatus({
                  code: SpanStatusCode.ERROR,
                  message: String(err),
                });
                otelSpan.end();
                throw err;
              }) as T;
          }
          otelSpan.setStatus({ code: SpanStatusCode.OK });
          otelSpan.end();
          return result;
        } catch (err) {
          otelSpan.setStatus({
            code: SpanStatusCode.ERROR,
            message: String(err),
          });
          otelSpan.end();
          throw err;
        }
      }
    );
  }
}
