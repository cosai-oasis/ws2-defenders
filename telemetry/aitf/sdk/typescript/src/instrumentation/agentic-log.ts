/**
 * AITF Agentic Log Instrumentation.
 *
 * Provides structured logging for AI agent actions based on Table 10.1:
 * Agentic log with minimum fields. Each log entry captures the essential
 * security-relevant context for every action taken by an AI agent.
 */

import {
  trace,
  Span,
  SpanKind,
  SpanStatusCode,
  Tracer,
  TracerProvider,
} from "@opentelemetry/api";
import { randomUUID } from "crypto";
import { AgenticLogAttributes } from "../semantic-conventions/attributes";

const TRACER_NAME = "instrumentation.agentic_log";

/** Options for creating an agentic log entry. */
export interface AgenticLogOptions {
  /** The unique, cryptographically verifiable agent identity. */
  agentId: string;
  /** The unique session/thought-process ID. */
  sessionId: string;
  /** Optional custom event ID (auto-generated if omitted). */
  eventId?: string;
  /** The high-level goal identifier. */
  goalId?: string;
  /** The specific immediate task identifier. */
  subTaskId?: string;
  /** The tool/function/API being invoked. */
  toolUsed?: string;
  /** Sanitized parameters (object or JSON string). */
  toolParameters?: Record<string, unknown> | string;
  /** Agent's success likelihood assessment (0.0-1.0). */
  confidenceScore?: number;
  /** How unusual this action is (0.0-1.0). */
  anomalyScore?: number;
}

/**
 * A single agentic log entry conforming to Table 10.1 minimal fields.
 * Wraps an OTel span and provides typed setters for all 12 mandatory fields.
 */
export class AgenticLogEntry {
  private readonly _span: Span;
  private readonly _eventId: string;
  private readonly _timestamp: string;

  constructor(span: Span, eventId: string, timestamp: string) {
    this._span = span;
    this._eventId = eventId;
    this._timestamp = timestamp;
  }

  get span(): Span {
    return this._span;
  }

  get eventId(): string {
    return this._eventId;
  }

  get timestamp(): string {
    return this._timestamp;
  }

  /** Set the high-level goal the agent is pursuing. */
  setGoalId(goalId: string): void {
    this._span.setAttribute(AgenticLogAttributes.GOAL_ID, goalId);
  }

  /** Set the specific, immediate task the agent is performing. */
  setSubTaskId(subTaskId: string): void {
    this._span.setAttribute(AgenticLogAttributes.SUB_TASK_ID, subTaskId);
  }

  /** Set the specific tool, function, or API being invoked. */
  setToolUsed(toolUsed: string): void {
    this._span.setAttribute(AgenticLogAttributes.TOOL_USED, toolUsed);
  }

  /** Set the sanitized tool parameters (PII/credentials redacted). */
  setToolParameters(parameters: Record<string, unknown> | string): void {
    const value =
      typeof parameters === "string"
        ? parameters
        : JSON.stringify(parameters);
    this._span.setAttribute(AgenticLogAttributes.TOOL_PARAMETERS, value);
  }

  /** Set the result of the action (e.g., SUCCESS, FAILURE, ERROR). */
  setOutcome(outcome: string): void {
    this._span.setAttribute(AgenticLogAttributes.OUTCOME, outcome);
    if (outcome === AgenticLogAttributes.Outcome.SUCCESS) {
      this._span.setStatus({ code: SpanStatusCode.OK });
    } else if (
      outcome === AgenticLogAttributes.Outcome.FAILURE ||
      outcome === AgenticLogAttributes.Outcome.ERROR
    ) {
      this._span.setStatus({
        code: SpanStatusCode.ERROR,
        message: `Outcome: ${outcome}`,
      });
    }
  }

  /** Set the agent's success likelihood assessment (0.0-1.0). */
  setConfidenceScore(score: number): void {
    this._span.setAttribute(AgenticLogAttributes.CONFIDENCE_SCORE, score);
  }

  /** Set the anomaly score from a real-time model (0.0-1.0). */
  setAnomalyScore(score: number): void {
    this._span.setAttribute(AgenticLogAttributes.ANOMALY_SCORE, score);
  }

  /** Set the policy evaluation record (e.g., from OPA). */
  setPolicyEvaluation(evaluation: Record<string, unknown> | string): void {
    const value =
      typeof evaluation === "string"
        ? evaluation
        : JSON.stringify(evaluation);
    this._span.setAttribute(AgenticLogAttributes.POLICY_EVALUATION, value);
  }
}

/**
 * Instrumentor for agentic log entries (Table 10.1 minimal fields).
 */
export class AgenticLogInstrumentor {
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
   * Create an agentic log entry with a callback.
   */
  logAction<T>(options: AgenticLogOptions, fn: (entry: AgenticLogEntry) => T): T;
  /**
   * Create an agentic log entry for manual management.
   */
  logAction(options: AgenticLogOptions): AgenticLogEntry;
  logAction<T>(
    options: AgenticLogOptions,
    fn?: (entry: AgenticLogEntry) => T
  ): AgenticLogEntry | T {
    const tracer = this.getTracer();
    const eventId = options.eventId ?? `e-${randomUUID().slice(0, 8)}`;
    const timestamp = new Date().toISOString().replace(/(\.\d{3})\d*Z/, "$1Z");

    const attributes: Record<string, string | number | boolean> = {
      [AgenticLogAttributes.EVENT_ID]: eventId,
      [AgenticLogAttributes.TIMESTAMP]: timestamp,
      [AgenticLogAttributes.AGENT_ID]: options.agentId,
      [AgenticLogAttributes.SESSION_ID]: options.sessionId,
    };

    if (options.goalId) {
      attributes[AgenticLogAttributes.GOAL_ID] = options.goalId;
    }
    if (options.subTaskId) {
      attributes[AgenticLogAttributes.SUB_TASK_ID] = options.subTaskId;
    }
    if (options.toolUsed) {
      attributes[AgenticLogAttributes.TOOL_USED] = options.toolUsed;
    }
    if (options.toolParameters) {
      attributes[AgenticLogAttributes.TOOL_PARAMETERS] =
        typeof options.toolParameters === "string"
          ? options.toolParameters
          : JSON.stringify(options.toolParameters);
    }
    if (options.confidenceScore !== undefined) {
      attributes[AgenticLogAttributes.CONFIDENCE_SCORE] =
        options.confidenceScore;
    }
    if (options.anomalyScore !== undefined) {
      attributes[AgenticLogAttributes.ANOMALY_SCORE] = options.anomalyScore;
    }

    if (fn) {
      return tracer.startActiveSpan(
        `agentic_log ${options.agentId}`,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const entry = new AgenticLogEntry(otelSpan, eventId, timestamp);
          try {
            const result = fn(entry);
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
                  otelSpan.recordException(err);
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
            otelSpan.recordException(err as Error);
            otelSpan.end();
            throw err;
          }
        }
      );
    }

    const otelSpan = tracer.startSpan(
      `agentic_log ${options.agentId}`,
      { kind: SpanKind.INTERNAL, attributes }
    );
    return new AgenticLogEntry(otelSpan, eventId, timestamp);
  }
}
