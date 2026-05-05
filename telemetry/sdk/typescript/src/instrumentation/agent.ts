/**
 * AITF Agent Instrumentation.
 *
 * Provides tracing for AI agent operations: sessions, steps, delegation,
 * multi-agent orchestration, and memory access.
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
import {
  AgentAttributes,
  MemoryAttributes,
} from "../semantic-conventions/attributes";

const TRACER_NAME = "instrumentation.agent";

/** Options for tracing an agent session. */
export interface TraceSessionOptions {
  agentName: string;
  agentId?: string;
  agentType?: string;
  framework?: string;
  version?: string;
  description?: string;
  sessionId?: string;
  teamName?: string;
}

/** Options for tracing a multi-agent team. */
export interface TraceTeamOptions {
  teamName: string;
  teamId?: string;
  topology?: string;
  members?: string[];
  coordinator?: string;
}

/**
 * Helper class for setting attributes on an agent step span.
 */
export class AgentStep {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  get span(): Span {
    return this._span;
  }

  setThought(thought: string): void {
    this._span.setAttribute(AgentAttributes.STEP_THOUGHT, thought);
  }

  setAction(action: string): void {
    this._span.setAttribute(AgentAttributes.STEP_ACTION, action);
  }

  setObservation(observation: string): void {
    this._span.setAttribute(AgentAttributes.STEP_OBSERVATION, observation);
  }

  setStatus(status: string): void {
    this._span.setAttribute(AgentAttributes.STEP_STATUS, status);
  }
}

/**
 * Helper for managing an agent session's spans.
 */
export class AgentSession {
  private readonly _span: Span;
  private readonly _tracer: Tracer;
  private readonly _agentName: string;
  private readonly _sessionId: string;
  private _stepCount = 0;

  constructor(span: Span, tracer: Tracer, agentName: string, sessionId: string) {
    this._span = span;
    this._tracer = tracer;
    this._agentName = agentName;
    this._sessionId = sessionId;
  }

  get span(): Span {
    return this._span;
  }

  get stepCount(): number {
    return this._stepCount;
  }

  /**
   * Create a child span for an agent step.
   */
  step<T>(stepType: string, fn: (step: AgentStep) => T): T;
  step(stepType: string): AgentStep;
  step<T>(
    stepType: string,
    fn?: (step: AgentStep) => T
  ): AgentStep | T {
    this._stepCount++;
    const attributes: Record<string, string | number | boolean> = {
      [AgentAttributes.NAME]: this._agentName,
      [AgentAttributes.STEP_TYPE]: stepType,
      [AgentAttributes.STEP_INDEX]: this._stepCount,
    };

    if (fn) {
      return this._tracer.startActiveSpan(
        `agent.step.${stepType} ${this._agentName}`,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const agentStep = new AgentStep(otelSpan);
          try {
            const result = fn(agentStep);
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

    const otelSpan = this._tracer.startSpan(
      `agent.step.${stepType} ${this._agentName}`,
      { kind: SpanKind.INTERNAL, attributes }
    );
    return new AgentStep(otelSpan);
  }

  /**
   * Create a delegation span.
   */
  delegate<T>(
    targetAgent: string,
    options: {
      targetAgentId?: string;
      reason?: string;
      strategy?: string;
      task?: string;
    },
    fn: (span: Span) => T
  ): T {
    this._stepCount++;
    const targetAgentId = options.targetAgentId ?? randomUUID();
    const attributes: Record<string, string | number | boolean> = {
      [AgentAttributes.NAME]: this._agentName,
      [AgentAttributes.STEP_TYPE]: AgentAttributes.StepType.DELEGATION,
      [AgentAttributes.STEP_INDEX]: this._stepCount,
      [AgentAttributes.DELEGATION_TARGET_AGENT]: targetAgent,
      [AgentAttributes.DELEGATION_TARGET_AGENT_ID]: targetAgentId,
      [AgentAttributes.DELEGATION_STRATEGY]: options.strategy ?? "capability",
    };
    if (options.reason) {
      attributes[AgentAttributes.DELEGATION_REASON] = options.reason;
    }
    if (options.task) {
      attributes[AgentAttributes.DELEGATION_TASK] = options.task;
    }

    return this._tracer.startActiveSpan(
      `agent.delegate ${this._agentName} -> ${targetAgent}`,
      { kind: SpanKind.INTERNAL, attributes },
      (otelSpan) => {
        try {
          const result = fn(otelSpan);
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

  /**
   * Create a memory access span.
   */
  memoryAccess<T>(
    operation: string,
    options: { store?: string; key?: string },
    fn: (span: Span) => T
  ): T {
    const attributes: Record<string, string | number | boolean> = {
      [AgentAttributes.NAME]: this._agentName,
      [MemoryAttributes.OPERATION]: operation,
      [MemoryAttributes.STORE]: options.store ?? "short_term",
    };
    if (options.key) {
      attributes[MemoryAttributes.KEY] = options.key;
    }

    return this._tracer.startActiveSpan(
      `agent.memory.${operation} ${this._agentName}`,
      { kind: SpanKind.INTERNAL, attributes },
      (otelSpan) => {
        try {
          const result = fn(otelSpan);
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

  /** Finalize the session span with turn count and OK status. */
  end(): void {
    this._span.setAttribute(
      AgentAttributes.SESSION_TURN_COUNT,
      this._stepCount
    );
    this._span.setStatus({ code: SpanStatusCode.OK });
    this._span.end();
  }

  /** End the session span with an error. */
  endWithError(err: Error): void {
    this._span.setStatus({
      code: SpanStatusCode.ERROR,
      message: String(err),
    });
    this._span.recordException(err);
    this._span.end();
  }
}

/**
 * Instrumentor for AI agent operations.
 */
export class AgentInstrumentor {
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
   * Trace an agent session.
   *
   * With callback:
   *   agent.traceSession({ agentName: "research-agent" }, async (session) => {
   *     session.step("planning", (step) => {
   *       step.setThought("I need to search for information");
   *     });
   *   });
   *
   * Without callback (manual management):
   *   const session = agent.traceSession({ agentName: "research-agent" });
   *   // ... use session ...
   *   session.end();
   */
  traceSession(options: TraceSessionOptions): AgentSession;
  traceSession<T>(
    options: TraceSessionOptions,
    fn: (session: AgentSession) => T
  ): T;
  traceSession<T>(
    options: TraceSessionOptions,
    fn?: (session: AgentSession) => T
  ): AgentSession | T {
    const tracer = this.getTracer();
    const sessionId = options.sessionId ?? randomUUID();
    const agentId = options.agentId ?? randomUUID();

    const attributes: Record<string, string | number | boolean> = {
      [AgentAttributes.NAME]: options.agentName,
      [AgentAttributes.ID]: agentId,
      [AgentAttributes.TYPE]: options.agentType ?? "autonomous",
      [AgentAttributes.FRAMEWORK]: options.framework ?? "custom",
      [AgentAttributes.SESSION_ID]: sessionId,
    };
    if (options.version) {
      attributes[AgentAttributes.VERSION] = options.version;
    }
    if (options.description) {
      attributes[AgentAttributes.DESCRIPTION] = options.description;
    }
    if (options.teamName) {
      attributes[AgentAttributes.TEAM_NAME] = options.teamName;
    }

    if (fn) {
      return tracer.startActiveSpan(
        `agent.session ${options.agentName}`,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const session = new AgentSession(
            otelSpan,
            tracer,
            options.agentName,
            sessionId
          );
          try {
            const result = fn(session);
            if (result instanceof Promise) {
              return (result as Promise<unknown>)
                .then((val) => {
                  session.end();
                  return val;
                })
                .catch((err) => {
                  session.endWithError(err);
                  throw err;
                }) as T;
            }
            session.end();
            return result;
          } catch (err) {
            session.endWithError(err as Error);
            throw err;
          }
        }
      );
    }

    const otelSpan = tracer.startSpan(
      `agent.session ${options.agentName}`,
      { kind: SpanKind.INTERNAL, attributes }
    );
    return new AgentSession(otelSpan, tracer, options.agentName, sessionId);
  }

  /**
   * Trace a multi-agent team orchestration.
   */
  traceTeam<T>(options: TraceTeamOptions, fn: (span: Span) => T): T {
    const tracer = this.getTracer();
    const teamId = options.teamId ?? randomUUID();
    const attributes: Record<string, string | number | boolean | string[]> = {
      [AgentAttributes.TEAM_NAME]: options.teamName,
      [AgentAttributes.TEAM_ID]: teamId,
      [AgentAttributes.TEAM_TOPOLOGY]: options.topology ?? "hierarchical",
    };
    if (options.members) {
      attributes[AgentAttributes.TEAM_MEMBERS] = options.members;
    }
    if (options.coordinator) {
      attributes[AgentAttributes.TEAM_COORDINATOR] = options.coordinator;
    }

    return tracer.startActiveSpan(
      `agent.team.orchestrate ${options.teamName}`,
      { kind: SpanKind.INTERNAL, attributes },
      (otelSpan) => {
        try {
          const result = fn(otelSpan);
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
}
