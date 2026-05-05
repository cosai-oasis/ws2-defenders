/**
 * AITF LLM Instrumentation.
 *
 * Provides tracing for LLM inference operations (chat completion, text completion,
 * embeddings) with extended attributes for cost, latency, and security.
 */

import {
  trace,
  Span,
  SpanKind,
  SpanStatusCode,
  Tracer,
  TracerProvider,
} from "@opentelemetry/api";
import {
  GenAIAttributes,
  CostAttributes,
  LatencyAttributes,
  SecurityAttributes,
} from "../semantic-conventions/attributes";

const TRACER_NAME = "instrumentation.llm";

/** Known options that should not be passed as extra span attributes. */
const KNOWN_OPTIONS = new Set([
  "model",
  "operation",
  "system",
  "temperature",
  "maxTokens",
  "stream",
  "tools",
]);

/** Allowed attribute key prefix for extra options. */
const EXTRA_ATTR_PREFIX = "gen_ai.request.";

/** Options for tracing an LLM inference operation. */
export interface TraceInferenceOptions {
  model: string;
  operation?: string;
  system?: string;
  temperature?: number;
  maxTokens?: number;
  stream?: boolean;
  tools?: Array<{ name: string; [key: string]: unknown }>;
  [key: string]: unknown;
}

/**
 * Helper class for setting attributes on an LLM inference span.
 */
export class InferenceSpan {
  private readonly _span: Span;
  private readonly _startTime: number;
  private _firstTokenTime: number | null = null;

  constructor(span: Span, startTime: number) {
    this._span = span;
    this._startTime = startTime;
  }

  /** Access the underlying OTel span. */
  get span(): Span {
    return this._span;
  }

  /** Record the prompt content as an event. */
  setPrompt(prompt: string): void {
    this._span.addEvent("gen_ai.content.prompt", {
      [GenAIAttributes.PROMPT]: prompt,
    });
  }

  /** Record the completion content as an event. */
  setCompletion(completion: string): void {
    this._span.addEvent("gen_ai.content.completion", {
      [GenAIAttributes.COMPLETION]: completion,
    });
  }

  /** Set response attributes. */
  setResponse(options: {
    responseId?: string;
    model?: string;
    finishReasons?: string[];
  }): void {
    if (options.responseId) {
      this._span.setAttribute(GenAIAttributes.RESPONSE_ID, options.responseId);
    }
    if (options.model) {
      this._span.setAttribute(GenAIAttributes.RESPONSE_MODEL, options.model);
    }
    if (options.finishReasons) {
      this._span.setAttribute(
        GenAIAttributes.RESPONSE_FINISH_REASONS,
        options.finishReasons
      );
    }
  }

  /** Set token usage attributes. */
  setUsage(options: {
    inputTokens?: number;
    outputTokens?: number;
    cachedTokens?: number;
    reasoningTokens?: number;
  }): void {
    this._span.setAttribute(
      GenAIAttributes.USAGE_INPUT_TOKENS,
      options.inputTokens ?? 0
    );
    this._span.setAttribute(
      GenAIAttributes.USAGE_OUTPUT_TOKENS,
      options.outputTokens ?? 0
    );
    if (options.cachedTokens) {
      this._span.setAttribute(
        GenAIAttributes.USAGE_CACHED_TOKENS,
        options.cachedTokens
      );
    }
    if (options.reasoningTokens) {
      this._span.setAttribute(
        GenAIAttributes.USAGE_REASONING_TOKENS,
        options.reasoningTokens
      );
    }
  }

  /** Set cost attributes. */
  setCost(options: {
    inputCost?: number;
    outputCost?: number;
    totalCost?: number;
    currency?: string;
  }): void {
    const inputCost = options.inputCost ?? 0;
    const outputCost = options.outputCost ?? 0;
    this._span.setAttribute(CostAttributes.INPUT_COST, inputCost);
    this._span.setAttribute(CostAttributes.OUTPUT_COST, outputCost);
    this._span.setAttribute(
      CostAttributes.TOTAL_COST,
      options.totalCost ?? inputCost + outputCost
    );
    this._span.setAttribute(
      CostAttributes.CURRENCY,
      options.currency ?? "USD"
    );
  }

  /** Record a tool/function call event. */
  setToolCall(name: string, callId: string, args: string): void {
    this._span.addEvent("gen_ai.tool.call", {
      [GenAIAttributes.TOOL_NAME]: name,
      [GenAIAttributes.TOOL_CALL_ID]: callId,
      [GenAIAttributes.TOOL_ARGUMENTS]: args,
    });
  }

  /** Record a tool/function result event. */
  setToolResult(name: string, callId: string, result: string): void {
    this._span.addEvent("gen_ai.tool.result", {
      [GenAIAttributes.TOOL_NAME]: name,
      [GenAIAttributes.TOOL_CALL_ID]: callId,
      [GenAIAttributes.TOOL_RESULT]: result,
    });
  }

  /** Mark when the first token is received (for streaming). */
  markFirstToken(): void {
    this._firstTokenTime = performance.now();
    const ttft = this._firstTokenTime - this._startTime;
    this._span.setAttribute(LatencyAttributes.TIME_TO_FIRST_TOKEN_MS, ttft);
  }

  /** Set latency metrics. */
  setLatency(options: {
    totalMs?: number;
    tokensPerSecond?: number;
    queueTimeMs?: number;
    inferenceTimeMs?: number;
  }): void {
    const totalMs =
      options.totalMs ?? performance.now() - this._startTime;
    this._span.setAttribute(LatencyAttributes.TOTAL_MS, totalMs);
    if (options.tokensPerSecond !== undefined) {
      this._span.setAttribute(
        LatencyAttributes.TOKENS_PER_SECOND,
        options.tokensPerSecond
      );
    }
    if (options.queueTimeMs !== undefined) {
      this._span.setAttribute(
        LatencyAttributes.QUEUE_TIME_MS,
        options.queueTimeMs
      );
    }
    if (options.inferenceTimeMs !== undefined) {
      this._span.setAttribute(
        LatencyAttributes.INFERENCE_TIME_MS,
        options.inferenceTimeMs
      );
    }
  }

  /** Set security assessment attributes. */
  setSecurity(riskScore: number = 0.0, riskLevel: string = "info"): void {
    this._span.setAttribute(SecurityAttributes.RISK_SCORE, riskScore);
    this._span.setAttribute(SecurityAttributes.RISK_LEVEL, riskLevel);
  }
}

/**
 * Instrumentor for LLM inference operations.
 *
 * Traces chat completions, text completions, and embedding operations
 * with OTel GenAI-compatible attributes plus AITF extensions.
 */
export class LLMInstrumentor {
  private _tracerProvider: TracerProvider | null;
  private _tracer: Tracer | null = null;
  private _instrumented = false;

  constructor(tracerProvider?: TracerProvider) {
    this._tracerProvider = tracerProvider ?? null;
  }

  /** Enable LLM instrumentation. */
  instrument(): void {
    const tp = this._tracerProvider ?? trace.getTracerProvider();
    this._tracer = tp.getTracer(TRACER_NAME);
    this._instrumented = true;
  }

  /** Disable LLM instrumentation. */
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

  /**
   * Trace an LLM inference operation.
   *
   * Usage:
   *   const span = llm.traceInference({ model: "gpt-4o", system: "openai" });
   *   span.setPrompt("Hello, world!");
   *   // ... perform inference ...
   *   span.setCompletion(response);
   *   span.setUsage({ inputTokens: 10, outputTokens: 50 });
   *   span.end();
   *
   * Or use the callback form:
   *   llm.traceInference({ model: "gpt-4o" }, async (span) => {
   *     span.setPrompt("Hello");
   *     const result = await doInference();
   *     span.setCompletion(result);
   *     span.setUsage({ inputTokens: 10, outputTokens: 50 });
   *     return result;
   *   });
   */
  traceInference(options: TraceInferenceOptions): InferenceSpan;
  traceInference<T>(
    options: TraceInferenceOptions,
    fn: (span: InferenceSpan) => T
  ): T;
  traceInference<T>(
    options: TraceInferenceOptions,
    fn?: (span: InferenceSpan) => T
  ): InferenceSpan | T {
    const tracer = this.getTracer();
    const operation = options.operation ?? "chat";
    const system = options.system ?? "openai";
    const spanName = `${operation} ${options.model}`;

    const attributes: Record<string, string | number | boolean> = {
      [GenAIAttributes.SYSTEM]: system,
      [GenAIAttributes.OPERATION_NAME]: operation,
      [GenAIAttributes.REQUEST_MODEL]: options.model,
    };
    if (options.temperature !== undefined) {
      attributes[GenAIAttributes.REQUEST_TEMPERATURE] = options.temperature;
    }
    if (options.maxTokens !== undefined) {
      attributes[GenAIAttributes.REQUEST_MAX_TOKENS] = options.maxTokens;
    }
    if (options.stream) {
      attributes[GenAIAttributes.REQUEST_STREAM] = true;
    }
    if (options.tools) {
      attributes[GenAIAttributes.REQUEST_TOOLS] = JSON.stringify(
        options.tools.map((t) => ({ name: t.name }))
      );
    }

    // Add extra attributes with validation
    // Only allow known-safe keys under gen_ai.request.* namespace
    for (const [key, value] of Object.entries(options)) {
      if (
        !Object.prototype.hasOwnProperty.call(options, key) ||
        KNOWN_OPTIONS.has(key) ||
        value === undefined
      ) {
        continue;
      }
      // Only allow simple scalar types as attribute values
      if (
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean"
      ) {
        // Validate key to prevent attribute namespace pollution
        const sanitizedKey = key.replace(/[^a-zA-Z0-9_]/g, "_");
        attributes[`${EXTRA_ATTR_PREFIX}${sanitizedKey}`] = value;
      }
    }

    const startTime = performance.now();

    if (fn) {
      return tracer.startActiveSpan(
        spanName,
        { kind: SpanKind.CLIENT, attributes },
        (otelSpan) => {
          const inferenceSpan = new InferenceSpan(otelSpan, startTime);
          try {
            const result = fn(inferenceSpan);
            // Handle promises
            if (result instanceof Promise) {
              return result
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

    // No callback: return InferenceSpan for manual management
    const otelSpan = tracer.startSpan(spanName, {
      kind: SpanKind.CLIENT,
      attributes,
    });
    return new InferenceSpan(otelSpan, startTime);
  }
}
