/**
 * AITF RAG (Retrieval-Augmented Generation) Instrumentation.
 *
 * Provides tracing for RAG pipeline stages: retrieval, reranking, generation,
 * and quality evaluation.
 */

import {
  trace,
  Span,
  SpanKind,
  SpanStatusCode,
  Tracer,
  TracerProvider,
} from "@opentelemetry/api";
import { RAGAttributes } from "../semantic-conventions/attributes";

const TRACER_NAME = "instrumentation.rag";

/** Options for tracing a RAG pipeline. */
export interface TracePipelineOptions {
  pipelineName: string;
  query?: string;
}

/** Options for tracing a retrieval operation. */
export interface TraceRetrieveOptions {
  database: string;
  index?: string;
  topK?: number;
  query?: string;
  embeddingModel?: string;
  filterExpr?: string;
}

/** Options for tracing a reranking operation. */
export interface TraceRerankOptions {
  model: string;
  inputCount?: number;
}

/**
 * Helper for retrieval span attributes.
 */
export class RetrievalSpan {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  get span(): Span {
    return this._span;
  }

  setResults(
    count: number,
    minScore?: number,
    maxScore?: number
  ): void {
    this._span.setAttribute(RAGAttributes.RETRIEVE_RESULTS_COUNT, count);
    if (minScore !== undefined) {
      this._span.setAttribute(RAGAttributes.RETRIEVE_MIN_SCORE, minScore);
    }
    if (maxScore !== undefined) {
      this._span.setAttribute(RAGAttributes.RETRIEVE_MAX_SCORE, maxScore);
    }
  }
}

/**
 * Helper for rerank span attributes.
 */
export class RerankSpan {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  get span(): Span {
    return this._span;
  }

  setResults(inputCount: number, outputCount: number): void {
    this._span.setAttribute(RAGAttributes.RERANK_INPUT_COUNT, inputCount);
    this._span.setAttribute(RAGAttributes.RERANK_OUTPUT_COUNT, outputCount);
  }
}

/**
 * Helper for managing RAG pipeline child spans.
 */
export class RAGPipeline {
  private readonly _span: Span;
  private readonly _tracer: Tracer;
  private readonly _pipelineName: string;

  constructor(span: Span, tracer: Tracer, pipelineName: string) {
    this._span = span;
    this._tracer = tracer;
    this._pipelineName = pipelineName;
  }

  get span(): Span {
    return this._span;
  }

  /** Create a retrieval child span. */
  retrieve<T>(
    database: string,
    options: { topK?: number; [key: string]: unknown },
    fn: (retrieval: RetrievalSpan) => T
  ): T {
    const attributes: Record<string, string | number | boolean> = {
      [RAGAttributes.PIPELINE_STAGE]: RAGAttributes.Stage.RETRIEVE,
      [RAGAttributes.PIPELINE_NAME]: this._pipelineName,
      [RAGAttributes.RETRIEVE_DATABASE]: database,
      [RAGAttributes.RETRIEVE_TOP_K]: options.topK ?? 10,
    };

    return this._tracer.startActiveSpan(
      `rag.retrieve ${database}`,
      { kind: SpanKind.CLIENT, attributes },
      (otelSpan) => {
        const retrieval = new RetrievalSpan(otelSpan);
        try {
          const result = fn(retrieval);
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

  /** Create a rerank child span. */
  rerank<T>(
    model: string,
    fn: (rerank: RerankSpan) => T
  ): T {
    const attributes: Record<string, string | number | boolean> = {
      [RAGAttributes.PIPELINE_STAGE]: RAGAttributes.Stage.RERANK,
      [RAGAttributes.PIPELINE_NAME]: this._pipelineName,
      [RAGAttributes.RERANK_MODEL]: model,
    };

    return this._tracer.startActiveSpan(
      `rag.rerank ${model}`,
      { kind: SpanKind.INTERNAL, attributes },
      (otelSpan) => {
        const rerank = new RerankSpan(otelSpan);
        try {
          const result = fn(rerank);
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

  /** Set quality metrics on the pipeline span. */
  setQuality(options: {
    contextRelevance?: number;
    answerRelevance?: number;
    faithfulness?: number;
    groundedness?: number;
  }): void {
    if (options.contextRelevance !== undefined) {
      this._span.setAttribute(
        RAGAttributes.QUALITY_CONTEXT_RELEVANCE,
        options.contextRelevance
      );
    }
    if (options.answerRelevance !== undefined) {
      this._span.setAttribute(
        RAGAttributes.QUALITY_ANSWER_RELEVANCE,
        options.answerRelevance
      );
    }
    if (options.faithfulness !== undefined) {
      this._span.setAttribute(
        RAGAttributes.QUALITY_FAITHFULNESS,
        options.faithfulness
      );
    }
    if (options.groundedness !== undefined) {
      this._span.setAttribute(
        RAGAttributes.QUALITY_GROUNDEDNESS,
        options.groundedness
      );
    }
  }

  /** End the pipeline span with OK status. */
  end(): void {
    this._span.setStatus({ code: SpanStatusCode.OK });
    this._span.end();
  }

  /** End the pipeline span with an error. */
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
 * Instrumentor for RAG pipeline operations.
 */
export class RAGInstrumentor {
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
   * Trace a complete RAG pipeline execution.
   */
  tracePipeline(options: TracePipelineOptions): RAGPipeline;
  tracePipeline<T>(
    options: TracePipelineOptions,
    fn: (pipeline: RAGPipeline) => T
  ): T;
  tracePipeline<T>(
    options: TracePipelineOptions,
    fn?: (pipeline: RAGPipeline) => T
  ): RAGPipeline | T {
    const tracer = this.getTracer();
    const attributes: Record<string, string | number | boolean> = {
      [RAGAttributes.PIPELINE_NAME]: options.pipelineName,
    };
    if (options.query) {
      attributes[RAGAttributes.QUERY] = options.query;
    }

    if (fn) {
      return tracer.startActiveSpan(
        `rag.pipeline ${options.pipelineName}`,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const pipeline = new RAGPipeline(
            otelSpan,
            tracer,
            options.pipelineName
          );
          try {
            const result = fn(pipeline);
            if (result instanceof Promise) {
              return (result as Promise<unknown>)
                .then((val) => {
                  pipeline.end();
                  return val;
                })
                .catch((err) => {
                  pipeline.endWithError(err);
                  throw err;
                }) as T;
            }
            pipeline.end();
            return result;
          } catch (err) {
            pipeline.endWithError(err as Error);
            throw err;
          }
        }
      );
    }

    const otelSpan = tracer.startSpan(
      `rag.pipeline ${options.pipelineName}`,
      { kind: SpanKind.INTERNAL, attributes }
    );
    return new RAGPipeline(otelSpan, tracer, options.pipelineName);
  }

  /**
   * Trace a vector retrieval operation.
   */
  traceRetrieve(options: TraceRetrieveOptions): RetrievalSpan;
  traceRetrieve<T>(
    options: TraceRetrieveOptions,
    fn: (retrieval: RetrievalSpan) => T
  ): T;
  traceRetrieve<T>(
    options: TraceRetrieveOptions,
    fn?: (retrieval: RetrievalSpan) => T
  ): RetrievalSpan | T {
    const tracer = this.getTracer();
    const attributes: Record<string, string | number | boolean> = {
      [RAGAttributes.PIPELINE_STAGE]: RAGAttributes.Stage.RETRIEVE,
      [RAGAttributes.RETRIEVE_DATABASE]: options.database,
      [RAGAttributes.RETRIEVE_TOP_K]: options.topK ?? 10,
    };
    if (options.index) {
      attributes[RAGAttributes.RETRIEVE_INDEX] = options.index;
    }
    if (options.query) {
      attributes[RAGAttributes.QUERY] = options.query;
    }
    if (options.embeddingModel) {
      attributes[RAGAttributes.QUERY_EMBEDDING_MODEL] =
        options.embeddingModel;
    }
    if (options.filterExpr) {
      attributes[RAGAttributes.RETRIEVE_FILTER] = options.filterExpr;
    }

    if (fn) {
      return tracer.startActiveSpan(
        `rag.retrieve ${options.database}`,
        { kind: SpanKind.CLIENT, attributes },
        (otelSpan) => {
          const retrieval = new RetrievalSpan(otelSpan);
          try {
            const result = fn(retrieval);
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
      `rag.retrieve ${options.database}`,
      { kind: SpanKind.CLIENT, attributes }
    );
    return new RetrievalSpan(otelSpan);
  }

  /**
   * Trace a reranking operation.
   */
  traceRerank(options: TraceRerankOptions): RerankSpan;
  traceRerank<T>(
    options: TraceRerankOptions,
    fn: (rerank: RerankSpan) => T
  ): T;
  traceRerank<T>(
    options: TraceRerankOptions,
    fn?: (rerank: RerankSpan) => T
  ): RerankSpan | T {
    const tracer = this.getTracer();
    const attributes: Record<string, string | number | boolean> = {
      [RAGAttributes.PIPELINE_STAGE]: RAGAttributes.Stage.RERANK,
      [RAGAttributes.RERANK_MODEL]: options.model,
    };
    if (options.inputCount !== undefined) {
      attributes[RAGAttributes.RERANK_INPUT_COUNT] = options.inputCount;
    }

    if (fn) {
      return tracer.startActiveSpan(
        `rag.rerank ${options.model}`,
        { kind: SpanKind.INTERNAL, attributes },
        (otelSpan) => {
          const rerank = new RerankSpan(otelSpan);
          try {
            const result = fn(rerank);
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
      `rag.rerank ${options.model}`,
      { kind: SpanKind.INTERNAL, attributes }
    );
    return new RerankSpan(otelSpan);
  }
}
