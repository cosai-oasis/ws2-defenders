/**
 * AITF MCP (Model Context Protocol) Instrumentation.
 *
 * Provides tracing for MCP server connections, tool discovery and invocation,
 * resource access, prompt management, and sampling operations.
 */

import {
  trace,
  Span,
  SpanKind,
  SpanStatusCode,
  Tracer,
  TracerProvider,
} from "@opentelemetry/api";
import { MCPAttributes } from "../semantic-conventions/attributes";

const TRACER_NAME = "instrumentation.mcp";

/** Options for tracing an MCP server connection. */
export interface TraceServerConnectOptions {
  serverName: string;
  transport?: string;
  serverVersion?: string;
  serverUrl?: string;
  protocolVersion?: string;
}

/** Options for tracing an MCP tool invocation. */
export interface TraceToolInvokeOptions {
  toolName: string;
  serverName: string;
  toolInput?: string;
  approvalRequired?: boolean;
}

/** Options for tracing an MCP resource read. */
export interface TraceResourceReadOptions {
  resourceUri: string;
  serverName: string;
  resourceName?: string;
  mimeType?: string;
}

/** Options for tracing an MCP prompt get. */
export interface TracePromptGetOptions {
  promptName: string;
  serverName: string;
  arguments?: string;
}

/**
 * Helper for MCP tool discovery results.
 */
export class MCPToolDiscovery {
  private readonly _span: Span;

  constructor(span: Span) {
    this._span = span;
  }

  setTools(toolNames: string[]): void {
    this._span.setAttribute(MCPAttributes.TOOL_COUNT, toolNames.length);
    this._span.setAttribute(MCPAttributes.TOOL_NAMES, toolNames);
  }
}

/**
 * Helper for managing MCP server connection spans.
 */
export class MCPServerConnection {
  private readonly _span: Span;
  private readonly _tracer: Tracer;
  private readonly _serverName: string;

  constructor(span: Span, tracer: Tracer, serverName: string) {
    this._span = span;
    this._tracer = tracer;
    this._serverName = serverName;
  }

  get span(): Span {
    return this._span;
  }

  /** Record server capabilities event. */
  setCapabilities(options: {
    tools?: boolean;
    resources?: boolean;
    prompts?: boolean;
    sampling?: boolean;
    roots?: boolean;
  }): void {
    this._span.addEvent("mcp.server.capabilities", {
      "mcp.capabilities.tools": options.tools ?? false,
      "mcp.capabilities.resources": options.resources ?? false,
      "mcp.capabilities.prompts": options.prompts ?? false,
      "mcp.capabilities.sampling": options.sampling ?? false,
      "mcp.capabilities.roots": options.roots ?? false,
    });
  }

  /** Trace tool discovery on this server. */
  discoverTools<T>(fn: (discovery: MCPToolDiscovery) => T): T {
    return this._tracer.startActiveSpan(
      `mcp.tool.discover ${this._serverName}`,
      {
        kind: SpanKind.CLIENT,
        attributes: { [MCPAttributes.SERVER_NAME]: this._serverName },
      },
      (otelSpan) => {
        const discovery = new MCPToolDiscovery(otelSpan);
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

  /** End the connection span with OK status. */
  end(): void {
    this._span.setStatus({ code: SpanStatusCode.OK });
    this._span.end();
  }

  /** End the connection span with an error. */
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
 * Helper for MCP tool invocation spans.
 */
export class MCPToolInvocation {
  private readonly _span: Span;
  private readonly _startTime: number;
  private _errorSet = false;

  constructor(span: Span, startTime: number) {
    this._span = span;
    this._startTime = startTime;
  }

  get span(): Span {
    return this._span;
  }

  setOutput(output: string, outputType: string = "text"): void {
    this._span.setAttribute(MCPAttributes.TOOL_OUTPUT, output);
    this._span.addEvent("mcp.tool.output", {
      "mcp.tool.output.content": output,
      "mcp.tool.output.type": outputType,
    });
  }

  setError(error: string): void {
    this._span.setAttribute(MCPAttributes.TOOL_IS_ERROR, true);
    this._errorSet = true;
    this._span.addEvent("mcp.tool.error", {
      "mcp.tool.error.message": error,
    });
  }

  setApproved(approved: boolean, approver?: string): void {
    this._span.setAttribute(MCPAttributes.TOOL_APPROVED, approved);
    const attrs: Record<string, string> = {
      "mcp.tool.approval.status": approved ? "approved" : "denied",
    };
    if (approver) {
      attrs["mcp.tool.approval.approver"] = approver;
    }
    this._span.addEvent("mcp.tool.approval", attrs);
  }

  /** End the invocation span with success, recording duration. */
  end(): void {
    const durationMs = performance.now() - this._startTime;
    this._span.setAttribute(MCPAttributes.TOOL_DURATION_MS, durationMs);
    if (!this._errorSet) {
      this._span.setAttribute(MCPAttributes.TOOL_IS_ERROR, false);
    }
    this._span.setStatus({ code: SpanStatusCode.OK });
    this._span.end();
  }

  /** End the invocation span with an error, recording duration. */
  endWithError(err: Error): void {
    const durationMs = performance.now() - this._startTime;
    this._span.setAttribute(MCPAttributes.TOOL_DURATION_MS, durationMs);
    this._span.setAttribute(MCPAttributes.TOOL_IS_ERROR, true);
    this._span.setStatus({
      code: SpanStatusCode.ERROR,
      message: String(err),
    });
    this._span.recordException(err);
    this._span.end();
  }
}

/**
 * Instrumentor for MCP protocol operations.
 */
export class MCPInstrumentor {
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
   * Trace an MCP server connection lifecycle.
   */
  traceServerConnect(
    options: TraceServerConnectOptions
  ): MCPServerConnection;
  traceServerConnect<T>(
    options: TraceServerConnectOptions,
    fn: (conn: MCPServerConnection) => T
  ): T;
  traceServerConnect<T>(
    options: TraceServerConnectOptions,
    fn?: (conn: MCPServerConnection) => T
  ): MCPServerConnection | T {
    const tracer = this.getTracer();
    const attributes: Record<string, string | number | boolean> = {
      [MCPAttributes.SERVER_NAME]: options.serverName,
      [MCPAttributes.SERVER_TRANSPORT]: options.transport ?? "stdio",
      [MCPAttributes.PROTOCOL_VERSION]:
        options.protocolVersion ?? "2025-03-26",
    };
    if (options.serverVersion) {
      attributes[MCPAttributes.SERVER_VERSION] = options.serverVersion;
    }
    if (options.serverUrl) {
      attributes[MCPAttributes.SERVER_URL] = options.serverUrl;
    }

    if (fn) {
      return tracer.startActiveSpan(
        `mcp.server.connect ${options.serverName}`,
        { kind: SpanKind.CLIENT, attributes },
        (otelSpan) => {
          const conn = new MCPServerConnection(
            otelSpan,
            tracer,
            options.serverName
          );
          try {
            const result = fn(conn);
            if (result instanceof Promise) {
              return (result as Promise<unknown>)
                .then((val) => {
                  conn.end();
                  return val;
                })
                .catch((err) => {
                  conn.endWithError(err);
                  throw err;
                }) as T;
            }
            conn.end();
            return result;
          } catch (err) {
            conn.endWithError(err as Error);
            throw err;
          }
        }
      );
    }

    const otelSpan = tracer.startSpan(
      `mcp.server.connect ${options.serverName}`,
      { kind: SpanKind.CLIENT, attributes }
    );
    return new MCPServerConnection(otelSpan, tracer, options.serverName);
  }

  /**
   * Trace an MCP tool invocation.
   */
  traceToolInvoke(
    options: TraceToolInvokeOptions
  ): MCPToolInvocation;
  traceToolInvoke<T>(
    options: TraceToolInvokeOptions,
    fn: (invocation: MCPToolInvocation) => T
  ): T;
  traceToolInvoke<T>(
    options: TraceToolInvokeOptions,
    fn?: (invocation: MCPToolInvocation) => T
  ): MCPToolInvocation | T {
    const tracer = this.getTracer();
    const startTime = performance.now();
    const attributes: Record<string, string | number | boolean> = {
      [MCPAttributes.TOOL_NAME]: options.toolName,
      [MCPAttributes.TOOL_SERVER]: options.serverName,
    };
    if (options.toolInput !== undefined) {
      attributes[MCPAttributes.TOOL_INPUT] = options.toolInput;
    }
    if (options.approvalRequired) {
      attributes[MCPAttributes.TOOL_APPROVAL_REQUIRED] = true;
    }

    if (fn) {
      return tracer.startActiveSpan(
        `mcp.tool.invoke ${options.toolName}`,
        { kind: SpanKind.CLIENT, attributes },
        (otelSpan) => {
          const invocation = new MCPToolInvocation(otelSpan, startTime);
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
      `mcp.tool.invoke ${options.toolName}`,
      { kind: SpanKind.CLIENT, attributes }
    );
    return new MCPToolInvocation(otelSpan, startTime);
  }

  /**
   * Trace an MCP resource read operation.
   */
  traceResourceRead<T>(
    options: TraceResourceReadOptions,
    fn: (span: Span) => T
  ): T {
    const tracer = this.getTracer();
    const attributes: Record<string, string | number | boolean> = {
      [MCPAttributes.RESOURCE_URI]: options.resourceUri,
      [MCPAttributes.SERVER_NAME]: options.serverName,
    };
    if (options.resourceName) {
      attributes[MCPAttributes.RESOURCE_NAME] = options.resourceName;
    }
    if (options.mimeType) {
      attributes[MCPAttributes.RESOURCE_MIME_TYPE] = options.mimeType;
    }

    return tracer.startActiveSpan(
      `mcp.resource.read ${options.resourceUri}`,
      { kind: SpanKind.CLIENT, attributes },
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
   * Trace an MCP prompt retrieval.
   */
  tracePromptGet<T>(
    options: TracePromptGetOptions,
    fn: (span: Span) => T
  ): T {
    const tracer = this.getTracer();
    const attributes: Record<string, string | number | boolean> = {
      [MCPAttributes.PROMPT_NAME]: options.promptName,
      [MCPAttributes.SERVER_NAME]: options.serverName,
    };
    if (options.arguments) {
      attributes[MCPAttributes.PROMPT_ARGUMENTS] = options.arguments;
    }

    return tracer.startActiveSpan(
      `mcp.prompt.get ${options.promptName}`,
      { kind: SpanKind.CLIENT, attributes },
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
