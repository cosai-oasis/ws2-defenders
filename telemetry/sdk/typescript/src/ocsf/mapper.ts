/**
 * AITF OCSF Mapper.
 *
 * Maps OpenTelemetry spans to OCSF Category 7 AI events.
 * Based on the OCSF mapper from the AITelemetry project, enhanced
 * for AITF with MCP, Skills, and extended agent support.
 */

import { ReadableSpan } from "@opentelemetry/sdk-trace-base";
import {
  AIModelInferenceEvent,
  AIAgentActivityEvent,
  AIToolExecutionEvent,
  AIDataRetrievalEvent,
  AISecurityFindingEvent,
  createModelInferenceEvent,
  createAgentActivityEvent,
  createToolExecutionEvent,
  createDataRetrievalEvent,
  createSecurityFindingEvent,
} from "./event-classes";
import {
  AIBaseEvent,
  AICostInfo,
  AILatencyMetrics,
  AIModelInfo,
  AISecurityFinding,
  AITokenUsage,
  OCSFSeverity,
  createTokenUsage,
} from "./schema";
import {
  AgentAttributes,
  CostAttributes,
  GenAIAttributes,
  LatencyAttributes,
  MCPAttributes,
  RAGAttributes,
  SecurityAttributes,
  SkillAttributes,
} from "../semantic-conventions/attributes";

type SpanAttributes = Record<string, unknown>;

/**
 * Maps OTel spans to OCSF Category 7 AI events.
 *
 * Usage:
 *   const mapper = new OCSFMapper();
 *   const ocsfEvent = mapper.mapSpan(span);
 *   if (ocsfEvent) {
 *     exportToSIEM(ocsfEvent);
 *   }
 */
export class OCSFMapper {
  /**
   * Map an OTel span to an OCSF event.
   * Returns the appropriate OCSF event class or null if the span
   * is not an AI-related span.
   */
  mapSpan(span: ReadableSpan): AIBaseEvent | null {
    const name = span.name ?? "";
    const attrs = { ...(span.attributes ?? {}) } as SpanAttributes;

    if (this._isInferenceSpan(name, attrs)) {
      return this._mapInference(span, attrs);
    } else if (this._isAgentSpan(name, attrs)) {
      return this._mapAgentActivity(span, attrs);
    } else if (this._isToolSpan(name, attrs)) {
      return this._mapToolExecution(span, attrs);
    } else if (this._isRagSpan(name, attrs)) {
      return this._mapDataRetrieval(span, attrs);
    } else if (this._isSecuritySpan(name, attrs)) {
      return this._mapSecurityFinding(span, attrs);
    }

    return null;
  }

  private _isInferenceSpan(name: string, attrs: SpanAttributes): boolean {
    return (
      name.startsWith("chat ") ||
      name.startsWith("embeddings ") ||
      name.startsWith("text_completion ") ||
      GenAIAttributes.SYSTEM in attrs
    );
  }

  private _isAgentSpan(name: string, attrs: SpanAttributes): boolean {
    return name.startsWith("agent.") || AgentAttributes.NAME in attrs;
  }

  private _isToolSpan(name: string, attrs: SpanAttributes): boolean {
    return (
      name.startsWith("mcp.tool.") ||
      name.startsWith("skill.invoke") ||
      MCPAttributes.TOOL_NAME in attrs ||
      SkillAttributes.NAME in attrs
    );
  }

  private _isRagSpan(name: string, attrs: SpanAttributes): boolean {
    return (
      name.startsWith("rag.") ||
      RAGAttributes.RETRIEVE_DATABASE in attrs
    );
  }

  private _isSecuritySpan(name: string, attrs: SpanAttributes): boolean {
    return SecurityAttributes.THREAT_DETECTED in attrs;
  }

  private _mapInference(
    span: ReadableSpan,
    attrs: SpanAttributes
  ): AIModelInferenceEvent {
    const modelId = String(attrs[GenAIAttributes.REQUEST_MODEL] ?? "unknown");
    const system = String(attrs[GenAIAttributes.SYSTEM] ?? "unknown");
    const operation = String(
      attrs[GenAIAttributes.OPERATION_NAME] ?? "chat"
    );

    const activityMap: Record<string, number> = {
      chat: 1,
      text_completion: 2,
      embeddings: 3,
    };
    const activityId = activityMap[operation] ?? 99;

    // Build parameters from request attributes
    const parameters: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(attrs)) {
      if (
        k.startsWith("gen_ai.request.") &&
        k !== GenAIAttributes.REQUEST_MODEL
      ) {
        parameters[k.replace("gen_ai.request.", "")] = v;
      }
    }

    const model: AIModelInfo = {
      model_id: modelId,
      name: modelId,
      provider: system,
      type: operation !== "embeddings" ? "llm" : "embedding",
      parameters:
        Object.keys(parameters).length > 0 ? parameters : undefined,
    };

    const tokenUsage = createTokenUsage({
      input_tokens: Number(attrs[GenAIAttributes.USAGE_INPUT_TOKENS] ?? 0),
      output_tokens: Number(attrs[GenAIAttributes.USAGE_OUTPUT_TOKENS] ?? 0),
      cached_tokens: Number(attrs[GenAIAttributes.USAGE_CACHED_TOKENS] ?? 0),
      reasoning_tokens: Number(
        attrs[GenAIAttributes.USAGE_REASONING_TOKENS] ?? 0
      ),
    });

    let latency: AILatencyMetrics | undefined;
    if (LatencyAttributes.TOTAL_MS in attrs) {
      latency = {
        total_ms: Number(attrs[LatencyAttributes.TOTAL_MS] ?? 0),
        time_to_first_token_ms: optFloat(
          attrs[LatencyAttributes.TIME_TO_FIRST_TOKEN_MS]
        ),
        tokens_per_second: optFloat(
          attrs[LatencyAttributes.TOKENS_PER_SECOND]
        ),
      };
    }

    let cost: AICostInfo | undefined;
    if (CostAttributes.TOTAL_COST in attrs) {
      cost = {
        input_cost_usd: Number(attrs[CostAttributes.INPUT_COST] ?? 0),
        output_cost_usd: Number(attrs[CostAttributes.OUTPUT_COST] ?? 0),
        total_cost_usd: Number(attrs[CostAttributes.TOTAL_COST] ?? 0),
        currency: "USD",
      };
    }

    const finishReasons = attrs[GenAIAttributes.RESPONSE_FINISH_REASONS];
    let finishReason = "stop";
    if (Array.isArray(finishReasons) && finishReasons.length > 0) {
      finishReason = String(finishReasons[0]);
    } else if (finishReasons) {
      finishReason = String(finishReasons);
    }

    return createModelInferenceEvent({
      model,
      tokenUsage,
      latency,
      cost,
      finishReason,
      streaming: Boolean(attrs[GenAIAttributes.REQUEST_STREAM] ?? false),
      activityId,
      message: `${operation} ${modelId}`,
      time: spanTime(span),
    });
  }

  private _mapAgentActivity(
    span: ReadableSpan,
    attrs: SpanAttributes
  ): AIAgentActivityEvent {
    const name = span.name ?? "";
    const agentName = String(attrs[AgentAttributes.NAME] ?? "unknown");
    const agentId = String(attrs[AgentAttributes.ID] ?? "unknown");
    const sessionId = String(attrs[AgentAttributes.SESSION_ID] ?? "unknown");

    let activityId: number;
    if (name.includes("session")) {
      activityId = 1; // Session Start
    } else if (name.includes("delegation") || name.includes("delegate")) {
      activityId = 4; // Delegation
    } else if (name.includes("memory")) {
      activityId = 5; // Memory Access
    } else {
      activityId = 3; // Step Execute
    }

    return createAgentActivityEvent({
      agentName,
      agentId,
      agentType: String(attrs[AgentAttributes.TYPE] ?? "autonomous"),
      framework: optStr(attrs[AgentAttributes.FRAMEWORK]),
      sessionId,
      stepType: optStr(attrs[AgentAttributes.STEP_TYPE]),
      stepIndex: optInt(attrs[AgentAttributes.STEP_INDEX]),
      thought: optStr(attrs[AgentAttributes.STEP_THOUGHT]),
      action: optStr(attrs[AgentAttributes.STEP_ACTION]),
      observation: optStr(attrs[AgentAttributes.STEP_OBSERVATION]),
      delegationTarget: optStr(
        attrs[AgentAttributes.DELEGATION_TARGET_AGENT]
      ),
      activityId,
      message: name,
      time: spanTime(span),
    });
  }

  private _mapToolExecution(
    span: ReadableSpan,
    attrs: SpanAttributes
  ): AIToolExecutionEvent {
    let toolName: string;
    let toolType: string;
    let activityId: number;

    if (MCPAttributes.TOOL_NAME in attrs) {
      toolName = String(attrs[MCPAttributes.TOOL_NAME]);
      toolType = "mcp_tool";
      activityId = 2; // MCP Tool Invoke
    } else if (SkillAttributes.NAME in attrs) {
      toolName = String(attrs[SkillAttributes.NAME]);
      toolType = "skill";
      activityId = 3; // Skill Invoke
    } else {
      toolName = String(attrs["gen_ai.tool.name"] ?? "unknown");
      toolType = "function";
      activityId = 1; // Function Call
    }

    return createToolExecutionEvent({
      toolName,
      toolType,
      toolInput: optStr(
        attrs[MCPAttributes.TOOL_INPUT] ?? attrs[SkillAttributes.INPUT]
      ),
      toolOutput: optStr(
        attrs[MCPAttributes.TOOL_OUTPUT] ?? attrs[SkillAttributes.OUTPUT]
      ),
      isError: Boolean(attrs[MCPAttributes.TOOL_IS_ERROR] ?? false),
      durationMs: optFloat(
        attrs[MCPAttributes.TOOL_DURATION_MS] ??
          attrs[SkillAttributes.DURATION_MS]
      ),
      mcpServer: optStr(attrs[MCPAttributes.TOOL_SERVER]),
      mcpTransport: optStr(attrs[MCPAttributes.SERVER_TRANSPORT]),
      skillCategory: optStr(attrs[SkillAttributes.CATEGORY]),
      skillVersion: optStr(attrs[SkillAttributes.VERSION]),
      approvalRequired: Boolean(
        attrs[MCPAttributes.TOOL_APPROVAL_REQUIRED] ?? false
      ),
      approved: optBool(attrs[MCPAttributes.TOOL_APPROVED]),
      activityId,
      message: span.name ?? `tool.execute ${toolName}`,
      time: spanTime(span),
    });
  }

  private _mapDataRetrieval(
    span: ReadableSpan,
    attrs: SpanAttributes
  ): AIDataRetrievalEvent {
    const database = String(
      attrs[RAGAttributes.RETRIEVE_DATABASE] ?? "unknown"
    );
    const stage = String(
      attrs[RAGAttributes.PIPELINE_STAGE] ?? "retrieve"
    );

    const activityMap: Record<string, number> = {
      retrieve: 1,
      rerank: 5,
      generate: 99,
      evaluate: 99,
    };
    const activityId = activityMap[stage] ?? 99;

    return createDataRetrievalEvent({
      databaseName: database,
      databaseType: database,
      query: optStr(attrs[RAGAttributes.QUERY]),
      topK: optInt(attrs[RAGAttributes.RETRIEVE_TOP_K]),
      resultsCount: Number(
        attrs[RAGAttributes.RETRIEVE_RESULTS_COUNT] ?? 0
      ),
      minScore: optFloat(attrs[RAGAttributes.RETRIEVE_MIN_SCORE]),
      maxScore: optFloat(attrs[RAGAttributes.RETRIEVE_MAX_SCORE]),
      filter: optStr(attrs[RAGAttributes.RETRIEVE_FILTER]),
      embeddingModel: optStr(attrs[RAGAttributes.QUERY_EMBEDDING_MODEL]),
      pipelineName: optStr(attrs[RAGAttributes.PIPELINE_NAME]),
      pipelineStage: stage,
      activityId,
      message: span.name ?? `rag.${stage} ${database}`,
      time: spanTime(span),
    });
  }

  private _mapSecurityFinding(
    span: ReadableSpan,
    attrs: SpanAttributes
  ): AISecurityFindingEvent {
    const riskLevel = String(
      attrs[SecurityAttributes.RISK_LEVEL] ?? "medium"
    );

    const finding: AISecurityFinding = {
      finding_type: String(
        attrs[SecurityAttributes.THREAT_TYPE] ?? "unknown"
      ),
      owasp_category: optStr(attrs[SecurityAttributes.OWASP_CATEGORY]),
      risk_level: riskLevel,
      risk_score: Number(attrs[SecurityAttributes.RISK_SCORE] ?? 50.0),
      confidence: Number(attrs[SecurityAttributes.CONFIDENCE] ?? 0.5),
      detection_method: String(
        attrs[SecurityAttributes.DETECTION_METHOD] ?? "pattern"
      ),
      blocked: Boolean(attrs[SecurityAttributes.BLOCKED] ?? false),
      pii_types: [],
      matched_patterns: [],
    };

    const severityMap: Record<string, OCSFSeverity> = {
      critical: OCSFSeverity.CRITICAL,
      high: OCSFSeverity.HIGH,
      medium: OCSFSeverity.MEDIUM,
      low: OCSFSeverity.LOW,
      info: OCSFSeverity.INFORMATIONAL,
    };

    return createSecurityFindingEvent({
      finding,
      severityId: severityMap[riskLevel] ?? OCSFSeverity.MEDIUM,
      activityId: 1, // Threat Detection
      message: span.name ?? `security.${finding.finding_type}`,
      time: spanTime(span),
    });
  }
}

// --- Utility Functions ---

function spanTime(span: ReadableSpan): string {
  if (span.startTime) {
    const [seconds, nanoseconds] = span.startTime;
    const ms = seconds * 1000 + nanoseconds / 1_000_000;
    return new Date(ms).toISOString();
  }
  return new Date().toISOString();
}

function optStr(val: unknown): string | undefined {
  return val !== undefined && val !== null ? String(val) : undefined;
}

function optInt(val: unknown): number | undefined {
  return val !== undefined && val !== null ? Number(val) : undefined;
}

function optFloat(val: unknown): number | undefined {
  return val !== undefined && val !== null ? Number(val) : undefined;
}

function optBool(val: unknown): boolean | undefined {
  return val !== undefined && val !== null ? Boolean(val) : undefined;
}
