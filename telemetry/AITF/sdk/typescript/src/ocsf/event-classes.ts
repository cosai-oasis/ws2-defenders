/**
 * AITF OCSF AI Event Classes.
 *
 * AITF AI events reuse existing OCSF classes (OCSF PR #1641 / issue #1640)
 * rather than a bespoke Category 7. Each factory sets both `category_uid` and
 * `class_uid` to the reused OCSF class; AI specifics ride on the
 * `ai_operation` profile.
 * Based on event classes from the AITelemetry project, extended
 * for AITF with MCP, Skills, ModelOps, Asset Inventory, and enhanced agent support.
 */

import {
  AIBaseEvent,
  AICostInfo,
  AILatencyMetrics,
  AIModelInfo,
  AISecurityFinding,
  AITeamInfo,
  AITokenUsage,
  OCSFAgentMessage,
  OCSFCategoryUID,
  OCSFClassUID,
  createBaseEvent,
  createTokenUsage,
} from "./schema";

/** AI model inference — reuses OCSF API Activity (6003). */
export interface AIModelInferenceEvent extends AIBaseEvent {
  model: AIModelInfo;
  token_usage: AITokenUsage;
  latency?: AILatencyMetrics;
  request_content?: string;
  response_content?: string;
  streaming: boolean;
  tools_provided: number;
  finish_reason: string;
  cost?: AICostInfo;
  error?: Record<string, unknown>;
}

/** Agent lifecycle — new OCSF `agent_activity` in the ai category (9). */
export interface AIAgentActivityEvent extends AIBaseEvent {
  agent_name: string;
  agent_id: string;
  agent_type: string;
  framework?: string;
  session_id: string;
  step_type?: string;
  step_index?: number;
  thought?: string;
  action?: string;
  observation?: string;
  delegation_target?: string;
  team_info?: AITeamInfo;
}

/**
 * Agent-to-agent communication (A2A / ACP / ANP / MCP).
 *
 * A single generic event for inter-agent messaging across protocols, in the
 * proposed OCSF `ai` category. The wire protocol is a discriminator on the
 * `agent_message` object rather than a dedicated class per protocol.
 */
export interface AIAgentCommunicationEvent extends AIBaseEvent {
  agent_message: OCSFAgentMessage;
}

/** Tool/MCP/function execution — reuses OCSF API Activity (6003). */
export interface AIToolExecutionEvent extends AIBaseEvent {
  tool_name: string;
  tool_type: string; // "function", "mcp_tool", "skill", "api"
  tool_input?: string;
  tool_output?: string;
  is_error: boolean;
  duration_ms?: number;
  mcp_server?: string;
  mcp_transport?: string;
  skill_category?: string;
  skill_version?: string;
  approval_required: boolean;
  approved?: boolean;
}

/** RAG / vector search — reuses OCSF Datastore Activity (6005). */
export interface AIDataRetrievalEvent extends AIBaseEvent {
  database_name: string;
  database_type: string;
  query?: string;
  top_k?: number;
  results_count: number;
  min_score?: number;
  max_score?: number;
  filter?: string;
  embedding_model?: string;
  embedding_dimensions?: number;
  pipeline_name?: string;
  pipeline_stage?: string;
  quality_scores?: Record<string, number>;
}

/** AI security finding — reuses OCSF Detection Finding (2004). */
export interface AISecurityFindingEvent extends AIBaseEvent {
  finding: AISecurityFinding;
}

/** AI supply chain — reuses OCSF Vulnerability Finding (2002). */
export interface AISupplyChainEvent extends AIBaseEvent {
  model_source: string;
  model_hash?: string;
  model_license?: string;
  model_signed: boolean;
  model_signer?: string;
  verification_result?: string; // "pass", "fail", "unknown"
  ai_bom_id?: string;
  ai_bom_components?: string; // JSON
}

/** AI governance/compliance — reuses OCSF Compliance Finding (2003). */
export interface AIGovernanceEvent extends AIBaseEvent {
  frameworks: string[];
  controls?: string; // JSON
  event_type: string;
  violation_detected: boolean;
  violation_severity?: string;
  remediation?: string;
  audit_id?: string;
}

/** Agent identity/auth — reuses OCSF Authentication (3002, IAM). */
export interface AIIdentityEvent extends AIBaseEvent {
  agent_name: string;
  agent_id: string;
  auth_method: string; // "api_key", "oauth", "mtls", "jwt"
  auth_result: string; // "success", "failure", "denied"
  permissions: string[];
  credential_type?: string;
  delegation_chain: string[];
  scope?: string;
}

/** Model lifecycle ops — reuses OCSF Application Lifecycle (6002). */
export interface AIModelOpsEvent extends AIBaseEvent {
  operation_type: string; // "training", "evaluation", "deployment", "serving", "monitoring", "prompt"
  model_id?: string;
  run_id?: string;
  framework?: string;
  status?: string;
  training_type?: string;
  base_model?: string;
  dataset_id?: string;
  epochs?: number;
  loss_final?: number;
  output_model_id?: string;
  evaluation_type?: string;
  metrics?: string; // JSON
  passed?: boolean;
  deployment_id?: string;
  strategy?: string;
  environment?: string;
  endpoint?: string;
  selected_model?: string;
  fallback_chain?: string; // JSON
  cache_hit?: boolean;
  check_type?: string;
  drift_score?: number;
  drift_type?: string;
  action_triggered?: string;
}

/** AI asset inventory — reuses OCSF Inventory Info (5001, Discovery). */
export interface AIAssetInventoryEvent extends AIBaseEvent {
  operation_type: string; // "register", "discover", "audit", "classify", "decommission"
  asset_id?: string;
  asset_name?: string;
  asset_type?: string;
  asset_version?: string;
  owner?: string;
  deployment_environment?: string;
  risk_classification?: string;
  discovery_scope?: string;
  discovery_method?: string;
  assets_found?: number;
  new_assets?: number;
  shadow_assets?: number;
  audit_type?: string;
  audit_result?: string;
  audit_framework?: string;
  audit_findings?: string; // JSON
  classification_framework?: string;
  previous_classification?: string;
  classification_reason?: string;
}

// --- Validation Helpers ---

/**
 * Valid OCSF (class_uid -> category_uid) pairs that AITF reuses.
 *
 * AITF reuses existing OCSF classes (OCSF PR #1641 / issue #1640); each class
 * lives under its own OCSF category, so class_uid is no longer unique per AITF
 * event type (inference and tool execution both reuse API Activity 6003).
 */
const VALID_CLASS_CATEGORY: ReadonlyMap<number, number> = new Map([
  [OCSFClassUID.API_ACTIVITY, OCSFCategoryUID.APPLICATION],
  [OCSFClassUID.DATASTORE_ACTIVITY, OCSFCategoryUID.APPLICATION],
  [OCSFClassUID.APPLICATION_LIFECYCLE, OCSFCategoryUID.APPLICATION],
  [OCSFClassUID.DETECTION_FINDING, OCSFCategoryUID.FINDINGS],
  [OCSFClassUID.VULNERABILITY_FINDING, OCSFCategoryUID.FINDINGS],
  [OCSFClassUID.COMPLIANCE_FINDING, OCSFCategoryUID.FINDINGS],
  [OCSFClassUID.AUTHENTICATION, OCSFCategoryUID.IAM],
  [OCSFClassUID.INVENTORY_INFO, OCSFCategoryUID.DISCOVERY],
  [OCSFClassUID.AGENT_ACTIVITY, OCSFCategoryUID.AI],
  [OCSFClassUID.DELEGATION_ACTIVITY, OCSFCategoryUID.AI],
  [OCSFClassUID.AGENT_COMMUNICATION, OCSFCategoryUID.AI],
]);

/**
 * Validate that the class_uid and category_uid form a known reused OCSF pair.
 * Called internally by factory functions after creating the base event.
 */
function validateBaseFields(event: AIBaseEvent, factoryName: string): void {
  const expectedCategory = VALID_CLASS_CATEGORY.get(event.class_uid);
  if (expectedCategory === undefined) {
    throw new Error(
      `${factoryName}: invalid class_uid ${event.class_uid}. ` +
        `Expected one of: ${[...VALID_CLASS_CATEGORY.keys()].join(", ")}`
    );
  }
  if (event.category_uid !== expectedCategory) {
    throw new Error(
      `${factoryName}: invalid category_uid ${event.category_uid} for ` +
        `class_uid ${event.class_uid}. Expected ${expectedCategory}.`
    );
  }
}

/**
 * Validate that a required string field is present and non-empty.
 */
function requireString(
  value: unknown,
  fieldName: string,
  factoryName: string
): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(
      `${factoryName}: required field '${fieldName}' must be a non-empty string.`
    );
  }
}

// --- Factory Functions ---

/** Create a Model Inference event. */
export function createModelInferenceEvent(
  options: {
    model: AIModelInfo;
    tokenUsage?: Partial<AITokenUsage>;
    latency?: AILatencyMetrics;
    cost?: AICostInfo;
    streaming?: boolean;
    toolsProvided?: number;
    finishReason?: string;
    requestContent?: string;
    responseContent?: string;
    activityId?: number;
    message?: string;
    time?: string;
  }
): AIModelInferenceEvent {
  if (!options.model || typeof options.model.model_id !== "string" || options.model.model_id.length === 0) {
    throw new Error("createModelInferenceEvent: required field 'model.model_id' must be a non-empty string.");
  }
  const base = createBaseEvent(OCSFClassUID.API_ACTIVITY, {
    category_uid: OCSFCategoryUID.APPLICATION,
    activity_id: options.activityId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createModelInferenceEvent");

  return {
    ...base,
    model: options.model,
    token_usage: createTokenUsage(options.tokenUsage),
    latency: options.latency,
    request_content: options.requestContent,
    response_content: options.responseContent,
    streaming: options.streaming ?? false,
    tools_provided: options.toolsProvided ?? 0,
    finish_reason: options.finishReason ?? "stop",
    cost: options.cost,
  };
}

/** Create an Agent Activity event. */
export function createAgentActivityEvent(
  options: {
    agentName: string;
    agentId: string;
    sessionId: string;
    agentType?: string;
    framework?: string;
    stepType?: string;
    stepIndex?: number;
    thought?: string;
    action?: string;
    observation?: string;
    delegationTarget?: string;
    teamInfo?: AITeamInfo;
    activityId?: number;
    message?: string;
    time?: string;
  }
): AIAgentActivityEvent {
  requireString(options.agentName, "agentName", "createAgentActivityEvent");
  requireString(options.agentId, "agentId", "createAgentActivityEvent");
  requireString(options.sessionId, "sessionId", "createAgentActivityEvent");
  const base = createBaseEvent(OCSFClassUID.AGENT_ACTIVITY, {
    category_uid: OCSFCategoryUID.AI,
    activity_id: options.activityId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createAgentActivityEvent");

  return {
    ...base,
    agent_name: options.agentName,
    agent_id: options.agentId,
    agent_type: options.agentType ?? "autonomous",
    framework: options.framework,
    session_id: options.sessionId,
    step_type: options.stepType,
    step_index: options.stepIndex,
    thought: options.thought,
    action: options.action,
    observation: options.observation,
    delegation_target: options.delegationTarget,
    team_info: options.teamInfo,
  };
}

/** Create an Agent Communication event. */
export function createAgentCommunicationEvent(
  options: {
    agentMessage: OCSFAgentMessage;
    activityId?: number;
    statusId?: number;
    message?: string;
    time?: string;
  }
): AIAgentCommunicationEvent {
  if (!options.agentMessage || typeof options.agentMessage !== "object") {
    throw new Error(
      "createAgentCommunicationEvent: required field 'agentMessage' must be a valid OCSFAgentMessage object."
    );
  }
  const base = createBaseEvent(OCSFClassUID.AGENT_COMMUNICATION, {
    category_uid: OCSFCategoryUID.AI,
    activity_id: options.activityId,
    status_id: options.statusId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createAgentCommunicationEvent");

  return {
    ...base,
    agent_message: options.agentMessage,
  };
}

/** Create a Tool Execution event. */
export function createToolExecutionEvent(
  options: {
    toolName: string;
    toolType: string;
    toolInput?: string;
    toolOutput?: string;
    isError?: boolean;
    durationMs?: number;
    mcpServer?: string;
    mcpTransport?: string;
    skillCategory?: string;
    skillVersion?: string;
    approvalRequired?: boolean;
    approved?: boolean;
    activityId?: number;
    message?: string;
    time?: string;
  }
): AIToolExecutionEvent {
  requireString(options.toolName, "toolName", "createToolExecutionEvent");
  requireString(options.toolType, "toolType", "createToolExecutionEvent");
  const base = createBaseEvent(OCSFClassUID.API_ACTIVITY, {
    category_uid: OCSFCategoryUID.APPLICATION,
    activity_id: options.activityId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createToolExecutionEvent");

  return {
    ...base,
    tool_name: options.toolName,
    tool_type: options.toolType,
    tool_input: options.toolInput,
    tool_output: options.toolOutput,
    is_error: options.isError ?? false,
    duration_ms: options.durationMs,
    mcp_server: options.mcpServer,
    mcp_transport: options.mcpTransport,
    skill_category: options.skillCategory,
    skill_version: options.skillVersion,
    approval_required: options.approvalRequired ?? false,
    approved: options.approved,
  };
}

/** Create a Data Retrieval event. */
export function createDataRetrievalEvent(
  options: {
    databaseName: string;
    databaseType: string;
    query?: string;
    topK?: number;
    resultsCount?: number;
    minScore?: number;
    maxScore?: number;
    filter?: string;
    embeddingModel?: string;
    embeddingDimensions?: number;
    pipelineName?: string;
    pipelineStage?: string;
    qualityScores?: Record<string, number>;
    activityId?: number;
    message?: string;
    time?: string;
  }
): AIDataRetrievalEvent {
  requireString(options.databaseName, "databaseName", "createDataRetrievalEvent");
  requireString(options.databaseType, "databaseType", "createDataRetrievalEvent");
  const base = createBaseEvent(OCSFClassUID.DATASTORE_ACTIVITY, {
    category_uid: OCSFCategoryUID.APPLICATION,
    activity_id: options.activityId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createDataRetrievalEvent");

  return {
    ...base,
    database_name: options.databaseName,
    database_type: options.databaseType,
    query: options.query,
    top_k: options.topK,
    results_count: options.resultsCount ?? 0,
    min_score: options.minScore,
    max_score: options.maxScore,
    filter: options.filter,
    embedding_model: options.embeddingModel,
    embedding_dimensions: options.embeddingDimensions,
    pipeline_name: options.pipelineName,
    pipeline_stage: options.pipelineStage,
    quality_scores: options.qualityScores,
  };
}

/** Create a Security Finding event. */
export function createSecurityFindingEvent(
  options: {
    finding: AISecurityFinding;
    severityId?: number;
    activityId?: number;
    message?: string;
    time?: string;
  }
): AISecurityFindingEvent {
  if (!options.finding || typeof options.finding !== "object") {
    throw new Error("createSecurityFindingEvent: required field 'finding' must be a valid AISecurityFinding object.");
  }
  requireString(options.finding.finding_type, "finding.finding_type", "createSecurityFindingEvent");
  requireString(options.finding.risk_level, "finding.risk_level", "createSecurityFindingEvent");
  const base = createBaseEvent(OCSFClassUID.DETECTION_FINDING, {
    category_uid: OCSFCategoryUID.FINDINGS,
    activity_id: options.activityId ?? 1,
    severity_id: options.severityId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createSecurityFindingEvent");

  return {
    ...base,
    finding: options.finding,
  };
}

/** Create a Supply Chain event. */
export function createSupplyChainEvent(
  options: {
    modelSource: string;
    modelHash?: string;
    modelLicense?: string;
    modelSigned?: boolean;
    modelSigner?: string;
    verificationResult?: string;
    aiBomId?: string;
    aiBomComponents?: string;
    activityId?: number;
    message?: string;
    time?: string;
  }
): AISupplyChainEvent {
  requireString(options.modelSource, "modelSource", "createSupplyChainEvent");
  const base = createBaseEvent(OCSFClassUID.VULNERABILITY_FINDING, {
    category_uid: OCSFCategoryUID.FINDINGS,
    activity_id: options.activityId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createSupplyChainEvent");

  return {
    ...base,
    model_source: options.modelSource,
    model_hash: options.modelHash,
    model_license: options.modelLicense,
    model_signed: options.modelSigned ?? false,
    model_signer: options.modelSigner,
    verification_result: options.verificationResult,
    ai_bom_id: options.aiBomId,
    ai_bom_components: options.aiBomComponents,
  };
}

/** Create a Governance event. */
export function createGovernanceEvent(
  options: {
    frameworks?: string[];
    controls?: string;
    eventType?: string;
    violationDetected?: boolean;
    violationSeverity?: string;
    remediation?: string;
    auditId?: string;
    activityId?: number;
    message?: string;
    time?: string;
  }
): AIGovernanceEvent {
  const base = createBaseEvent(OCSFClassUID.COMPLIANCE_FINDING, {
    category_uid: OCSFCategoryUID.FINDINGS,
    activity_id: options.activityId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createGovernanceEvent");

  return {
    ...base,
    frameworks: options.frameworks ?? [],
    controls: options.controls,
    event_type: options.eventType ?? "",
    violation_detected: options.violationDetected ?? false,
    violation_severity: options.violationSeverity,
    remediation: options.remediation,
    audit_id: options.auditId,
  };
}

/** Create an Identity event. */
export function createIdentityEvent(
  options: {
    agentName: string;
    agentId: string;
    authMethod: string;
    authResult: string;
    permissions?: string[];
    credentialType?: string;
    delegationChain?: string[];
    scope?: string;
    activityId?: number;
    message?: string;
    time?: string;
  }
): AIIdentityEvent {
  requireString(options.agentName, "agentName", "createIdentityEvent");
  requireString(options.agentId, "agentId", "createIdentityEvent");
  requireString(options.authMethod, "authMethod", "createIdentityEvent");
  requireString(options.authResult, "authResult", "createIdentityEvent");
  const base = createBaseEvent(OCSFClassUID.AUTHENTICATION, {
    category_uid: OCSFCategoryUID.IAM,
    activity_id: options.activityId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createIdentityEvent");

  return {
    ...base,
    agent_name: options.agentName,
    agent_id: options.agentId,
    auth_method: options.authMethod,
    auth_result: options.authResult,
    permissions: options.permissions ?? [],
    credential_type: options.credentialType,
    delegation_chain: options.delegationChain ?? [],
    scope: options.scope,
  };
}

/** Create a Model Operations event. */
export function createModelOpsEvent(
  options: {
    operationType: string;
    modelId?: string;
    runId?: string;
    framework?: string;
    status?: string;
    trainingType?: string;
    baseModel?: string;
    datasetId?: string;
    epochs?: number;
    lossFinal?: number;
    outputModelId?: string;
    evaluationType?: string;
    metrics?: string;
    passed?: boolean;
    deploymentId?: string;
    strategy?: string;
    environment?: string;
    endpoint?: string;
    selectedModel?: string;
    fallbackChain?: string;
    cacheHit?: boolean;
    checkType?: string;
    driftScore?: number;
    driftType?: string;
    actionTriggered?: string;
    activityId?: number;
    message?: string;
    time?: string;
  }
): AIModelOpsEvent {
  requireString(options.operationType, "operationType", "createModelOpsEvent");
  const base = createBaseEvent(OCSFClassUID.APPLICATION_LIFECYCLE, {
    category_uid: OCSFCategoryUID.APPLICATION,
    activity_id: options.activityId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createModelOpsEvent");

  return {
    ...base,
    operation_type: options.operationType,
    model_id: options.modelId,
    run_id: options.runId,
    framework: options.framework,
    status: options.status,
    training_type: options.trainingType,
    base_model: options.baseModel,
    dataset_id: options.datasetId,
    epochs: options.epochs,
    loss_final: options.lossFinal,
    output_model_id: options.outputModelId,
    evaluation_type: options.evaluationType,
    metrics: options.metrics,
    passed: options.passed,
    deployment_id: options.deploymentId,
    strategy: options.strategy,
    environment: options.environment,
    endpoint: options.endpoint,
    selected_model: options.selectedModel,
    fallback_chain: options.fallbackChain,
    cache_hit: options.cacheHit,
    check_type: options.checkType,
    drift_score: options.driftScore,
    drift_type: options.driftType,
    action_triggered: options.actionTriggered,
  };
}

/** Create an Asset Inventory event. */
export function createAssetInventoryEvent(
  options: {
    operationType: string;
    assetId?: string;
    assetName?: string;
    assetType?: string;
    assetVersion?: string;
    owner?: string;
    deploymentEnvironment?: string;
    riskClassification?: string;
    discoveryScope?: string;
    discoveryMethod?: string;
    assetsFound?: number;
    newAssets?: number;
    shadowAssets?: number;
    auditType?: string;
    auditResult?: string;
    auditFramework?: string;
    auditFindings?: string;
    classificationFramework?: string;
    previousClassification?: string;
    classificationReason?: string;
    activityId?: number;
    message?: string;
    time?: string;
  }
): AIAssetInventoryEvent {
  requireString(options.operationType, "operationType", "createAssetInventoryEvent");
  const base = createBaseEvent(OCSFClassUID.INVENTORY_INFO, {
    category_uid: OCSFCategoryUID.DISCOVERY,
    activity_id: options.activityId,
    message: options.message,
    time: options.time,
  });
  validateBaseFields(base, "createAssetInventoryEvent");

  return {
    ...base,
    operation_type: options.operationType,
    asset_id: options.assetId,
    asset_name: options.assetName,
    asset_type: options.assetType,
    asset_version: options.assetVersion,
    owner: options.owner,
    deployment_environment: options.deploymentEnvironment,
    risk_classification: options.riskClassification,
    discovery_scope: options.discoveryScope,
    discovery_method: options.discoveryMethod,
    assets_found: options.assetsFound,
    new_assets: options.newAssets,
    shadow_assets: options.shadowAssets,
    audit_type: options.auditType,
    audit_result: options.auditResult,
    audit_framework: options.auditFramework,
    audit_findings: options.auditFindings,
    classification_framework: options.classificationFramework,
    previous_classification: options.previousClassification,
    classification_reason: options.classificationReason,
  };
}
