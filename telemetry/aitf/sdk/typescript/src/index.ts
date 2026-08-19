/**
 * AITF - AI Telemetry Framework.
 *
 * A comprehensive, security-first telemetry framework for AI systems
 * built on OpenTelemetry and OCSF. AITF supports dual-pipeline export:
 * spans flow simultaneously to OTel backends (via OTLP) and SIEM/XDR
 * (via OCSF), giving you observability and security from the same
 * instrumentation.
 */

export const VERSION = "1.0.0";

// Semantic Conventions
export {
  GenAIAttributes,
  AgentAttributes,
  MCPAttributes,
  SkillAttributes,
  RAGAttributes,
  SecurityAttributes,
  ComplianceAttributes,
  CostAttributes,
  QualityAttributes,
  SupplyChainAttributes,
  MemoryAttributes,
  LatencyAttributes,
  ModelOpsAttributes,
  IdentityAttributes,
  AssetInventoryAttributes,
  DriftDetectionAttributes,
  MemorySecurityAttributes,
  AgenticLogAttributes,
} from "./semantic-conventions/attributes";

export { AITFMetrics } from "./semantic-conventions/metrics";

// Instrumentation
export {
  LLMInstrumentor,
  InferenceSpan,
  type TraceInferenceOptions,
} from "./instrumentation/llm";

export {
  AgentInstrumentor,
  AgentSession,
  AgentStep,
  type TraceSessionOptions,
  type TraceTeamOptions,
} from "./instrumentation/agent";

export {
  MCPInstrumentor,
  MCPServerConnection,
  MCPToolInvocation,
  MCPToolDiscovery,
  type TraceServerConnectOptions,
  type TraceToolInvokeOptions,
  type TraceResourceReadOptions,
  type TracePromptGetOptions,
} from "./instrumentation/mcp";

export {
  RAGInstrumentor,
  RAGPipeline,
  RetrievalSpan,
  RerankSpan,
  type TracePipelineOptions,
  type TraceRetrieveOptions,
  type TraceRerankOptions,
} from "./instrumentation/rag";

export {
  SkillInstrumentor,
  SkillInvocation,
  SkillDiscovery,
  SkillComposition,
  type TraceInvokeOptions,
  type TraceDiscoverOptions,
} from "./instrumentation/skills";

export {
  ModelOpsInstrumentor,
  TrainingRun,
  EvaluationRun,
  DeploymentOperation,
  CacheLookup,
  MonitoringCheck,
  PromptOperation,
  type TraceTrainingOptions,
  type TraceEvaluationOptions,
  type TraceRegistryOptions,
  type TraceDeploymentOptions,
  type TraceRouteOptions,
  type TraceFallbackOptions,
  type TraceCacheLookupOptions,
  type TraceMonitoringCheckOptions,
  type TracePromptOptions,
} from "./instrumentation/model-ops";

export {
  DriftDetectionInstrumentor,
  DriftDetection,
  DriftBaseline,
  DriftInvestigation,
  DriftRemediation,
  type TraceDetectOptions,
  type TraceBaselineOptions,
  type TraceInvestigateOptions,
  type TraceRemediateOptions,
} from "./instrumentation/drift-detection";

export {
  IdentityInstrumentor,
  IdentityLifecycle,
  AuthenticationAttempt,
  AuthorizationCheck,
  DelegationOperation as IdentityDelegationOperation,
  TrustOperation,
  IdentitySession,
  type TraceLifecycleOptions,
  type TraceAuthenticationOptions,
  type TraceAuthorizationOptions,
  type TraceDelegationOptions,
  type TraceTrustOptions,
  type TraceSessionOptions as TraceIdentitySessionOptions,
} from "./instrumentation/identity";

export {
  AssetInventoryInstrumentor,
  AssetRegistration,
  AssetDiscovery,
  AssetAudit,
  AssetClassification,
  type TraceRegisterOptions,
  type TraceDiscoverOptions as TraceAssetDiscoverOptions,
  type TraceAuditOptions,
  type TraceClassifyOptions,
  type TraceDecommissionOptions,
} from "./instrumentation/asset-inventory";

export {
  AgenticLogInstrumentor,
  AgenticLogEntry,
  type AgenticLogOptions,
} from "./instrumentation/agentic-log";

// Processors
export {
  SecurityProcessor,
  type SecurityFinding,
  type SecurityProcessorOptions,
} from "./processors/security-processor";

export {
  PIIProcessor,
  type PIIDetection,
  type PIIProcessorOptions,
} from "./processors/pii-processor";

export {
  ComplianceProcessor,
  COMPLIANCE_MAPPINGS,
  type ComplianceMapping,
  type ComplianceProcessorOptions,
} from "./processors/compliance-processor";

export {
  CostProcessor,
  MODEL_PRICING,
  type CostResult,
  type CostProcessorOptions,
} from "./processors/cost-processor";

export {
  MemoryStateProcessor,
  type MemorySnapshot,
  type MemorySecurityEvent,
  type MemoryStateProcessorOptions,
  type SessionStats,
} from "./processors/memory-state-processor";

// OCSF Schema
export {
  OCSFSeverity,
  OCSFStatus,
  OCSFActivity,
  AIClassUID,
  createMetadata,
  createTokenUsage,
  createBaseEvent,
  stripNulls,
  type OCSFMetadata,
  type OCSFActor,
  type OCSFDevice,
  type OCSFEnrichment,
  type OCSFObservable,
  type AIModelInfo,
  type AITokenUsage,
  type AILatencyMetrics,
  type AICostInfo,
  type AITeamInfo,
  type AISecurityFinding,
  type ComplianceMetadata,
  type AIBaseEvent,
} from "./ocsf/schema";

// OCSF Event Classes
export {
  type AIModelInferenceEvent,
  type AIAgentActivityEvent,
  type AIToolExecutionEvent,
  type AIDataRetrievalEvent,
  type AISecurityFindingEvent,
  type AISupplyChainEvent,
  type AIGovernanceEvent,
  type AIIdentityEvent,
  type AIModelOpsEvent,
  type AIAssetInventoryEvent,
  createModelInferenceEvent,
  createAgentActivityEvent,
  createToolExecutionEvent,
  createDataRetrievalEvent,
  createSecurityFindingEvent,
  createSupplyChainEvent,
  createGovernanceEvent,
  createIdentityEvent,
  createModelOpsEvent,
  createAssetInventoryEvent,
} from "./ocsf/event-classes";

// OCSF Mappers
export { OCSFMapper } from "./ocsf/mapper";

export {
  ComplianceMapper,
  FRAMEWORK_MAPPINGS,
} from "./ocsf/compliance-mapper";

// Exporters
export {
  OCSFExporter,
  type OCSFExporterOptions,
} from "./exporters/ocsf-exporter";

// Pipeline (Dual OTel + OCSF export)
export {
  DualPipelineProvider,
  createDualPipelineProvider,
  createOTelOnlyProvider,
  createOCSFOnlyProvider,
  type DualPipelineOptions,
} from "./pipeline";
