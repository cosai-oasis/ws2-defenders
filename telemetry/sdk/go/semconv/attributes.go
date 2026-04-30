// Package semconv provides AITF semantic convention constants for Go.
//
// All attribute keys used across AITF instrumentation, processors, and exporters.
// OTel GenAI attributes (gen_ai.*) are preserved for compatibility.
// AITF extensions use the aitf.* namespace.
package semconv

import "go.opentelemetry.io/otel/attribute"

// --- OTel GenAI Attributes (Preserved) ---

const (
	GenAISystemKey        = attribute.Key("gen_ai.provider.name")
	GenAIOperationNameKey = attribute.Key("gen_ai.operation.name")

	// Request
	GenAIRequestModelKey            = attribute.Key("gen_ai.request.model")
	GenAIRequestMaxTokensKey        = attribute.Key("gen_ai.request.max_tokens")
	GenAIRequestTemperatureKey      = attribute.Key("gen_ai.request.temperature")
	GenAIRequestTopPKey             = attribute.Key("gen_ai.request.top_p")
	GenAIRequestTopKKey             = attribute.Key("gen_ai.request.top_k")
	GenAIRequestStreamKey           = attribute.Key("gen_ai.request.stream")
	GenAIRequestToolsKey            = attribute.Key("gen_ai.request.tools")
	GenAIRequestToolChoiceKey       = attribute.Key("gen_ai.request.tool_choice")
	GenAIRequestResponseFormatKey   = attribute.Key("gen_ai.request.response_format")
	GenAIRequestFrequencyPenaltyKey = attribute.Key("gen_ai.request.frequency_penalty")
	GenAIRequestPresencePenaltyKey  = attribute.Key("gen_ai.request.presence_penalty")
	GenAIRequestSeedKey             = attribute.Key("gen_ai.request.seed")

	// Response
	GenAIResponseIDKey            = attribute.Key("gen_ai.response.id")
	GenAIResponseModelKey         = attribute.Key("gen_ai.response.model")
	GenAIResponseFinishReasonsKey = attribute.Key("gen_ai.response.finish_reasons")

	// Usage
	GenAIUsageInputTokensKey     = attribute.Key("gen_ai.usage.input_tokens")
	GenAIUsageOutputTokensKey    = attribute.Key("gen_ai.usage.output_tokens")
	GenAIUsageCachedTokensKey    = attribute.Key("gen_ai.usage.cached_tokens")
	GenAIUsageReasoningTokensKey = attribute.Key("gen_ai.usage.reasoning_tokens")

	// System prompt hash (CoSAI WS2: AI_INTERACTION)
	GenAISystemPromptHashKey = attribute.Key("gen_ai.system_prompt.hash")

	// Events
	GenAIPromptKey        = attribute.Key("gen_ai.prompt")
	GenAICompletionKey    = attribute.Key("gen_ai.completion")
	GenAIToolNameKey      = attribute.Key("gen_ai.tool.name")
	GenAIToolCallIDKey    = attribute.Key("gen_ai.tool.call_id")
	GenAIToolArgumentsKey = attribute.Key("gen_ai.tool.arguments")
	GenAIToolResultKey    = attribute.Key("gen_ai.tool.result")
)

// GenAI system values.
const (
	GenAISystemOpenAI    = "openai"
	GenAISystemAnthropic = "anthropic"
	GenAISystemBedrock   = "bedrock"
	GenAISystemAzure     = "azure"
	GenAISystemGCPVertex = "gcp_vertex"
	GenAISystemCohere    = "cohere"
	GenAISystemMistral   = "mistral"
	GenAISystemMeta      = "meta"
	GenAISystemGoogle    = "google"
)

// GenAI operation values.
const (
	GenAIOperationChat           = "chat"
	GenAIOperationTextCompletion = "text_completion"
	GenAIOperationEmbeddings     = "embeddings"
	GenAIOperationImageGen       = "image_generation"
	GenAIOperationAudio          = "audio"
)

// --- AITF Agent Attributes ---

const (
	AgentNameKey        = attribute.Key("gen_ai.agent.name")
	AgentIDKey          = attribute.Key("gen_ai.agent.id")
	AgentTypeKey        = attribute.Key("agent.type")
	AgentFrameworkKey   = attribute.Key("agent.framework")
	AgentVersionKey     = attribute.Key("agent.version")
	AgentDescriptionKey = attribute.Key("gen_ai.agent.description")

	AgentSessionIDKey        = attribute.Key("gen_ai.conversation.id")
	AgentSessionTurnCountKey = attribute.Key("agent.session.turn_count")

	// CoSAI WS2: AGENT_TRACE fields
	AgentWorkflowIDKey = attribute.Key("agent.workflow_id")
	AgentStateKey      = attribute.Key("agent.state")
	AgentScratchpadKey = attribute.Key("agent.scratchpad")
	AgentNextActionKey = attribute.Key("agent.next_action")

	AgentStepTypeKey        = attribute.Key("agent.step.type")
	AgentStepIndexKey       = attribute.Key("agent.step.index")
	AgentStepThoughtKey     = attribute.Key("agent.step.thought")
	AgentStepActionKey      = attribute.Key("agent.step.action")
	AgentStepObservationKey = attribute.Key("agent.step.observation")
	AgentStepStatusKey      = attribute.Key("agent.step.status")

	AgentDelegationTargetAgentKey   = attribute.Key("agent.delegation.target_agent")
	AgentDelegationTargetAgentIDKey = attribute.Key("agent.delegation.target_agent_id")
	AgentDelegationReasonKey        = attribute.Key("agent.delegation.reason")
	AgentDelegationStrategyKey      = attribute.Key("agent.delegation.strategy")
	AgentDelegationTaskKey          = attribute.Key("agent.delegation.task")

	AgentTeamNameKey            = attribute.Key("agent.team.name")
	AgentTeamIDKey              = attribute.Key("agent.team.id")
	AgentTeamTopologyKey        = attribute.Key("agent.team.topology")
	AgentTeamCoordinatorKey     = attribute.Key("agent.team.coordinator")
	AgentTeamConsensusMethodKey = attribute.Key("agent.team.consensus_method")
)

// Agent type values.
const (
	AgentTypeConversational = "conversational"
	AgentTypeAutonomous     = "autonomous"
	AgentTypeReactive       = "reactive"
	AgentTypeProactive      = "proactive"
)

// Agent framework values.
const (
	AgentFrameworkLangChain      = "langchain"
	AgentFrameworkLangGraph      = "langgraph"
	AgentFrameworkCrewAI         = "crewai"
	AgentFrameworkAutoGen        = "autogen"
	AgentFrameworkSemanticKernel = "semantic_kernel"
	AgentFrameworkCustom         = "custom"
)

// Agent step type values.
const (
	AgentStepPlanning      = "planning"
	AgentStepReasoning     = "reasoning"
	AgentStepToolUse       = "tool_use"
	AgentStepDelegation    = "delegation"
	AgentStepResponse      = "response"
	AgentStepReflection    = "reflection"
	AgentStepMemoryAccess  = "memory_access"
	AgentStepGuardrail     = "guardrail_check"
	AgentStepHumanInLoop   = "human_in_loop"
	AgentStepErrorRecovery = "error_recovery"
)

// Agent team topology values.
const (
	TeamTopologyHierarchical = "hierarchical"
	TeamTopologyPeer         = "peer"
	TeamTopologyPipeline     = "pipeline"
	TeamTopologyConsensus    = "consensus"
	TeamTopologyDebate       = "debate"
	TeamTopologySwarm        = "swarm"
)

// --- AITF MCP Attributes ---

const (
	MCPServerNameKey      = attribute.Key("mcp.server.name")
	MCPServerVersionKey   = attribute.Key("mcp.server.version")
	MCPServerTransportKey = attribute.Key("mcp.server.transport")
	MCPServerURLKey       = attribute.Key("mcp.server.url")
	MCPProtocolVersionKey = attribute.Key("mcp.protocol.version")

	MCPToolNameKey             = attribute.Key("gen_ai.tool.name")
	MCPToolServerKey           = attribute.Key("mcp.tool.server")
	MCPToolInputKey            = attribute.Key("gen_ai.tool.call.arguments")
	MCPToolOutputKey           = attribute.Key("gen_ai.tool.call.result")
	MCPToolIsErrorKey          = attribute.Key("mcp.tool.is_error")
	MCPToolDurationMsKey       = attribute.Key("mcp.tool.duration_ms")
	MCPToolApprovalRequiredKey = attribute.Key("mcp.tool.approval_required")
	MCPToolApprovedKey         = attribute.Key("mcp.tool.approved")
	MCPToolCountKey            = attribute.Key("mcp.tool.count")

	// CoSAI WS2: MCP_ACTIVITY fields
	MCPToolResponseErrorKey = attribute.Key("mcp.tool.response_error")
	MCPConnectionIDKey      = attribute.Key("mcp.connection.id")

	MCPResourceURIKey      = attribute.Key("mcp.resource.uri")
	MCPResourceNameKey     = attribute.Key("mcp.resource.name")
	MCPResourceMimeTypeKey = attribute.Key("mcp.resource.mime_type")
	MCPResourceSizeBytesKey = attribute.Key("mcp.resource.size_bytes")

	MCPPromptNameKey      = attribute.Key("mcp.prompt.name")
	MCPPromptArgumentsKey = attribute.Key("mcp.prompt.arguments")

	MCPSamplingModelKey          = attribute.Key("mcp.sampling.model")
	MCPSamplingMaxTokensKey      = attribute.Key("mcp.sampling.max_tokens")
	MCPSamplingIncludeContextKey = attribute.Key("mcp.sampling.include_context")
)

// MCP transport values.
const (
	MCPTransportStdio          = "stdio"
	MCPTransportSSE            = "sse"
	MCPTransportStreamableHTTP = "streamable_http"
)

// --- AITF Skill Attributes ---

const (
	SkillNameKey        = attribute.Key("skill.name")
	SkillIDKey          = attribute.Key("skill.id")
	SkillVersionKey     = attribute.Key("skill.version")
	SkillProviderKey    = attribute.Key("skill.provider")
	SkillCategoryKey    = attribute.Key("skill.category")
	SkillDescriptionKey = attribute.Key("skill.description")
	SkillInputKey       = attribute.Key("skill.input")
	SkillOutputKey      = attribute.Key("skill.output")
	SkillStatusKey      = attribute.Key("skill.status")
	SkillDurationMsKey  = attribute.Key("skill.duration_ms")
	SkillRetryCountKey  = attribute.Key("skill.retry_count")
	SkillSourceKey      = attribute.Key("skill.source")
	SkillHashKey        = attribute.Key("skill.hash")
	SkillAuthorsKey     = attribute.Key("skill.authors")
	SkillCountKey       = attribute.Key("skill.count")

	SkillComposeNameKey    = attribute.Key("skill.compose.name")
	SkillComposePatternKey = attribute.Key("skill.compose.pattern")
	SkillComposeTotalKey   = attribute.Key("skill.compose.total_skills")
)

// Skill status values.
const (
	SkillStatusSuccess = "success"
	SkillStatusError   = "error"
	SkillStatusTimeout = "timeout"
	SkillStatusDenied  = "denied"
	SkillStatusRetry   = "retry"
)

// Skill category values.
const (
	SkillCategorySearch        = "search"
	SkillCategoryCode          = "code"
	SkillCategoryData          = "data"
	SkillCategoryCommunication = "communication"
	SkillCategoryAnalysis      = "analysis"
	SkillCategoryGeneration    = "generation"
	SkillCategoryKnowledge     = "knowledge"
	SkillCategorySecurity      = "security"
	SkillCategoryIntegration   = "integration"
	SkillCategoryWorkflow      = "workflow"
)

// --- AITF RAG Attributes ---

const (
	RAGPipelineNameKey  = attribute.Key("rag.pipeline.name")
	RAGPipelineStageKey = attribute.Key("rag.pipeline.stage")
	RAGQueryKey         = attribute.Key("rag.query")

	RAGRetrieveDatabaseKey     = attribute.Key("gen_ai.data_source.id")
	RAGRetrieveIndexKey        = attribute.Key("rag.retrieve.index")
	RAGRetrieveTopKKey         = attribute.Key("rag.retrieve.top_k")
	RAGRetrieveResultsCountKey = attribute.Key("rag.retrieve.results_count")
	RAGRetrieveMinScoreKey     = attribute.Key("rag.retrieve.min_score")
	RAGRetrieveMaxScoreKey     = attribute.Key("rag.retrieve.max_score")
	RAGRetrieveFilterKey       = attribute.Key("rag.retrieve.filter")

	// CoSAI WS2: RAG_CONTEXT document-level fields
	RAGDocIDKey         = attribute.Key("rag.doc.id")
	RAGDocScoreKey      = attribute.Key("rag.doc.score")
	RAGDocProvenanceKey = attribute.Key("rag.doc.provenance")
	RAGRetrievalDocsKey = attribute.Key("rag.retrieval.docs")

	RAGRerankModelKey       = attribute.Key("rag.rerank.model")
	RAGRerankInputCountKey  = attribute.Key("rag.rerank.input_count")
	RAGRerankOutputCountKey = attribute.Key("rag.rerank.output_count")

	RAGQualityContextRelevanceKey = attribute.Key("rag.quality.context_relevance")
	RAGQualityFaithfulnessKey     = attribute.Key("rag.quality.faithfulness")
	RAGQualityGroundednessKey     = attribute.Key("rag.quality.groundedness")
)

// RAG stage values.
const (
	RAGStageRetrieve = "retrieve"
	RAGStageRerank   = "rerank"
	RAGStageGenerate = "generate"
	RAGStageEvaluate = "evaluate"
)

// --- AITF Security Attributes ---

const (
	SecurityRiskScoreKey       = attribute.Key("security.risk_score")
	SecurityRiskLevelKey       = attribute.Key("security.risk_level")
	SecurityThreatDetectedKey  = attribute.Key("security.threat_detected")
	SecurityThreatTypeKey      = attribute.Key("security.threat_type")
	SecurityOWASPCategoryKey   = attribute.Key("security.owasp_category")
	SecurityBlockedKey         = attribute.Key("security.blocked")
	SecurityDetectionMethodKey = attribute.Key("security.detection_method")
	SecurityConfidenceKey      = attribute.Key("security.confidence")

	SecurityGuardrailNameKey     = attribute.Key("security.guardrail.name")
	SecurityGuardrailTypeKey     = attribute.Key("security.guardrail.type")
	SecurityGuardrailResultKey   = attribute.Key("security.guardrail.result")
	SecurityGuardrailProviderKey = attribute.Key("security.guardrail.provider")

	SecurityPIIDetectedKey = attribute.Key("security.pii.detected")
	SecurityPIICountKey    = attribute.Key("security.pii.count")
	SecurityPIIActionKey   = attribute.Key("security.pii.action")
)

// OWASP LLM Top 10 categories.
const (
	OWASPLICM01 = "LLM01" // Prompt Injection
	OWASPLICM02 = "LLM02" // Sensitive Information Disclosure
	OWASPLICM03 = "LLM03" // Supply Chain
	OWASPLICM04 = "LLM04" // Data and Model Poisoning
	OWASPLICM05 = "LLM05" // Improper Output Handling
	OWASPLICM06 = "LLM06" // Excessive Agency
	OWASPLICM07 = "LLM07" // System Prompt Leakage
	OWASPLICM08 = "LLM08" // Vector and Embedding Weaknesses
	OWASPLICM09 = "LLM09" // Misinformation
	OWASPLICM10 = "LLM10" // Unbounded Consumption
)

// Security risk level values.
const (
	RiskLevelCritical = "critical"
	RiskLevelHigh     = "high"
	RiskLevelMedium   = "medium"
	RiskLevelLow      = "low"
	RiskLevelInfo     = "info"
)

// Threat type values.
const (
	ThreatTypePromptInjection = "prompt_injection"
	ThreatTypeJailbreak       = "jailbreak"
	ThreatTypeDataExfil       = "data_exfiltration"
	ThreatTypeSystemPromptLeak = "system_prompt_leak"
	ThreatTypeModelTheft      = "model_theft"
)

// --- AITF Cost Attributes ---

const (
	CostInputCostKey  = attribute.Key("cost.input_cost")
	CostOutputCostKey = attribute.Key("cost.output_cost")
	CostTotalCostKey  = attribute.Key("cost.total_cost")
	CostCurrencyKey   = attribute.Key("cost.currency")

	CostPricingInputPer1MKey  = attribute.Key("cost.model_pricing.input_per_1m")
	CostPricingOutputPer1MKey = attribute.Key("cost.model_pricing.output_per_1m")

	CostBudgetLimitKey     = attribute.Key("cost.budget.limit")
	CostBudgetUsedKey      = attribute.Key("cost.budget.used")
	CostBudgetRemainingKey = attribute.Key("cost.budget.remaining")

	CostAttributionUserKey    = attribute.Key("cost.attribution.user")
	CostAttributionTeamKey    = attribute.Key("cost.attribution.team")
	CostAttributionProjectKey = attribute.Key("cost.attribution.project")
)

// --- AITF Compliance Attributes ---

const (
	ComplianceNISTControlsKey  = attribute.Key("compliance.nist_ai_rmf.controls")
	ComplianceMITRETechniquesKey = attribute.Key("compliance.mitre_atlas.techniques")
	ComplianceISOControlsKey   = attribute.Key("compliance.iso_42001.controls")
	ComplianceEUArticlesKey    = attribute.Key("compliance.eu_ai_act.articles")
	ComplianceSOC2ControlsKey  = attribute.Key("compliance.soc2.controls")
	ComplianceGDPRArticlesKey  = attribute.Key("compliance.gdpr.articles")
	ComplianceCCPASectionsKey  = attribute.Key("compliance.ccpa.sections")
	ComplianceCSAAICMControlsKey = attribute.Key("compliance.csa_aicm.controls")
)

// --- AITF Latency Attributes ---

const (
	LatencyTotalMsKey            = attribute.Key("latency.total_ms")
	LatencyTimeToFirstTokenMsKey = attribute.Key("latency.time_to_first_token_ms")
	LatencyTokensPerSecondKey    = attribute.Key("latency.tokens_per_second")
	LatencyQueueTimeMsKey        = attribute.Key("latency.queue_time_ms")
	LatencyInferenceTimeMsKey    = attribute.Key("latency.inference_time_ms")
)

// --- AITF Memory Attributes ---

const (
	MemoryOperationKey  = attribute.Key("memory.operation")
	MemoryStoreKey      = attribute.Key("memory.store")
	MemoryKeyKey        = attribute.Key("memory.key")
	MemoryTTLSecondsKey = attribute.Key("memory.ttl_seconds")
	MemoryHitKey        = attribute.Key("memory.hit")
	MemoryProvenanceKey = attribute.Key("memory.provenance")
)

// --- AITF Quality Attributes ---

const (
	QualityHallucinationScoreKey = attribute.Key("quality.hallucination_score")
	QualityConfidenceKey         = attribute.Key("quality.confidence")
	QualityFactualityKey         = attribute.Key("quality.factuality")
	QualityToxicityScoreKey      = attribute.Key("quality.toxicity_score")
	QualityFeedbackRatingKey     = attribute.Key("quality.feedback.rating")
	QualityFeedbackThumbsKey     = attribute.Key("quality.feedback.thumbs")
)

// --- AITF Model Operations Attributes ---

const (
	// Training attributes
	ModelOpsTrainingRunIDKey          = attribute.Key("model_ops.training.run_id")
	ModelOpsTrainingTypeKey           = attribute.Key("model_ops.training.type")
	ModelOpsTrainingBaseModelKey      = attribute.Key("model_ops.training.base_model")
	ModelOpsTrainingFrameworkKey      = attribute.Key("model_ops.training.framework")
	ModelOpsTrainingDatasetIDKey      = attribute.Key("model_ops.training.dataset.id")
	ModelOpsTrainingDatasetVersionKey = attribute.Key("model_ops.training.dataset.version")
	ModelOpsTrainingDatasetSizeKey    = attribute.Key("model_ops.training.dataset.size")
	ModelOpsTrainingHyperparamsKey    = attribute.Key("model_ops.training.hyperparameters")
	ModelOpsTrainingEpochsKey         = attribute.Key("model_ops.training.epochs")
	ModelOpsTrainingLossFinalKey      = attribute.Key("model_ops.training.loss_final")
	ModelOpsTrainingValLossFinalKey   = attribute.Key("model_ops.training.val_loss_final")
	ModelOpsTrainingGPUTypeKey        = attribute.Key("model_ops.training.compute.gpu_type")
	ModelOpsTrainingGPUCountKey       = attribute.Key("model_ops.training.compute.gpu_count")
	ModelOpsTrainingGPUHoursKey       = attribute.Key("model_ops.training.compute.gpu_hours")
	ModelOpsTrainingOutputModelIDKey  = attribute.Key("model_ops.training.output_model.id")
	ModelOpsTrainingOutputModelHashKey = attribute.Key("model_ops.training.output_model.hash")
	ModelOpsTrainingCodeCommitKey     = attribute.Key("model_ops.training.code_commit")
	ModelOpsTrainingExperimentIDKey   = attribute.Key("model_ops.training.experiment.id")
	ModelOpsTrainingExperimentNameKey = attribute.Key("model_ops.training.experiment.name")
	ModelOpsTrainingStatusKey         = attribute.Key("model_ops.training.status")

	// Evaluation attributes
	ModelOpsEvalRunIDKey              = attribute.Key("model_ops.evaluation.run_id")
	ModelOpsEvalModelIDKey            = attribute.Key("model_ops.evaluation.model_id")
	ModelOpsEvalTypeKey               = attribute.Key("model_ops.evaluation.type")
	ModelOpsEvalDatasetIDKey          = attribute.Key("model_ops.evaluation.dataset.id")
	ModelOpsEvalDatasetSizeKey        = attribute.Key("model_ops.evaluation.dataset.size")
	ModelOpsEvalMetricsKey            = attribute.Key("model_ops.evaluation.metrics")
	ModelOpsEvalJudgeModelKey         = attribute.Key("model_ops.evaluation.judge_model")
	ModelOpsEvalBaselineModelKey      = attribute.Key("model_ops.evaluation.baseline_model")
	ModelOpsEvalRegressionDetectedKey = attribute.Key("model_ops.evaluation.regression_detected")
	ModelOpsEvalPassKey               = attribute.Key("model_ops.evaluation.pass")

	// Registry attributes
	ModelOpsRegistryOperationKey        = attribute.Key("model_ops.registry.operation")
	ModelOpsRegistryModelIDKey          = attribute.Key("model_ops.registry.model_id")
	ModelOpsRegistryModelVersionKey     = attribute.Key("model_ops.registry.model_version")
	ModelOpsRegistryModelAliasKey       = attribute.Key("model_ops.registry.model_alias")
	ModelOpsRegistryStageKey            = attribute.Key("model_ops.registry.stage")
	ModelOpsRegistryOwnerKey            = attribute.Key("model_ops.registry.owner")
	ModelOpsRegistryTrainingRunIDKey    = attribute.Key("model_ops.registry.lineage.training_run_id")
	ModelOpsRegistryParentModelIDKey    = attribute.Key("model_ops.registry.lineage.parent_model_id")

	// Deployment attributes
	ModelOpsDeploymentIDKey            = attribute.Key("model_ops.deployment.id")
	ModelOpsDeploymentModelIDKey       = attribute.Key("model_ops.deployment.model_id")
	ModelOpsDeploymentStrategyKey      = attribute.Key("model_ops.deployment.strategy")
	ModelOpsDeploymentEnvironmentKey   = attribute.Key("model_ops.deployment.environment")
	ModelOpsDeploymentEndpointKey      = attribute.Key("model_ops.deployment.endpoint")
	ModelOpsDeploymentInfraProviderKey = attribute.Key("model_ops.deployment.infrastructure.provider")
	ModelOpsDeploymentInfraGPUTypeKey  = attribute.Key("model_ops.deployment.infrastructure.gpu_type")
	ModelOpsDeploymentInfraReplicasKey = attribute.Key("model_ops.deployment.infrastructure.replicas")
	ModelOpsDeploymentCanaryPctKey     = attribute.Key("model_ops.deployment.canary_percent")
	ModelOpsDeploymentStatusKey        = attribute.Key("model_ops.deployment.status")
	ModelOpsDeploymentHealthStatusKey  = attribute.Key("model_ops.deployment.health_check.status")
	ModelOpsDeploymentHealthLatencyKey = attribute.Key("model_ops.deployment.health_check.latency_ms")

	// Serving attributes
	ModelOpsServingOperationKey         = attribute.Key("model_ops.serving.operation")
	ModelOpsServingRouteSelectedKey     = attribute.Key("model_ops.serving.route.selected_model")
	ModelOpsServingRouteReasonKey       = attribute.Key("model_ops.serving.route.reason")
	ModelOpsServingRouteCandidatesKey   = attribute.Key("model_ops.serving.route.candidates")
	ModelOpsServingFallbackChainKey     = attribute.Key("model_ops.serving.fallback.chain")
	ModelOpsServingFallbackDepthKey     = attribute.Key("model_ops.serving.fallback.depth")
	ModelOpsServingFallbackTriggerKey   = attribute.Key("model_ops.serving.fallback.trigger")
	ModelOpsServingFallbackOriginalKey  = attribute.Key("model_ops.serving.fallback.original_model")
	ModelOpsServingFallbackFinalKey     = attribute.Key("model_ops.serving.fallback.final_model")
	ModelOpsServingCacheHitKey          = attribute.Key("model_ops.serving.cache.hit")
	ModelOpsServingCacheTypeKey         = attribute.Key("model_ops.serving.cache.type")
	ModelOpsServingCacheSimilarityKey   = attribute.Key("model_ops.serving.cache.similarity_score")
	ModelOpsServingCacheCostSavedKey    = attribute.Key("model_ops.serving.cache.cost_saved_usd")

	// Monitoring attributes
	ModelOpsMonitorCheckTypeKey      = attribute.Key("model_ops.monitoring.check_type")
	ModelOpsMonitorModelIDKey        = attribute.Key("model_ops.monitoring.model_id")
	ModelOpsMonitorResultKey         = attribute.Key("model_ops.monitoring.result")
	ModelOpsMonitorMetricNameKey     = attribute.Key("model_ops.monitoring.metric_name")
	ModelOpsMonitorMetricValueKey    = attribute.Key("model_ops.monitoring.metric_value")
	ModelOpsMonitorBaselineValueKey  = attribute.Key("model_ops.monitoring.baseline_value")
	ModelOpsMonitorDriftScoreKey     = attribute.Key("model_ops.monitoring.drift_score")
	ModelOpsMonitorDriftTypeKey      = attribute.Key("model_ops.monitoring.drift_type")
	ModelOpsMonitorActionTriggeredKey = attribute.Key("model_ops.monitoring.action_triggered")

	// Prompt lifecycle attributes
	ModelOpsPromptNameKey        = attribute.Key("model_ops.prompt.name")
	ModelOpsPromptOperationKey   = attribute.Key("model_ops.prompt.operation")
	ModelOpsPromptVersionKey     = attribute.Key("model_ops.prompt.version")
	ModelOpsPromptContentHashKey = attribute.Key("model_ops.prompt.content_hash")
	ModelOpsPromptLabelKey       = attribute.Key("model_ops.prompt.label")
	ModelOpsPromptModelTargetKey = attribute.Key("model_ops.prompt.model_target")
	ModelOpsPromptEvalScoreKey   = attribute.Key("model_ops.prompt.evaluation.score")
	ModelOpsPromptEvalPassKey    = attribute.Key("model_ops.prompt.evaluation.pass")
	ModelOpsPromptABTestIDKey    = attribute.Key("model_ops.prompt.a_b_test.id")
	ModelOpsPromptABTestVariantKey = attribute.Key("model_ops.prompt.a_b_test.variant")
)

// --- AITF Drift Detection Attributes ---

const (
	DriftModelIDKey          = attribute.Key("drift.model_id")
	DriftTypeKey             = attribute.Key("drift.type")
	DriftScoreKey            = attribute.Key("drift.score")
	DriftResultKey           = attribute.Key("drift.result")
	DriftDetectionMethodKey  = attribute.Key("drift.detection_method")
	DriftBaselineMetricKey   = attribute.Key("drift.baseline_metric")
	DriftCurrentMetricKey    = attribute.Key("drift.current_metric")
	DriftMetricNameKey       = attribute.Key("drift.metric_name")
	DriftThresholdKey        = attribute.Key("drift.threshold")
	DriftPValueKey           = attribute.Key("drift.p_value")
	DriftRefDatasetKey       = attribute.Key("drift.reference_dataset")
	DriftRefPeriodKey        = attribute.Key("drift.reference_period")
	DriftSampleSizeKey       = attribute.Key("drift.sample_size")
	DriftAffectedSegmentsKey = attribute.Key("drift.affected_segments")
	DriftFeatureNameKey      = attribute.Key("drift.feature_name")
	DriftFeatureImportanceKey = attribute.Key("drift.feature_importance")
	DriftActionTriggeredKey  = attribute.Key("drift.action_triggered")

	// Baseline attributes
	DriftBaselineOperationKey  = attribute.Key("drift.baseline.operation")
	DriftBaselineIDKey         = attribute.Key("drift.baseline.id")
	DriftBaselineDatasetKey    = attribute.Key("drift.baseline.dataset")
	DriftBaselineSampleSizeKey = attribute.Key("drift.baseline.sample_size")
	DriftBaselinePeriodKey     = attribute.Key("drift.baseline.period")
	DriftBaselineMetricsKey    = attribute.Key("drift.baseline.metrics")
	DriftBaselineFeaturesKey   = attribute.Key("drift.baseline.features")
	DriftBaselinePreviousIDKey = attribute.Key("drift.baseline.previous_id")

	// Investigation attributes
	DriftInvestTriggerIDKey       = attribute.Key("drift.investigation.trigger_id")
	DriftInvestRootCauseKey       = attribute.Key("drift.investigation.root_cause")
	DriftInvestRootCauseCatKey    = attribute.Key("drift.investigation.root_cause_category")
	DriftInvestAffectedSegmentsKey = attribute.Key("drift.investigation.affected_segments")
	DriftInvestAffectedUsersKey   = attribute.Key("drift.investigation.affected_users_estimate")
	DriftInvestBlastRadiusKey     = attribute.Key("drift.investigation.blast_radius")
	DriftInvestSeverityKey        = attribute.Key("drift.investigation.severity")
	DriftInvestRecommendationKey  = attribute.Key("drift.investigation.recommendation")

	// Remediation attributes
	DriftRemediationActionKey      = attribute.Key("drift.remediation.action")
	DriftRemediationTriggerIDKey   = attribute.Key("drift.remediation.trigger_id")
	DriftRemediationAutomatedKey   = attribute.Key("drift.remediation.automated")
	DriftRemediationInitiatedByKey = attribute.Key("drift.remediation.initiated_by")
	DriftRemediationStatusKey      = attribute.Key("drift.remediation.status")
	DriftRemediationRollbackToKey  = attribute.Key("drift.remediation.rollback_to")
	DriftRemediationRetrainKey     = attribute.Key("drift.remediation.retrain_dataset")
	DriftRemediationValidPassedKey = attribute.Key("drift.remediation.validation_passed")
)

// --- AITF Identity Attributes ---

const (
	// Core identity attributes
	IdentityAgentIDKey       = attribute.Key("identity.agent_id")
	IdentityAgentNameKey     = attribute.Key("identity.agent_name")
	IdentityTypeKey          = attribute.Key("identity.type")
	IdentityProviderKey      = attribute.Key("identity.provider")
	IdentityOwnerKey         = attribute.Key("identity.owner")
	IdentityOwnerTypeKey     = attribute.Key("identity.owner_type")
	IdentityCredentialTypeKey = attribute.Key("identity.credential_type")
	IdentityCredentialIDKey  = attribute.Key("identity.credential_id")
	IdentityStatusKey        = attribute.Key("identity.status")
	IdentityPreviousStatusKey = attribute.Key("identity.previous_status")
	IdentityScopeKey         = attribute.Key("identity.scope")
	IdentityExpiresAtKey     = attribute.Key("identity.expires_at")
	IdentityTTLSecondsKey    = attribute.Key("identity.ttl_seconds")
	IdentityAutoRotateKey    = attribute.Key("identity.auto_rotate")
	IdentityRotationIntervalKey = attribute.Key("identity.rotation_interval_seconds")

	// Lifecycle
	IdentityLifecycleOpKey = attribute.Key("identity.lifecycle.operation")

	// Authentication attributes
	IdentityAuthMethodKey         = attribute.Key("identity.auth.method")
	IdentityAuthResultKey         = attribute.Key("identity.auth.result")
	IdentityAuthProviderKey       = attribute.Key("identity.auth.provider")
	IdentityAuthTargetServiceKey  = attribute.Key("identity.auth.target_service")
	IdentityAuthFailureReasonKey  = attribute.Key("identity.auth.failure_reason")
	IdentityAuthTokenTypeKey      = attribute.Key("identity.auth.token_type")
	IdentityAuthScopeRequestedKey = attribute.Key("identity.auth.scope_requested")
	IdentityAuthScopeGrantedKey   = attribute.Key("identity.auth.scope_granted")
	IdentityAuthContinuousKey     = attribute.Key("identity.auth.continuous")
	IdentityAuthPKCEUsedKey       = attribute.Key("identity.auth.pkce_used")
	IdentityAuthDPoPUsedKey       = attribute.Key("identity.auth.dpop_used")

	// Authorization attributes
	IdentityAuthzDecisionKey     = attribute.Key("identity.authz.decision")
	IdentityAuthzResourceKey     = attribute.Key("identity.authz.resource")
	IdentityAuthzActionKey       = attribute.Key("identity.authz.action")
	IdentityAuthzPolicyEngineKey = attribute.Key("identity.authz.policy_engine")
	IdentityAuthzPolicyIDKey     = attribute.Key("identity.authz.policy_id")
	IdentityAuthzDenyReasonKey   = attribute.Key("identity.authz.deny_reason")
	IdentityAuthzRiskScoreKey    = attribute.Key("identity.authz.risk_score")
	IdentityAuthzJEAKey          = attribute.Key("identity.authz.jea")
	IdentityAuthzTimeLimitedKey  = attribute.Key("identity.authz.time_limited")
	IdentityAuthzExpiresAtKey    = attribute.Key("identity.authz.expires_at")

	// Delegation attributes
	IdentityDelegDelegatorKey      = attribute.Key("identity.delegation.delegator")
	IdentityDelegDelegatorIDKey    = attribute.Key("identity.delegation.delegator_id")
	IdentityDelegDelegateeKey      = attribute.Key("identity.delegation.delegatee")
	IdentityDelegDelegateeIDKey    = attribute.Key("identity.delegation.delegatee_id")
	IdentityDelegTypeKey           = attribute.Key("identity.delegation.type")
	IdentityDelegChainKey          = attribute.Key("identity.delegation.chain")
	IdentityDelegChainDepthKey     = attribute.Key("identity.delegation.chain_depth")
	IdentityDelegScopeDelegatedKey = attribute.Key("identity.delegation.scope_delegated")
	IdentityDelegScopeAttenuatedKey = attribute.Key("identity.delegation.scope_attenuated")
	IdentityDelegResultKey         = attribute.Key("identity.delegation.result")
	IdentityDelegProofTypeKey      = attribute.Key("identity.delegation.proof_type")
	IdentityDelegTTLSecondsKey     = attribute.Key("identity.delegation.ttl_seconds")

	// Trust attributes
	IdentityTrustOperationKey  = attribute.Key("identity.trust.operation")
	IdentityTrustPeerAgentKey  = attribute.Key("identity.trust.peer_agent")
	IdentityTrustPeerAgentIDKey = attribute.Key("identity.trust.peer_agent_id")
	IdentityTrustResultKey     = attribute.Key("identity.trust.result")
	IdentityTrustMethodKey     = attribute.Key("identity.trust.method")
	IdentityTrustDomainKey     = attribute.Key("identity.trust.trust_domain")
	IdentityTrustPeerDomainKey = attribute.Key("identity.trust.peer_trust_domain")
	IdentityTrustCrossDomainKey = attribute.Key("identity.trust.cross_domain")
	IdentityTrustLevelKey      = attribute.Key("identity.trust.trust_level")
	IdentityTrustProtocolKey   = attribute.Key("identity.trust.protocol")

	// Session attributes
	IdentitySessionIDKey              = attribute.Key("identity.session.id")
	IdentitySessionOperationKey       = attribute.Key("identity.session.operation")
	IdentitySessionScopeKey           = attribute.Key("identity.session.scope")
	IdentitySessionExpiresAtKey       = attribute.Key("identity.session.expires_at")
	IdentitySessionActionsCountKey    = attribute.Key("identity.session.actions_count")
	IdentitySessionTerminationReasonKey = attribute.Key("identity.session.termination_reason")
)

// --- AITF Asset Inventory Attributes ---

const (
	// Core asset attributes
	AssetIDKey                = attribute.Key("asset.id")
	AssetNameKey              = attribute.Key("asset.name")
	AssetTypeKey              = attribute.Key("asset.type")
	AssetVersionKey           = attribute.Key("asset.version")
	AssetHashKey              = attribute.Key("asset.hash")
	AssetOwnerKey             = attribute.Key("asset.owner")
	AssetOwnerTypeKey         = attribute.Key("asset.owner_type")
	AssetDeployEnvKey         = attribute.Key("asset.deployment_environment")
	AssetRiskClassificationKey = attribute.Key("asset.risk_classification")
	AssetSourceRepoKey        = attribute.Key("asset.source_repository")
	AssetTagsKey              = attribute.Key("asset.tags")

	// Discovery attributes
	AssetDiscoveryScopeKey       = attribute.Key("asset.discovery.scope")
	AssetDiscoveryMethodKey      = attribute.Key("asset.discovery.method")
	AssetDiscoveryAssetsFoundKey = attribute.Key("asset.discovery.assets_found")
	AssetDiscoveryNewAssetsKey   = attribute.Key("asset.discovery.new_assets")
	AssetDiscoveryShadowKey      = attribute.Key("asset.discovery.shadow_assets")
	AssetDiscoveryStatusKey      = attribute.Key("asset.discovery.status")

	// Audit attributes
	AssetAuditTypeKey            = attribute.Key("asset.audit.type")
	AssetAuditResultKey          = attribute.Key("asset.audit.result")
	AssetAuditAuditorKey         = attribute.Key("asset.audit.auditor")
	AssetAuditFrameworkKey       = attribute.Key("asset.audit.framework")
	AssetAuditFindingsKey        = attribute.Key("asset.audit.findings")
	AssetAuditNextDueKey         = attribute.Key("asset.audit.next_audit_due")
	AssetAuditRiskScoreKey       = attribute.Key("asset.audit.risk_score")
	AssetAuditIntegrityKey       = attribute.Key("asset.audit.integrity_verified")
	AssetAuditComplianceKey      = attribute.Key("asset.audit.compliance_status")

	// Classification attributes
	AssetClassFrameworkKey        = attribute.Key("asset.classification.framework")
	AssetClassPreviousKey         = attribute.Key("asset.classification.previous")
	AssetClassReasonKey           = attribute.Key("asset.classification.reason")
	AssetClassAssessorKey         = attribute.Key("asset.classification.assessor")
	AssetClassUseCaseKey          = attribute.Key("asset.classification.use_case")
	AssetClassAutonomousDecisionKey = attribute.Key("asset.classification.autonomous_decision")

	// Decommission attributes
	AssetDecommissionReasonKey      = attribute.Key("asset.decommission.reason")
	AssetDecommissionReplacementKey = attribute.Key("asset.decommission.replacement_id")
	AssetDecommissionApprovedByKey  = attribute.Key("asset.decommission.approved_by")
)

// --- AITF Memory Security Attributes ---

const (
	MemorySecurityContentHashKey    = attribute.Key("memory.security.content_hash")
	MemorySecurityContentSizeKey    = attribute.Key("memory.security.content_size")
	MemorySecurityIntegrityHashKey  = attribute.Key("memory.security.integrity_hash")
	MemorySecurityPoisoningScoreKey = attribute.Key("memory.security.poisoning_score")
	MemorySecurityCrossSessionKey   = attribute.Key("memory.security.cross_session")
)

// --- AITF A2A (Agent-to-Agent Protocol) Attributes ---

const (
	A2AAgentNameKey            = attribute.Key("a2a.agent.name")
	A2AAgentURLKey             = attribute.Key("a2a.agent.url")
	A2AAgentVersionKey         = attribute.Key("a2a.agent.version")
	A2AAgentProviderOrgKey     = attribute.Key("a2a.agent.provider.organization")
	A2AAgentSkillsKey          = attribute.Key("a2a.agent.skills")
	A2AAgentCapStreamingKey    = attribute.Key("a2a.agent.capabilities.streaming")
	A2AAgentCapPushKey         = attribute.Key("a2a.agent.capabilities.push_notifications")
	A2AProtocolVersionKey      = attribute.Key("a2a.protocol.version")
	A2ATransportKey            = attribute.Key("a2a.transport")

	A2ATaskIDKey               = attribute.Key("a2a.task.id")
	A2ATaskContextIDKey        = attribute.Key("a2a.task.context_id")
	A2ATaskStateKey            = attribute.Key("a2a.task.state")
	A2ATaskPreviousStateKey    = attribute.Key("a2a.task.previous_state")
	A2ATaskArtifactsCountKey   = attribute.Key("a2a.task.artifacts_count")
	A2ATaskHistoryLengthKey    = attribute.Key("a2a.task.history_length")

	A2AMessageIDKey            = attribute.Key("a2a.message.id")
	A2AMessageRoleKey          = attribute.Key("a2a.message.role")
	A2AMessagePartsCountKey    = attribute.Key("a2a.message.parts_count")
	A2AMessagePartTypesKey     = attribute.Key("a2a.message.part_types")

	A2AMethodKey               = attribute.Key("a2a.method")
	A2AInteractionModeKey      = attribute.Key("a2a.interaction_mode")
	A2AJSONRPCRequestIDKey     = attribute.Key("a2a.jsonrpc.request_id")
	A2AJSONRPCErrorCodeKey     = attribute.Key("a2a.jsonrpc.error_code")
	A2AJSONRPCErrorMessageKey  = attribute.Key("a2a.jsonrpc.error_message")

	A2AArtifactIDKey           = attribute.Key("a2a.artifact.id")
	A2AArtifactNameKey         = attribute.Key("a2a.artifact.name")
	A2AArtifactPartsCountKey   = attribute.Key("a2a.artifact.parts_count")

	A2AStreamEventTypeKey      = attribute.Key("a2a.stream.event_type")
	A2AStreamIsFinalKey        = attribute.Key("a2a.stream.is_final")
	A2AStreamEventsCountKey    = attribute.Key("a2a.stream.events_count")

	A2APushURLKey              = attribute.Key("a2a.push.url")
)

// A2A task state values.
const (
	A2ATaskStateSubmitted     = "submitted"
	A2ATaskStateWorking       = "working"
	A2ATaskStateInputRequired = "input-required"
	A2ATaskStateCompleted     = "completed"
	A2ATaskStateCanceled      = "canceled"
	A2ATaskStateFailed        = "failed"
	A2ATaskStateRejected      = "rejected"
	A2ATaskStateAuthRequired  = "auth-required"
)

// A2A transport values.
const (
	A2ATransportJSONRPC  = "jsonrpc"
	A2ATransportGRPC     = "grpc"
	A2ATransportHTTPJSON = "http_json"
)

// --- AITF ACP (Agent Communication Protocol) Attributes ---

const (
	ACPAgentNameKey              = attribute.Key("acp.agent.name")
	ACPAgentDescriptionKey       = attribute.Key("acp.agent.description")
	ACPAgentInputContentTypesKey = attribute.Key("acp.agent.input_content_types")
	ACPAgentOutputContentTypesKey = attribute.Key("acp.agent.output_content_types")
	ACPAgentFrameworkKey         = attribute.Key("acp.agent.framework")
	ACPAgentSuccessRateKey       = attribute.Key("acp.agent.status.success_rate")
	ACPAgentAvgRunTimeKey        = attribute.Key("acp.agent.status.avg_run_time_seconds")

	ACPRunIDKey                  = attribute.Key("acp.run.id")
	ACPRunAgentNameKey           = attribute.Key("acp.run.agent_name")
	ACPRunSessionIDKey           = attribute.Key("acp.run.session_id")
	ACPRunModeKey                = attribute.Key("acp.run.mode")
	ACPRunStatusKey              = attribute.Key("acp.run.status")
	ACPRunPreviousStatusKey      = attribute.Key("acp.run.previous_status")
	ACPRunErrorCodeKey           = attribute.Key("acp.run.error.code")
	ACPRunErrorMessageKey        = attribute.Key("acp.run.error.message")
	ACPRunCreatedAtKey           = attribute.Key("acp.run.created_at")
	ACPRunFinishedAtKey          = attribute.Key("acp.run.finished_at")
	ACPRunDurationMsKey          = attribute.Key("acp.run.duration_ms")

	ACPMessageRoleKey            = attribute.Key("acp.message.role")
	ACPMessagePartsCountKey      = attribute.Key("acp.message.parts_count")
	ACPMessageContentTypesKey    = attribute.Key("acp.message.content_types")
	ACPMessageHasCitationsKey    = attribute.Key("acp.message.has_citations")
	ACPMessageHasTrajectoryKey   = attribute.Key("acp.message.has_trajectory")

	ACPAwaitActiveKey            = attribute.Key("acp.await.active")
	ACPAwaitCountKey             = attribute.Key("acp.await.count")
	ACPAwaitDurationMsKey        = attribute.Key("acp.await.duration_ms")

	ACPInputMessageCountKey      = attribute.Key("acp.input.message_count")
	ACPOutputMessageCountKey     = attribute.Key("acp.output.message_count")

	ACPOperationKey              = attribute.Key("acp.operation")
	ACPHTTPMethodKey             = attribute.Key("acp.http.method")
	ACPHTTPStatusCodeKey         = attribute.Key("acp.http.status_code")
	ACPHTTPURLKey                = attribute.Key("acp.http.url")

	ACPTrajectoryToolNameKey     = attribute.Key("acp.trajectory.tool_name")
	ACPTrajectoryMessageKey      = attribute.Key("acp.trajectory.message")
)

// ACP run status values.
const (
	ACPRunStatusCreated    = "created"
	ACPRunStatusInProgress = "in-progress"
	ACPRunStatusAwaiting   = "awaiting"
	ACPRunStatusCancelling = "cancelling"
	ACPRunStatusCancelled  = "cancelled"
	ACPRunStatusCompleted  = "completed"
	ACPRunStatusFailed     = "failed"
)

// ACP run mode values.
const (
	ACPRunModeSync  = "sync"
	ACPRunModeAsync = "async"
	ACPRunModeStream = "stream"
)

// --- AITF Agentic Log Attributes (Table 10.1 minimal fields) ---

const (
	// EventID: A unique identifier for the specific log entry
	AgenticLogEventIDKey = attribute.Key("agentic_log.event_id")

	// Timestamp: ISO 8601 formatted timestamp with millisecond precision
	AgenticLogTimestampKey = attribute.Key("agentic_log.timestamp")

	// AgentID: The unique, cryptographically verifiable identity of the agent
	AgenticLogAgentIDKey = attribute.Key("agentic_log.agent_id")

	// SessionID: A unique ID for the agent's current operational session
	AgenticLogSessionIDKey = attribute.Key("agentic_log.session_id")

	// GoalID: An identifier for the high-level goal the agent is pursuing
	AgenticLogGoalIDKey = attribute.Key("agentic_log.goal_id")

	// SubTaskID: The specific, immediate task the agent is performing
	AgenticLogSubTaskIDKey = attribute.Key("agentic_log.sub_task_id")

	// ToolUsed: The specific tool, function, or API being invoked
	AgenticLogToolUsedKey = attribute.Key("agentic_log.tool_used")

	// ToolParameters: Sanitized log of parameters (PII/credentials redacted)
	AgenticLogToolParametersKey = attribute.Key("agentic_log.tool_parameters")

	// Outcome: The result of the action (success, failure, error code)
	AgenticLogOutcomeKey = attribute.Key("agentic_log.outcome")

	// ConfidenceScore: Agent's own assessment of how likely the action succeeds
	AgenticLogConfidenceScoreKey = attribute.Key("agentic_log.confidence_score")

	// AnomalyScore: Score indicating how unusual this action is
	AgenticLogAnomalyScoreKey = attribute.Key("agentic_log.anomaly_score")

	// PolicyEvaluation: Record of a check against a security policy engine
	AgenticLogPolicyEvaluationKey = attribute.Key("agentic_log.policy_evaluation")
)

// Agentic log outcome values.
const (
	AgenticLogOutcomeSuccess = "SUCCESS"
	AgenticLogOutcomeFailure = "FAILURE"
	AgenticLogOutcomeError   = "ERROR"
	AgenticLogOutcomeDenied  = "DENIED"
	AgenticLogOutcomeTimeout = "TIMEOUT"
	AgenticLogOutcomePartial = "PARTIAL"
)

// Agentic log policy evaluation result values.
const (
	AgenticLogPolicyPass = "PASS"
	AgenticLogPolicyFail = "FAIL"
	AgenticLogPolicyWarn = "WARN"
	AgenticLogPolicySkip = "SKIP"
)
