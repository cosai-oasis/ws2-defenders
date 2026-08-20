/**
 * AITF Semantic Convention Attribute Constants.
 *
 * All attribute keys used across AITF instrumentation, processors, and exporters.
 * OTel GenAI attributes (gen_ai.*) are preserved for compatibility.
 * AITF extensions use the aitf.* namespace.
 */

/** OpenTelemetry GenAI semantic convention attributes (preserved). */
export const GenAIAttributes = {
  SYSTEM: "gen_ai.provider.name",
  OPERATION_NAME: "gen_ai.operation.name",

  // Request attributes
  REQUEST_MODEL: "gen_ai.request.model",
  REQUEST_MAX_TOKENS: "gen_ai.request.max_tokens",
  REQUEST_TEMPERATURE: "gen_ai.request.temperature",
  REQUEST_TOP_P: "gen_ai.request.top_p",
  REQUEST_TOP_K: "gen_ai.request.top_k",
  REQUEST_STOP_SEQUENCES: "gen_ai.request.stop_sequences",
  REQUEST_FREQUENCY_PENALTY: "gen_ai.request.frequency_penalty",
  REQUEST_PRESENCE_PENALTY: "gen_ai.request.presence_penalty",
  REQUEST_SEED: "gen_ai.request.seed",
  REQUEST_STREAM: "gen_ai.request.stream",
  REQUEST_TOOLS: "gen_ai.request.tools",
  REQUEST_TOOL_CHOICE: "gen_ai.request.tool_choice",
  REQUEST_RESPONSE_FORMAT: "gen_ai.request.response_format",

  // Response attributes
  RESPONSE_ID: "gen_ai.response.id",
  RESPONSE_MODEL: "gen_ai.response.model",
  RESPONSE_FINISH_REASONS: "gen_ai.response.finish_reasons",

  // Usage attributes
  USAGE_INPUT_TOKENS: "gen_ai.usage.input_tokens",
  USAGE_OUTPUT_TOKENS: "gen_ai.usage.output_tokens",
  USAGE_CACHED_TOKENS: "gen_ai.usage.cached_tokens",
  USAGE_REASONING_TOKENS: "gen_ai.usage.reasoning_tokens",

  // Token attributes
  TOKEN_TYPE: "gen_ai.token.type",

  // System prompt hash (CoSAI WS2: AI_INTERACTION)
  SYSTEM_PROMPT_HASH: "gen_ai.system_prompt.hash",

  // Event attributes
  PROMPT: "gen_ai.prompt",
  COMPLETION: "gen_ai.completion",
  TOOL_NAME: "gen_ai.tool.name",
  TOOL_CALL_ID: "gen_ai.tool.call_id",
  TOOL_ARGUMENTS: "gen_ai.tool.arguments",
  TOOL_RESULT: "gen_ai.tool.result",

  /** System values */
  System: {
    OPENAI: "openai",
    ANTHROPIC: "anthropic",
    BEDROCK: "bedrock",
    AZURE: "azure",
    GCP_VERTEX: "gcp_vertex",
    COHERE: "cohere",
    MISTRAL: "mistral",
    META: "meta",
    GOOGLE: "google",
  },

  /** Operation values */
  Operation: {
    CHAT: "chat",
    TEXT_COMPLETION: "text_completion",
    EMBEDDINGS: "embeddings",
    IMAGE_GENERATION: "image_generation",
    AUDIO: "audio",
  },
} as const;

/** AITF Agent semantic convention attributes. */
export const AgentAttributes = {
  // Core agent attributes
  NAME: "gen_ai.agent.name",
  ID: "gen_ai.agent.id",
  TYPE: "agent.type",
  FRAMEWORK: "agent.framework",
  VERSION: "agent.version",
  DESCRIPTION: "gen_ai.agent.description",

  // Session attributes
  SESSION_ID: "gen_ai.conversation.id",
  SESSION_TURN_COUNT: "agent.session.turn_count",
  SESSION_START_TIME: "agent.session.start_time",

  // CoSAI WS2: AGENT_TRACE fields
  WORKFLOW_ID: "agent.workflow_id",
  STATE: "agent.state",
  SCRATCHPAD: "agent.scratchpad",
  NEXT_ACTION: "agent.next_action",

  // Step attributes
  STEP_TYPE: "agent.step.type",
  STEP_INDEX: "agent.step.index",
  STEP_THOUGHT: "agent.step.thought",
  STEP_ACTION: "agent.step.action",
  STEP_OBSERVATION: "agent.step.observation",
  STEP_STATUS: "agent.step.status",

  // Delegation attributes
  DELEGATION_TARGET_AGENT: "agent.delegation.target_agent",
  DELEGATION_TARGET_AGENT_ID: "agent.delegation.target_agent_id",
  DELEGATION_REASON: "agent.delegation.reason",
  DELEGATION_STRATEGY: "agent.delegation.strategy",
  DELEGATION_TASK: "agent.delegation.task",
  DELEGATION_RESULT: "agent.delegation.result",

  // Team attributes
  TEAM_NAME: "agent.team.name",
  TEAM_ID: "agent.team.id",
  TEAM_TOPOLOGY: "agent.team.topology",
  TEAM_MEMBERS: "agent.team.members",
  TEAM_COORDINATOR: "agent.team.coordinator",
  TEAM_CONSENSUS_METHOD: "agent.team.consensus_method",

  /** Type values */
  Type: {
    CONVERSATIONAL: "conversational",
    AUTONOMOUS: "autonomous",
    REACTIVE: "reactive",
    PROACTIVE: "proactive",
  },

  /** Framework values */
  Framework: {
    LANGCHAIN: "langchain",
    LANGGRAPH: "langgraph",
    CREWAI: "crewai",
    AUTOGEN: "autogen",
    SEMANTIC_KERNEL: "semantic_kernel",
    CUSTOM: "custom",
  },

  /** Step type values */
  StepType: {
    PLANNING: "planning",
    REASONING: "reasoning",
    TOOL_USE: "tool_use",
    DELEGATION: "delegation",
    RESPONSE: "response",
    REFLECTION: "reflection",
    MEMORY_ACCESS: "memory_access",
    GUARDRAIL_CHECK: "guardrail_check",
    HUMAN_IN_LOOP: "human_in_loop",
    ERROR_RECOVERY: "error_recovery",
  },

  /** Team topology values */
  TeamTopology: {
    HIERARCHICAL: "hierarchical",
    PEER: "peer",
    PIPELINE: "pipeline",
    CONSENSUS: "consensus",
    DEBATE: "debate",
    SWARM: "swarm",
  },
} as const;

/** AITF MCP (Model Context Protocol) semantic convention attributes. */
export const MCPAttributes = {
  // Server attributes
  SERVER_NAME: "mcp.server.name",
  SERVER_VERSION: "mcp.server.version",
  SERVER_TRANSPORT: "mcp.server.transport",
  SERVER_URL: "mcp.server.url",
  PROTOCOL_VERSION: "mcp.protocol.version",

  // Tool attributes
  TOOL_NAME: "gen_ai.tool.name",
  TOOL_SERVER: "mcp.tool.server",
  TOOL_INPUT: "gen_ai.tool.call.arguments",
  TOOL_OUTPUT: "gen_ai.tool.call.result",
  TOOL_IS_ERROR: "mcp.tool.is_error",
  TOOL_DURATION_MS: "mcp.tool.duration_ms",
  TOOL_APPROVAL_REQUIRED: "mcp.tool.approval_required",
  TOOL_APPROVED: "mcp.tool.approved",
  TOOL_COUNT: "mcp.tool.count",
  TOOL_NAMES: "mcp.tool.names",

  // CoSAI WS2: MCP_ACTIVITY fields
  TOOL_RESPONSE_ERROR: "mcp.tool.response_error",
  CONNECTION_ID: "mcp.connection.id",

  // Resource attributes
  RESOURCE_URI: "mcp.resource.uri",
  RESOURCE_NAME: "mcp.resource.name",
  RESOURCE_MIME_TYPE: "mcp.resource.mime_type",
  RESOURCE_SIZE_BYTES: "mcp.resource.size_bytes",

  // Prompt attributes
  PROMPT_NAME: "mcp.prompt.name",
  PROMPT_ARGUMENTS: "mcp.prompt.arguments",
  PROMPT_DESCRIPTION: "mcp.prompt.description",

  // Sampling attributes
  SAMPLING_MODEL: "mcp.sampling.model",
  SAMPLING_MAX_TOKENS: "mcp.sampling.max_tokens",
  SAMPLING_INCLUDE_CONTEXT: "mcp.sampling.include_context",

  /** Transport values */
  Transport: {
    STDIO: "stdio",
    SSE: "sse",
    STREAMABLE_HTTP: "streamable_http",
  },
} as const;

/** AITF Skills semantic convention attributes. */
export const SkillAttributes = {
  NAME: "skill.name",
  ID: "skill.id",
  VERSION: "skill.version",
  PROVIDER: "skill.provider",
  CATEGORY: "skill.category",
  DESCRIPTION: "skill.description",
  INPUT: "skill.input",
  OUTPUT: "skill.output",
  STATUS: "skill.status",
  DURATION_MS: "skill.duration_ms",
  RETRY_COUNT: "skill.retry_count",
  SOURCE: "skill.source",
  PERMISSIONS: "skill.permissions",
  HASH: "skill.hash",
  AUTHORS: "skill.authors",
  COUNT: "skill.count",
  NAMES: "skill.names",

  // Composition attributes
  COMPOSE_NAME: "skill.compose.name",
  COMPOSE_SKILLS: "skill.compose.skills",
  COMPOSE_PATTERN: "skill.compose.pattern",
  COMPOSE_TOTAL: "skill.compose.total_skills",
  COMPOSE_COMPLETED: "skill.compose.completed_skills",

  // Resolution attributes
  RESOLVE_CAPABILITY: "skill.resolve.capability",
  RESOLVE_CANDIDATES: "skill.resolve.candidates",
  RESOLVE_SELECTED: "skill.resolve.selected",
  RESOLVE_REASON: "skill.resolve.reason",

  /** Provider values */
  Provider: {
    BUILTIN: "builtin",
    MARKETPLACE: "marketplace",
    CUSTOM: "custom",
    MCP: "mcp",
  },

  /** Category values */
  Category: {
    SEARCH: "search",
    CODE: "code",
    DATA: "data",
    COMMUNICATION: "communication",
    ANALYSIS: "analysis",
    GENERATION: "generation",
    KNOWLEDGE: "knowledge",
    SECURITY: "security",
    INTEGRATION: "integration",
    WORKFLOW: "workflow",
  },

  /** Status values */
  Status: {
    SUCCESS: "success",
    ERROR: "error",
    TIMEOUT: "timeout",
    DENIED: "denied",
    RETRY: "retry",
  },
} as const;

/** AITF RAG (Retrieval-Augmented Generation) semantic convention attributes. */
export const RAGAttributes = {
  // Pipeline attributes
  PIPELINE_NAME: "rag.pipeline.name",
  PIPELINE_STAGE: "rag.pipeline.stage",
  QUERY: "rag.query",
  QUERY_EMBEDDING_MODEL: "rag.query.embedding_model",
  QUERY_EMBEDDING_DIMENSIONS: "rag.query.embedding_dimensions",

  // Retrieval attributes
  RETRIEVE_DATABASE: "gen_ai.data_source.id",
  RETRIEVE_INDEX: "rag.retrieve.index",
  RETRIEVE_TOP_K: "rag.retrieve.top_k",
  RETRIEVE_RESULTS_COUNT: "rag.retrieve.results_count",
  RETRIEVE_MIN_SCORE: "rag.retrieve.min_score",
  RETRIEVE_MAX_SCORE: "rag.retrieve.max_score",
  RETRIEVE_FILTER: "rag.retrieve.filter",

  // CoSAI WS2: RAG_CONTEXT document-level fields
  DOC_ID: "rag.doc.id",
  DOC_SCORE: "rag.doc.score",
  DOC_PROVENANCE: "rag.doc.provenance",
  RETRIEVAL_DOCS: "rag.retrieval.docs",

  // Reranking attributes
  RERANK_MODEL: "rag.rerank.model",
  RERANK_INPUT_COUNT: "rag.rerank.input_count",
  RERANK_OUTPUT_COUNT: "rag.rerank.output_count",

  // Quality attributes
  QUALITY_CONTEXT_RELEVANCE: "rag.quality.context_relevance",
  QUALITY_ANSWER_RELEVANCE: "rag.quality.answer_relevance",
  QUALITY_FAITHFULNESS: "rag.quality.faithfulness",
  QUALITY_GROUNDEDNESS: "rag.quality.groundedness",

  /** Stage values */
  Stage: {
    RETRIEVE: "retrieve",
    RERANK: "rerank",
    GENERATE: "generate",
    EVALUATE: "evaluate",
  },
} as const;

/** AITF Security semantic convention attributes. */
export const SecurityAttributes = {
  RISK_SCORE: "security.risk_score",
  RISK_LEVEL: "security.risk_level",
  THREAT_DETECTED: "security.threat_detected",
  THREAT_TYPE: "security.threat_type",
  OWASP_CATEGORY: "security.owasp_category",
  BLOCKED: "security.blocked",
  DETECTION_METHOD: "security.detection_method",
  CONFIDENCE: "security.confidence",

  // Guardrail attributes
  GUARDRAIL_NAME: "security.guardrail.name",
  GUARDRAIL_TYPE: "security.guardrail.type",
  GUARDRAIL_RESULT: "security.guardrail.result",
  GUARDRAIL_PROVIDER: "security.guardrail.provider",
  GUARDRAIL_POLICY: "security.guardrail.policy",

  // PII attributes
  PII_DETECTED: "security.pii.detected",
  PII_TYPES: "security.pii.types",
  PII_COUNT: "security.pii.count",
  PII_ACTION: "security.pii.action",

  /** Risk level values */
  RiskLevel: {
    CRITICAL: "critical",
    HIGH: "high",
    MEDIUM: "medium",
    LOW: "low",
    INFO: "info",
  },

  /** OWASP LLM Top 10 */
  OWASP: {
    LLM01: "LLM01", // Prompt Injection
    LLM02: "LLM02", // Sensitive Information Disclosure
    LLM03: "LLM03", // Supply Chain Vulnerabilities
    LLM04: "LLM04", // Data and Model Poisoning
    LLM05: "LLM05", // Improper Output Handling
    LLM06: "LLM06", // Excessive Agency
    LLM07: "LLM07", // System Prompt Leakage
    LLM08: "LLM08", // Vector and Embedding Weaknesses
    LLM09: "LLM09", // Misinformation
    LLM10: "LLM10", // Unbounded Consumption
  },

  /** Threat type values */
  ThreatType: {
    PROMPT_INJECTION: "prompt_injection",
    SENSITIVE_DATA_EXPOSURE: "sensitive_data_exposure",
    SUPPLY_CHAIN: "supply_chain",
    DATA_POISONING: "data_poisoning",
    IMPROPER_OUTPUT: "improper_output",
    EXCESSIVE_AGENCY: "excessive_agency",
    SYSTEM_PROMPT_LEAK: "system_prompt_leak",
    VECTOR_DATA_WEAKNESS: "vector_data_weakness",
    MISINFORMATION: "misinformation",
    UNBOUNDED_CONSUMPTION: "unbounded_consumption",
    JAILBREAK: "jailbreak",
    DATA_EXFILTRATION: "data_exfiltration",
    MODEL_THEFT: "model_theft",
  },
} as const;

/** AITF Compliance semantic convention attributes. */
export const ComplianceAttributes = {
  FRAMEWORKS: "compliance.frameworks",
  NIST_AI_RMF_CONTROLS: "compliance.nist_ai_rmf.controls",
  MITRE_ATLAS_TECHNIQUES: "compliance.mitre_atlas.techniques",
  ISO_42001_CONTROLS: "compliance.iso_42001.controls",
  EU_AI_ACT_ARTICLES: "compliance.eu_ai_act.articles",
  SOC2_CONTROLS: "compliance.soc2.controls",
  GDPR_ARTICLES: "compliance.gdpr.articles",
  CCPA_SECTIONS: "compliance.ccpa.sections",
  CSA_AICM_CONTROLS: "compliance.csa_aicm.controls",
} as const;

/** AITF Cost semantic convention attributes. */
export const CostAttributes = {
  INPUT_COST: "cost.input_cost",
  OUTPUT_COST: "cost.output_cost",
  TOTAL_COST: "cost.total_cost",
  CURRENCY: "cost.currency",

  // Model pricing
  PRICING_INPUT_PER_1M: "cost.model_pricing.input_per_1m",
  PRICING_OUTPUT_PER_1M: "cost.model_pricing.output_per_1m",

  // Budget
  BUDGET_LIMIT: "cost.budget.limit",
  BUDGET_USED: "cost.budget.used",
  BUDGET_REMAINING: "cost.budget.remaining",

  // Attribution
  ATTRIBUTION_USER: "cost.attribution.user",
  ATTRIBUTION_TEAM: "cost.attribution.team",
  ATTRIBUTION_PROJECT: "cost.attribution.project",
} as const;

/** AITF Quality semantic convention attributes. */
export const QualityAttributes = {
  HALLUCINATION_SCORE: "quality.hallucination_score",
  CONFIDENCE: "quality.confidence",
  FACTUALITY: "quality.factuality",
  COHERENCE: "quality.coherence",
  TOXICITY_SCORE: "quality.toxicity_score",
  BIAS_SCORE: "quality.bias_score",
  FEEDBACK_RATING: "quality.feedback.rating",
  FEEDBACK_THUMBS: "quality.feedback.thumbs",
  FEEDBACK_COMMENT: "quality.feedback.comment",
} as const;

/** AITF Supply Chain semantic convention attributes. */
export const SupplyChainAttributes = {
  MODEL_SOURCE: "supply_chain.model.source",
  MODEL_HASH: "supply_chain.model.hash",
  MODEL_LICENSE: "supply_chain.model.license",
  MODEL_TRAINING_DATA: "supply_chain.model.training_data",
  MODEL_SIGNED: "supply_chain.model.signed",
  MODEL_SIGNER: "supply_chain.model.signer",
  AI_BOM_ID: "supply_chain.ai_bom.id",
  AI_BOM_COMPONENTS: "supply_chain.ai_bom.components",
} as const;

/** AITF Memory semantic convention attributes. */
export const MemoryAttributes = {
  OPERATION: "memory.operation",
  STORE: "memory.store",
  KEY: "memory.key",
  TTL_SECONDS: "memory.ttl_seconds",
  HIT: "memory.hit",
  PROVENANCE: "memory.provenance",

  Operation: {
    STORE: "store",
    RETRIEVE: "retrieve",
    UPDATE: "update",
    DELETE: "delete",
    SEARCH: "search",
  },

  Store: {
    SHORT_TERM: "short_term",
    LONG_TERM: "long_term",
    EPISODIC: "episodic",
    SEMANTIC: "semantic",
    PROCEDURAL: "procedural",
  },
} as const;

/** AITF Latency attributes for performance tracking. */
export const LatencyAttributes = {
  TOTAL_MS: "latency.total_ms",
  TIME_TO_FIRST_TOKEN_MS: "latency.time_to_first_token_ms",
  TOKENS_PER_SECOND: "latency.tokens_per_second",
  QUEUE_TIME_MS: "latency.queue_time_ms",
  INFERENCE_TIME_MS: "latency.inference_time_ms",
} as const;

/** AITF Model Operations (LLMOps/MLOps) semantic convention attributes. */
export const ModelOpsAttributes = {
  // Training attributes
  TRAINING_RUN_ID: "model_ops.training.run_id",
  TRAINING_TYPE: "model_ops.training.type",
  TRAINING_BASE_MODEL: "model_ops.training.base_model",
  TRAINING_FRAMEWORK: "model_ops.training.framework",
  TRAINING_DATASET_ID: "model_ops.training.dataset.id",
  TRAINING_DATASET_VERSION: "model_ops.training.dataset.version",
  TRAINING_DATASET_SIZE: "model_ops.training.dataset.size",
  TRAINING_HYPERPARAMETERS: "model_ops.training.hyperparameters",
  TRAINING_EPOCHS: "model_ops.training.epochs",
  TRAINING_BATCH_SIZE: "model_ops.training.batch_size",
  TRAINING_LEARNING_RATE: "model_ops.training.learning_rate",
  TRAINING_LOSS_FINAL: "model_ops.training.loss_final",
  TRAINING_VAL_LOSS_FINAL: "model_ops.training.val_loss_final",
  TRAINING_COMPUTE_GPU_TYPE: "model_ops.training.compute.gpu_type",
  TRAINING_COMPUTE_GPU_COUNT: "model_ops.training.compute.gpu_count",
  TRAINING_COMPUTE_GPU_HOURS: "model_ops.training.compute.gpu_hours",
  TRAINING_OUTPUT_MODEL_ID: "model_ops.training.output_model.id",
  TRAINING_OUTPUT_MODEL_HASH: "model_ops.training.output_model.hash",
  TRAINING_CODE_COMMIT: "model_ops.training.code_commit",
  TRAINING_EXPERIMENT_ID: "model_ops.training.experiment.id",
  TRAINING_EXPERIMENT_NAME: "model_ops.training.experiment.name",
  TRAINING_STATUS: "model_ops.training.status",

  // Evaluation attributes
  EVALUATION_RUN_ID: "model_ops.evaluation.run_id",
  EVALUATION_MODEL_ID: "model_ops.evaluation.model_id",
  EVALUATION_TYPE: "model_ops.evaluation.type",
  EVALUATION_DATASET_ID: "model_ops.evaluation.dataset.id",
  EVALUATION_DATASET_VERSION: "model_ops.evaluation.dataset.version",
  EVALUATION_DATASET_SIZE: "model_ops.evaluation.dataset.size",
  EVALUATION_METRICS: "model_ops.evaluation.metrics",
  EVALUATION_JUDGE_MODEL: "model_ops.evaluation.judge_model",
  EVALUATION_BASELINE_MODEL: "model_ops.evaluation.baseline_model",
  EVALUATION_REGRESSION_DETECTED: "model_ops.evaluation.regression_detected",
  EVALUATION_PASS: "model_ops.evaluation.pass",

  // Registry attributes
  REGISTRY_OPERATION: "model_ops.registry.operation",
  REGISTRY_MODEL_ID: "model_ops.registry.model_id",
  REGISTRY_MODEL_VERSION: "model_ops.registry.model_version",
  REGISTRY_MODEL_ALIAS: "model_ops.registry.model_alias",
  REGISTRY_STAGE: "model_ops.registry.stage",
  REGISTRY_PREVIOUS_STAGE: "model_ops.registry.previous_stage",
  REGISTRY_OWNER: "model_ops.registry.owner",
  REGISTRY_LINEAGE_TRAINING_RUN_ID: "model_ops.registry.lineage.training_run_id",
  REGISTRY_LINEAGE_PARENT_MODEL_ID: "model_ops.registry.lineage.parent_model_id",

  // Deployment attributes
  DEPLOYMENT_ID: "model_ops.deployment.id",
  DEPLOYMENT_MODEL_ID: "model_ops.deployment.model_id",
  DEPLOYMENT_STRATEGY: "model_ops.deployment.strategy",
  DEPLOYMENT_MODEL_VERSION: "model_ops.deployment.model_version",
  DEPLOYMENT_ENVIRONMENT: "model_ops.deployment.environment",
  DEPLOYMENT_ENDPOINT: "model_ops.deployment.endpoint",
  DEPLOYMENT_INFRA_PROVIDER: "model_ops.deployment.infrastructure.provider",
  DEPLOYMENT_INFRA_GPU_TYPE: "model_ops.deployment.infrastructure.gpu_type",
  DEPLOYMENT_INFRA_REPLICAS: "model_ops.deployment.infrastructure.replicas",
  DEPLOYMENT_CANARY_PERCENT: "model_ops.deployment.canary_percent",
  DEPLOYMENT_STATUS: "model_ops.deployment.status",
  DEPLOYMENT_HEALTH_STATUS: "model_ops.deployment.health_check.status",
  DEPLOYMENT_HEALTH_LATENCY: "model_ops.deployment.health_check.latency_ms",

  // Serving attributes
  SERVING_OPERATION: "model_ops.serving.operation",
  SERVING_ROUTE_SELECTED_MODEL: "model_ops.serving.route.selected_model",
  SERVING_ROUTE_REASON: "model_ops.serving.route.reason",
  SERVING_ROUTE_CANDIDATES: "model_ops.serving.route.candidates",
  SERVING_FALLBACK_CHAIN: "model_ops.serving.fallback.chain",
  SERVING_FALLBACK_DEPTH: "model_ops.serving.fallback.depth",
  SERVING_FALLBACK_TRIGGER: "model_ops.serving.fallback.trigger",
  SERVING_FALLBACK_ORIGINAL_MODEL: "model_ops.serving.fallback.original_model",
  SERVING_FALLBACK_FINAL_MODEL: "model_ops.serving.fallback.final_model",
  SERVING_CACHE_HIT: "model_ops.serving.cache.hit",
  SERVING_CACHE_TYPE: "model_ops.serving.cache.type",
  SERVING_CACHE_SIMILARITY_SCORE: "model_ops.serving.cache.similarity_score",
  SERVING_CACHE_COST_SAVED: "model_ops.serving.cache.cost_saved_usd",
  SERVING_CIRCUIT_BREAKER_STATE: "model_ops.serving.circuit_breaker.state",
  SERVING_CIRCUIT_BREAKER_MODEL: "model_ops.serving.circuit_breaker.model",

  // Monitoring attributes
  MONITORING_CHECK_TYPE: "model_ops.monitoring.check_type",
  MONITORING_MODEL_ID: "model_ops.monitoring.model_id",
  MONITORING_RESULT: "model_ops.monitoring.result",
  MONITORING_METRIC_NAME: "model_ops.monitoring.metric_name",
  MONITORING_METRIC_VALUE: "model_ops.monitoring.metric_value",
  MONITORING_BASELINE_VALUE: "model_ops.monitoring.baseline_value",
  MONITORING_DRIFT_SCORE: "model_ops.monitoring.drift_score",
  MONITORING_DRIFT_TYPE: "model_ops.monitoring.drift_type",
  MONITORING_ACTION_TRIGGERED: "model_ops.monitoring.action_triggered",

  // Prompt attributes
  PROMPT_NAME: "model_ops.prompt.name",
  PROMPT_OPERATION: "model_ops.prompt.operation",
  PROMPT_VERSION: "model_ops.prompt.version",
  PROMPT_CONTENT_HASH: "model_ops.prompt.content_hash",
  PROMPT_LABEL: "model_ops.prompt.label",
  PROMPT_MODEL_TARGET: "model_ops.prompt.model_target",
  PROMPT_EVAL_SCORE: "model_ops.prompt.evaluation.score",
  PROMPT_EVAL_PASS: "model_ops.prompt.evaluation.pass",
  PROMPT_AB_TEST_ID: "model_ops.prompt.a_b_test.id",
  PROMPT_AB_TEST_VARIANT: "model_ops.prompt.a_b_test.variant",

  /** Training type values */
  TrainingType: {
    PRE_TRAINING: "pre_training",
    FINE_TUNING: "fine_tuning",
    RLHF: "rlhf",
    DPO: "dpo",
    LORA: "lora",
    QLORA: "qlora",
    DISTILLATION: "distillation",
    CONTINUED_PRE_TRAINING: "continued_pre_training",
  },

  /** Deployment strategy values */
  DeploymentStrategy: {
    ROLLING: "rolling",
    CANARY: "canary",
    BLUE_GREEN: "blue_green",
    SHADOW: "shadow",
    AB_TEST: "a_b_test",
    IMMEDIATE: "immediate",
  },

  /** Drift type values */
  DriftType: {
    DATA: "data",
    PREDICTION: "prediction",
    CONCEPT: "concept",
    EMBEDDING: "embedding",
    FEATURE: "feature",
  },
} as const;

/** AITF Agentic Identity semantic convention attributes. */
export const IdentityAttributes = {
  // Core identity attributes
  AGENT_ID: "identity.agent_id",
  AGENT_NAME: "identity.agent_name",
  TYPE: "identity.type",
  PROVIDER: "identity.provider",
  OWNER: "identity.owner",
  OWNER_TYPE: "identity.owner_type",
  CREDENTIAL_TYPE: "identity.credential_type",
  CREDENTIAL_ID: "identity.credential_id",
  STATUS: "identity.status",
  PREVIOUS_STATUS: "identity.previous_status",
  SCOPE: "identity.scope",
  EXPIRES_AT: "identity.expires_at",
  TTL_SECONDS: "identity.ttl_seconds",
  AUTO_ROTATE: "identity.auto_rotate",
  ROTATION_INTERVAL: "identity.rotation_interval_seconds",

  // Lifecycle attributes
  LIFECYCLE_OPERATION: "identity.lifecycle.operation",

  // Authentication attributes
  AUTH_METHOD: "identity.auth.method",
  AUTH_RESULT: "identity.auth.result",
  AUTH_PROVIDER: "identity.auth.provider",
  AUTH_TARGET_SERVICE: "identity.auth.target_service",
  AUTH_FAILURE_REASON: "identity.auth.failure_reason",
  AUTH_TOKEN_TYPE: "identity.auth.token_type",
  AUTH_SCOPE_REQUESTED: "identity.auth.scope_requested",
  AUTH_SCOPE_GRANTED: "identity.auth.scope_granted",
  AUTH_CONTINUOUS: "identity.auth.continuous",
  AUTH_PKCE_USED: "identity.auth.pkce_used",
  AUTH_DPOP_USED: "identity.auth.dpop_used",

  // Authorization attributes
  AUTHZ_DECISION: "identity.authz.decision",
  AUTHZ_RESOURCE: "identity.authz.resource",
  AUTHZ_ACTION: "identity.authz.action",
  AUTHZ_POLICY_ENGINE: "identity.authz.policy_engine",
  AUTHZ_POLICY_ID: "identity.authz.policy_id",
  AUTHZ_DENY_REASON: "identity.authz.deny_reason",
  AUTHZ_RISK_SCORE: "identity.authz.risk_score",
  AUTHZ_PRIVILEGE_LEVEL: "identity.authz.privilege_level",
  AUTHZ_JEA: "identity.authz.jea",
  AUTHZ_TIME_LIMITED: "identity.authz.time_limited",
  AUTHZ_EXPIRES_AT: "identity.authz.expires_at",

  // Delegation attributes
  DELEGATION_DELEGATOR: "identity.delegation.delegator",
  DELEGATION_DELEGATOR_ID: "identity.delegation.delegator_id",
  DELEGATION_DELEGATEE: "identity.delegation.delegatee",
  DELEGATION_DELEGATEE_ID: "identity.delegation.delegatee_id",
  DELEGATION_TYPE: "identity.delegation.type",
  DELEGATION_CHAIN: "identity.delegation.chain",
  DELEGATION_CHAIN_DEPTH: "identity.delegation.chain_depth",
  DELEGATION_SCOPE_DELEGATED: "identity.delegation.scope_delegated",
  DELEGATION_SCOPE_ATTENUATED: "identity.delegation.scope_attenuated",
  DELEGATION_RESULT: "identity.delegation.result",
  DELEGATION_PROOF_TYPE: "identity.delegation.proof_type",
  DELEGATION_TTL_SECONDS: "identity.delegation.ttl_seconds",

  // Trust attributes
  TRUST_OPERATION: "identity.trust.operation",
  TRUST_PEER_AGENT: "identity.trust.peer_agent",
  TRUST_PEER_AGENT_ID: "identity.trust.peer_agent_id",
  TRUST_RESULT: "identity.trust.result",
  TRUST_METHOD: "identity.trust.method",
  TRUST_DOMAIN: "identity.trust.trust_domain",
  TRUST_PEER_DOMAIN: "identity.trust.peer_trust_domain",
  TRUST_CROSS_DOMAIN: "identity.trust.cross_domain",
  TRUST_LEVEL: "identity.trust.trust_level",
  TRUST_PROTOCOL: "identity.trust.protocol",

  // Session attributes
  SESSION_ID: "identity.session.id",
  SESSION_OPERATION: "identity.session.operation",
  SESSION_SCOPE: "identity.session.scope",
  SESSION_EXPIRES_AT: "identity.session.expires_at",
  SESSION_ACTIONS_COUNT: "identity.session.actions_count",
  SESSION_DELEGATIONS_COUNT: "identity.session.delegations_count",
  SESSION_TERMINATION_REASON: "identity.session.termination_reason",

  /** Identity type values */
  IdentityType: {
    PERSISTENT: "persistent",
    EPHEMERAL: "ephemeral",
    DELEGATED: "delegated",
    FEDERATED: "federated",
    WORKLOAD: "workload",
  },

  /** Auth method values */
  AuthMethod: {
    API_KEY: "api_key",
    OAUTH2: "oauth2",
    OAUTH2_PKCE: "oauth2_pkce",
    JWT_BEARER: "jwt_bearer",
    MTLS: "mtls",
    SPIFFE_SVID: "spiffe_svid",
    DID_VC: "did_vc",
    HTTP_SIGNATURE: "http_signature",
    TOKEN_EXCHANGE: "token_exchange",
  },

  /** Delegation type values */
  DelegationType: {
    ON_BEHALF_OF: "on_behalf_of",
    TOKEN_EXCHANGE: "token_exchange",
    CREDENTIAL_FORWARDING: "credential_forwarding",
    IMPERSONATION: "impersonation",
    CAPABILITY_GRANT: "capability_grant",
    SCOPED_PROXY: "scoped_proxy",
  },
} as const;

/** AITF AI Asset Inventory semantic convention attributes. */
export const AssetInventoryAttributes = {
  // Core asset attributes
  ID: "asset.id",
  NAME: "asset.name",
  TYPE: "asset.type",
  VERSION: "asset.version",
  HASH: "asset.hash",
  OWNER: "asset.owner",
  OWNER_TYPE: "asset.owner_type",
  DEPLOYMENT_ENVIRONMENT: "asset.deployment_environment",
  RISK_CLASSIFICATION: "asset.risk_classification",
  DESCRIPTION: "asset.description",
  TAGS: "asset.tags",
  SOURCE_REPOSITORY: "asset.source_repository",
  CREATED_AT: "asset.created_at",

  // Discovery attributes
  DISCOVERY_SCOPE: "asset.discovery.scope",
  DISCOVERY_METHOD: "asset.discovery.method",
  DISCOVERY_ASSETS_FOUND: "asset.discovery.assets_found",
  DISCOVERY_NEW_ASSETS: "asset.discovery.new_assets",
  DISCOVERY_SHADOW_ASSETS: "asset.discovery.shadow_assets",
  DISCOVERY_STATUS: "asset.discovery.status",

  // Audit attributes
  AUDIT_TYPE: "asset.audit.type",
  AUDIT_RESULT: "asset.audit.result",
  AUDIT_AUDITOR: "asset.audit.auditor",
  AUDIT_FRAMEWORK: "asset.audit.framework",
  AUDIT_FINDINGS: "asset.audit.findings",
  AUDIT_LAST_AUDIT_TIME: "asset.audit.last_audit_time",
  AUDIT_NEXT_AUDIT_DUE: "asset.audit.next_audit_due",
  AUDIT_RISK_SCORE: "asset.audit.risk_score",
  AUDIT_INTEGRITY_VERIFIED: "asset.audit.integrity_verified",
  AUDIT_COMPLIANCE_STATUS: "asset.audit.compliance_status",

  // Classification attributes
  CLASSIFICATION_FRAMEWORK: "asset.classification.framework",
  CLASSIFICATION_PREVIOUS: "asset.classification.previous",
  CLASSIFICATION_REASON: "asset.classification.reason",
  CLASSIFICATION_ASSESSOR: "asset.classification.assessor",
  CLASSIFICATION_USE_CASE: "asset.classification.use_case",
  CLASSIFICATION_AFFECTED_PERSONS: "asset.classification.affected_persons",
  CLASSIFICATION_SECTOR: "asset.classification.sector",
  CLASSIFICATION_BIOMETRIC: "asset.classification.biometric",
  CLASSIFICATION_AUTONOMOUS_DECISION: "asset.classification.autonomous_decision",

  // Dependency attributes
  DEPENDENCY_OPERATION: "asset.dependency.operation",
  DEPENDENCY_COUNT: "asset.dependency.count",
  DEPENDENCY_VULNERABLE_COUNT: "asset.dependency.vulnerable_count",

  // Decommission attributes
  DECOMMISSION_REASON: "asset.decommission.reason",
  DECOMMISSION_REPLACEMENT_ID: "asset.decommission.replacement_id",
  DECOMMISSION_DATA_RETENTION: "asset.decommission.data_retention",
  DECOMMISSION_APPROVED_BY: "asset.decommission.approved_by",

  /** Asset type values */
  AssetType: {
    MODEL: "model",
    DATASET: "dataset",
    PROMPT_TEMPLATE: "prompt_template",
    VECTOR_DB: "vector_db",
    MCP_SERVER: "mcp_server",
    AGENT: "agent",
    PIPELINE: "pipeline",
    GUARDRAIL: "guardrail",
    EMBEDDING_MODEL: "embedding_model",
    KNOWLEDGE_BASE: "knowledge_base",
  },

  /** Risk classification values */
  RiskClassification: {
    UNACCEPTABLE: "unacceptable",
    HIGH_RISK: "high_risk",
    LIMITED_RISK: "limited_risk",
    MINIMAL_RISK: "minimal_risk",
    SYSTEMIC: "systemic",
    NOT_CLASSIFIED: "not_classified",
  },

  /** Deployment environment values */
  DeploymentEnvironment: {
    PRODUCTION: "production",
    STAGING: "staging",
    DEVELOPMENT: "development",
    SHADOW: "shadow",
  },
} as const;

/** AITF Model Drift Detection semantic convention attributes. */
export const DriftDetectionAttributes = {
  MODEL_ID: "drift.model_id",
  TYPE: "drift.type",
  SCORE: "drift.score",
  RESULT: "drift.result",
  DETECTION_METHOD: "drift.detection_method",
  BASELINE_METRIC: "drift.baseline_metric",
  CURRENT_METRIC: "drift.current_metric",
  METRIC_NAME: "drift.metric_name",
  THRESHOLD: "drift.threshold",
  P_VALUE: "drift.p_value",
  REFERENCE_DATASET: "drift.reference_dataset",
  REFERENCE_PERIOD: "drift.reference_period",
  EVALUATION_WINDOW: "drift.evaluation_window",
  SAMPLE_SIZE: "drift.sample_size",
  AFFECTED_SEGMENTS: "drift.affected_segments",
  FEATURE_NAME: "drift.feature_name",
  FEATURE_IMPORTANCE: "drift.feature_importance",
  ACTION_TRIGGERED: "drift.action_triggered",

  BASELINE_OPERATION: "drift.baseline.operation",
  BASELINE_ID: "drift.baseline.id",
  BASELINE_DATASET: "drift.baseline.dataset",
  BASELINE_SAMPLE_SIZE: "drift.baseline.sample_size",
  BASELINE_PERIOD: "drift.baseline.period",
  BASELINE_METRICS: "drift.baseline.metrics",
  BASELINE_FEATURES: "drift.baseline.features",
  BASELINE_PREVIOUS_ID: "drift.baseline.previous_id",

  INVESTIGATION_TRIGGER_ID: "drift.investigation.trigger_id",
  INVESTIGATION_ROOT_CAUSE: "drift.investigation.root_cause",
  INVESTIGATION_ROOT_CAUSE_CATEGORY: "drift.investigation.root_cause_category",
  INVESTIGATION_AFFECTED_SEGMENTS: "drift.investigation.affected_segments",
  INVESTIGATION_AFFECTED_USERS: "drift.investigation.affected_users_estimate",
  INVESTIGATION_BLAST_RADIUS: "drift.investigation.blast_radius",
  INVESTIGATION_SEVERITY: "drift.investigation.severity",
  INVESTIGATION_RECOMMENDATION: "drift.investigation.recommendation",

  REMEDIATION_ACTION: "drift.remediation.action",
  REMEDIATION_TRIGGER_ID: "drift.remediation.trigger_id",
  REMEDIATION_AUTOMATED: "drift.remediation.automated",
  REMEDIATION_INITIATED_BY: "drift.remediation.initiated_by",
  REMEDIATION_STATUS: "drift.remediation.status",
  REMEDIATION_ROLLBACK_TO: "drift.remediation.rollback_to",
  REMEDIATION_RETRAIN_DATASET: "drift.remediation.retrain_dataset",
  REMEDIATION_VALIDATION_PASSED: "drift.remediation.validation_passed",

  /** Drift type values */
  DriftType: {
    DATA_DISTRIBUTION: "data_distribution",
    CONCEPT: "concept",
    PERFORMANCE: "performance",
    CALIBRATION: "calibration",
    EMBEDDING: "embedding",
    FEATURE: "feature",
    PREDICTION: "prediction",
    LABEL: "label",
  },

  /** Detection method values */
  DetectionMethod: {
    PSI: "psi",
    KS_TEST: "ks_test",
    CHI_SQUARED: "chi_squared",
    JS_DIVERGENCE: "js_divergence",
    KL_DIVERGENCE: "kl_divergence",
    WASSERSTEIN: "wasserstein",
    MMD: "mmd",
    ADWIN: "adwin",
    DDM: "ddm",
    PAGE_HINKLEY: "page_hinkley",
    CUSTOM: "custom",
  },

  /** Remediation action values */
  RemediationAction: {
    RETRAIN: "retrain",
    ROLLBACK: "rollback",
    RECALIBRATE: "recalibrate",
    FEATURE_GATE: "feature_gate",
    TRAFFIC_SHIFT: "traffic_shift",
    ALERT_ONLY: "alert_only",
    QUARANTINE: "quarantine",
  },
} as const;

/** AITF Memory Security semantic convention attributes (extends aitf.memory.*). */
export const MemorySecurityAttributes = {
  CONTENT_HASH: "memory.security.content_hash",
  CONTENT_SIZE: "memory.security.content_size",
  INTEGRITY_HASH: "memory.security.integrity_hash",
  PROVENANCE_VERIFIED: "memory.security.provenance_verified",
  POISONING_SCORE: "memory.security.poisoning_score",
  CROSS_SESSION: "memory.security.cross_session",
  ISOLATION_VERIFIED: "memory.security.isolation_verified",
  MUTATION_COUNT: "memory.security.mutation_count",
  SNAPSHOT_BEFORE: "memory.security.snapshot_before",
  SNAPSHOT_AFTER: "memory.security.snapshot_after",
} as const;

/** AITF A2A (Agent-to-Agent Protocol) semantic convention attributes. */
export const A2AAttributes = {
  // Agent Card / Discovery
  AGENT_NAME: "a2a.agent.name",
  AGENT_URL: "a2a.agent.url",
  AGENT_VERSION: "a2a.agent.version",
  AGENT_PROVIDER_ORG: "a2a.agent.provider.organization",
  AGENT_SKILLS: "a2a.agent.skills",
  AGENT_CAPABILITIES_STREAMING: "a2a.agent.capabilities.streaming",
  AGENT_CAPABILITIES_PUSH: "a2a.agent.capabilities.push_notifications",
  PROTOCOL_VERSION: "a2a.protocol.version",
  TRANSPORT: "a2a.transport",

  // Task
  TASK_ID: "a2a.task.id",
  TASK_CONTEXT_ID: "a2a.task.context_id",
  TASK_STATE: "a2a.task.state",
  TASK_PREVIOUS_STATE: "a2a.task.previous_state",
  TASK_ARTIFACTS_COUNT: "a2a.task.artifacts_count",
  TASK_HISTORY_LENGTH: "a2a.task.history_length",

  // Message
  MESSAGE_ID: "a2a.message.id",
  MESSAGE_ROLE: "a2a.message.role",
  MESSAGE_PARTS_COUNT: "a2a.message.parts_count",
  MESSAGE_PART_TYPES: "a2a.message.part_types",

  // Operation
  METHOD: "a2a.method",
  INTERACTION_MODE: "a2a.interaction_mode",
  JSONRPC_REQUEST_ID: "a2a.jsonrpc.request_id",
  JSONRPC_ERROR_CODE: "a2a.jsonrpc.error_code",
  JSONRPC_ERROR_MESSAGE: "a2a.jsonrpc.error_message",

  // Artifact
  ARTIFACT_ID: "a2a.artifact.id",
  ARTIFACT_NAME: "a2a.artifact.name",
  ARTIFACT_PARTS_COUNT: "a2a.artifact.parts_count",

  // Streaming
  STREAM_EVENT_TYPE: "a2a.stream.event_type",
  STREAM_IS_FINAL: "a2a.stream.is_final",
  STREAM_EVENTS_COUNT: "a2a.stream.events_count",

  // Push notifications
  PUSH_URL: "a2a.push.url",

  /** Task state values */
  TaskState: {
    SUBMITTED: "submitted",
    WORKING: "working",
    INPUT_REQUIRED: "input-required",
    COMPLETED: "completed",
    CANCELED: "canceled",
    FAILED: "failed",
    REJECTED: "rejected",
    AUTH_REQUIRED: "auth-required",
  },

  /** Interaction mode values */
  InteractionMode: {
    SYNC: "sync",
    STREAM: "stream",
    PUSH: "push",
  },

  /** Transport values */
  Transport: {
    JSONRPC: "jsonrpc",
    GRPC: "grpc",
    HTTP_JSON: "http_json",
  },
} as const;

/** AITF ACP (Agent Communication Protocol) semantic convention attributes. */
export const ACPAttributes = {
  // Agent discovery
  AGENT_NAME: "acp.agent.name",
  AGENT_DESCRIPTION: "acp.agent.description",
  AGENT_INPUT_CONTENT_TYPES: "acp.agent.input_content_types",
  AGENT_OUTPUT_CONTENT_TYPES: "acp.agent.output_content_types",
  AGENT_FRAMEWORK: "acp.agent.framework",
  AGENT_SUCCESS_RATE: "acp.agent.status.success_rate",
  AGENT_AVG_RUN_TIME: "acp.agent.status.avg_run_time_seconds",

  // Run
  RUN_ID: "acp.run.id",
  RUN_AGENT_NAME: "acp.run.agent_name",
  RUN_SESSION_ID: "acp.run.session_id",
  RUN_MODE: "acp.run.mode",
  RUN_STATUS: "acp.run.status",
  RUN_PREVIOUS_STATUS: "acp.run.previous_status",
  RUN_ERROR_CODE: "acp.run.error.code",
  RUN_ERROR_MESSAGE: "acp.run.error.message",
  RUN_CREATED_AT: "acp.run.created_at",
  RUN_FINISHED_AT: "acp.run.finished_at",
  RUN_DURATION_MS: "acp.run.duration_ms",

  // Message
  MESSAGE_ROLE: "acp.message.role",
  MESSAGE_PARTS_COUNT: "acp.message.parts_count",
  MESSAGE_CONTENT_TYPES: "acp.message.content_types",
  MESSAGE_HAS_CITATIONS: "acp.message.has_citations",
  MESSAGE_HAS_TRAJECTORY: "acp.message.has_trajectory",

  // Await/Resume
  AWAIT_ACTIVE: "acp.await.active",
  AWAIT_COUNT: "acp.await.count",
  AWAIT_DURATION_MS: "acp.await.duration_ms",

  // I/O counts
  INPUT_MESSAGE_COUNT: "acp.input.message_count",
  OUTPUT_MESSAGE_COUNT: "acp.output.message_count",

  // Operation
  OPERATION: "acp.operation",
  HTTP_METHOD: "acp.http.method",
  HTTP_STATUS_CODE: "acp.http.status_code",
  HTTP_URL: "acp.http.url",

  // Trajectory metadata
  TRAJECTORY_TOOL_NAME: "acp.trajectory.tool_name",
  TRAJECTORY_MESSAGE: "acp.trajectory.message",

  /** Run status values */
  RunStatus: {
    CREATED: "created",
    IN_PROGRESS: "in-progress",
    AWAITING: "awaiting",
    CANCELLING: "cancelling",
    CANCELLED: "cancelled",
    COMPLETED: "completed",
    FAILED: "failed",
  },

  /** Run mode values */
  RunMode: {
    SYNC: "sync",
    ASYNC: "async",
    STREAM: "stream",
  },
} as const;

/**
 * AITF Agentic Log semantic convention attributes.
 *
 * Based on Table 10.1: Agentic log with minimum fields.
 * These attributes capture the essential security-relevant context
 * for every action taken by an AI agent.
 */
export const AgenticLogAttributes = {
  /** EventID: A unique identifier for the specific log entry */
  EVENT_ID: "agentic_log.event_id",

  /** Timestamp: ISO 8601 formatted timestamp with millisecond precision */
  TIMESTAMP: "agentic_log.timestamp",

  /** AgentID: The unique, cryptographically verifiable identity of the agent */
  AGENT_ID: "agentic_log.agent_id",

  /** SessionID: A unique ID for the agent's current operational session */
  SESSION_ID: "agentic_log.session_id",

  /** GoalID: An identifier for the high-level goal the agent is pursuing */
  GOAL_ID: "agentic_log.goal_id",

  /** SubTaskID: The specific, immediate task the agent is performing */
  SUB_TASK_ID: "agentic_log.sub_task_id",

  /** ToolUsed: The specific tool, function, or API being invoked */
  TOOL_USED: "agentic_log.tool_used",

  /** ToolParameters: Sanitized log of parameters (PII/credentials redacted) */
  TOOL_PARAMETERS: "agentic_log.tool_parameters",

  /** Outcome: The result of the action (success, failure, error code) */
  OUTCOME: "agentic_log.outcome",

  /** ConfidenceScore: Agent's assessment of how likely the action succeeds */
  CONFIDENCE_SCORE: "agentic_log.confidence_score",

  /** AnomalyScore: Score indicating how unusual this action is */
  ANOMALY_SCORE: "agentic_log.anomaly_score",

  /** PolicyEvaluation: Record of a check against a security policy engine */
  POLICY_EVALUATION: "agentic_log.policy_evaluation",

  /** Outcome values */
  Outcome: {
    SUCCESS: "SUCCESS",
    FAILURE: "FAILURE",
    ERROR: "ERROR",
    DENIED: "DENIED",
    TIMEOUT: "TIMEOUT",
    PARTIAL: "PARTIAL",
  },

  /** Policy evaluation result values */
  PolicyResult: {
    PASS: "PASS",
    FAIL: "FAIL",
    WARN: "WARN",
    SKIP: "SKIP",
  },
} as const;
