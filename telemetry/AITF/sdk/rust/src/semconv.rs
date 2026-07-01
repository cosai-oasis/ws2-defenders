//! AITF semantic convention constants.
//!
//! Attribute key string constants used across AITF instrumentation, processors,
//! and exporters. OTel GenAI attributes (`gen_ai.*`) are preserved for
//! compatibility; AITF extensions use dedicated namespaces. Values mirror the
//! Go (`semconv/attributes.go`) and Python (`semantic_conventions/attributes.py`)
//! SDKs exactly.

/// OTel GenAI attributes (preserved) plus AITF GenAI extensions.
pub mod gen_ai {
    pub const SYSTEM: &str = "gen_ai.provider.name";
    pub const PROVIDER_NAME: &str = "gen_ai.provider.name";
    pub const OPERATION_NAME: &str = "gen_ai.operation.name";

    // Prompt management
    pub const PROMPT_VERSION: &str = "gen_ai.prompt.version";
    pub const PROMPT_LABEL: &str = "gen_ai.prompt.label";

    // End-user / tagging (general; e.g. Langfuse userId / tags)
    pub const USER_ID: &str = "user.id";
    pub const TAGS: &str = "tags";

    // Evaluation
    pub const EVALUATION_NAME: &str = "gen_ai.evaluation.name";
    pub const EVALUATION_SCORE_VALUE: &str = "gen_ai.evaluation.score.value";
    pub const EVALUATION_SCORE_LABEL: &str = "gen_ai.evaluation.score.label";
    pub const EVALUATION_EXPLANATION: &str = "gen_ai.evaluation.explanation";
    pub const EVALUATION_SCORE_DATA_TYPE: &str = "gen_ai.evaluation.score.data_type";
    pub const EVALUATION_SOURCE: &str = "gen_ai.evaluation.source";
    pub const EVALUATION_COMMENT: &str = "gen_ai.evaluation.comment";
    pub const EVALUATION_DATASET_ITEM_ID: &str = "gen_ai.evaluation.dataset.item_id";

    // Request
    pub const REQUEST_MODEL: &str = "gen_ai.request.model";
    pub const REQUEST_MAX_TOKENS: &str = "gen_ai.request.max_tokens";
    pub const REQUEST_TEMPERATURE: &str = "gen_ai.request.temperature";
    pub const REQUEST_TOP_P: &str = "gen_ai.request.top_p";
    pub const REQUEST_TOP_K: &str = "gen_ai.request.top_k";
    pub const REQUEST_STREAM: &str = "gen_ai.request.stream";
    pub const REQUEST_TOOLS: &str = "gen_ai.request.tools";
    pub const REQUEST_TOOL_CHOICE: &str = "gen_ai.request.tool_choice";
    pub const REQUEST_RESPONSE_FORMAT: &str = "gen_ai.request.response_format";
    pub const REQUEST_FREQUENCY_PENALTY: &str = "gen_ai.request.frequency_penalty";
    pub const REQUEST_PRESENCE_PENALTY: &str = "gen_ai.request.presence_penalty";
    pub const REQUEST_SEED: &str = "gen_ai.request.seed";

    // Response
    pub const RESPONSE_ID: &str = "gen_ai.response.id";
    pub const RESPONSE_MODEL: &str = "gen_ai.response.model";
    pub const RESPONSE_FINISH_REASONS: &str = "gen_ai.response.finish_reasons";

    // Usage
    pub const USAGE_INPUT_TOKENS: &str = "gen_ai.usage.input_tokens";
    pub const USAGE_OUTPUT_TOKENS: &str = "gen_ai.usage.output_tokens";
    pub const USAGE_CACHED_TOKENS: &str = "gen_ai.usage.cached_tokens";
    pub const USAGE_REASONING_TOKENS: &str = "gen_ai.usage.reasoning_tokens";

    // System prompt hash (CoSAI WS2: AI_INTERACTION)
    pub const SYSTEM_PROMPT_HASH: &str = "gen_ai.system_prompt.hash";

    // Events
    pub const PROMPT: &str = "gen_ai.prompt";
    pub const COMPLETION: &str = "gen_ai.completion";
    pub const TOOL_NAME: &str = "gen_ai.tool.name";
    pub const TOOL_CALL_ID: &str = "gen_ai.tool.call_id";
    pub const TOOL_ARGUMENTS: &str = "gen_ai.tool.arguments";
    pub const TOOL_RESULT: &str = "gen_ai.tool.result";
    pub const TOOL_CALL_ARGUMENTS: &str = "gen_ai.tool.call.arguments";
    pub const TOOL_CALL_RESULT: &str = "gen_ai.tool.call.result";

    // Data source / RAG
    pub const DATA_SOURCE_ID: &str = "gen_ai.data_source.id";
}

/// AITF agent attributes.
pub mod agent {
    pub const NAME: &str = "gen_ai.agent.name";
    pub const ID: &str = "gen_ai.agent.id";
    pub const TYPE: &str = "agent.type";
    pub const FRAMEWORK: &str = "agent.framework";
    pub const VERSION: &str = "agent.version";
    pub const DESCRIPTION: &str = "gen_ai.agent.description";

    pub const SESSION_ID: &str = "gen_ai.conversation.id";
    pub const CONVERSATION_ID: &str = "gen_ai.conversation.id";
    pub const SESSION_TURN_COUNT: &str = "agent.session.turn_count";

    pub const WORKFLOW_ID: &str = "agent.workflow_id";
    pub const STATE: &str = "agent.state";
    pub const SCRATCHPAD: &str = "agent.scratchpad";
    pub const NEXT_ACTION: &str = "agent.next_action";

    pub const STEP_TYPE: &str = "agent.step.type";
    pub const STEP_INDEX: &str = "agent.step.index";
    pub const STEP_THOUGHT: &str = "agent.step.thought";
    pub const STEP_ACTION: &str = "agent.step.action";
    pub const STEP_OBSERVATION: &str = "agent.step.observation";
    pub const STEP_STATUS: &str = "agent.step.status";

    pub const DELEGATION_TARGET_AGENT: &str = "agent.delegation.target_agent";
    pub const DELEGATION_TARGET_AGENT_ID: &str = "agent.delegation.target_agent_id";
    pub const DELEGATION_REASON: &str = "agent.delegation.reason";
    pub const DELEGATION_STRATEGY: &str = "agent.delegation.strategy";
    pub const DELEGATION_TASK: &str = "agent.delegation.task";

    pub const TEAM_NAME: &str = "agent.team.name";
    pub const TEAM_ID: &str = "agent.team.id";
    pub const TEAM_TOPOLOGY: &str = "agent.team.topology";
    pub const TEAM_COORDINATOR: &str = "agent.team.coordinator";
    pub const TEAM_CONSENSUS_METHOD: &str = "agent.team.consensus_method";
}

/// AITF MCP attributes.
pub mod mcp {
    pub const SERVER_NAME: &str = "mcp.server.name";
    pub const SERVER_VERSION: &str = "mcp.server.version";
    pub const SERVER_TRANSPORT: &str = "mcp.server.transport";
    pub const SERVER_URL: &str = "mcp.server.url";
    pub const PROTOCOL_VERSION: &str = "mcp.protocol.version";

    pub const TOOL_NAME: &str = "gen_ai.tool.name";
    pub const TOOL_SERVER: &str = "mcp.tool.server";
    pub const TOOL_INPUT: &str = "gen_ai.tool.call.arguments";
    pub const TOOL_OUTPUT: &str = "gen_ai.tool.call.result";
    pub const TOOL_IS_ERROR: &str = "mcp.tool.is_error";
    pub const TOOL_DURATION_MS: &str = "mcp.tool.duration_ms";
    pub const TOOL_APPROVAL_REQUIRED: &str = "mcp.tool.approval_required";
    pub const TOOL_APPROVED: &str = "mcp.tool.approved";
    pub const TOOL_COUNT: &str = "mcp.tool.count";

    pub const RESOURCE_URI: &str = "mcp.resource.uri";
    pub const RESOURCE_NAME: &str = "mcp.resource.name";
    pub const RESOURCE_MIME_TYPE: &str = "mcp.resource.mime_type";
}

/// AITF skill attributes.
pub mod skill {
    pub const NAME: &str = "skill.name";
    pub const ID: &str = "skill.id";
    pub const VERSION: &str = "skill.version";
    pub const PROVIDER: &str = "skill.provider";
    pub const CATEGORY: &str = "skill.category";
    pub const DESCRIPTION: &str = "skill.description";
    pub const INPUT: &str = "skill.input";
    pub const OUTPUT: &str = "skill.output";
    pub const STATUS: &str = "skill.status";
    pub const DURATION_MS: &str = "skill.duration_ms";
}

/// AITF RAG attributes.
pub mod rag {
    pub const PIPELINE_NAME: &str = "rag.pipeline.name";
    pub const PIPELINE_STAGE: &str = "rag.pipeline.stage";
    pub const QUERY: &str = "rag.query";

    pub const RETRIEVE_DATABASE: &str = "gen_ai.data_source.id";
    pub const RETRIEVE_INDEX: &str = "rag.retrieve.index";
    pub const RETRIEVE_TOP_K: &str = "rag.retrieve.top_k";
    pub const RETRIEVE_RESULTS_COUNT: &str = "rag.retrieve.results_count";
    pub const RETRIEVE_MIN_SCORE: &str = "rag.retrieve.min_score";
    pub const RETRIEVE_MAX_SCORE: &str = "rag.retrieve.max_score";
    pub const RETRIEVE_FILTER: &str = "rag.retrieve.filter";
}

/// AITF security attributes.
pub mod security {
    pub const RISK_SCORE: &str = "security.risk_score";
    pub const RISK_LEVEL: &str = "security.risk_level";
    pub const THREAT_DETECTED: &str = "security.threat_detected";
    pub const THREAT_TYPE: &str = "security.threat_type";
    pub const OWASP_CATEGORY: &str = "security.owasp_category";
    pub const BLOCKED: &str = "security.blocked";
    pub const DETECTION_METHOD: &str = "security.detection_method";
    pub const CONFIDENCE: &str = "security.confidence";
}

/// AITF supply-chain attributes.
pub mod supply_chain {
    pub const MODEL_SOURCE: &str = "supply_chain.model_source";
    pub const MODEL_HASH: &str = "supply_chain.model_hash";
    pub const MODEL_LICENSE: &str = "supply_chain.model_license";
    pub const MODEL_SIGNED: &str = "supply_chain.model_signed";
    pub const MODEL_SIGNER: &str = "supply_chain.model_signer";
    pub const AI_BOM_ID: &str = "supply_chain.ai_bom_id";
    pub const AI_BOM_COMPONENTS: &str = "supply_chain.ai_bom_components";
}

/// AITF compliance framework attributes.
pub mod compliance {
    pub const FRAMEWORKS: &str = "compliance.frameworks";
    pub const NIST_CONTROLS: &str = "compliance.nist_ai_rmf.controls";
    pub const MITRE_TECHNIQUES: &str = "compliance.mitre_atlas.techniques";
    pub const ISO_CONTROLS: &str = "compliance.iso_42001.controls";
    pub const EU_ARTICLES: &str = "compliance.eu_ai_act.articles";
    pub const SOC2_CONTROLS: &str = "compliance.soc2.controls";
    pub const GDPR_ARTICLES: &str = "compliance.gdpr.articles";
    pub const CCPA_SECTIONS: &str = "compliance.ccpa.sections";
    pub const CSA_AICM_CONTROLS: &str = "compliance.csa_aicm.controls";
}

/// AITF latency attributes.
pub mod latency {
    pub const TOTAL_MS: &str = "latency.total_ms";
    pub const TIME_TO_FIRST_TOKEN_MS: &str = "latency.time_to_first_token_ms";
    pub const TOKENS_PER_SECOND: &str = "latency.tokens_per_second";
    pub const QUEUE_TIME_MS: &str = "latency.queue_time_ms";
    pub const INFERENCE_TIME_MS: &str = "latency.inference_time_ms";
}

/// AITF cost attributes.
pub mod cost {
    pub const INPUT_COST: &str = "cost.input_cost";
    pub const OUTPUT_COST: &str = "cost.output_cost";
    pub const TOTAL_COST: &str = "cost.total_cost";
    pub const CURRENCY: &str = "cost.currency";
}

/// AITF quality attributes.
pub mod quality {
    pub const HALLUCINATION_SCORE: &str = "quality.hallucination_score";
    pub const CONFIDENCE: &str = "quality.confidence";
    pub const FACTUALITY: &str = "quality.factuality";
    pub const TOXICITY_SCORE: &str = "quality.toxicity_score";
    pub const FEEDBACK_RATING: &str = "quality.feedback.rating";
    pub const FEEDBACK_THUMBS: &str = "quality.feedback.thumbs";
}

/// AITF model-operations attributes (subset used by the mapper).
pub mod model_ops {
    pub const TRAINING_RUN_ID: &str = "model_ops.training.run_id";
    pub const TRAINING_TYPE: &str = "model_ops.training.type";
    pub const TRAINING_BASE_MODEL: &str = "model_ops.training.base_model";
    pub const TRAINING_DATASET_ID: &str = "model_ops.training.dataset.id";
    pub const TRAINING_EPOCHS: &str = "model_ops.training.epochs";
    pub const TRAINING_LOSS_FINAL: &str = "model_ops.training.loss_final";
    pub const TRAINING_OUTPUT_MODEL_ID: &str = "model_ops.training.output_model.id";
    pub const TRAINING_STATUS: &str = "model_ops.training.status";

    pub const EVALUATION_RUN_ID: &str = "model_ops.evaluation.run_id";
    pub const EVALUATION_MODEL_ID: &str = "model_ops.evaluation.model_id";
    pub const EVALUATION_TYPE: &str = "model_ops.evaluation.type";
    pub const EVALUATION_METRICS: &str = "model_ops.evaluation.metrics";
    pub const EVALUATION_PASS: &str = "model_ops.evaluation.pass";

    pub const REGISTRY_MODEL_ID: &str = "model_ops.registry.model_id";

    pub const DEPLOYMENT_ID: &str = "model_ops.deployment.id";
    pub const DEPLOYMENT_MODEL_ID: &str = "model_ops.deployment.model_id";
    pub const DEPLOYMENT_STRATEGY: &str = "model_ops.deployment.strategy";
    pub const DEPLOYMENT_ENVIRONMENT: &str = "model_ops.deployment.environment";
    pub const DEPLOYMENT_ENDPOINT: &str = "model_ops.deployment.endpoint";
    pub const DEPLOYMENT_STATUS: &str = "model_ops.deployment.status";

    pub const SERVING_ROUTE_SELECTED_MODEL: &str = "model_ops.serving.route.selected_model";
    pub const SERVING_FALLBACK_CHAIN: &str = "model_ops.serving.fallback.chain";
    pub const SERVING_CACHE_HIT: &str = "model_ops.serving.cache.hit";

    pub const MONITORING_CHECK_TYPE: &str = "model_ops.monitoring.check_type";
    pub const MONITORING_DRIFT_SCORE: &str = "model_ops.monitoring.drift_score";
    pub const MONITORING_DRIFT_TYPE: &str = "model_ops.monitoring.drift_type";
    pub const MONITORING_ACTION_TRIGGERED: &str = "model_ops.monitoring.action_triggered";
}

/// AITF drift-detection attributes (subset used by the mapper).
pub mod drift {
    pub const MODEL_ID: &str = "drift.model_id";
    pub const TYPE: &str = "drift.type";
    pub const SCORE: &str = "drift.score";
    pub const ACTION_TRIGGERED: &str = "drift.action_triggered";
}

/// AITF asset-inventory attributes.
pub mod asset_inventory {
    pub const ID: &str = "asset.id";
    pub const NAME: &str = "asset.name";
    pub const TYPE: &str = "asset.type";
    pub const VERSION: &str = "asset.version";
    pub const OWNER: &str = "asset.owner";
    pub const DEPLOYMENT_ENVIRONMENT: &str = "asset.deployment_environment";
    pub const RISK_CLASSIFICATION: &str = "asset.risk_classification";

    pub const DISCOVERY_SCOPE: &str = "asset.discovery.scope";
    pub const DISCOVERY_METHOD: &str = "asset.discovery.method";
    pub const DISCOVERY_ASSETS_FOUND: &str = "asset.discovery.assets_found";
    pub const DISCOVERY_NEW_ASSETS: &str = "asset.discovery.new_assets";
    pub const DISCOVERY_SHADOW_ASSETS: &str = "asset.discovery.shadow_assets";

    pub const AUDIT_TYPE: &str = "asset.audit.type";
    pub const AUDIT_RESULT: &str = "asset.audit.result";
    pub const AUDIT_FRAMEWORK: &str = "asset.audit.framework";
    pub const AUDIT_FINDINGS: &str = "asset.audit.findings";

    pub const CLASSIFICATION_FRAMEWORK: &str = "asset.classification.framework";
    pub const CLASSIFICATION_PREVIOUS: &str = "asset.classification.previous";
    pub const CLASSIFICATION_REASON: &str = "asset.classification.reason";
}

/// AITF identity attributes (subset used by the mapper / crosswalk).
pub mod identity {
    pub const AGENT_ID: &str = "identity.agent_id";
    pub const AGENT_NAME: &str = "identity.agent_name";
    pub const TYPE: &str = "identity.type";
    pub const PROVIDER: &str = "identity.provider";
    pub const CREDENTIAL_TYPE: &str = "identity.credential_type";
    pub const SCOPE: &str = "identity.scope";

    pub const AUTH_METHOD: &str = "identity.auth.method";
    pub const AUTH_RESULT: &str = "identity.auth.result";

    pub const DELEGATION_DELEGATOR: &str = "identity.delegation.delegator";
    pub const DELEGATION_DELEGATOR_ID: &str = "identity.delegation.delegator_id";
    pub const DELEGATION_DELEGATEE: &str = "identity.delegation.delegatee";
    pub const DELEGATION_DELEGATEE_ID: &str = "identity.delegation.delegatee_id";
    pub const DELEGATION_TYPE: &str = "identity.delegation.type";
    pub const DELEGATION_CHAIN: &str = "identity.delegation.chain";
    pub const DELEGATION_SCOPE_DELEGATED: &str = "identity.delegation.scope_delegated";
    pub const DELEGATION_PROOF_TYPE: &str = "identity.delegation.proof_type";
    pub const DELEGATION_TTL_SECONDS: &str = "identity.delegation.ttl_seconds";
}

/// AITF A2A (Agent-to-Agent Protocol) attributes.
pub mod a2a {
    pub const AGENT_NAME: &str = "a2a.agent.name";
    pub const AGENT_URL: &str = "a2a.agent.url";
    pub const AGENT_VERSION: &str = "a2a.agent.version";
    pub const PROTOCOL_VERSION: &str = "a2a.protocol.version";
    pub const TRANSPORT: &str = "a2a.transport";

    pub const TASK_ID: &str = "a2a.task.id";
    pub const TASK_STATE: &str = "a2a.task.state";
    pub const TASK_PREVIOUS_STATE: &str = "a2a.task.previous_state";
    pub const TASK_ARTIFACTS_COUNT: &str = "a2a.task.artifacts_count";

    pub const MESSAGE_ID: &str = "a2a.message.id";
    pub const MESSAGE_PARTS_COUNT: &str = "a2a.message.parts_count";
    pub const MESSAGE_PART_TYPES: &str = "a2a.message.part_types";

    pub const METHOD: &str = "a2a.method";
    pub const INTERACTION_MODE: &str = "a2a.interaction_mode";
    pub const JSONRPC_ERROR_CODE: &str = "a2a.jsonrpc.error_code";
    pub const JSONRPC_ERROR_MESSAGE: &str = "a2a.jsonrpc.error_message";
}

/// AITF ACP (Agent Communication Protocol) attributes.
pub mod acp {
    pub const AGENT_NAME: &str = "acp.agent.name";
    pub const RUN_ID: &str = "acp.run.id";
    pub const RUN_MODE: &str = "acp.run.mode";
    pub const RUN_STATUS: &str = "acp.run.status";
    pub const RUN_PREVIOUS_STATUS: &str = "acp.run.previous_status";
    pub const RUN_ERROR_CODE: &str = "acp.run.error.code";
    pub const RUN_ERROR_MESSAGE: &str = "acp.run.error.message";
    pub const RUN_DURATION_MS: &str = "acp.run.duration_ms";

    pub const MESSAGE_PARTS_COUNT: &str = "acp.message.parts_count";
    pub const MESSAGE_CONTENT_TYPES: &str = "acp.message.content_types";

    pub const OPERATION: &str = "acp.operation";
    pub const HTTP_URL: &str = "acp.http.url";
}

/// AITF ANP (Agent Network Protocol) attributes.
pub mod anp {
    pub const PROTOCOL_VERSION: &str = "anp.protocol.version";
    pub const TRANSPORT: &str = "anp.transport";

    pub const DID: &str = "anp.did";
    pub const PEER_DID: &str = "anp.peer.did";

    pub const META_PROTOCOL_NAME: &str = "anp.meta_protocol.name";

    pub const MESSAGE_ID: &str = "anp.message.id";
    pub const MESSAGE_TYPE: &str = "anp.message.type";
    pub const MESSAGE_PARTS_COUNT: &str = "anp.message.parts_count";

    pub const TRUST_DOMAIN: &str = "anp.trust.domain";
    pub const PEER_TRUST_DOMAIN: &str = "anp.trust.peer_domain";
    pub const CROSS_DOMAIN: &str = "anp.trust.cross_domain";

    pub const ERROR_CODE: &str = "anp.error.code";
    pub const ERROR_MESSAGE: &str = "anp.error.message";
}

/// AITF canonical agent-communication attributes — a single, protocol-agnostic
/// namespace that A2A / ACP / ANP (and future protocols) normalize onto.
pub mod agent_comm {
    pub const PROTOCOL: &str = "agent.comm.protocol";
    pub const PROTOCOL_VERSION: &str = "agent.comm.protocol_version";
    pub const DIRECTION: &str = "agent.comm.direction";
    pub const ROLE: &str = "agent.comm.role";
    pub const OPERATION: &str = "agent.comm.operation";
    pub const UNIT_ID: &str = "agent.comm.unit_id";
    pub const UNIT_TYPE: &str = "agent.comm.unit_type";
    pub const STATUS: &str = "agent.comm.status";
    pub const PREVIOUS_STATUS: &str = "agent.comm.previous_status";
    pub const SRC_AGENT_ID: &str = "agent.comm.src_agent_id";
    pub const SRC_AGENT_NAME: &str = "agent.comm.src_agent_name";
    pub const PEER_AGENT_ID: &str = "agent.comm.peer_agent_id";
    pub const PEER_AGENT_NAME: &str = "agent.comm.peer_agent_name";
    pub const PEER_DID: &str = "agent.comm.peer_did";
    pub const PARTS_COUNT: &str = "agent.comm.parts_count";
    pub const PART_TYPES: &str = "agent.comm.part_types";
    pub const ARTIFACTS_COUNT: &str = "agent.comm.artifacts_count";
    pub const TRANSPORT: &str = "agent.comm.transport";
    pub const ENDPOINT: &str = "agent.comm.endpoint";
    pub const PEER_ENDPOINT: &str = "agent.comm.peer_endpoint";
    pub const TRUST_DOMAIN: &str = "agent.comm.trust_domain";
    pub const PEER_TRUST_DOMAIN: &str = "agent.comm.peer_trust_domain";
    pub const CROSS_DOMAIN: &str = "agent.comm.cross_domain";
    pub const ERROR_CODE: &str = "agent.comm.error_code";
    pub const ERROR_MESSAGE: &str = "agent.comm.error_message";
    pub const DURATION_MS: &str = "agent.comm.duration_ms";

    // Canonical lifecycle status values.
    pub const STATUS_SUBMITTED: &str = "submitted";
    pub const STATUS_WORKING: &str = "working";
    pub const STATUS_INPUT_REQUIRED: &str = "input_required";
    pub const STATUS_COMPLETED: &str = "completed";
    pub const STATUS_FAILED: &str = "failed";
    pub const STATUS_CANCELING: &str = "canceling";
    pub const STATUS_CANCELED: &str = "canceled";

    // Canonical protocol values.
    pub const PROTOCOL_A2A: &str = "a2a";
    pub const PROTOCOL_ACP: &str = "acp";
    pub const PROTOCOL_ANP: &str = "anp";
    pub const PROTOCOL_MCP: &str = "mcp";
    pub const PROTOCOL_CUSTOM: &str = "custom";
}

/// AITF metric-name constants (ported from Go `semconv/metrics.go`).
pub mod metrics {
    // OTel GenAI metrics (preserved)
    pub const GEN_AI_TOKEN_USAGE: &str = "gen_ai.client.token.usage";
    pub const GEN_AI_OPERATION_DURATION: &str = "gen_ai.client.operation.duration";

    // Inference metrics
    pub const INFERENCE_REQUESTS: &str = "inference.requests";
    pub const INFERENCE_ERRORS: &str = "inference.errors";
    pub const INFERENCE_TTFT: &str = "inference.time_to_first_token";
    pub const INFERENCE_TPS: &str = "inference.tokens_per_second";

    // Agent metrics
    pub const AGENT_SESSIONS: &str = "agent.sessions";
    pub const AGENT_STEPS: &str = "agent.steps";
    pub const AGENT_SESSION_DURATION: &str = "agent.session.duration";
    pub const AGENT_DELEGATIONS: &str = "agent.delegations";

    // MCP metrics
    pub const MCP_TOOL_INVOCATIONS: &str = "mcp.tool.invocations";
    pub const MCP_TOOL_DURATION: &str = "mcp.tool.duration";
    pub const MCP_SERVER_CONNECTIONS: &str = "mcp.server.connections";
    pub const MCP_TOOL_APPROVALS: &str = "mcp.tool.approvals";

    // Skill metrics
    pub const SKILL_INVOCATIONS: &str = "skill.invocations";
    pub const SKILL_DURATION: &str = "skill.duration";

    // Cost metrics
    pub const COST_TOTAL: &str = "cost.total";
    pub const COST_BUDGET_UTILIZATION: &str = "cost.budget.utilization";

    // Security metrics
    pub const SECURITY_THREATS: &str = "security.threats_detected";
    pub const SECURITY_BLOCKED: &str = "security.requests_blocked";
    pub const SECURITY_PII: &str = "security.pii_detected";
    pub const SECURITY_GUARDRAILS: &str = "security.guardrail.checks";

    // RAG metrics
    pub const RAG_RETRIEVALS: &str = "rag.retrievals";
    pub const RAG_RETRIEVAL_DURATION: &str = "rag.retrieval.duration";

    // Quality metrics
    pub const QUALITY_HALLUCINATION: &str = "quality.hallucination";
    pub const QUALITY_USER_RATING: &str = "quality.user_rating";
}

/// Anthropic Claude Compliance API (Activity Feed) attributes.
pub mod claude_compliance {
    pub const ACTIVITY_ID: &str = "claude.compliance.activity.id";
    pub const ACTIVITY_TYPE: &str = "claude.compliance.activity.type";
    pub const ACTIVITY_CATEGORY: &str = "claude.compliance.activity.category";
    pub const CREATED_AT: &str = "claude.compliance.activity.created_at";
    pub const ORGANIZATION_ID: &str = "claude.compliance.organization.id";
    pub const ORGANIZATION_UUID: &str = "claude.compliance.organization.uuid";

    pub const ACTOR_TYPE: &str = "claude.compliance.actor.type";
    pub const ACTOR_EMAIL: &str = "claude.compliance.actor.email_address";
    pub const ACTOR_USER_ID: &str = "claude.compliance.actor.user_id";
    pub const ACTOR_IP: &str = "claude.compliance.actor.ip_address";
    pub const ACTOR_USER_AGENT: &str = "claude.compliance.actor.user_agent";
    pub const ACTOR_API_KEY_ID: &str = "claude.compliance.actor.api_key_id";
    pub const ACTOR_ADMIN_API_KEY_ID: &str = "claude.compliance.actor.admin_api_key_id";
    pub const ACTOR_DIRECTORY_ID: &str = "claude.compliance.actor.directory_id";

    pub const CHAT_ID: &str = "claude.compliance.chat.id";
    pub const PROJECT_ID: &str = "claude.compliance.project.id";
    pub const FILE_ID: &str = "claude.compliance.file.id";
    pub const FILENAME: &str = "claude.compliance.file.name";
    pub const TARGET_USER_ID: &str = "claude.compliance.target.user_id";
}
