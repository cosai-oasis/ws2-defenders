/**
 * AITF OCSF Base Schema.
 *
 * OCSF v1.1.0 base objects and AI-specific extension models.
 * Based on the OCSF schema from the AITelemetry project, enhanced
 * for AITF AI events that reuse existing OCSF classes (OCSF PR #1641 /
 * issue #1640).
 */

import { randomUUID } from "crypto";

// --- OCSF Enumerations ---

export enum OCSFSeverity {
  UNKNOWN = 0,
  INFORMATIONAL = 1,
  LOW = 2,
  MEDIUM = 3,
  HIGH = 4,
  CRITICAL = 5,
  FATAL = 6,
}

export enum OCSFStatus {
  UNKNOWN = 0,
  SUCCESS = 1,
  FAILURE = 2,
  OTHER = 99,
}

export enum OCSFActivity {
  UNKNOWN = 0,
  CREATE = 1,
  READ = 2,
  UPDATE = 3,
  DELETE = 4,
  OTHER = 99,
}

/**
 * OCSF category UIDs that AITF AI events map onto.
 *
 * Following OCSF's "reuse existing objects and profiles" approach
 * (OCSF PR #1641 / issue #1640), AITF emits AI telemetry under existing
 * OCSF categories enriched with the `ai_operation` profile, and uses the
 * proposed `ai` category (uid 9) only for genuinely new control-plane
 * classes (agent / delegation lifecycle).
 */
export enum OCSFCategoryUID {
  FINDINGS = 2,
  IAM = 3,
  DISCOVERY = 5,
  APPLICATION = 6,
  AI = 9, // proposed "AI Activity" category (OCSF issue #1640)
}

/**
 * OCSF event class UIDs that AITF AI events map onto.
 *
 * Data-plane AI activity reuses existing OCSF classes; only the agent and
 * delegation control-plane lifecycle use the proposed `ai` category.
 */
export enum OCSFClassUID {
  // Reused existing OCSF classes (verified against the OCSF schema).
  VULNERABILITY_FINDING = 2002,
  COMPLIANCE_FINDING = 2003,
  DETECTION_FINDING = 2004,
  ACCOUNT_CHANGE = 3001,
  AUTHENTICATION = 3002,
  ENTITY_MANAGEMENT = 3004,
  USER_ACCESS_MANAGEMENT = 3005,
  INVENTORY_INFO = 5001,
  WEB_RESOURCES_ACTIVITY = 6001,
  APPLICATION_LIFECYCLE = 6002,
  API_ACTIVITY = 6003,
  DATASTORE_ACTIVITY = 6005,
  // New control-plane classes in the proposed `ai` category (uid 9).
  // UIDs are provisional pending OCSF issue #1640 ratification.
  AGENT_ACTIVITY = 9001,
  DELEGATION_ACTIVITY = 9002,
  AGENT_COMMUNICATION = 9003,
}

/**
 * Backward-compatible alias. AITF previously defined a bespoke Category 7 with
 * classes 7001-7010; events now reuse the OCSF classes above per OCSF's
 * object/profile-reuse model. Kept so existing imports keep working.
 */
export const AIClassUID = OCSFClassUID;

/**
 * OCSF `ai_agent.type_id` — normalized agent framework.
 *
 * Mirrors the enum introduced by OCSF PR #1641 (`objects/ai_agent.json`)
 * so AITF telemetry maps cleanly onto the upstream OCSF `ai_agent` object.
 */
export enum AgentTypeID {
  UNKNOWN = 0,
  NATIVE = 1,
  LANGCHAIN = 2,
  AUTOGEN = 3,
  CREWAI = 4,
  OTHER = 99,
}

/** Caption labels for AgentTypeID, per OCSF PR #1641. */
export const AGENT_TYPE_LABELS: Record<number, string> = {
  0: "Unknown",
  1: "Native",
  2: "LangChain",
  3: "AutoGen",
  4: "CrewAI",
  99: "Other",
};

/**
 * AITF framework value -> OCSF ai_agent.type_id. Frameworks without a
 * dedicated OCSF enum member (langgraph, semantic_kernel, custom, ...)
 * normalize to OTHER (99), matching OCSF's open-enum guidance.
 */
const FRAMEWORK_TO_TYPE_ID: Record<string, AgentTypeID> = {
  native: AgentTypeID.NATIVE,
  langchain: AgentTypeID.LANGCHAIN,
  langgraph: AgentTypeID.LANGCHAIN,
  autogen: AgentTypeID.AUTOGEN,
  crewai: AgentTypeID.CREWAI,
};

/** Map an AITF framework string to an OCSF `ai_agent.type_id` value. */
export function normalizeAgentTypeId(framework?: string | null): number {
  if (!framework) {
    return AgentTypeID.UNKNOWN;
  }
  const key = framework.trim().toLowerCase();
  return key in FRAMEWORK_TO_TYPE_ID
    ? FRAMEWORK_TO_TYPE_ID[key]
    : AgentTypeID.OTHER;
}

/**
 * OCSF AI category proposed in OCSF issue #1640. AITF reuses existing OCSF
 * classes for data-plane activity and uses this proposed `ai` category only
 * for the new agent / delegation control-plane classes.
 */
export const OCSF_AI_CATEGORY_UID = OCSFCategoryUID.AI; // proposed "AI Activity" category (OCSF issue #1640)

// --- OCSF Base Object Interfaces ---

/** OCSF event metadata. */
export interface OCSFMetadata {
  version: string;
  product: {
    name: string;
    vendor_name: string;
    version: string;
  };
  uid: string;
  correlation_uid?: string;
  original_time?: string;
  logged_time: string;
}

/** OCSF actor information. */
export interface OCSFActor {
  user?: Record<string, unknown>;
  session?: Record<string, unknown>;
  app_name?: string;
}

/** OCSF device/host information. */
export interface OCSFDevice {
  hostname?: string;
  ip?: string;
  type?: string;
  os?: Record<string, string>;
  cloud?: Record<string, string>;
  container?: Record<string, string>;
}

/** OCSF enrichment data. */
export interface OCSFEnrichment {
  name: string;
  value: string;
  type?: string;
  provider?: string;
}

/** OCSF observable value. */
export interface OCSFObservable {
  name: string;
  type: string;
  value: string;
}

// --- AI-Specific Extension Interfaces ---

/** AI model information. */
export interface AIModelInfo {
  model_id: string;
  name?: string;
  version?: string;
  provider?: string;
  type?: string; // llm, embedding, image, audio, multimodal
  parameters?: Record<string, unknown>;
}

/** AI token usage statistics. */
export interface AITokenUsage {
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cached_tokens: number;
  reasoning_tokens: number;
  estimated_cost_usd?: number;
}

/** AI operation latency metrics. */
export interface AILatencyMetrics {
  total_ms: number;
  time_to_first_token_ms?: number;
  tokens_per_second?: number;
  queue_time_ms?: number;
  inference_time_ms?: number;
}

/** AI operation cost information. */
export interface AICostInfo {
  input_cost_usd: number;
  output_cost_usd: number;
  total_cost_usd: number;
  currency: string;
}

/** Multi-agent team information. */
export interface AITeamInfo {
  team_name: string;
  team_id?: string;
  topology?: string;
  members: string[];
  coordinator?: string;
}

/** Security finding details. */
export interface AISecurityFinding {
  finding_type: string;
  owasp_category?: string;
  risk_level: string;
  risk_score: number;
  confidence: number;
  detection_method: string;
  blocked: boolean;
  details?: string;
  pii_types: string[];
  matched_patterns: string[];
  remediation?: string;
}

/**
 * OCSF `ai_agent` object (OCSF PR #1641).
 *
 * An autonomous AI agent operating under delegated authority. Distinct from
 * the OCSF `agent` object (which models security sensors such as EDR/DLP)
 * and from human principals. Attached to events via the `ai_operation`
 * profile so any activity can be attributed to the agent that performed it.
 */
export interface OCSFAIAgent {
  uid: string; // required: stable logical identifier
  instance_uid?: string; // restart-sensitive running instance id
  name?: string;
  type?: string; // caption of type_id (Native, LangChain, ...)
  type_id: number;
  ai_model?: string; // model backing the agent at event time
  version?: string; // agent code/configuration revision
  charter?: string; // role / operating-boundary reference
}

/**
 * OCSF `delegation` object (OCSF issue #1640).
 *
 * A durable authorization context that persists independently of any single
 * trace or session. `uid`/`parent_uid`/`issuer_uid` provide the OCSF core;
 * the remaining fields preserve AITF's richer delegation telemetry.
 */
export interface OCSFDelegation {
  uid: string; // required: stable delegation identifier
  parent_uid?: string; // parent delegation (lineage)
  issuer_uid?: string; // trusted issuer that minted the delegation
  delegator?: string;
  delegatee?: string;
  type?: string; // on_behalf_of, token_exchange, capability_grant, ...
  scope: string[];
  proof_type?: string; // dpop, mtls_binding, signed_assertion
  ttl_seconds?: number;
}

/** A single node in an OCSF `delegation_lineage` graph (OCSF issue #1640). */
export interface OCSFDelegationNode {
  uid: string;
  parent_uid?: string;
  agent_uid?: string;
  depth?: number;
}

/** OCSF `delegation_lineage` — directed graph for ancestry queries. */
export interface OCSFDelegationLineage {
  nodes: OCSFDelegationNode[];
}

/**
 * Agent-to-agent communication protocol (OCSF `agent_message.protocol_id`).
 *
 * One generic discriminator across agentic protocols rather than a dedicated
 * OCSF object per protocol — protocol-specific detail stays in the
 * per-protocol OTel namespaces.
 */
export enum AgentProtocolID {
  UNKNOWN = 0,
  A2A = 1,
  ACP = 2,
  ANP = 3,
  MCP = 4,
  OTHER = 99,
}

export const AGENT_PROTOCOL_LABELS: Record<number, string> = {
  0: "Unknown",
  1: "A2A",
  2: "ACP",
  3: "ANP",
  4: "MCP",
  99: "Other",
};

const PROTOCOL_TO_ID: Record<string, AgentProtocolID> = {
  a2a: AgentProtocolID.A2A,
  acp: AgentProtocolID.ACP,
  anp: AgentProtocolID.ANP,
  mcp: AgentProtocolID.MCP,
};

/** Map a protocol string to an OCSF `agent_message.protocol_id`. */
export function normalizeAgentProtocolId(protocol?: string | null): number {
  if (!protocol) {
    return AgentProtocolID.UNKNOWN;
  }
  const key = protocol.trim().toLowerCase();
  return key in PROTOCOL_TO_ID ? PROTOCOL_TO_ID[key] : AgentProtocolID.OTHER;
}

/**
 * OCSF `agent_message` object — one generic representation of an
 * agent-to-agent communication across A2A / ACP / ANP / MCP.
 *
 * Carries the wire `protocol_id` discriminator plus the shared core (peer
 * agents, unit of work + lifecycle status, transport, trust); protocol-specific
 * extras live in `metadata`.
 */
export interface OCSFAgentMessage {
  protocol_id: number;
  protocol?: string;
  protocol_version?: string;
  direction?: string; // request | response | stream | notification
  role?: string; // client | server
  operation?: string;
  unit_uid?: string;
  unit_type?: string; // task | run | message
  status?: string; // canonical lifecycle status
  previous_status?: string;
  src_agent?: OCSFAIAgent;
  dst_agent?: OCSFAIAgent;
  delegation?: OCSFDelegation;
  parts_count?: number;
  part_types: string[];
  artifacts_count?: number;
  transport?: string;
  endpoint?: string;
  peer_endpoint?: string;
  trust_domain?: string;
  peer_trust_domain?: string;
  cross_domain?: boolean;
  peer_did?: string;
  error_code?: string;
  error_message?: string;
  duration_ms?: number;
  metadata?: Record<string, unknown>;
}

/** Compliance framework mappings. */
export interface ComplianceMetadata {
  nist_ai_rmf?: Record<string, unknown>;
  mitre_atlas?: Record<string, unknown>;
  iso_42001?: Record<string, unknown>;
  eu_ai_act?: Record<string, unknown>;
  soc2?: Record<string, unknown>;
  gdpr?: Record<string, unknown>;
  ccpa?: Record<string, unknown>;
  csa_aicm?: Record<string, unknown>;
}

// --- OCSF Base Event ---

/**
 * Base OCSF event for AITF AI events.
 *
 * Subclasses/factories set `category_uid` and `class_uid` to the OCSF class
 * they reuse (OCSF PR #1641 / issue #1640). AI-specific context is carried on
 * the `ai_operation` profile (`ai_agent`, `ai_model`, `delegation`).
 */
export interface AIBaseEvent {
  activity_id: number;
  category_uid: number;
  class_uid: number;
  type_uid: number;
  time: string;
  severity_id: number;
  status_id: number;
  message: string;
  metadata: OCSFMetadata;
  actor?: OCSFActor;
  device?: OCSFDevice;
  compliance?: ComplianceMetadata;
  observables: OCSFObservable[];
  enrichments: OCSFEnrichment[];

  // OCSF `ai_operation` profile (OCSF PR #1641) + delegation context
  // (OCSF issue #1640). Populated by the crosswalk so every AITF event can
  // be attributed to the AI agent and delegation that produced it.
  ai_agent?: OCSFAIAgent;
  ai_model?: string;
  delegation?: OCSFDelegation;
  delegation_lineage?: OCSFDelegationLineage;
}

// --- Factory Functions ---

/** Create default OCSF metadata. */
export function createMetadata(
  correlationUid?: string
): OCSFMetadata {
  return {
    version: "1.1.0",
    product: {
      name: "AITF",
      vendor_name: "AITF",
      version: "1.0.0",
    },
    uid: randomUUID(),
    correlation_uid: correlationUid,
    logged_time: new Date().toISOString(),
  };
}

/** Create default token usage. */
export function createTokenUsage(
  options: Partial<AITokenUsage> = {}
): AITokenUsage {
  const usage: AITokenUsage = {
    input_tokens: options.input_tokens ?? 0,
    output_tokens: options.output_tokens ?? 0,
    total_tokens: options.total_tokens ?? 0,
    cached_tokens: options.cached_tokens ?? 0,
    reasoning_tokens: options.reasoning_tokens ?? 0,
    estimated_cost_usd: options.estimated_cost_usd,
  };
  if (usage.total_tokens === 0) {
    usage.total_tokens = usage.input_tokens + usage.output_tokens;
  }
  return usage;
}

/** Create a base OCSF AI event. */
export function createBaseEvent(
  classUid: number,
  options: Partial<AIBaseEvent> = {}
): AIBaseEvent {
  const activityId = options.activity_id ?? OCSFActivity.OTHER;
  return {
    activity_id: activityId,
    // Default to APPLICATION (6); factories override with the reused OCSF
    // category for the class they emit (OCSF PR #1641 / issue #1640).
    category_uid: options.category_uid ?? OCSFCategoryUID.APPLICATION,
    class_uid: classUid,
    type_uid: options.type_uid ?? classUid * 100 + activityId,
    time: options.time ?? new Date().toISOString(),
    severity_id: options.severity_id ?? OCSFSeverity.INFORMATIONAL,
    status_id: options.status_id ?? OCSFStatus.SUCCESS,
    message: options.message ?? "",
    metadata: options.metadata ?? createMetadata(),
    actor: options.actor,
    device: options.device,
    compliance: options.compliance,
    observables: options.observables ?? [],
    enrichments: options.enrichments ?? [],
  };
}

/**
 * Remove undefined/null properties from an object (for JSON export).
 */
export function stripNulls<T extends Record<string, unknown>>(
  obj: T
): Partial<T> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value !== undefined && value !== null) {
      if (
        typeof value === "object" &&
        !Array.isArray(value) &&
        value !== null
      ) {
        const stripped = stripNulls(value as Record<string, unknown>);
        if (Object.keys(stripped).length > 0) {
          result[key] = stripped;
        }
      } else {
        result[key] = value;
      }
    }
  }
  return result as Partial<T>;
}
