/**
 * Agent-to-agent communication normalization (A2A / ACP / ANP).
 *
 * One generic OCSF `agent_message` object with a `protocol_id` discriminator
 * rather than a per-protocol object. Per-protocol lifecycle states are
 * normalized to a single canonical status set.
 */

import {
  AgentProtocolID,
  OCSFAgentMessage,
  OCSFAIAgent,
  normalizeAgentProtocolId,
} from "./schema";
import { buildAiAgent, buildDelegation } from "./crosswalk";
import {
  A2AAttributes,
  ACPAttributes,
  ANPAttributes,
  AgentCommAttributes,
} from "../semantic-conventions/attributes";

type SpanAttributes = Record<string, unknown>;

const CANONICAL = AgentCommAttributes.Status;

// A2A task.state -> canonical
const A2A_STATUS: Record<string, string> = {
  submitted: CANONICAL.SUBMITTED,
  working: CANONICAL.WORKING,
  "input-required": CANONICAL.INPUT_REQUIRED,
  "auth-required": CANONICAL.INPUT_REQUIRED,
  completed: CANONICAL.COMPLETED,
  failed: CANONICAL.FAILED,
  rejected: CANONICAL.FAILED,
  canceled: CANONICAL.CANCELED,
};

// ACP run.status -> canonical
const ACP_STATUS: Record<string, string> = {
  created: CANONICAL.SUBMITTED,
  "in-progress": CANONICAL.WORKING,
  awaiting: CANONICAL.INPUT_REQUIRED,
  completed: CANONICAL.COMPLETED,
  failed: CANONICAL.FAILED,
  cancelling: CANONICAL.CANCELING,
  cancelled: CANONICAL.CANCELED,
};

const STATUS_TABLES: Record<number, Record<string, string>> = {
  [AgentProtocolID.A2A]: A2A_STATUS,
  [AgentProtocolID.ACP]: ACP_STATUS,
};

/** Normalize a protocol-specific lifecycle state to the canonical set. */
export function canonicalCommStatus(
  protocolId: number,
  status: unknown
): string | undefined {
  if (status === undefined || status === null) {
    return undefined;
  }
  const table = STATUS_TABLES[protocolId] ?? {};
  const raw = String(status);
  return raw in table ? table[raw] : raw;
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

function asList(val: unknown): string[] {
  if (val === undefined || val === null) {
    return [];
  }
  if (Array.isArray(val)) {
    return val.map((v) => String(v));
  }
  return [String(val)];
}

/** Detect the agent-comm protocol from attribute namespaces. */
function detectProtocol(attrs: SpanAttributes): number {
  const explicit = attrs[AgentCommAttributes.PROTOCOL];
  if (explicit) {
    return normalizeAgentProtocolId(String(explicit));
  }
  const keys = Object.keys(attrs);
  if (keys.some((k) => k.startsWith("a2a."))) {
    return AgentProtocolID.A2A;
  }
  if (keys.some((k) => k.startsWith("acp."))) {
    return AgentProtocolID.ACP;
  }
  if (keys.some((k) => k.startsWith("anp."))) {
    return AgentProtocolID.ANP;
  }
  return AgentProtocolID.UNKNOWN;
}

function first(attrs: SpanAttributes, ...keys: string[]): unknown {
  for (const k of keys) {
    if (attrs[k] !== undefined && attrs[k] !== null) {
      return attrs[k];
    }
  }
  return undefined;
}

/**
 * Build a generic OCSF `agent_message` from A2A/ACP/ANP/canonical attrs.
 *
 * Returns `undefined` when the span carries no agent-communication context.
 */
export function buildAgentMessage(
  attrs: SpanAttributes
): OCSFAgentMessage | undefined {
  const protocolId = detectProtocol(attrs);
  if (
    protocolId === AgentProtocolID.UNKNOWN &&
    attrs[AgentCommAttributes.UNIT_ID] === undefined
  ) {
    return undefined;
  }

  const msg: OCSFAgentMessage = {
    protocol_id: protocolId,
    protocol: optStr(attrs[AgentCommAttributes.PROTOCOL]),
    part_types: [],
  };

  if (protocolId === AgentProtocolID.A2A) {
    msg.protocol_version = optStr(attrs[A2AAttributes.PROTOCOL_VERSION]);
    msg.transport = optStr(attrs[A2AAttributes.TRANSPORT]);
    msg.operation = optStr(attrs[A2AAttributes.METHOD]);
    if (attrs[A2AAttributes.TASK_ID] !== undefined && attrs[A2AAttributes.TASK_ID] !== null) {
      msg.unit_uid = optStr(attrs[A2AAttributes.TASK_ID]);
      msg.unit_type = "task";
      msg.status = canonicalCommStatus(protocolId, attrs[A2AAttributes.TASK_STATE]);
      msg.previous_status = canonicalCommStatus(
        protocolId,
        attrs[A2AAttributes.TASK_PREVIOUS_STATE]
      );
    } else {
      msg.unit_uid = optStr(attrs[A2AAttributes.MESSAGE_ID]);
      msg.unit_type = "message";
    }
    const mode = String(attrs[A2AAttributes.INTERACTION_MODE] ?? "").toLowerCase();
    msg.direction =
      mode === "stream" ? "stream" : mode === "push" ? "notification" : "request";
    msg.parts_count = optInt(attrs[A2AAttributes.MESSAGE_PARTS_COUNT]);
    msg.part_types = asList(attrs[A2AAttributes.MESSAGE_PART_TYPES]);
    msg.artifacts_count = optInt(attrs[A2AAttributes.TASK_ARTIFACTS_COUNT]);
    msg.peer_endpoint = optStr(attrs[A2AAttributes.AGENT_URL]);
    msg.error_code = optStr(attrs[A2AAttributes.JSONRPC_ERROR_CODE]);
    msg.error_message = optStr(attrs[A2AAttributes.JSONRPC_ERROR_MESSAGE]);
    if (attrs[A2AAttributes.AGENT_NAME]) {
      msg.dst_agent = {
        uid: String(attrs[A2AAttributes.AGENT_NAME]),
        name: String(attrs[A2AAttributes.AGENT_NAME]),
        type_id: 0,
        version: optStr(attrs[A2AAttributes.AGENT_VERSION]),
      };
    }
  } else if (protocolId === AgentProtocolID.ACP) {
    msg.operation = optStr(first(attrs, ACPAttributes.OPERATION, ACPAttributes.RUN_MODE));
    msg.unit_uid = optStr(attrs[ACPAttributes.RUN_ID]);
    msg.unit_type = "run";
    msg.status = canonicalCommStatus(protocolId, attrs[ACPAttributes.RUN_STATUS]);
    msg.previous_status = canonicalCommStatus(
      protocolId,
      attrs[ACPAttributes.RUN_PREVIOUS_STATUS]
    );
    const mode = String(attrs[ACPAttributes.RUN_MODE] ?? "").toLowerCase();
    msg.direction = mode === "stream" ? "stream" : "request";
    msg.transport = "http";
    msg.endpoint = optStr(attrs[ACPAttributes.HTTP_URL]);
    msg.parts_count = optInt(attrs[ACPAttributes.MESSAGE_PARTS_COUNT]);
    msg.part_types = asList(attrs[ACPAttributes.MESSAGE_CONTENT_TYPES]);
    msg.duration_ms = optFloat(attrs[ACPAttributes.RUN_DURATION_MS]);
    msg.error_code = optStr(attrs[ACPAttributes.RUN_ERROR_CODE]);
    msg.error_message = optStr(attrs[ACPAttributes.RUN_ERROR_MESSAGE]);
    if (attrs[ACPAttributes.AGENT_NAME]) {
      msg.dst_agent = {
        uid: String(attrs[ACPAttributes.AGENT_NAME]),
        name: String(attrs[ACPAttributes.AGENT_NAME]),
        type_id: 0,
      };
    }
  } else if (protocolId === AgentProtocolID.ANP) {
    msg.protocol_version = optStr(attrs[ANPAttributes.PROTOCOL_VERSION]);
    msg.transport = optStr(attrs[ANPAttributes.TRANSPORT]);
    msg.operation = optStr(
      first(attrs, ANPAttributes.META_PROTOCOL_NAME, ANPAttributes.MESSAGE_TYPE)
    );
    msg.unit_uid = optStr(attrs[ANPAttributes.MESSAGE_ID]);
    msg.unit_type = "message";
    msg.parts_count = optInt(attrs[ANPAttributes.MESSAGE_PARTS_COUNT]);
    msg.peer_did = optStr(attrs[ANPAttributes.PEER_DID]);
    msg.trust_domain = optStr(attrs[ANPAttributes.TRUST_DOMAIN]);
    msg.peer_trust_domain = optStr(attrs[ANPAttributes.PEER_TRUST_DOMAIN]);
    msg.cross_domain = optBool(attrs[ANPAttributes.CROSS_DOMAIN]);
    msg.error_code = optStr(attrs[ANPAttributes.ERROR_CODE]);
    msg.error_message = optStr(attrs[ANPAttributes.ERROR_MESSAGE]);
  }

  // Canonical agent.comm.* attributes override / fill in any protocol.
  applyCanonical(msg, attrs);

  // Source agent from gen_ai.agent.* / canonical, if present.
  if (msg.src_agent === undefined) {
    msg.src_agent = buildAiAgent(attrs);
  }

  // Delegation context (issue #1640) rides on the comms event when present.
  msg.delegation = buildDelegation(attrs);
  return msg;
}

/** Overlay explicit canonical agent.comm.* attributes onto the message. */
function applyCanonical(msg: OCSFAgentMessage, attrs: SpanAttributes): void {
  const A = AgentCommAttributes;
  const overrides: Array<[keyof OCSFAgentMessage, string]> = [
    ["protocol_version", A.PROTOCOL_VERSION],
    ["direction", A.DIRECTION],
    ["role", A.ROLE],
    ["operation", A.OPERATION],
    ["unit_uid", A.UNIT_ID],
    ["unit_type", A.UNIT_TYPE],
    ["status", A.STATUS],
    ["previous_status", A.PREVIOUS_STATUS],
    ["transport", A.TRANSPORT],
    ["endpoint", A.ENDPOINT],
    ["peer_endpoint", A.PEER_ENDPOINT],
    ["trust_domain", A.TRUST_DOMAIN],
    ["peer_trust_domain", A.PEER_TRUST_DOMAIN],
    ["peer_did", A.PEER_DID],
    ["error_code", A.ERROR_CODE],
    ["error_message", A.ERROR_MESSAGE],
  ];
  const target = msg as unknown as Record<string, unknown>;
  for (const [field, key] of overrides) {
    if (attrs[key] !== undefined && attrs[key] !== null) {
      target[field as string] = optStr(attrs[key]);
    }
  }
  if (attrs[A.PARTS_COUNT] !== undefined && attrs[A.PARTS_COUNT] !== null) {
    msg.parts_count = optInt(attrs[A.PARTS_COUNT]);
  }
  if (attrs[A.ARTIFACTS_COUNT] !== undefined && attrs[A.ARTIFACTS_COUNT] !== null) {
    msg.artifacts_count = optInt(attrs[A.ARTIFACTS_COUNT]);
  }
  if (attrs[A.PART_TYPES] !== undefined && attrs[A.PART_TYPES] !== null) {
    msg.part_types = asList(attrs[A.PART_TYPES]);
  }
  if (attrs[A.CROSS_DOMAIN] !== undefined && attrs[A.CROSS_DOMAIN] !== null) {
    msg.cross_domain = optBool(attrs[A.CROSS_DOMAIN]);
  }
  if (attrs[A.DURATION_MS] !== undefined && attrs[A.DURATION_MS] !== null) {
    msg.duration_ms = optFloat(attrs[A.DURATION_MS]);
  }
  if (attrs[A.PEER_AGENT_ID] || attrs[A.PEER_AGENT_NAME]) {
    const dst: OCSFAIAgent = {
      uid: String(attrs[A.PEER_AGENT_ID] ?? attrs[A.PEER_AGENT_NAME]),
      name: optStr(attrs[A.PEER_AGENT_NAME]),
      type_id: 0,
    };
    msg.dst_agent = dst;
  }
}
