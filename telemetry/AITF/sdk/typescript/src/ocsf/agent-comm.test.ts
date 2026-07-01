/**
 * Tests for unified A2A / ACP / ANP agent-communication -> OCSF mapping.
 */

import { ReadableSpan } from "@opentelemetry/sdk-trace-base";
import {
  buildAgentMessage,
  canonicalCommStatus,
} from "./agent-comm";
import { AgentProtocolID, normalizeAgentProtocolId } from "./schema";
import { OCSFMapper } from "./mapper";
import { AIAgentCommunicationEvent } from "./event-classes";
import {
  A2AAttributes,
  ACPAttributes,
  ANPAttributes,
  AgentCommAttributes,
} from "../semantic-conventions/attributes";

/** Build a minimal fake ReadableSpan for the mapper. */
function fakeSpan(
  name: string,
  attributes: Record<string, unknown>
): ReadableSpan {
  return {
    name,
    attributes,
    startTime: [1_700_000_000, 0],
  } as unknown as ReadableSpan;
}

describe("protocol normalization", () => {
  it("maps protocol strings to ids", () => {
    expect(normalizeAgentProtocolId("a2a")).toBe(AgentProtocolID.A2A);
    expect(normalizeAgentProtocolId("ACP")).toBe(AgentProtocolID.ACP);
    expect(normalizeAgentProtocolId("anp")).toBe(AgentProtocolID.ANP);
    expect(normalizeAgentProtocolId("mcp")).toBe(AgentProtocolID.MCP);
    expect(normalizeAgentProtocolId("something")).toBe(AgentProtocolID.OTHER);
    expect(normalizeAgentProtocolId(undefined)).toBe(AgentProtocolID.UNKNOWN);
  });

  it("normalizes per-protocol status to the canonical set", () => {
    expect(canonicalCommStatus(AgentProtocolID.A2A, "input-required")).toBe(
      "input_required"
    );
    expect(canonicalCommStatus(AgentProtocolID.A2A, "rejected")).toBe("failed");
    expect(canonicalCommStatus(AgentProtocolID.ACP, "in-progress")).toBe(
      "working"
    );
    expect(canonicalCommStatus(AgentProtocolID.ACP, "cancelled")).toBe(
      "canceled"
    );
  });
});

describe("buildAgentMessage", () => {
  it("builds an A2A message", () => {
    const msg = buildAgentMessage({
      [A2AAttributes.PROTOCOL_VERSION]: "0.2",
      [A2AAttributes.TRANSPORT]: "jsonrpc",
      [A2AAttributes.METHOD]: "message/send",
      [A2AAttributes.TASK_ID]: "task_1",
      [A2AAttributes.TASK_STATE]: "working",
      [A2AAttributes.MESSAGE_PARTS_COUNT]: 2,
      [A2AAttributes.INTERACTION_MODE]: "stream",
      [A2AAttributes.AGENT_NAME]: "planner",
      [A2AAttributes.AGENT_URL]: "https://p.example/a2a",
    });
    expect(msg).toBeDefined();
    expect(msg!.protocol_id).toBe(AgentProtocolID.A2A);
    expect(msg!.unit_type).toBe("task");
    expect(msg!.unit_uid).toBe("task_1");
    expect(msg!.status).toBe("working");
    expect(msg!.direction).toBe("stream");
    expect(msg!.transport).toBe("jsonrpc");
    expect(msg!.dst_agent?.name).toBe("planner");
    expect(msg!.peer_endpoint).toBe("https://p.example/a2a");
  });

  it("builds an ACP message", () => {
    const msg = buildAgentMessage({
      [ACPAttributes.RUN_ID]: "run_9",
      [ACPAttributes.RUN_STATUS]: "in-progress",
      [ACPAttributes.RUN_MODE]: "async",
      [ACPAttributes.OPERATION]: "runs.create",
      [ACPAttributes.HTTP_URL]: "https://acp.example/runs",
    });
    expect(msg!.protocol_id).toBe(AgentProtocolID.ACP);
    expect(msg!.unit_type).toBe("run");
    expect(msg!.unit_uid).toBe("run_9");
    expect(msg!.status).toBe("working"); // in-progress -> working
    expect(msg!.transport).toBe("http");
    expect(msg!.endpoint).toBe("https://acp.example/runs");
  });

  it("builds an ANP message", () => {
    const msg = buildAgentMessage({
      [ANPAttributes.PROTOCOL_VERSION]: "1.0",
      [ANPAttributes.TRANSPORT]: "ws",
      [ANPAttributes.PEER_DID]: "did:wba:peer",
      [ANPAttributes.META_PROTOCOL_NAME]: "negotiate",
      [ANPAttributes.MESSAGE_ID]: "m1",
      [ANPAttributes.CROSS_DOMAIN]: true,
    });
    expect(msg!.protocol_id).toBe(AgentProtocolID.ANP);
    expect(msg!.peer_did).toBe("did:wba:peer");
    expect(msg!.operation).toBe("negotiate");
    expect(msg!.cross_domain).toBe(true);
  });

  it("applies canonical agent.comm.* overrides", () => {
    const msg = buildAgentMessage({
      [AgentCommAttributes.PROTOCOL]: "custom",
      [AgentCommAttributes.UNIT_ID]: "u1",
      [AgentCommAttributes.STATUS]: "completed",
      [AgentCommAttributes.PEER_AGENT_NAME]: "peer-x",
    });
    expect(msg!.protocol_id).toBe(AgentProtocolID.OTHER);
    expect(msg!.status).toBe("completed");
    expect(msg!.dst_agent?.name).toBe("peer-x");
  });

  it("returns undefined when there is no agent-comm context", () => {
    expect(buildAgentMessage({ "http.method": "GET" })).toBeUndefined();
  });
});

describe("OCSFMapper agent communication", () => {
  const mapper = new OCSFMapper();

  it("maps all three protocols to one class (9003)", () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      [
        "a2a.message.send",
        { [A2AAttributes.TASK_ID]: "t1", [A2AAttributes.TASK_STATE]: "working" },
      ],
      [
        "acp.run.create",
        { [ACPAttributes.RUN_ID]: "r1", [ACPAttributes.RUN_STATUS]: "completed" },
      ],
      ["anp.message", { [ANPAttributes.MESSAGE_ID]: "m1" }],
    ];
    for (const [name, attrs] of cases) {
      const event = mapper.mapSpan(fakeSpan(name, attrs));
      expect(event).not.toBeNull();
      expect(event!.category_uid).toBe(9);
      expect(event!.class_uid).toBe(9003); // one generic agent_communication class
    }
  });

  it("sets a Failure status for failed/errored comms", () => {
    const event = mapper.mapSpan(
      fakeSpan("a2a.message.send", {
        [A2AAttributes.TASK_ID]: "t1",
        [A2AAttributes.TASK_STATE]: "failed",
        [A2AAttributes.JSONRPC_ERROR_CODE]: "-32000",
      })
    ) as AIAgentCommunicationEvent;
    expect(event.status_id).toBe(2); // Failure
    expect(event.agent_message.error_code).toBe("-32000");
  });
});
