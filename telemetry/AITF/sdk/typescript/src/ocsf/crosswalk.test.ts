/**
 * Tests for the AITF <-> OCSF agentic crosswalk (OCSF PR #1641 / issue #1640).
 */

import { ReadableSpan } from "@opentelemetry/sdk-trace-base";
import {
  buildAiAgent,
  buildDelegation,
  buildDelegationLineage,
  OCSF_AGENT_ACTIVITY_CROSSWALK,
  OCSF_CLASS_CROSSWALK,
} from "./crosswalk";
import { AgentTypeID, OCSF_AI_CATEGORY_UID, normalizeAgentTypeId } from "./schema";
import { OCSFMapper } from "./mapper";
import {
  AgentAttributes,
  IdentityAttributes,
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

describe("normalizeAgentTypeId", () => {
  it("maps langchain to LangChain (2)", () => {
    expect(normalizeAgentTypeId("langchain")).toBe(AgentTypeID.LANGCHAIN);
  });

  it("maps langgraph to LangChain (2)", () => {
    expect(normalizeAgentTypeId("langgraph")).toBe(AgentTypeID.LANGCHAIN);
  });

  it("maps crewai to CrewAI (4)", () => {
    expect(normalizeAgentTypeId("crewai")).toBe(AgentTypeID.CREWAI);
  });

  it("maps an unknown non-empty framework to Other (99)", () => {
    expect(normalizeAgentTypeId("semantic_kernel")).toBe(AgentTypeID.OTHER);
  });

  it("maps undefined/empty to Unknown (0)", () => {
    expect(normalizeAgentTypeId(undefined)).toBe(AgentTypeID.UNKNOWN);
    expect(normalizeAgentTypeId("")).toBe(AgentTypeID.UNKNOWN);
  });
});

describe("buildAiAgent", () => {
  it("returns undefined when no agent identity is present", () => {
    expect(buildAiAgent({})).toBeUndefined();
  });

  it("builds type_id=4 / type=CrewAI for a crewai agent", () => {
    const agent = buildAiAgent({
      [AgentAttributes.ID]: "agent-1",
      [AgentAttributes.NAME]: "Researcher",
      [AgentAttributes.FRAMEWORK]: "crewai",
    });
    expect(agent).toBeDefined();
    expect(agent!.uid).toBe("agent-1");
    expect(agent!.name).toBe("Researcher");
    expect(agent!.type_id).toBe(AgentTypeID.CREWAI);
    expect(agent!.type).toBe("CrewAI");
  });
});

describe("buildDelegation", () => {
  it("returns undefined when no delegation context is present", () => {
    expect(buildDelegation({})).toBeUndefined();
  });

  it("uses delegatee_id as uid and delegator_id as parent_uid", () => {
    const delegation = buildDelegation({
      [IdentityAttributes.DELEGATION_DELEGATEE_ID]: "delegatee-9",
      [IdentityAttributes.DELEGATION_DELEGATOR_ID]: "delegator-3",
      [IdentityAttributes.DELEGATION_SCOPE_DELEGATED]: ["read", "write"],
    });
    expect(delegation).toBeDefined();
    expect(delegation!.uid).toBe("delegatee-9");
    expect(delegation!.parent_uid).toBe("delegator-3");
    expect(delegation!.scope).toEqual(["read", "write"]);
  });
});

describe("buildDelegationLineage", () => {
  it("materializes the delegation chain into a directed graph", () => {
    const lineage = buildDelegationLineage({
      [IdentityAttributes.DELEGATION_CHAIN]: ["a", "b", "c"],
    });
    expect(lineage).toBeDefined();
    expect(lineage!.nodes).toHaveLength(3);
    expect(lineage!.nodes[0]).toMatchObject({
      uid: "a",
      parent_uid: undefined,
      depth: 0,
    });
    expect(lineage!.nodes[2]).toMatchObject({
      uid: "c",
      parent_uid: "b",
      depth: 2,
    });
  });
});

describe("OCSFMapper ai_operation enrichment", () => {
  it("attaches event.ai_agent to a mapped agent span", () => {
    const mapper = new OCSFMapper();
    const span = fakeSpan("agent.step.execute", {
      [AgentAttributes.NAME]: "Planner",
      [AgentAttributes.ID]: "agent-42",
      [AgentAttributes.FRAMEWORK]: "langchain",
      [AgentAttributes.SESSION_ID]: "conv-1",
    });
    const event = mapper.mapSpan(span);
    expect(event).not.toBeNull();
    expect(event!.ai_agent).toBeDefined();
    expect(event!.ai_agent!.uid).toBe("agent-42");
    expect(event!.ai_agent!.type_id).toBe(AgentTypeID.LANGCHAIN);
    expect(event!.ai_agent!.type).toBe("LangChain");
  });
});

describe("crosswalk tables", () => {
  it("reuses existing OCSF classes for data-plane events", () => {
    expect(OCSF_CLASS_CROSSWALK["model_inference"]).toEqual({
      ocsf_category_uid: 6,
      ocsf_class_uid: 6003,
      ocsf_class: "api_activity",
    });
    // Inference and tool execution both reuse API Activity (6003).
    expect(OCSF_CLASS_CROSSWALK["tool_execution"].ocsf_class_uid).toBe(6003);
    expect(OCSF_CLASS_CROSSWALK["data_retrieval"].ocsf_class_uid).toBe(6005);
    expect(OCSF_CLASS_CROSSWALK["security_finding"].ocsf_class_uid).toBe(2004);
    expect(OCSF_CLASS_CROSSWALK["supply_chain"].ocsf_class_uid).toBe(2002);
    expect(OCSF_CLASS_CROSSWALK["governance"].ocsf_class_uid).toBe(2003);
    expect(OCSF_CLASS_CROSSWALK["identity"].ocsf_class_uid).toBe(3002);
    expect(OCSF_CLASS_CROSSWALK["model_ops"].ocsf_class_uid).toBe(6002);
    expect(OCSF_CLASS_CROSSWALK["asset_inventory"].ocsf_class_uid).toBe(5001);
  });

  it("uses the proposed ai category (9) only for control-plane classes", () => {
    expect(OCSF_AI_CATEGORY_UID).toBe(9);
    expect(OCSF_CLASS_CROSSWALK["agent_activity"]).toEqual({
      ocsf_category_uid: OCSF_AI_CATEGORY_UID,
      ocsf_class_uid: 9001,
      ocsf_class: "agent_activity",
    });
    expect(OCSF_CLASS_CROSSWALK["delegation_activity"]).toEqual({
      ocsf_category_uid: OCSF_AI_CATEGORY_UID,
      ocsf_class_uid: 9002,
      ocsf_class: "delegation_activity",
    });
  });

  it("collapses to 9 distinct reused class_uids", () => {
    const classUids = new Set(
      Object.values(OCSF_CLASS_CROSSWALK).map((t) => t.ocsf_class_uid)
    );
    expect(classUids).toEqual(
      new Set([6003, 6005, 6002, 2004, 2002, 2003, 3002, 5001, 9001, 9002])
    );
  });

  it("maps agent activity_id 1 (Session Start) to Spawn", () => {
    expect(OCSF_AGENT_ACTIVITY_CROSSWALK[1]).toBe("Spawn");
    expect(OCSF_AGENT_ACTIVITY_CROSSWALK[99]).toBe("Unknown");
  });
});
