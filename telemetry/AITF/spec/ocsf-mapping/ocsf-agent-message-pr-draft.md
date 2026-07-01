# OCSF PR (standalone) — `agent_message`: one generic object for agent-to-agent communication

> **Draft PR for [ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema).**
> **Depends on** the `ai` category proposed in
> [issue #1640](https://github.com/ocsf/ocsf-schema/issues/1640); reuses the
> `ai_agent` object ([PR #1641](https://github.com/ocsf/ocsf-schema/pull/1641))
> and the `delegation` object (#1640). Sequence **after** the `ai` category
> lands. Kept separate from the additive `ai_operation` PR (which touches only
> existing classes) so that PR isn't blocked on the new category.

**Title:**

```
Add a generic agent_message object + agent_communication class for A2A/ACP/ANP/MCP
```

---

## Description

Adds **one** object — `agent_message` — and **one** class —
`agent_communication` (in the `ai` category) — to represent agent-to-agent
communication across protocols (A2A, ACP, ANP, MCP, …) with a `protocol_id`
**discriminator**, rather than a dedicated object/class per protocol.

## Motivation — one generic object, not one per protocol

OCSF gives SMTP/SMB/DNS/SSH/TLS dedicated objects/classes because those
protocols are mature, ubiquitous, semantically distinct, and have decades-old
detection ecosystems. The new agentic protocols are the opposite:

| Per-protocol modeling pays off when… | A2A / ACP / ANP are… |
|---|---|
| protocol is stable for years | revving monthly |
| protocols are semantically distinct | converging on one model |
| large existing detection corpus | greenfield |

Their conceptual core is identical: **a source agent talks to a peer agent,
under some delegated authority, about a unit of work (task / run / message)
that has a lifecycle status, via a transport, carrying parts/artifacts, and may
error.** A per-protocol object would (a) fragment cross-protocol detection —
a SOC wants "agent contacted an *untrusted* peer" regardless of wire protocol —
and (b) force schema churn on every protocol revision.

This mirrors OCSF's own deeper pattern: a generic class carrying a protocol
object + id (e.g. `network_activity` with `tls` / `dns_query`). Per-protocol
detail that doesn't generalize stays in a `metadata` map.

## Proposed changes

### New object — `objects/agent_message.json`

```json
{
  "caption": "Agent Message",
  "name": "agent_message",
  "description": "A communication between two AI agents over an agentic protocol (A2A, ACP, ANP, MCP, ...). One generic object discriminated by protocol_id rather than a per-protocol object.",
  "extends": "object",
  "attributes": {
    "protocol_id": {
      "requirement": "recommended",
      "enum": {
        "0": { "caption": "Unknown" },
        "1": { "caption": "A2A" },
        "2": { "caption": "ACP" },
        "3": { "caption": "ANP" },
        "4": { "caption": "MCP" },
        "99": { "caption": "Other" }
      }
    },
    "protocol":        { "requirement": "optional", "description": "Protocol name; caption of protocol_id." },
    "protocol_version":{ "requirement": "optional" },
    "direction_id": {
      "requirement": "recommended",
      "enum": {
        "0": { "caption": "Unknown" },
        "1": { "caption": "Request" },
        "2": { "caption": "Response" },
        "3": { "caption": "Stream" },
        "4": { "caption": "Notification" },
        "99": { "caption": "Other" }
      }
    },
    "role_id": {
      "requirement": "optional",
      "enum": {
        "0": { "caption": "Unknown" }, "1": { "caption": "Client" },
        "2": { "caption": "Server" }, "99": { "caption": "Other" }
      }
    },
    "operation":   { "requirement": "optional", "description": "Method/capability invoked (e.g. A2A method, ACP run mode, ANP meta-protocol)." },
    "unit_uid":    { "requirement": "recommended", "description": "Normalized id of the unit of work (task/run/message)." },
    "unit_type":   { "requirement": "optional", "description": "task | run | message." },
    "status_id": {
      "requirement": "recommended",
      "description": "Canonical lifecycle status (normalized across protocols).",
      "enum": {
        "0":  { "caption": "Unknown" },
        "1":  { "caption": "Submitted" },
        "2":  { "caption": "Working" },
        "3":  { "caption": "Input Required" },
        "4":  { "caption": "Completed" },
        "5":  { "caption": "Failed" },
        "6":  { "caption": "Canceling" },
        "7":  { "caption": "Canceled" },
        "99": { "caption": "Other" }
      }
    },
    "previous_status_id": { "requirement": "optional", "description": "Prior status_id (same enum)." },
    "src_agent":   { "requirement": "recommended", "description": "Initiating agent (ai_agent)." },
    "dst_agent":   { "requirement": "recommended", "description": "Peer/target agent (ai_agent)." },
    "delegation":  { "requirement": "optional", "description": "Authorization context for the call (delegation object, #1640)." },
    "parts_count":     { "requirement": "optional" },
    "part_types":      { "requirement": "optional" },
    "artifacts_count": { "requirement": "optional" },
    "transport":   { "requirement": "optional", "description": "jsonrpc | grpc | http | sse | ws." },
    "src_endpoint":{ "requirement": "optional", "description": "Initiator endpoint (network_endpoint)." },
    "dst_endpoint":{ "requirement": "optional", "description": "Peer endpoint (network_endpoint)." },
    "trust_domain":     { "requirement": "optional" },
    "peer_trust_domain":{ "requirement": "optional" },
    "is_cross_domain":  { "requirement": "optional" },
    "peer_did":    { "requirement": "optional", "description": "Peer decentralized identifier (ANP)." },
    "error_code":  { "requirement": "optional" },
    "error_message":{ "requirement": "optional" },
    "duration":    { "requirement": "optional", "description": "Duration in milliseconds." },
    "metadata":    { "requirement": "optional", "description": "Protocol-specific fields that do not generalize." }
  }
}
```

`src_agent` / `dst_agent` reuse the **`ai_agent`** object (#1641);
`src_endpoint` / `dst_endpoint` reuse **`network_endpoint`**; `delegation`
reuses the **`delegation`** object (#1640).

### New class — `events/ai/agent_communication.json` (`ai` category)

```json
{
  "caption": "Agent Communication",
  "name": "agent_communication",
  "extends": "base_event",
  "category": "ai",
  "description": "Records a communication between AI agents over an agentic protocol. Carries the agent_message object and the ai_operation profile.",
  "profiles": ["ai_operation"],
  "attributes": {
    "activity_id": {
      "enum": {
        "0":  { "caption": "Unknown" },
        "1":  { "caption": "Send" },
        "2":  { "caption": "Receive" },
        "3":  { "caption": "Stream" },
        "4":  { "caption": "Notify" },
        "99": { "caption": "Other" }
      }
    },
    "agent_message": { "requirement": "required" },
    "src_agent":     { "requirement": "recommended" },
    "dst_agent":     { "requirement": "recommended" }
  }
}
```

> `category` / `class_uid` follow whatever the `ai` category from #1640
> finalizes (AITF uses provisional `class_uid 9003`).

### Dictionary additions — `dictionary.json`

```json
{
  "attributes": {
    "agent_message":    { "caption": "Agent Message", "description": "An agent-to-agent communication.", "type": "agent_message" },
    "protocol_version": { "caption": "Protocol Version", "description": "Version of the agentic protocol.", "type": "string_t" },
    "unit_uid":         { "caption": "Unit UID", "description": "Normalized unit-of-work id (task/run/message).", "type": "string_t" },
    "unit_type":        { "caption": "Unit Type", "description": "task | run | message.", "type": "string_t" },
    "peer_did":         { "caption": "Peer DID", "description": "Peer decentralized identifier.", "type": "string_t" },
    "peer_trust_domain":{ "caption": "Peer Trust Domain", "description": "Trust domain of the peer agent.", "type": "string_t" },
    "part_types":       { "caption": "Part Types", "description": "Content part media types.", "type": "string_t", "is_array": true },
    "parts_count":      { "caption": "Parts Count", "type": "integer_t" },
    "artifacts_count":  { "caption": "Artifacts Count", "type": "integer_t" }
  }
}
```

> Reuse existing dictionary attributes where present: `protocol`/`protocol_id`,
> `direction`/`direction_id`, `role_id`, `operation`, `status_id`,
> `previous_status_id`, `src_agent`/`dst_agent`, `delegation`, `transport`,
> `src_endpoint`/`dst_endpoint`, `trust_domain`, `is_cross_domain`,
> `error_code`/`error_message`, `duration`, `metadata`. Only add the entries
> above that are not already defined on `main`.

## Cross-protocol status normalization (informative)

Producers map protocol-native lifecycle states onto the canonical `status_id`:

| canonical `status_id` | A2A `task.state` | ACP `run.status` |
|---|---|---|
| Submitted (1) | `submitted` | `created` |
| Working (2) | `working` | `in-progress` |
| Input Required (3) | `input-required`, `auth-required` | `awaiting` |
| Completed (4) | `completed` | `completed` |
| Failed (5) | `failed`, `rejected` | `failed` |
| Canceling (6) | — | `cancelling` |
| Canceled (7) | `canceled` | `cancelled` |

## Backwards compatibility

Additive: one new object + one new class in the (new) `ai` category, all
attributes optional except `agent_message` on the class. No existing object,
class, or attribute changes.

## Testing

- [ ] Schema validation passes with the new object and class.
- [ ] Server renders `agent_message`, the enums, and the `agent_communication` class.
- [ ] `dictionary.json` references resolve.

## Checklist

- [ ] `objects/agent_message.json` added.
- [ ] `events/ai/agent_communication.json` added (after the `ai` category lands).
- [ ] `dictionary.json` updated.
- [ ] `CHANGELOG.md` updated.
- [ ] Linked to #1640 (depends on the `ai` category) and #1641 (`ai_agent`).
