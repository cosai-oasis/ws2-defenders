# Agentic Identity Span Conventions

AITF defines comprehensive semantic conventions for AI agent identity management — covering the full lifecycle from identity creation through authentication, authorization, delegation, and revocation. These conventions enable secure, auditable, and observable identity operations in single-agent and multi-agent systems.

## Overview

The `identity.*` namespace covers the complete agent identity lifecycle:

| Stage | Span Name | Description |
|-------|-----------|-------------|
| Lifecycle | `identity.lifecycle` | Identity creation, rotation, suspension, revocation |
| Authentication | `identity.authentication` | Agent authentication (OAuth, mTLS, SPIFFE, JWT) |
| Authorization | `identity.authorization` | Permission checks, policy evaluation |
| Delegation | `identity.delegation` | Credential delegation, token exchange, OBO flows |
| Trust | `identity.trust` | Agent-to-agent trust establishment, VC verification |
| Session | `identity.session` | Identity session management |

---

## Span: `identity.lifecycle`

Represents an agent identity lifecycle event (creation, rotation, revocation).

### Span Name

Format: `identity.lifecycle.{identity.lifecycle.operation} {identity.agent_id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.agent_id` | string | Agent identity identifier |
| `identity.agent_name` | string | Agent name |
| `identity.lifecycle.operation` | string | Lifecycle operation (see below) |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.type` | string | Identity type (see below) |
| `identity.provider` | string | Identity provider (`"okta"`, `"entra_id"`, `"auth0"`, `"spiffe"`, `"custom"`) |
| `identity.owner` | string | Human or system owner of this identity |
| `identity.owner_type` | string | `"human"`, `"service"`, `"organization"` |
| `identity.credential_type` | string | `"api_key"`, `"oauth_token"`, `"jwt"`, `"mtls_cert"`, `"spiffe_svid"`, `"did"` |
| `identity.credential_id` | string | Credential identifier (not the secret) |
| `identity.expires_at` | string | Credential expiration ISO timestamp |
| `identity.ttl_seconds` | int | Time to live in seconds |
| `identity.auto_rotate` | boolean | Whether credential auto-rotates |
| `identity.rotation_interval_seconds` | int | Rotation interval |
| `identity.scope` | string[] | Granted scopes |
| `identity.tags` | string | JSON-encoded identity metadata tags |
| `identity.status` | string | `"active"`, `"suspended"`, `"revoked"`, `"expired"` |
| `identity.previous_status` | string | Previous status (for transitions) |

### Lifecycle Operations

| Value | Description |
|-------|-------------|
| `create` | Create new agent identity |
| `register` | Register identity with an IdP or service |
| `activate` | Activate a pending identity |
| `rotate` | Rotate credentials (key, cert, token) |
| `suspend` | Temporarily suspend an identity |
| `reactivate` | Reactivate a suspended identity |
| `revoke` | Permanently revoke an identity |
| `expire` | Identity expired automatically |
| `update` | Update identity metadata or scope |

### Identity Types

| Value | Description |
|-------|-------------|
| `persistent` | Long-lived agent identity with stable credentials |
| `ephemeral` | Short-lived identity created for a single task |
| `delegated` | Identity derived from delegation of another identity |
| `federated` | Identity from a federated trust domain |
| `workload` | SPIFFE-style workload identity |

---

## Span: `identity.authentication`

Represents an agent authentication attempt.

### Span Name

Format: `identity.auth {identity.agent_name}`

### Span Kind

`CLIENT`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.agent_id` | string | Agent identity ID |
| `identity.agent_name` | string | Agent name |
| `identity.auth.method` | string | Authentication method (see below) |
| `identity.auth.result` | string | `"success"`, `"failure"`, `"denied"`, `"expired"`, `"revoked"` |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.auth.provider` | string | Auth provider service |
| `identity.auth.target_service` | string | Service being authenticated to |
| `identity.auth.failure_reason` | string | Reason for failure (if applicable) |
| `identity.auth.token_type` | string | Token type received (`"bearer"`, `"dpop"`, `"mtls_bound"`) |
| `identity.auth.token_lifetime_seconds` | int | Token lifetime |
| `identity.auth.scope_requested` | string[] | Scopes requested |
| `identity.auth.scope_granted` | string[] | Scopes actually granted |
| `identity.auth.mfa_used` | boolean | Whether MFA was used |
| `identity.auth.continuous` | boolean | Whether this is continuous re-authentication |
| `identity.auth.protocol_version` | string | Auth protocol version |
| `identity.auth.client_id` | string | OAuth client ID |
| `identity.auth.pkce_used` | boolean | Whether PKCE was used |
| `identity.auth.dpop_used` | boolean | Whether DPoP proof was included |

### Authentication Methods

| Value | Description |
|-------|-------------|
| `api_key` | Static API key authentication |
| `oauth2` | OAuth 2.0/2.1 flow |
| `oauth2_pkce` | OAuth 2.1 with PKCE (MCP standard) |
| `jwt_bearer` | JWT Bearer token (RFC 7523) |
| `mtls` | Mutual TLS certificate authentication |
| `spiffe_svid` | SPIFFE Verifiable Identity Document |
| `did_vc` | Decentralized Identifier + Verifiable Credential |
| `http_signature` | HTTP Message Signature (W3C) |
| `token_exchange` | OAuth Token Exchange (RFC 8693) |
| `saml` | SAML assertion |

---

## Span: `identity.authorization`

Represents a permission check or policy evaluation.

### Span Name

Format: `identity.authz {identity.agent_name} -> {identity.authz.resource}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.agent_id` | string | Agent identity ID |
| `identity.agent_name` | string | Agent name |
| `identity.authz.decision` | string | `"allow"`, `"deny"`, `"conditional"` |
| `identity.authz.resource` | string | Resource being accessed |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.authz.action` | string | Action being performed (`"read"`, `"write"`, `"execute"`, `"delete"`) |
| `identity.authz.policy_engine` | string | Policy engine (`"opa"`, `"cedar"`, `"casbin"`, `"custom"`) |
| `identity.authz.policy_id` | string | Matched policy identifier |
| `identity.authz.policy_version` | string | Policy version |
| `identity.authz.deny_reason` | string | Reason for denial (if denied) |
| `identity.authz.conditions` | string | JSON-encoded conditions (for conditional allow) |
| `identity.authz.scope_required` | string[] | Scopes required for this action |
| `identity.authz.scope_present` | string[] | Scopes present in token |
| `identity.authz.risk_score` | double | Risk-based authorization score (0-100) |
| `identity.authz.context` | string | JSON-encoded authorization context (time, location, etc.) |
| `identity.authz.privilege_level` | string | `"standard"`, `"elevated"`, `"admin"` |
| `identity.authz.jea` | boolean | Whether Just-Enough-Access was applied |
| `identity.authz.time_limited` | boolean | Whether permission is time-limited |
| `identity.authz.expires_at` | string | Permission expiration ISO timestamp |

---

## Span: `identity.delegation`

Represents credential delegation in a multi-agent system — On-Behalf-Of flows, token exchange, and authority attenuation.

### Span Name

Format: `identity.delegate {identity.delegation.delegator} -> {identity.delegation.delegatee}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.delegation.delegator` | string | Agent/user delegating authority |
| `identity.delegation.delegator_id` | string | Delegator identity ID |
| `identity.delegation.delegatee` | string | Agent receiving delegated authority |
| `identity.delegation.delegatee_id` | string | Delegatee identity ID |
| `identity.delegation.type` | string | Delegation type (see below) |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.delegation.chain` | string[] | Full delegation chain (ordered from origin) |
| `identity.delegation.chain_depth` | int | Depth of delegation chain |
| `identity.delegation.scope_delegated` | string[] | Scopes being delegated |
| `identity.delegation.scope_attenuated` | boolean | Whether scope was reduced (should always be true) |
| `identity.delegation.original_scope` | string[] | Original (broader) scope |
| `identity.delegation.result` | string | `"success"`, `"failure"`, `"denied"`, `"expired"` |
| `identity.delegation.reason` | string | Reason for delegation |
| `identity.delegation.task_id` | string | Task this delegation is for |
| `identity.delegation.expires_at` | string | Delegation expiration ISO timestamp |
| `identity.delegation.ttl_seconds` | int | Delegation time to live |
| `identity.delegation.revocable` | boolean | Whether delegation can be revoked |
| `identity.delegation.proof_type` | string | `"dpop"`, `"mtls_binding"`, `"signed_assertion"` |
| `identity.delegation.obo_token_id` | string | On-Behalf-Of token identifier |
| `identity.delegation.act_claim` | string | JWT `act` claim value |

### Delegation Types

| Value | Description |
|-------|-------------|
| `on_behalf_of` | OAuth On-Behalf-Of (OBO) delegation |
| `token_exchange` | OAuth Token Exchange (RFC 8693) |
| `credential_forwarding` | Forwarding credentials to sub-agent |
| `impersonation` | Agent impersonating delegator (with explicit grant) |
| `capability_grant` | Granting specific capabilities to another agent |
| `scoped_proxy` | Scoped proxy access through the delegator |

---

## Span: `identity.trust`

Represents trust establishment between agents — agent-to-agent authentication, verifiable credential exchange, and trust boundary crossings.

### Span Name

Format: `identity.trust.{identity.trust.operation} {identity.trust.peer_agent}`

### Span Kind

`CLIENT`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.agent_id` | string | This agent's identity ID |
| `identity.agent_name` | string | This agent's name |
| `identity.trust.operation` | string | Trust operation (see below) |
| `identity.trust.peer_agent` | string | Peer agent name |
| `identity.trust.peer_agent_id` | string | Peer agent identity ID |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.trust.result` | string | `"established"`, `"failed"`, `"rejected"`, `"revoked"` |
| `identity.trust.method` | string | `"mtls"`, `"spiffe"`, `"did_vc"`, `"http_signature"`, `"pki"` |
| `identity.trust.trust_domain` | string | Trust domain (e.g., SPIFFE trust domain) |
| `identity.trust.peer_trust_domain` | string | Peer's trust domain |
| `identity.trust.cross_domain` | boolean | Whether this is a cross-domain trust operation |
| `identity.trust.vc_type` | string | Verifiable Credential type presented |
| `identity.trust.vc_issuer` | string | VC issuer |
| `identity.trust.vc_verified` | boolean | Whether VC was successfully verified |
| `identity.trust.trust_level` | string | `"none"`, `"basic"`, `"verified"`, `"high"`, `"full"` |
| `identity.trust.protocol` | string | Trust protocol (`"mcp"`, `"a2a"`, `"custom"`) |
| `identity.trust.federation_id` | string | Federation identifier (for federated trust) |

### Trust Operations

| Value | Description |
|-------|-------------|
| `establish` | Establish trust with a peer agent |
| `verify` | Verify a peer agent's identity |
| `present_credential` | Present a verifiable credential to a peer |
| `verify_credential` | Verify a peer's verifiable credential |
| `federation_join` | Join a trust federation |
| `federation_leave` | Leave a trust federation |
| `boundary_cross` | Cross a trust boundary between domains |
| `revoke_trust` | Revoke trust with a peer |

---

## Span: `identity.session`

Represents an identity session — binding an authenticated identity to a set of operations.

### Span Name

Format: `identity.session {identity.agent_name}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.agent_id` | string | Agent identity ID |
| `identity.agent_name` | string | Agent name |
| `identity.session.id` | string | Identity session ID |
| `identity.session.operation` | string | Session operation (see below) |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.session.auth_method` | string | Authentication method used |
| `identity.session.scope` | string[] | Active session scopes |
| `identity.session.expires_at` | string | Session expiration ISO timestamp |
| `identity.session.created_at` | string | Session creation ISO timestamp |
| `identity.session.last_activity` | string | Last activity ISO timestamp |
| `identity.session.actions_count` | int | Number of actions in this session |
| `identity.session.delegations_count` | int | Number of delegations from this session |
| `identity.session.ip_address` | string | Source IP (if network-based) |
| `identity.session.user_agent` | string | Client user agent |
| `identity.session.termination_reason` | string | `"completed"`, `"timeout"`, `"revoked"`, `"error"`, `"manual"` |

### Session Operations

| Value | Description |
|-------|-------------|
| `create` | Create new identity session |
| `refresh` | Refresh session credentials |
| `validate` | Validate an existing session |
| `terminate` | Terminate a session |
| `timeout` | Session timed out |
| `hijack_detected` | Potential session hijacking detected |

---

## Example: Multi-Agent Delegation Chain

```
Span: identity.lifecycle.create agent-orchestrator
  identity.type: "persistent"
  identity.credential_type: "spiffe_svid"
  identity.provider: "spiffe"
  identity.owner: "platform-team"
  │
  └─ Span: identity.auth agent-orchestrator
       identity.auth.method: "spiffe_svid"
       identity.auth.result: "success"
       identity.auth.scope_granted: ["tools:*", "agents:delegate", "data:read"]
       │
       ├─ Span: identity.authz agent-orchestrator -> customer-db
       │    identity.authz.decision: "allow"
       │    identity.authz.action: "read"
       │    identity.authz.policy_engine: "opa"
       │
       └─ Span: identity.delegate agent-orchestrator -> agent-researcher
            identity.delegation.type: "on_behalf_of"
            identity.delegation.scope_delegated: ["data:read"]
            identity.delegation.scope_attenuated: true
            identity.delegation.chain: ["user-alice", "agent-orchestrator", "agent-researcher"]
            identity.delegation.chain_depth: 2
            │
            └─ Span: identity.trust.establish agent-writer
                 identity.trust.method: "mtls"
                 identity.trust.result: "established"
                 identity.trust.cross_domain: false
```

## Example: Ephemeral Task Identity

```
Span: identity.lifecycle.create task-agent-7f3a
  identity.type: "ephemeral"
  identity.credential_type: "jwt"
  identity.ttl_seconds: 300
  identity.owner: "agent-orchestrator"
  identity.scope: ["tools:web_search", "data:read:public"]
  │
  ├─ Span: identity.session task-agent-7f3a
  │    identity.session.operation: "create"
  │    identity.session.scope: ["tools:web_search", "data:read:public"]
  │    identity.session.expires_at: "2026-02-16T10:05:00Z"
  │
  ├─ Span: identity.authz task-agent-7f3a -> web-search-api
  │    identity.authz.decision: "allow"
  │    identity.authz.jea: true
  │    identity.authz.time_limited: true
  │
  └─ Span: identity.lifecycle.expire task-agent-7f3a
       identity.status: "expired"
       identity.previous_status: "active"
```
