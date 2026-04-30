"""AITF Agentic Identity Instrumentation.

Provides tracing for the complete agent identity lifecycle: identity creation,
authentication, authorization, delegation, trust establishment, and session
management. Supports OAuth 2.1, SPIFFE, mTLS, DID/VC, and other modern
identity protocols for AI agents.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import IdentityAttributes

_TRACER_NAME = "aitf.instrumentation.identity"


class IdentityInstrumentor:
    """Instrumentor for AI agent identity operations."""

    def __init__(self, tracer_provider: TracerProvider | None = None):
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False

    def instrument(self) -> None:
        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)
        self._instrumented = True

    def uninstrument(self) -> None:
        self._tracer = None
        self._instrumented = False

    def get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    # ── Lifecycle ─────────────────────────────────────────────────────

    @contextmanager
    def trace_lifecycle(
        self,
        agent_id: str,
        agent_name: str,
        operation: str,
        identity_type: str = "persistent",
        provider: str | None = None,
        owner: str | None = None,
        owner_type: str | None = None,
        credential_type: str | None = None,
        scope: list[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> Generator[IdentityLifecycle, None, None]:
        """Context manager for tracing identity lifecycle operations.

        Usage:
            with identity.trace_lifecycle(
                agent_id="agent-orch-001",
                agent_name="orchestrator",
                operation="create",
                identity_type="persistent",
                provider="spiffe",
                credential_type="spiffe_svid",
            ) as lifecycle:
                lifecycle.set_status("active")
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            IdentityAttributes.AGENT_ID: agent_id,
            IdentityAttributes.AGENT_NAME: agent_name,
            IdentityAttributes.LIFECYCLE_OPERATION: operation,
            IdentityAttributes.TYPE: identity_type,
        }
        if provider:
            attributes[IdentityAttributes.PROVIDER] = provider
        if owner:
            attributes[IdentityAttributes.OWNER] = owner
        if owner_type:
            attributes[IdentityAttributes.OWNER_TYPE] = owner_type
        if credential_type:
            attributes[IdentityAttributes.CREDENTIAL_TYPE] = credential_type
        if scope:
            attributes[IdentityAttributes.SCOPE] = scope
        if ttl_seconds is not None:
            attributes[IdentityAttributes.TTL_SECONDS] = ttl_seconds

        with tracer.start_as_current_span(
            name=f"identity.lifecycle.{operation} {agent_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            lifecycle = IdentityLifecycle(span)
            try:
                yield lifecycle
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Authentication ────────────────────────────────────────────────

    @contextmanager
    def trace_authentication(
        self,
        agent_id: str,
        agent_name: str,
        method: str,
        target_service: str | None = None,
        provider: str | None = None,
        scope_requested: list[str] | None = None,
    ) -> Generator[AuthenticationAttempt, None, None]:
        """Context manager for tracing an agent authentication attempt.

        Usage:
            with identity.trace_authentication(
                agent_id="agent-orch-001",
                agent_name="orchestrator",
                method="spiffe_svid",
                target_service="customer-db",
            ) as auth:
                # ... perform authentication ...
                auth.set_result("success", scope_granted=["data:read"])
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            IdentityAttributes.AGENT_ID: agent_id,
            IdentityAttributes.AGENT_NAME: agent_name,
            IdentityAttributes.AUTH_METHOD: method,
        }
        if target_service:
            attributes[IdentityAttributes.AUTH_TARGET_SERVICE] = target_service
        if provider:
            attributes[IdentityAttributes.AUTH_PROVIDER] = provider
        if scope_requested:
            attributes[IdentityAttributes.AUTH_SCOPE_REQUESTED] = scope_requested

        with tracer.start_as_current_span(
            name=f"identity.auth {agent_name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            auth = AuthenticationAttempt(span)
            try:
                yield auth
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Authorization ─────────────────────────────────────────────────

    @contextmanager
    def trace_authorization(
        self,
        agent_id: str,
        agent_name: str,
        resource: str,
        action: str = "read",
        policy_engine: str | None = None,
    ) -> Generator[AuthorizationCheck, None, None]:
        """Context manager for tracing an authorization decision.

        Usage:
            with identity.trace_authorization(
                agent_id="agent-orch-001",
                agent_name="orchestrator",
                resource="customer-db",
                action="read",
                policy_engine="opa",
            ) as authz:
                authz.set_decision("allow", policy_id="pol-agent-db-read")
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            IdentityAttributes.AGENT_ID: agent_id,
            IdentityAttributes.AGENT_NAME: agent_name,
            IdentityAttributes.AUTHZ_RESOURCE: resource,
            IdentityAttributes.AUTHZ_ACTION: action,
        }
        if policy_engine:
            attributes[IdentityAttributes.AUTHZ_POLICY_ENGINE] = policy_engine

        with tracer.start_as_current_span(
            name=f"identity.authz {agent_name} -> {resource}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            authz = AuthorizationCheck(span)
            try:
                yield authz
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Delegation ────────────────────────────────────────────────────

    @contextmanager
    def trace_delegation(
        self,
        delegator: str,
        delegator_id: str,
        delegatee: str,
        delegatee_id: str,
        delegation_type: str = "on_behalf_of",
        scope_delegated: list[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> Generator[DelegationOperation, None, None]:
        """Context manager for tracing credential delegation.

        Usage:
            with identity.trace_delegation(
                delegator="agent-orchestrator",
                delegator_id="agent-orch-001",
                delegatee="agent-researcher",
                delegatee_id="agent-res-002",
                delegation_type="on_behalf_of",
                scope_delegated=["data:read"],
            ) as delegation:
                delegation.set_chain(["user-alice", "agent-orch", "agent-res"])
                delegation.set_result("success")
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            IdentityAttributes.DELEGATION_DELEGATOR: delegator,
            IdentityAttributes.DELEGATION_DELEGATOR_ID: delegator_id,
            IdentityAttributes.DELEGATION_DELEGATEE: delegatee,
            IdentityAttributes.DELEGATION_DELEGATEE_ID: delegatee_id,
            IdentityAttributes.DELEGATION_TYPE: delegation_type,
        }
        if scope_delegated:
            attributes[IdentityAttributes.DELEGATION_SCOPE_DELEGATED] = scope_delegated
        if ttl_seconds is not None:
            attributes[IdentityAttributes.DELEGATION_TTL_SECONDS] = ttl_seconds

        with tracer.start_as_current_span(
            name=f"identity.delegate {delegator} -> {delegatee}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            delegation = DelegationOperation(span)
            try:
                yield delegation
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Trust ─────────────────────────────────────────────────────────

    @contextmanager
    def trace_trust(
        self,
        agent_id: str,
        agent_name: str,
        operation: str,
        peer_agent: str,
        peer_agent_id: str,
        method: str = "mtls",
    ) -> Generator[TrustOperation, None, None]:
        """Context manager for tracing trust establishment between agents.

        Usage:
            with identity.trace_trust(
                agent_id="agent-orch-001",
                agent_name="orchestrator",
                operation="establish",
                peer_agent="agent-writer",
                peer_agent_id="agent-wrt-003",
                method="spiffe",
            ) as trust:
                trust.set_result("established", trust_level="verified")
        """
        tracer = self.get_tracer()

        attributes: dict[str, Any] = {
            IdentityAttributes.AGENT_ID: agent_id,
            IdentityAttributes.AGENT_NAME: agent_name,
            IdentityAttributes.TRUST_OPERATION: operation,
            IdentityAttributes.TRUST_PEER_AGENT: peer_agent,
            IdentityAttributes.TRUST_PEER_AGENT_ID: peer_agent_id,
            IdentityAttributes.TRUST_METHOD: method,
        }

        with tracer.start_as_current_span(
            name=f"identity.trust.{operation} {peer_agent}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            trust = TrustOperation(span)
            try:
                yield trust
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    # ── Session ───────────────────────────────────────────────────────

    @contextmanager
    def trace_session(
        self,
        agent_id: str,
        agent_name: str,
        operation: str = "create",
        session_id: str | None = None,
        scope: list[str] | None = None,
        expires_at: str | None = None,
    ) -> Generator[IdentitySession, None, None]:
        """Context manager for tracing identity session operations."""
        tracer = self.get_tracer()
        session_id = session_id or str(uuid.uuid4())

        attributes: dict[str, Any] = {
            IdentityAttributes.AGENT_ID: agent_id,
            IdentityAttributes.AGENT_NAME: agent_name,
            IdentityAttributes.SESSION_ID: session_id,
            IdentityAttributes.SESSION_OPERATION: operation,
        }
        if scope:
            attributes[IdentityAttributes.SESSION_SCOPE] = scope
        if expires_at:
            attributes[IdentityAttributes.SESSION_EXPIRES_AT] = expires_at

        with tracer.start_as_current_span(
            name=f"identity.session {agent_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            session = IdentitySession(span, session_id)
            try:
                yield session
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


# ── Helper Classes ────────────────────────────────────────────────────


class IdentityLifecycle:
    """Helper for recording identity lifecycle attributes."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_status(self, status: str, previous_status: str | None = None) -> None:
        self._span.set_attribute(IdentityAttributes.STATUS, status)
        if previous_status:
            self._span.set_attribute(IdentityAttributes.PREVIOUS_STATUS, previous_status)

    def set_credential(self, credential_id: str, expires_at: str | None = None) -> None:
        self._span.set_attribute(IdentityAttributes.CREDENTIAL_ID, credential_id)
        if expires_at:
            self._span.set_attribute(IdentityAttributes.EXPIRES_AT, expires_at)

    def set_auto_rotate(self, enabled: bool, interval_seconds: int | None = None) -> None:
        self._span.set_attribute(IdentityAttributes.AUTO_ROTATE, enabled)
        if interval_seconds is not None:
            self._span.set_attribute(IdentityAttributes.ROTATION_INTERVAL, interval_seconds)

    @property
    def span(self) -> trace.Span:
        return self._span


class AuthenticationAttempt:
    """Helper for recording authentication attempt results."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_result(
        self,
        result: str,
        scope_granted: list[str] | None = None,
        token_type: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        self._span.set_attribute(IdentityAttributes.AUTH_RESULT, result)
        if scope_granted:
            self._span.set_attribute(IdentityAttributes.AUTH_SCOPE_GRANTED, scope_granted)
        if token_type:
            self._span.set_attribute(IdentityAttributes.AUTH_TOKEN_TYPE, token_type)
        if failure_reason:
            self._span.set_attribute(IdentityAttributes.AUTH_FAILURE_REASON, failure_reason)

    def set_pkce(self, used: bool) -> None:
        self._span.set_attribute(IdentityAttributes.AUTH_PKCE_USED, used)

    def set_dpop(self, used: bool) -> None:
        self._span.set_attribute(IdentityAttributes.AUTH_DPOP_USED, used)

    def set_continuous(self, continuous: bool) -> None:
        self._span.set_attribute(IdentityAttributes.AUTH_CONTINUOUS, continuous)

    @property
    def span(self) -> trace.Span:
        return self._span


class AuthorizationCheck:
    """Helper for recording authorization check results."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_decision(
        self,
        decision: str,
        policy_id: str | None = None,
        deny_reason: str | None = None,
        risk_score: float | None = None,
    ) -> None:
        self._span.set_attribute(IdentityAttributes.AUTHZ_DECISION, decision)
        if policy_id:
            self._span.set_attribute(IdentityAttributes.AUTHZ_POLICY_ID, policy_id)
        if deny_reason:
            self._span.set_attribute(IdentityAttributes.AUTHZ_DENY_REASON, deny_reason)
        if risk_score is not None:
            self._span.set_attribute(IdentityAttributes.AUTHZ_RISK_SCORE, risk_score)

    def set_jea(self, enabled: bool, time_limited: bool = False, expires_at: str | None = None) -> None:
        self._span.set_attribute(IdentityAttributes.AUTHZ_JEA, enabled)
        self._span.set_attribute(IdentityAttributes.AUTHZ_TIME_LIMITED, time_limited)
        if expires_at:
            self._span.set_attribute(IdentityAttributes.AUTHZ_EXPIRES_AT, expires_at)

    @property
    def span(self) -> trace.Span:
        return self._span


class DelegationOperation:
    """Helper for recording delegation operation results."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_chain(self, chain: list[str]) -> None:
        self._span.set_attribute(IdentityAttributes.DELEGATION_CHAIN, chain)
        self._span.set_attribute(IdentityAttributes.DELEGATION_CHAIN_DEPTH, len(chain) - 1)

    def set_result(self, result: str) -> None:
        self._span.set_attribute(IdentityAttributes.DELEGATION_RESULT, result)

    def set_scope_attenuated(self, attenuated: bool, original_scope: list[str] | None = None) -> None:
        self._span.set_attribute(IdentityAttributes.DELEGATION_SCOPE_ATTENUATED, attenuated)

    def set_proof(self, proof_type: str) -> None:
        self._span.set_attribute(IdentityAttributes.DELEGATION_PROOF_TYPE, proof_type)

    @property
    def span(self) -> trace.Span:
        return self._span


class TrustOperation:
    """Helper for recording trust establishment results."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_result(
        self,
        result: str,
        trust_level: str | None = None,
        cross_domain: bool = False,
    ) -> None:
        self._span.set_attribute(IdentityAttributes.TRUST_RESULT, result)
        if trust_level:
            self._span.set_attribute(IdentityAttributes.TRUST_LEVEL, trust_level)
        self._span.set_attribute(IdentityAttributes.TRUST_CROSS_DOMAIN, cross_domain)

    def set_trust_domain(self, domain: str, peer_domain: str | None = None) -> None:
        self._span.set_attribute(IdentityAttributes.TRUST_DOMAIN, domain)
        if peer_domain:
            self._span.set_attribute(IdentityAttributes.TRUST_PEER_DOMAIN, peer_domain)

    def set_protocol(self, protocol: str) -> None:
        self._span.set_attribute(IdentityAttributes.TRUST_PROTOCOL, protocol)

    @property
    def span(self) -> trace.Span:
        return self._span


class IdentitySession:
    """Helper for recording identity session attributes."""

    def __init__(self, span: trace.Span, session_id: str):
        self._span = span
        self.session_id = session_id
        self._actions_count = 0

    def record_action(self) -> None:
        self._actions_count += 1
        self._span.set_attribute(IdentityAttributes.SESSION_ACTIONS_COUNT, self._actions_count)

    def set_termination(self, reason: str) -> None:
        self._span.set_attribute(IdentityAttributes.SESSION_TERMINATION_REASON, reason)

    @property
    def span(self) -> trace.Span:
        return self._span
