"""AITF Agent Instrumentation.

Provides tracing for AI agent operations: sessions, steps, delegation,
multi-agent orchestration, and memory access.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import AgentAttributes, GenAIAttributes, MemoryAttributes

_TRACER_NAME = "instrumentation.agent"


class AgentInstrumentor:
    """Instrumentor for AI agent operations."""

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

    @contextmanager
    def trace_session(
        self,
        agent_name: str,
        agent_id: str | None = None,
        agent_type: str = "autonomous",
        framework: str = "custom",
        version: str | None = None,
        description: str | None = None,
        session_id: str | None = None,
        team_name: str | None = None,
        workflow_id: str | None = None,
        state: str | None = None,
    ) -> Generator[AgentSession, None, None]:
        """Context manager for tracing an agent session.

        Usage:
            with agent.trace_session("research-agent", framework="langchain") as session:
                with session.step("planning") as step:
                    step.set_thought("I need to search for information")
                with session.step("tool_use") as step:
                    result = call_tool(...)
                    step.set_observation(result)
        """
        tracer = self.get_tracer()
        session_id = session_id or str(uuid.uuid4())
        agent_id = agent_id or str(uuid.uuid4())

        attributes: dict[str, Any] = {
            GenAIAttributes.AGENT_NAME: agent_name,
            GenAIAttributes.AGENT_ID: agent_id,
            AgentAttributes.TYPE: agent_type,
            AgentAttributes.FRAMEWORK: framework,
            GenAIAttributes.CONVERSATION_ID: session_id,
        }
        if version:
            attributes[GenAIAttributes.AGENT_VERSION] = version
        if description:
            attributes[GenAIAttributes.AGENT_DESCRIPTION] = description
        if team_name:
            attributes[AgentAttributes.TEAM_NAME] = team_name
        if workflow_id:
            attributes[AgentAttributes.WORKFLOW_ID] = workflow_id
        if state:
            attributes[AgentAttributes.STATE] = state

        with tracer.start_as_current_span(
            name=f"agent.session {agent_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            session = AgentSession(span, tracer, agent_name, session_id)
            try:
                yield session
                span.set_attribute(AgentAttributes.SESSION_TURN_COUNT, session.step_count)
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_team(
        self,
        team_name: str,
        team_id: str | None = None,
        topology: str = "hierarchical",
        members: list[str] | None = None,
        coordinator: str | None = None,
    ) -> Generator[trace.Span, None, None]:
        """Context manager for tracing a multi-agent team orchestration."""
        tracer = self.get_tracer()
        team_id = team_id or str(uuid.uuid4())
        attributes: dict[str, Any] = {
            AgentAttributes.TEAM_NAME: team_name,
            AgentAttributes.TEAM_ID: team_id,
            AgentAttributes.TEAM_TOPOLOGY: topology,
        }
        if members:
            attributes[AgentAttributes.TEAM_MEMBERS] = members
        if coordinator:
            attributes[AgentAttributes.TEAM_COORDINATOR] = coordinator

        with tracer.start_as_current_span(
            name=f"agent.team.orchestrate {team_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


class AgentSession:
    """Helper for managing an agent session's spans."""

    def __init__(
        self,
        span: trace.Span,
        tracer: trace.Tracer,
        agent_name: str,
        session_id: str,
    ):
        self._span = span
        self._tracer = tracer
        self._agent_name = agent_name
        self._session_id = session_id
        self._step_count = 0

    @property
    def span(self) -> trace.Span:
        return self._span

    @property
    def step_count(self) -> int:
        return self._step_count

    def set_state(self, state: str) -> None:
        """Set the agent lifecycle state (CoSAI WS2: AGENT_TRACE)."""
        self._span.set_attribute(AgentAttributes.STATE, state)

    def set_workflow_id(self, workflow_id: str) -> None:
        """Set the workflow ID (CoSAI WS2: AGENT_TRACE)."""
        self._span.set_attribute(AgentAttributes.WORKFLOW_ID, workflow_id)

    @contextmanager
    def step(
        self,
        step_type: str,
        **kwargs: Any,
    ) -> Generator[AgentStep, None, None]:
        """Create a child span for an agent step."""
        self._step_count += 1
        attributes: dict[str, Any] = {
            GenAIAttributes.AGENT_NAME: self._agent_name,
            AgentAttributes.STEP_TYPE: step_type,
            AgentAttributes.STEP_INDEX: self._step_count,
        }
        # Validate extra attributes to prevent namespace pollution
        _ALLOWED_VALUE_TYPES = (str, int, float, bool)
        _MAX_ATTR_KEY_LEN = 128
        for key, value in kwargs.items():
            if len(key) > _MAX_ATTR_KEY_LEN:
                continue
            if not isinstance(value, _ALLOWED_VALUE_TYPES):
                continue
            attr_key = f"agent.step.{key}"
            attributes[attr_key] = value

        with self._tracer.start_as_current_span(
            name=f"agent.step.{step_type} {self._agent_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            step = AgentStep(span)
            try:
                yield step
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def delegate(
        self,
        target_agent: str,
        target_agent_id: str | None = None,
        reason: str | None = None,
        strategy: str = "capability",
        task: str | None = None,
    ) -> Generator[trace.Span, None, None]:
        """Create a delegation span."""
        self._step_count += 1
        target_agent_id = target_agent_id or str(uuid.uuid4())
        attributes: dict[str, Any] = {
            GenAIAttributes.AGENT_NAME: self._agent_name,
            AgentAttributes.STEP_TYPE: AgentAttributes.StepType.DELEGATION,
            AgentAttributes.STEP_INDEX: self._step_count,
            AgentAttributes.DELEGATION_TARGET_AGENT: target_agent,
            AgentAttributes.DELEGATION_TARGET_AGENT_ID: target_agent_id,
            AgentAttributes.DELEGATION_STRATEGY: strategy,
        }
        if reason:
            attributes[AgentAttributes.DELEGATION_REASON] = reason
        if task:
            attributes[AgentAttributes.DELEGATION_TASK] = task

        with self._tracer.start_as_current_span(
            name=f"agent.delegate {self._agent_name} -> {target_agent}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def memory_access(
        self,
        operation: str,
        store: str = "short_term",
        key: str | None = None,
    ) -> Generator[trace.Span, None, None]:
        """Create a memory access span."""
        attributes: dict[str, Any] = {
            GenAIAttributes.AGENT_NAME: self._agent_name,
            MemoryAttributes.OPERATION: operation,
            MemoryAttributes.STORE: store,
        }
        if key:
            attributes[MemoryAttributes.KEY] = key

        with self._tracer.start_as_current_span(
            name=f"agent.memory.{operation} {self._agent_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


class AgentStep:
    """Helper for setting attributes on an agent step span."""

    def __init__(self, span: trace.Span):
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_thought(self, thought: str) -> None:
        self._span.set_attribute(AgentAttributes.STEP_THOUGHT, thought)

    def set_action(self, action: str) -> None:
        self._span.set_attribute(AgentAttributes.STEP_ACTION, action)

    def set_observation(self, observation: str) -> None:
        self._span.set_attribute(AgentAttributes.STEP_OBSERVATION, observation)

    def set_status(self, status: str) -> None:
        self._span.set_attribute(AgentAttributes.STEP_STATUS, status)

    def set_scratchpad(self, scratchpad: str) -> None:
        """Set the agent scratchpad / working memory (CoSAI WS2: AGENT_TRACE)."""
        self._span.set_attribute(AgentAttributes.SCRATCHPAD, scratchpad)

    def set_next_action(self, next_action: str) -> None:
        """Set the next planned action (CoSAI WS2: AGENT_TRACE)."""
        self._span.set_attribute(AgentAttributes.NEXT_ACTION, next_action)


def agent_span(
    agent_name: str,
    framework: str = "custom",
    agent_type: str = "autonomous",
) -> Callable:
    """Decorator for tracing agent functions.

    Usage:
        @agent_span(agent_name="research-agent", framework="langchain")
        async def research_agent(query: str):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            instrumentor = AgentInstrumentor()
            with instrumentor.trace_session(
                agent_name=agent_name,
                framework=framework,
                agent_type=agent_type,
            ):
                return func(*args, **kwargs)

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            instrumentor = AgentInstrumentor()
            with instrumentor.trace_session(
                agent_name=agent_name,
                framework=framework,
                agent_type=agent_type,
            ):
                return await func(*args, **kwargs)

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator
