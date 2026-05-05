"""AITF Skills Instrumentation.

Provides tracing for skill discovery, invocation, composition, and resolution.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import SkillAttributes

_TRACER_NAME = "instrumentation.skills"


class SkillInstrumentor:
    """Instrumentor for skill operations."""

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
    def trace_invoke(
        self,
        skill_name: str,
        version: str = "1.0.0",
        skill_id: str | None = None,
        provider: str = "custom",
        category: str | None = None,
        description: str | None = None,
        skill_input: str | None = None,
        source: str | None = None,
        permissions: list[str] | None = None,
        skill_hash: str | None = None,
        authors: list[str] | None = None,
    ) -> Generator[SkillInvocation, None, None]:
        """Trace a skill invocation."""
        tracer = self.get_tracer()
        start = time.monotonic()
        attributes: dict[str, Any] = {
            SkillAttributes.NAME: skill_name,
            SkillAttributes.VERSION: version,
            SkillAttributes.PROVIDER: provider,
        }
        if skill_id:
            attributes[SkillAttributes.ID] = skill_id
        if category:
            attributes[SkillAttributes.CATEGORY] = category
        if description:
            attributes[SkillAttributes.DESCRIPTION] = description
        if skill_input is not None:
            attributes[SkillAttributes.INPUT] = skill_input
        if source:
            attributes[SkillAttributes.SOURCE] = source
        if permissions:
            attributes[SkillAttributes.PERMISSIONS] = permissions
        if skill_hash:
            attributes[SkillAttributes.HASH] = skill_hash
        if authors:
            attributes[SkillAttributes.AUTHORS] = authors

        with tracer.start_as_current_span(
            name=f"skill.invoke {skill_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            invocation = SkillInvocation(span, start)
            try:
                yield invocation
                duration = (time.monotonic() - start) * 1000
                span.set_attribute(SkillAttributes.DURATION_MS, duration)
                if not invocation._status_set:
                    span.set_attribute(SkillAttributes.STATUS, SkillAttributes.Status.SUCCESS)
                span.set_status(StatusCode.OK)
            except Exception as exc:
                duration = (time.monotonic() - start) * 1000
                span.set_attribute(SkillAttributes.DURATION_MS, duration)
                span.set_attribute(SkillAttributes.STATUS, SkillAttributes.Status.ERROR)
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_discover(
        self,
        source: str,
        filter_category: str | None = None,
    ) -> Generator[SkillDiscovery, None, None]:
        """Trace skill discovery from a source."""
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            SkillAttributes.SOURCE: source,
        }
        if filter_category:
            attributes["skill.filter.category"] = filter_category

        with tracer.start_as_current_span(
            name=f"skill.discover {source}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            discovery = SkillDiscovery(span)
            try:
                yield discovery
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    @contextmanager
    def trace_compose(
        self,
        workflow_name: str,
        skills: list[str],
        pattern: str = "sequential",
    ) -> Generator[SkillComposition, None, None]:
        """Trace a skill composition/workflow."""
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            SkillAttributes.COMPOSE_NAME: workflow_name,
            SkillAttributes.COMPOSE_SKILLS: skills,
            SkillAttributes.COMPOSE_PATTERN: pattern,
            SkillAttributes.COMPOSE_TOTAL: len(skills),
        }

        with tracer.start_as_current_span(
            name=f"skill.compose {workflow_name}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            composition = SkillComposition(span, tracer)
            try:
                yield composition
                span.set_attribute(
                    SkillAttributes.COMPOSE_COMPLETED, composition.completed_count
                )
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                raise


class SkillInvocation:
    """Helper for skill invocation spans."""

    def __init__(self, span: trace.Span, start_time: float):
        self._span = span
        self._start_time = start_time
        self._status_set = False

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_output(self, output: str) -> None:
        self._span.set_attribute(SkillAttributes.OUTPUT, output)
        self._span.add_event(
            "skill.output",
            attributes={"skill.output.content": output},
        )

    def set_status(self, status: str) -> None:
        self._span.set_attribute(SkillAttributes.STATUS, status)
        self._status_set = True

    def set_error(self, error_type: str, message: str, retryable: bool = False) -> None:
        self._span.set_attribute(SkillAttributes.STATUS, SkillAttributes.Status.ERROR)
        self._status_set = True
        self._span.add_event(
            "skill.error",
            attributes={
                "skill.error.type": error_type,
                "skill.error.message": message,
                "skill.error.retryable": retryable,
            },
        )

    def set_retry_count(self, count: int) -> None:
        self._span.set_attribute(SkillAttributes.RETRY_COUNT, count)

    def set_hash(self, hash_value: str) -> None:
        self._span.set_attribute(SkillAttributes.HASH, hash_value)

    def set_authors(self, authors: list[str]) -> None:
        self._span.set_attribute(SkillAttributes.AUTHORS, authors)


class SkillDiscovery:
    """Helper for skill discovery spans."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_skills(self, skill_names: list[str]) -> None:
        self._span.set_attribute(SkillAttributes.COUNT, len(skill_names))
        self._span.set_attribute(SkillAttributes.NAMES, skill_names)


class SkillComposition:
    """Helper for skill composition spans."""

    def __init__(self, span: trace.Span, tracer: trace.Tracer):
        self._span = span
        self._tracer = tracer
        self._completed = 0

    @property
    def completed_count(self) -> int:
        return self._completed

    def mark_completed(self) -> None:
        self._completed += 1


def skill_span(
    skill_name: str,
    version: str = "1.0.0",
    category: str | None = None,
    provider: str = "custom",
) -> Callable:
    """Decorator for tracing skill functions.

    Usage:
        @skill_span(skill_name="web-search", version="2.1.0", category="search")
        async def web_search(query: str):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            instrumentor = SkillInstrumentor()
            with instrumentor.trace_invoke(
                skill_name=skill_name,
                version=version,
                category=category,
                provider=provider,
            ):
                return func(*args, **kwargs)

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            instrumentor = SkillInstrumentor()
            with instrumentor.trace_invoke(
                skill_name=skill_name,
                version=version,
                category=category,
                provider=provider,
            ):
                return await func(*args, **kwargs)

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator
