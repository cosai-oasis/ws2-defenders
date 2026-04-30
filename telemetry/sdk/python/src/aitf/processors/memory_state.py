"""AITF Memory State Tracking Processor.

An OTel SpanProcessor that monitors agent memory mutations for security-relevant
patterns. Aligned with CoSAI AI Incident Response requirement for memory state
change logging in agentic systems.

Capabilities:
  - Tracks memory writes/updates/deletes with before/after snapshots
  - Detects memory poisoning (unexpected content injection)
  - Verifies session memory isolation
  - Monitors long-term memory growth anomalies
  - Emits security events for suspicious memory operations
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor
from opentelemetry.trace import StatusCode


@dataclass
class MemorySnapshot:
    """Snapshot of a memory entry before/after a mutation."""

    key: str
    store: str
    operation: str
    content_hash_before: str | None = None
    content_hash_after: str | None = None
    size_before: int | None = None
    size_after: int | None = None
    provenance: str | None = None
    session_id: str | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class MemorySecurityEvent:
    """A security event detected by the memory processor."""

    event_type: str
    severity: str
    details: str
    span_id: str
    session_id: str | None = None
    memory_key: str | None = None
    timestamp: float = field(default_factory=time.time)


class MemoryStateProcessor(SpanProcessor):
    """SpanProcessor that tracks memory state changes and detects anomalies.

    Configuration:
        max_memory_entries_per_session: Alert threshold for memory growth.
        max_memory_size_bytes: Alert threshold for total memory size.
        allowed_provenances: Set of trusted provenance sources.
        poisoning_score_threshold: Threshold (0-1) for poisoning detection.
        enable_snapshots: Whether to capture before/after snapshots.
        cross_session_alert: Whether to alert on cross-session memory access.

    Usage:
        from opentelemetry.sdk.trace import TracerProvider
        from aitf.processors.memory_state import MemoryStateProcessor

        processor = MemoryStateProcessor(
            max_memory_entries_per_session=500,
            allowed_provenances={"conversation", "tool_result", "system"},
        )
        provider = TracerProvider()
        provider.add_span_processor(processor)
    """

    def __init__(
        self,
        max_memory_entries_per_session: int = 1000,
        max_memory_size_bytes: int = 50 * 1024 * 1024,  # 50 MB
        allowed_provenances: set[str] | None = None,
        poisoning_score_threshold: float = 0.7,
        enable_snapshots: bool = True,
        cross_session_alert: bool = True,
        max_events: int = 10000,
        max_snapshots: int = 1000,
    ):
        self._max_entries = max_memory_entries_per_session
        self._max_size = max_memory_size_bytes
        self._allowed_provenances = allowed_provenances or {
            "conversation", "tool_result", "system", "imported",
        }
        self._poisoning_threshold = poisoning_score_threshold
        self._enable_snapshots = enable_snapshots
        self._cross_session_alert = cross_session_alert
        self._max_events = max_events
        self._max_snapshots = max_snapshots

        # Lock protecting _session_memory, _session_entry_counts,
        # _session_total_size, _memory_hashes, _events, and _snapshots.
        self._lock = threading.Lock()

        # State tracking
        self._session_memory: dict[str, dict[str, MemorySnapshot]] = defaultdict(dict)
        self._session_entry_counts: dict[str, int] = defaultdict(int)
        self._session_total_size: dict[str, int] = defaultdict(int)
        self._memory_hashes: dict[str, str] = {}
        self._events: list[MemorySecurityEvent] = []
        self._snapshots: list[MemorySnapshot] = []

    def on_start(self, span: Span, parent_context: Any = None) -> None:
        """Called when a span starts — check if it's a memory operation."""
        # We process on_end when all attributes are available.
        pass

    def on_end(self, span: ReadableSpan) -> None:
        """Process completed memory operation spans."""
        attrs = span.attributes or {}

        # Only process memory-related spans
        operation = attrs.get("memory.operation")
        if not operation:
            return

        memory_key = attrs.get("memory.key", "")
        store = attrs.get("memory.store", "unknown")
        provenance = attrs.get("memory.provenance", "unknown")
        session_id = attrs.get("agent.session.id", "unknown")
        content_hash = attrs.get("memory.security.content_hash")
        content_size = attrs.get("memory.security.content_size", 0)
        poisoning_score = attrs.get("memory.security.poisoning_score")
        cross_session = attrs.get("memory.security.cross_session", False)
        integrity_hash = attrs.get("memory.security.integrity_hash")

        span_id = format(span.context.span_id, "016x") if span.context else "unknown"

        with self._lock:
            # ── 1. Capture snapshot ──

            if self._enable_snapshots and operation in ("store", "update", "delete"):
                previous_hash = self._memory_hashes.get(f"{session_id}:{memory_key}")
                snapshot = MemorySnapshot(
                    key=memory_key,
                    store=store,
                    operation=operation,
                    content_hash_before=previous_hash,
                    content_hash_after=content_hash if operation != "delete" else None,
                    size_before=self._session_memory.get(session_id, {}).get(
                        memory_key, MemorySnapshot(key="", store="", operation="")
                    ).size_after,
                    size_after=content_size if operation != "delete" else 0,
                    provenance=provenance,
                    session_id=session_id,
                )
                self._snapshots.append(snapshot)

                # Enforce max_snapshots bound — drop oldest entries
                if len(self._snapshots) > self._max_snapshots:
                    self._snapshots = self._snapshots[-self._max_snapshots:]

                # Update tracked hash
                if operation == "delete":
                    self._memory_hashes.pop(f"{session_id}:{memory_key}", None)
                elif content_hash:
                    self._memory_hashes[f"{session_id}:{memory_key}"] = content_hash

            # ── 2. Provenance check — detect untrusted sources ──

            if provenance not in self._allowed_provenances:
                self._emit_event(MemorySecurityEvent(
                    event_type="untrusted_provenance",
                    severity="high",
                    details=(
                        f"Memory write from untrusted provenance '{provenance}' "
                        f"for key '{memory_key}' in store '{store}'"
                    ),
                    span_id=span_id,
                    session_id=session_id,
                    memory_key=memory_key,
                ))

            # ── 3. Poisoning detection ──

            if poisoning_score is not None and poisoning_score >= self._poisoning_threshold:
                self._emit_event(MemorySecurityEvent(
                    event_type="memory_poisoning_detected",
                    severity="critical",
                    details=(
                        f"Memory poisoning detected for key '{memory_key}' "
                        f"(score={poisoning_score:.2f}, threshold={self._poisoning_threshold}). "
                        f"Provenance: {provenance}"
                    ),
                    span_id=span_id,
                    session_id=session_id,
                    memory_key=memory_key,
                ))

            # ── 4. Integrity verification ──

            if integrity_hash and content_hash and integrity_hash != content_hash:
                self._emit_event(MemorySecurityEvent(
                    event_type="memory_integrity_violation",
                    severity="critical",
                    details=(
                        f"Memory integrity hash mismatch for key '{memory_key}'. "
                        f"Expected: {integrity_hash}, Got: {content_hash}"
                    ),
                    span_id=span_id,
                    session_id=session_id,
                    memory_key=memory_key,
                ))

            # ── 5. Cross-session isolation check ──

            if self._cross_session_alert and cross_session:
                self._emit_event(MemorySecurityEvent(
                    event_type="cross_session_memory_access",
                    severity="high",
                    details=(
                        f"Cross-session memory access detected for key '{memory_key}'. "
                        f"Session '{session_id}' accessed memory belonging to another session."
                    ),
                    span_id=span_id,
                    session_id=session_id,
                    memory_key=memory_key,
                ))

            # ── 6. Memory growth anomaly detection ──

            if operation in ("store", "update"):
                self._session_entry_counts[session_id] += 1 if operation == "store" else 0
                self._session_total_size[session_id] += content_size

                entry_count = self._session_entry_counts[session_id]
                total_size = self._session_total_size[session_id]

                if entry_count > self._max_entries:
                    self._emit_event(MemorySecurityEvent(
                        event_type="memory_growth_anomaly",
                        severity="medium",
                        details=(
                            f"Session '{session_id}' exceeded max memory entries: "
                            f"{entry_count} > {self._max_entries}"
                        ),
                        span_id=span_id,
                        session_id=session_id,
                    ))

                if total_size > self._max_size:
                    self._emit_event(MemorySecurityEvent(
                        event_type="memory_size_anomaly",
                        severity="high",
                        details=(
                            f"Session '{session_id}' exceeded max memory size: "
                            f"{total_size} bytes > {self._max_size} bytes"
                        ),
                        span_id=span_id,
                        session_id=session_id,
                    ))

            # ── 7. Update tracking state ──

            if operation == "delete":
                self._session_memory.get(session_id, {}).pop(memory_key, None)
            else:
                self._session_memory[session_id][memory_key] = MemorySnapshot(
                    key=memory_key,
                    store=store,
                    operation=operation,
                    content_hash_after=content_hash,
                    size_after=content_size,
                    provenance=provenance,
                    session_id=session_id,
                )

    def _emit_event(self, event: MemorySecurityEvent) -> None:
        """Append a security event, enforcing max_events bound.

        Must be called while holding self._lock.
        """
        self._events.append(event)
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]

    def shutdown(self) -> None:
        """Shutdown the processor."""
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Force flush any pending state."""
        return True

    # ── Public API ────────────────────────────────────────────────────

    def get_events(self, min_severity: str = "low") -> list[MemorySecurityEvent]:
        """Get security events at or above a severity level."""
        severity_order = {
            "informational": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        min_level = severity_order.get(min_severity, 0)
        with self._lock:
            return [
                e for e in self._events
                if severity_order.get(e.severity, 0) >= min_level
            ]

    def get_snapshots(self, session_id: str | None = None) -> list[MemorySnapshot]:
        """Get memory mutation snapshots, optionally filtered by session."""
        with self._lock:
            if session_id:
                return [s for s in self._snapshots if s.session_id == session_id]
            return list(self._snapshots)

    def get_session_stats(self, session_id: str) -> dict[str, Any]:
        """Get memory statistics for a session."""
        with self._lock:
            return {
                "entry_count": self._session_entry_counts.get(session_id, 0),
                "total_size_bytes": self._session_total_size.get(session_id, 0),
                "active_keys": list(self._session_memory.get(session_id, {}).keys()),
                "events": len([e for e in self._events if e.session_id == session_id]),
            }

    def clear_session(self, session_id: str) -> None:
        """Clear tracking state for a session (e.g., on session end)."""
        with self._lock:
            self._session_memory.pop(session_id, None)
            self._session_entry_counts.pop(session_id, None)
            self._session_total_size.pop(session_id, None)
            # Clean up hashes for this session
            keys_to_remove = [
                k for k in self._memory_hashes if k.startswith(f"{session_id}:")
            ]
            for k in keys_to_remove:
                del self._memory_hashes[k]
