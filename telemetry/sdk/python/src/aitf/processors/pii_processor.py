"""AITF PII Detection Processor.

OTel SpanProcessor that detects and optionally redacts Personally
Identifiable Information (PII) in AI inputs and outputs.

Based on PII detection patterns from AITelemetry project.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Any

from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor

from aitf.semantic_conventions.attributes import SecurityAttributes

# Maximum content length to analyze (prevent unbounded CPU usage)
_MAX_CONTENT_LENGTH = 100_000

# PII detection patterns
# Note: Credit card pattern uses explicit groups instead of nested
# quantifiers to prevent ReDoS
PII_PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "phone": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "ssn": re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    ),
    "credit_card": re.compile(
        # Explicit repetition instead of nested quantifier {3} to prevent ReDoS
        r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
    ),
    "api_key": re.compile(
        r"\b(?:sk-|pk-|ak-|key-)[A-Za-z0-9]{20,}\b"
    ),
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
    ),
    "ip_address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "password": re.compile(
        r"(?:password|passwd|pwd)\s*[=:]\s*\S+", re.IGNORECASE
    ),
    "aws_key": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    ),
}


@dataclass
class PIIDetection:
    """A PII detection result."""

    pii_type: str
    count: int
    locations: list[tuple[int, int]]  # (start, end) positions


class PIIProcessor(SpanProcessor):
    """OTel SpanProcessor that detects PII in AI span content.

    Can operate in three modes:
    - "flag": Detect PII and add span attributes (default)
    - "redact": Replace PII with [REDACTED] placeholder
    - "hash": Replace PII with HMAC-SHA256 hash (keyed, non-reversible)

    Usage:
        provider.add_span_processor(PIIProcessor(
            detect_types=["email", "ssn", "credit_card", "api_key"],
            action="redact",
        ))
    """

    def __init__(
        self,
        detect_types: list[str] | None = None,
        action: str = "flag",
        custom_patterns: dict[str, re.Pattern] | None = None,
        hash_key: bytes | None = None,
    ):
        self._detect_types = detect_types or list(PII_PATTERNS.keys())
        self._action = action
        self._patterns: dict[str, re.Pattern] = {}

        # Generate a random HMAC key for PII hashing if not provided
        # This ensures hashes are unique per processor instance and
        # cannot be reversed by an attacker who knows the algorithm
        self._hash_key = hash_key or os.urandom(32)

        # Build active pattern set
        for pii_type in self._detect_types:
            if pii_type in PII_PATTERNS:
                self._patterns[pii_type] = PII_PATTERNS[pii_type]

        # Validate and add custom patterns
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                if not isinstance(pattern, re.Pattern):
                    raise TypeError(
                        f"Custom pattern '{name}' must be a compiled re.Pattern"
                    )
                # Verify the pattern compiles and test it with empty string
                # to detect obvious issues
                try:
                    pattern.search("")
                except re.error as e:
                    raise ValueError(
                        f"Custom pattern '{name}' is invalid: {e}"
                    ) from e
                self._patterns[name] = pattern

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        pass

    def on_end(self, span: ReadableSpan) -> None:
        """Detect PII in span content."""
        attrs = span.attributes or {}
        if not any(key.startswith(("gen_ai.", "agent.", "mcp.", "skill.", "security.", "cost.")) for key in attrs.keys()):
            return

        all_detections: list[PIIDetection] = []

        # Check span events for content
        for event in span.events or []:
            event_attrs = event.attributes or {}
            for val in event_attrs.values():
                if isinstance(val, str):
                    detections = self.detect_pii(val)
                    all_detections.extend(detections)

        # Check relevant span attributes
        for key in (
            "gen_ai.tool.call.arguments",
            "gen_ai.tool.call.result",
            "skill.input",
            "skill.output",
        ):
            val = attrs.get(key)
            if isinstance(val, str):
                detections = self.detect_pii(val)
                all_detections.extend(detections)

    def detect_pii(self, text: str) -> list[PIIDetection]:
        """Detect PII in text. Returns list of PIIDetection objects."""
        # Truncate to prevent excessive CPU usage
        if len(text) > _MAX_CONTENT_LENGTH:
            text = text[:_MAX_CONTENT_LENGTH]

        detections: list[PIIDetection] = []
        for pii_type, pattern in self._patterns.items():
            matches = list(pattern.finditer(text))
            if matches:
                detections.append(PIIDetection(
                    pii_type=pii_type,
                    count=len(matches),
                    locations=[(m.start(), m.end()) for m in matches],
                ))
        return detections

    def redact_pii(self, text: str) -> tuple[str, list[PIIDetection]]:
        """Detect and redact PII from text.

        Returns (redacted_text, detections).
        """
        detections = self.detect_pii(text)
        if not detections:
            return text, []

        result = text
        for detection in sorted(detections, key=lambda d: d.locations[0][0], reverse=True):
            for start, end in sorted(detection.locations, reverse=True):
                original = result[start:end]
                if self._action == "redact":
                    replacement = f"[{detection.pii_type.upper()}_REDACTED]"
                elif self._action == "hash":
                    # Use HMAC-SHA256 with instance-specific key for secure hashing
                    hash_val = hmac.new(
                        self._hash_key,
                        original.encode(),
                        hashlib.sha256,
                    ).hexdigest()[:16]
                    replacement = f"[{detection.pii_type.upper()}:{hash_val}]"
                else:
                    continue
                result = result[:start] + replacement + result[end:]

        return result, detections

    def get_pii_summary(self, text: str) -> dict[str, Any]:
        """Get a summary of PII detected in text."""
        detections = self.detect_pii(text)
        if not detections:
            return {
                SecurityAttributes.PII_DETECTED: False,
                SecurityAttributes.PII_TYPES: [],
                SecurityAttributes.PII_COUNT: 0,
                SecurityAttributes.PII_ACTION: self._action,
            }
        return {
            SecurityAttributes.PII_DETECTED: True,
            SecurityAttributes.PII_TYPES: [d.pii_type for d in detections],
            SecurityAttributes.PII_COUNT: sum(d.count for d in detections),
            SecurityAttributes.PII_ACTION: self._action,
        }

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
