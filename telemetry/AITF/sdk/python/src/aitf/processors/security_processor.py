"""AITF Security Processor.

OTel SpanProcessor that detects security threats in AI operations,
including OWASP LLM Top 10 patterns, jailbreaks, and data exfiltration.

Based on OWASP detection patterns from AITelemetry project.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from opentelemetry.context import Context
from opentelemetry.sdk.trace import ReadableSpan, Span, SpanProcessor

from aitf.semantic_conventions.attributes import GenAIAttributes, SecurityAttributes

logger = logging.getLogger(__name__)

# Maximum content length to analyze (prevent unbounded CPU usage)
_MAX_CONTENT_LENGTH = 100_000


@dataclass
class SecurityFinding:
    """A security finding detected in a span."""

    threat_type: str
    owasp_category: str
    risk_level: str
    risk_score: float
    confidence: float
    detection_method: str = "pattern"
    details: str = ""
    blocked: bool = False


# OWASP LLM Top 10 detection patterns (adapted from AITelemetry)
# Note: All patterns use bounded quantifiers to prevent ReDoS
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?above\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(your|previous)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.IGNORECASE),
    re.compile(r"new\s+instructions?:\s*", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+are", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"<\|im_start\|>system", re.IGNORECASE),
    re.compile(r"pretend\s+you\s+are", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if|though)\s+you", re.IGNORECASE),
    re.compile(r"override\s+(your\s+)?instructions", re.IGNORECASE),
]

JAILBREAK_PATTERNS = [
    re.compile(r"DAN\s+mode", re.IGNORECASE),
    re.compile(r"developer\s+mode\s+enabled", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"bypass\s+(safety|content|filter)", re.IGNORECASE),
    re.compile(r"without\s+(any\s+)?restrictions", re.IGNORECASE),
    re.compile(r"no\s+(ethical|moral)\s+(guidelines|restrictions)", re.IGNORECASE),
    re.compile(r"unfiltered\s+(mode|response)", re.IGNORECASE),
]

SYSTEM_PROMPT_LEAK_PATTERNS = [
    # Bounded quantifier {0,30} allows natural language like "show me your system prompt"
    re.compile(r"(show|reveal|display|print|output|repeat)\s+[^\n]{0,30}(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"what\s+(are|is)\s+your\s+(system\s+)?(instructions|prompt|rules)", re.IGNORECASE),
    re.compile(r"(beginning|start)\s+of\s+(your|the)\s+(conversation|system)", re.IGNORECASE),
]

DATA_EXFILTRATION_PATTERNS = [
    # Bounded quantifier to prevent ReDoS (was: .* which causes catastrophic backtracking)
    re.compile(r"(send|post|transmit|upload)\s+[^\n]{0,200}(to|at)\s+https?://", re.IGNORECASE),
    re.compile(r"(curl|wget|fetch)\s+", re.IGNORECASE),
    re.compile(r"base64\s+encode", re.IGNORECASE),
    re.compile(r"exfiltrat", re.IGNORECASE),
]

COMMAND_INJECTION_PATTERNS = [
    re.compile(r";\s*(rm|del|drop|shutdown|kill)\s+", re.IGNORECASE),
    re.compile(r"\|\s*(bash|sh|cmd|powershell)", re.IGNORECASE),
    # Bounded quantifiers to prevent ReDoS (was: `.*` and \$\(.*\))
    re.compile(r"`[^`]{0,500}`"),
    re.compile(r"\$\([^)]{0,500}\)"),
    re.compile(r"&&\s*(rm|del|drop)", re.IGNORECASE),
]

SQL_INJECTION_PATTERNS = [
    re.compile(r"('\s*OR\s+'1'\s*=\s*'1)", re.IGNORECASE),
    re.compile(r"(UNION\s+SELECT)", re.IGNORECASE),
    re.compile(r"(DROP\s+TABLE)", re.IGNORECASE),
    re.compile(r"(;\s*DELETE\s+FROM)", re.IGNORECASE),
    re.compile(r"(--\s*$)", re.MULTILINE),
]


class SecurityProcessor(SpanProcessor):
    """OTel SpanProcessor that detects security threats in AI spans.

    Analyzes prompt content, completion content, and tool inputs/outputs
    for OWASP LLM Top 10 patterns and other security threats.

    Usage:
        from opentelemetry.sdk.trace import TracerProvider
        from aitf.processors import SecurityProcessor

        provider = TracerProvider()
        provider.add_span_processor(SecurityProcessor(
            detect_prompt_injection=True,
            detect_data_exfiltration=True,
            block_on_critical=False,
        ))
    """

    def __init__(
        self,
        detect_prompt_injection: bool = True,
        detect_jailbreak: bool = True,
        detect_system_prompt_leak: bool = True,
        detect_data_exfiltration: bool = True,
        detect_command_injection: bool = True,
        detect_sql_injection: bool = True,
        block_on_critical: bool = False,
        owasp_checks: bool = True,
    ):
        self._detect_prompt_injection = detect_prompt_injection
        self._detect_jailbreak = detect_jailbreak
        self._detect_system_prompt_leak = detect_system_prompt_leak
        self._detect_data_exfiltration = detect_data_exfiltration
        self._detect_command_injection = detect_command_injection
        self._detect_sql_injection = detect_sql_injection
        self._block_on_critical = block_on_critical
        self._owasp_checks = owasp_checks

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        """Called when a span is started."""
        pass

    def on_end(self, span: ReadableSpan) -> None:
        """Called when a span is ended. Analyze content for threats."""
        # Only process AI-related spans
        attrs = span.attributes or {}
        if not any(
            key.startswith(("gen_ai.", "agent.", "mcp.", "skill.", "security.", "cost.")) for key in attrs.keys()
        ):
            return

        findings: list[SecurityFinding] = []

        # Extract content to analyze
        content_to_analyze: list[str] = []
        for event in span.events or []:
            if event.name in ("gen_ai.content.prompt", "gen_ai.content.completion"):
                event_attrs = event.attributes or {}
                for key in (GenAIAttributes.PROMPT, GenAIAttributes.COMPLETION):
                    val = event_attrs.get(key)
                    if val:
                        content_to_analyze.append(str(val))

            if event.name in ("mcp.tool.input", "mcp.tool.output", "skill.input"):
                for val in (event.attributes or {}).values():
                    if val:
                        content_to_analyze.append(str(val))

        # Also check tool input/output attributes
        for key in ("gen_ai.tool.call.arguments", "gen_ai.tool.call.result", "skill.input"):
            val = attrs.get(key)
            if val:
                content_to_analyze.append(str(val))

        # Run detection patterns
        for content in content_to_analyze:
            findings.extend(self._analyze_content(content))

        # Log findings since ReadableSpan attributes are immutable
        if findings:
            max_risk = max(f.risk_score for f in findings)
            max_level = max(findings, key=lambda f: f.risk_score).risk_level
            threat_types = [f.threat_type for f in findings]
            logger.warning(
                "Security findings detected in span %s: risk_level=%s risk_score=%.1f threats=%s",
                span.context.span_id if span.context else "unknown",
                max_level,
                max_risk,
                threat_types,
            )

    def analyze_text(self, text: str) -> list[SecurityFinding]:
        """Public API to analyze text for security threats.

        Returns list of SecurityFinding objects.
        """
        return self._analyze_content(text)

    def _analyze_content(self, content: str) -> list[SecurityFinding]:
        # Truncate content to prevent excessive CPU usage
        if len(content) > _MAX_CONTENT_LENGTH:
            content = content[:_MAX_CONTENT_LENGTH]

        findings: list[SecurityFinding] = []

        if self._detect_prompt_injection:
            for pattern in PROMPT_INJECTION_PATTERNS:
                if pattern.search(content):
                    findings.append(SecurityFinding(
                        threat_type=SecurityAttributes.ThreatType.PROMPT_INJECTION,
                        owasp_category=SecurityAttributes.OWASP.LLM01,
                        risk_level=SecurityAttributes.RiskLevel.HIGH,
                        risk_score=80.0,
                        confidence=0.85,
                        details="Prompt injection pattern detected",
                    ))
                    break

        if self._detect_jailbreak:
            for pattern in JAILBREAK_PATTERNS:
                if pattern.search(content):
                    findings.append(SecurityFinding(
                        threat_type=SecurityAttributes.ThreatType.JAILBREAK,
                        owasp_category=SecurityAttributes.OWASP.LLM01,
                        risk_level=SecurityAttributes.RiskLevel.CRITICAL,
                        risk_score=95.0,
                        confidence=0.90,
                        details="Jailbreak attempt detected",
                    ))
                    break

        if self._detect_system_prompt_leak:
            for pattern in SYSTEM_PROMPT_LEAK_PATTERNS:
                if pattern.search(content):
                    findings.append(SecurityFinding(
                        threat_type=SecurityAttributes.ThreatType.SYSTEM_PROMPT_LEAK,
                        owasp_category=SecurityAttributes.OWASP.LLM07,
                        risk_level=SecurityAttributes.RiskLevel.MEDIUM,
                        risk_score=60.0,
                        confidence=0.75,
                        details="System prompt leak attempt detected",
                    ))
                    break

        if self._detect_data_exfiltration:
            for pattern in DATA_EXFILTRATION_PATTERNS:
                if pattern.search(content):
                    findings.append(SecurityFinding(
                        threat_type=SecurityAttributes.ThreatType.DATA_EXFILTRATION,
                        owasp_category=SecurityAttributes.OWASP.LLM02,
                        risk_level=SecurityAttributes.RiskLevel.HIGH,
                        risk_score=85.0,
                        confidence=0.70,
                        details="Data exfiltration pattern detected",
                    ))
                    break

        if self._detect_command_injection:
            for pattern in COMMAND_INJECTION_PATTERNS:
                if pattern.search(content):
                    findings.append(SecurityFinding(
                        threat_type="command_injection",
                        owasp_category=SecurityAttributes.OWASP.LLM05,
                        risk_level=SecurityAttributes.RiskLevel.CRITICAL,
                        risk_score=90.0,
                        confidence=0.80,
                        details="Command injection pattern detected",
                    ))
                    break

        if self._detect_sql_injection:
            for pattern in SQL_INJECTION_PATTERNS:
                if pattern.search(content):
                    findings.append(SecurityFinding(
                        threat_type="sql_injection",
                        owasp_category=SecurityAttributes.OWASP.LLM05,
                        risk_level=SecurityAttributes.RiskLevel.HIGH,
                        risk_score=80.0,
                        confidence=0.75,
                        details="SQL injection pattern detected",
                    ))
                    break

        return findings

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
