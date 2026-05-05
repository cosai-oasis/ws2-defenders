"""Tests for security fixes identified during the SDK security audit.

Covers:
  1. vendor_mapper.py - ReDoS prevention, oversized regex, invalid regex, logging
  2. immutable_log.py - Path traversal validation, resume_chain DoS guard
  3. ai_bom.py - Thread-safe span_count increment
  4. llm.py - kwargs attribute validation
  5. agent.py - kwargs attribute validation
  6. agentic_log.py - Score range clamping
  7. cef_syslog_exporter.py - flexString2 overwrite fix
  8. ocsf_exporter.py - Thread-safe file writes
"""

import json
import re
import threading
from pathlib import Path
from typing import Sequence
from unittest.mock import MagicMock

import pytest

from opentelemetry.sdk.trace import TracerProvider, ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.trace import StatusCode


# ── Helpers ──────────────────────────────────────────────────────────

class _InMemoryExporter(SpanExporter):
    def __init__(self):
        self._spans: list[ReadableSpan] = []

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self._spans.extend(spans)
        return SpanExportResult.SUCCESS

    def get_finished_spans(self) -> list[ReadableSpan]:
        return list(self._spans)

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


def _make_provider():
    exporter = _InMemoryExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


# ══════════════════════════════════════════════════════════════════════
# 1. Vendor Mapper – ReDoS prevention
# ══════════════════════════════════════════════════════════════════════

class TestVendorMapperReDoSPrevention:
    """Verify that oversized and invalid regex patterns are rejected."""

    def test_oversized_pattern_is_skipped(self):
        from aitf.ocsf.vendor_mapper import VendorMapping, _MAX_PATTERN_LENGTH

        data = {
            "vendor": "test-vendor",
            "span_name_patterns": {
                "inference": ["a" * (_MAX_PATTERN_LENGTH + 1)],
            },
        }
        mapping = VendorMapping(data)
        # The oversized pattern should have been skipped
        assert len(mapping.span_name_patterns.get("inference", [])) == 0

    def test_valid_pattern_is_kept(self):
        from aitf.ocsf.vendor_mapper import VendorMapping

        data = {
            "vendor": "test-vendor",
            "span_name_patterns": {
                "inference": [r"ChatOpenAI", r"^embeddings\."],
            },
        }
        mapping = VendorMapping(data)
        assert len(mapping.span_name_patterns["inference"]) == 2

    def test_invalid_regex_is_skipped(self):
        from aitf.ocsf.vendor_mapper import VendorMapping

        data = {
            "vendor": "test-vendor",
            "span_name_patterns": {
                "inference": [r"[invalid", r"ChatOpenAI"],  # first is bad regex
            },
        }
        mapping = VendorMapping(data)
        # Only the valid pattern should remain
        assert len(mapping.span_name_patterns["inference"]) == 1
        assert mapping.classify_span("ChatOpenAI") == "inference"

    def test_max_patterns_per_event_type_enforced(self):
        from aitf.ocsf.vendor_mapper import VendorMapping, _MAX_PATTERNS_PER_EVENT_TYPE

        data = {
            "vendor": "test-vendor",
            "span_name_patterns": {
                "inference": [f"pattern_{i}" for i in range(_MAX_PATTERNS_PER_EVENT_TYPE + 10)],
            },
        }
        mapping = VendorMapping(data)
        assert len(mapping.span_name_patterns["inference"]) == _MAX_PATTERNS_PER_EVENT_TYPE


class TestVendorMapperLogging:
    """Verify that invalid files produce warnings instead of silent failure."""

    def test_load_dir_logs_invalid_json(self, tmp_path):
        from aitf.ocsf.vendor_mapper import VendorMapper

        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json {{{", encoding="utf-8")
        # Use vendors=[] to skip built-in mappings, only test extra_dirs
        mapper = VendorMapper(vendors=[], extra_dirs=[tmp_path])
        assert mapper.vendors == []  # Skipped gracefully

    def test_load_dir_logs_missing_vendor_key(self, tmp_path):
        from aitf.ocsf.vendor_mapper import VendorMapper

        no_vendor = tmp_path / "no_vendor.json"
        no_vendor.write_text(json.dumps({"description": "no vendor key"}), encoding="utf-8")
        mapper = VendorMapper(vendors=[], extra_dirs=[tmp_path])
        assert mapper.vendors == []


# ══════════════════════════════════════════════════════════════════════
# 2. Immutable Log – Path traversal & resume DoS
# ══════════════════════════════════════════════════════════════════════

class TestImmutableLogPathValidation:
    """Verify path traversal prevention in ImmutableLogExporter."""

    def test_path_traversal_rejected(self, tmp_path):
        from aitf.exporters.immutable_log import ImmutableLogExporter

        # Attempt to escape via ../../
        traversal_path = str(tmp_path) + "/logs/../../etc/passwd"
        with pytest.raises(ValueError, match="Path traversal detected"):
            ImmutableLogExporter(log_file=traversal_path)

    def test_normal_path_accepted(self, tmp_path):
        from aitf.exporters.immutable_log import ImmutableLogExporter

        normal_path = str(tmp_path / "audit.jsonl")
        exporter = ImmutableLogExporter(log_file=normal_path)
        assert exporter._log_file.exists() is False  # File not created until write
        assert str(exporter._log_file) == str(Path(normal_path).resolve())

    def test_resume_chain_skips_oversized_file(self, tmp_path):
        from aitf.exporters.immutable_log import ImmutableLogExporter, _MAX_RESUME_FILE_SIZE

        log_path = tmp_path / "big.jsonl"
        # Create a file just over the limit
        log_path.write_bytes(b"x" * (_MAX_RESUME_FILE_SIZE + 1))

        # Should not crash, just start fresh
        exporter = ImmutableLogExporter(log_file=str(log_path))
        assert exporter._seq == 0
        assert exporter._prev_hash == "0" * 64


# ══════════════════════════════════════════════════════════════════════
# 3. AI-BOM – Thread-safe span_count
# ══════════════════════════════════════════════════════════════════════

class TestAIBOMThreadSafety:
    """Verify _span_count is protected by the lock."""

    def test_span_count_under_lock(self):
        from aitf.generators.ai_bom import AIBOMGenerator

        gen = AIBOMGenerator(system_name="test")
        # Create a mock span with model attributes
        mock_span = MagicMock(spec=ReadableSpan)
        mock_span.name = "chat gpt-4o"
        mock_span.attributes = {
            "gen_ai.request.model": "gpt-4o",
            "gen_ai.system": "openai",
        }
        mock_span.events = []

        # Export from multiple threads concurrently
        errors = []
        def worker():
            try:
                gen.export([mock_span] * 10)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # 10 threads * 10 spans = 100
        assert gen._span_count == 100


# ══════════════════════════════════════════════════════════════════════
# 4 & 5. LLM / Agent – kwargs attribute validation
# ══════════════════════════════════════════════════════════════════════

class TestLLMKwargsValidation:
    """Verify that only valid attribute types and key lengths are accepted."""

    def test_valid_kwargs_accepted(self):
        from aitf.instrumentation.llm import LLMInstrumentor

        provider, exporter = _make_provider()
        inst = LLMInstrumentor(tracer_provider=provider)

        with inst.trace_inference(
            model="gpt-4o", seed=42, top_p=0.9, user="test"
        ) as span:
            pass

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)
        assert attrs["gen_ai.request.seed"] == 42
        assert attrs["gen_ai.request.top_p"] == 0.9
        assert attrs["gen_ai.request.user"] == "test"

    def test_invalid_type_kwargs_rejected(self):
        from aitf.instrumentation.llm import LLMInstrumentor

        provider, exporter = _make_provider()
        inst = LLMInstrumentor(tracer_provider=provider)

        # list, dict, and None are not valid OTel attribute types
        with inst.trace_inference(
            model="gpt-4o", bad_list=[1, 2], bad_dict={"a": "b"}, bad_none=None
        ) as span:
            pass

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)
        assert "gen_ai.request.bad_list" not in attrs
        assert "gen_ai.request.bad_dict" not in attrs
        assert "gen_ai.request.bad_none" not in attrs

    def test_oversized_key_rejected(self):
        from aitf.instrumentation.llm import LLMInstrumentor

        provider, exporter = _make_provider()
        inst = LLMInstrumentor(tracer_provider=provider)

        long_key = "x" * 200
        with inst.trace_inference(model="gpt-4o", **{long_key: "val"}) as span:
            pass

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)
        assert f"gen_ai.request.{long_key}" not in attrs


class TestAgentKwargsValidation:
    """Verify agent step kwargs validation."""

    def test_valid_step_kwargs_accepted(self):
        from aitf.instrumentation.agent import AgentInstrumentor

        provider, exporter = _make_provider()
        inst = AgentInstrumentor(tracer_provider=provider)

        with inst.trace_session("test-agent") as session:
            with session.step("planning", priority=1, label="test") as step:
                pass

        spans = exporter.get_finished_spans()
        # Find the step span
        step_span = next(s for s in spans if "step" in s.name)
        attrs = dict(step_span.attributes)
        assert attrs["aitf.agent.step.priority"] == 1
        assert attrs["aitf.agent.step.label"] == "test"

    def test_invalid_step_kwargs_rejected(self):
        from aitf.instrumentation.agent import AgentInstrumentor

        provider, exporter = _make_provider()
        inst = AgentInstrumentor(tracer_provider=provider)

        with inst.trace_session("test-agent") as session:
            with session.step("planning", bad_list=[1, 2, 3]) as step:
                pass

        spans = exporter.get_finished_spans()
        step_span = next(s for s in spans if "step" in s.name)
        attrs = dict(step_span.attributes)
        assert "aitf.agent.step.bad_list" not in attrs


# ══════════════════════════════════════════════════════════════════════
# 6. Agentic Log – Score range clamping
# ══════════════════════════════════════════════════════════════════════

class TestAgenticLogScoreClamping:
    """Verify confidence and anomaly scores are clamped to [0.0, 1.0]."""

    def _make_instrumentor(self):
        from aitf.instrumentation.agentic_log import AgenticLogInstrumentor

        exporter = _InMemoryExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        return AgenticLogInstrumentor(tracer_provider=provider), exporter

    def test_confidence_score_clamped_above(self):
        inst, exporter = self._make_instrumentor()
        with inst.log_action(agent_id="a", session_id="s") as entry:
            entry.set_confidence_score(1.5)

        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["aitf.agentic_log.confidence_score"] == 1.0

    def test_confidence_score_clamped_below(self):
        inst, exporter = self._make_instrumentor()
        with inst.log_action(agent_id="a", session_id="s") as entry:
            entry.set_confidence_score(-0.5)

        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["aitf.agentic_log.confidence_score"] == 0.0

    def test_anomaly_score_clamped_above(self):
        inst, exporter = self._make_instrumentor()
        with inst.log_action(agent_id="a", session_id="s") as entry:
            entry.set_anomaly_score(2.0)

        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["aitf.agentic_log.anomaly_score"] == 1.0

    def test_anomaly_score_clamped_below(self):
        inst, exporter = self._make_instrumentor()
        with inst.log_action(agent_id="a", session_id="s") as entry:
            entry.set_anomaly_score(-1.0)

        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["aitf.agentic_log.anomaly_score"] == 0.0

    def test_valid_scores_unchanged(self):
        inst, exporter = self._make_instrumentor()
        with inst.log_action(agent_id="a", session_id="s") as entry:
            entry.set_confidence_score(0.75)
            entry.set_anomaly_score(0.15)

        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["aitf.agentic_log.confidence_score"] == 0.75
        assert attrs["aitf.agentic_log.anomaly_score"] == 0.15

    def test_kwargs_scores_clamped(self):
        """Scores passed via log_action kwargs should also be clamped."""
        inst, exporter = self._make_instrumentor()
        with inst.log_action(
            agent_id="a", session_id="s",
            confidence_score=5.0, anomaly_score=-3.0,
        ):
            pass

        attrs = dict(exporter.get_finished_spans()[0].attributes)
        assert attrs["aitf.agentic_log.confidence_score"] == 1.0
        assert attrs["aitf.agentic_log.anomaly_score"] == 0.0


# ══════════════════════════════════════════════════════════════════════
# 7. CEF Syslog – flexString2 overwrite fix
# ══════════════════════════════════════════════════════════════════════

class TestCEFComplianceFieldSeparation:
    """Verify MITRE technique and compliance use separate CEF fields."""

    def test_mitre_and_compliance_in_separate_fields(self):
        from aitf.exporters.cef_syslog_exporter import ocsf_event_to_cef

        event = {
            "class_uid": 7005,
            "activity_id": 1,
            "severity_id": 4,
            "finding": {
                "finding_type": "prompt_injection",
                "owasp_category": "LLM01",
                "risk_score": 85.0,
                "mitre_technique": "AML.T0051",
            },
            "compliance": {
                "nist_ai_rmf": "MANAGE-2.4",
                "eu_ai_act": "Article 9",
            },
        }
        cef = ocsf_event_to_cef(event)

        # MITRE technique should be in flexString2
        assert "flexString2=AML.T0051" in cef
        assert "flexString2Label=mitre_technique" in cef

        # Compliance should be in cs7 (not flexString2)
        assert "cs7=" in cef
        assert "cs7Label=compliance_frameworks" in cef

        # Ensure the MITRE value is not overwritten by compliance
        parts = cef.split(" ")
        flex2_values = [p for p in parts if p.startswith("flexString2=")]
        assert len(flex2_values) == 1  # Only one flexString2


# ══════════════════════════════════════════════════════════════════════
# 8. OCSF Exporter – Thread-safe file writes
# ══════════════════════════════════════════════════════════════════════

class TestOCSFExporterThreadSafety:
    """Verify file writes are protected by a lock."""

    def test_exporter_has_file_lock(self, tmp_path):
        from aitf.exporters.ocsf_exporter import OCSFExporter

        exporter = OCSFExporter(output_file=str(tmp_path / "out.jsonl"))
        assert hasattr(exporter, "_file_lock")
        assert isinstance(exporter._file_lock, type(threading.Lock()))


# ══════════════════════════════════════════════════════════════════════
# Regression: existing security features still work
# ══════════════════════════════════════════════════════════════════════

class TestExistingSecurityFeatures:
    """Ensure existing security hardening still functions."""

    def test_security_processor_content_length_limit(self):
        from aitf.processors.security_processor import SecurityProcessor, _MAX_CONTENT_LENGTH

        proc = SecurityProcessor()
        # Create content that exceeds the limit
        content = "x" * (_MAX_CONTENT_LENGTH + 10000)
        # Should not hang or crash
        findings = proc.analyze_text(content)
        assert isinstance(findings, list)

    def test_pii_processor_content_length_limit(self):
        from aitf.processors.pii_processor import PIIProcessor, _MAX_CONTENT_LENGTH

        proc = PIIProcessor()
        content = "x" * (_MAX_CONTENT_LENGTH + 10000)
        detections = proc.detect_pii(content)
        assert isinstance(detections, list)

    def test_cost_processor_token_limit(self):
        from aitf.processors.cost_processor import CostProcessor, _MAX_TOKENS

        proc = CostProcessor()
        cost = proc.calculate_cost("gpt-4o", _MAX_TOKENS * 2, _MAX_TOKENS * 2)
        assert cost is not None
        # Tokens should be clamped to _MAX_TOKENS
        expected_input = (_MAX_TOKENS / 1_000_000) * 2.50
        assert cost["input_cost"] == round(expected_input, 8)

    def test_ocsf_exporter_endpoint_validation(self):
        from aitf.exporters.ocsf_exporter import OCSFExporter

        # HTTPS with API key should work
        exporter = OCSFExporter(
            endpoint="https://siem.example.com/api",
            api_key="test-key",
        )
        assert exporter._endpoint == "https://siem.example.com/api"

        # HTTP with API key on non-localhost should fail
        with pytest.raises(ValueError, match="HTTPS is required"):
            OCSFExporter(
                endpoint="http://remote.example.com/api",
                api_key="test-key",
            )

    def test_ocsf_exporter_path_traversal_rejected(self):
        from aitf.exporters.ocsf_exporter import OCSFExporter

        with pytest.raises(ValueError, match="Path traversal"):
            OCSFExporter(output_file="/tmp/logs/../../etc/passwd")
