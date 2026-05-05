"""AITF Immutable Log Exporter.

OTel SpanExporter that writes AI telemetry events to an append-only,
hash-chained log file providing cryptographic tamper evidence.

Each log entry includes a SHA-256 hash of the previous entry, creating
an unbroken chain. Any modification to a historical entry invalidates
all subsequent hashes, making tampering detectable.

This satisfies audit requirements for:
    - EU AI Act Article 12 (record-keeping obligations)
    - NIST AI RMF GOVERN-1.5 (audit trail for AI decisions)
    - SOC 2 CC8.1 (change management and integrity)
    - ISO/IEC 42001 (AI management system records)

Log format (JSONL, one entry per line):
    {
        "seq": 1,
        "timestamp": "2026-02-16T12:00:00.000Z",
        "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "hash": "a1b2c3...",
        "event": { ... OCSF event ... }
    }

Verification:
    The integrity of the entire log can be verified by replaying the
    hash chain from entry 0 (genesis). Use ``ImmutableLogVerifier.verify()``
    to check an existing log file.

Usage:
    from aitf.exporters.immutable_log import ImmutableLogExporter

    exporter = ImmutableLogExporter(
        log_file="/var/log/aitf/immutable_audit.jsonl",
        compliance_frameworks=["eu_ai_act", "nist_ai_rmf", "soc2"],
    )
    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(exporter))
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from aitf.ocsf.compliance_mapper import ComplianceMapper
from aitf.ocsf.mapper import OCSFMapper

logger = logging.getLogger(__name__)

# Genesis hash (the "previous hash" for the very first entry)
_GENESIS_HASH = "0" * 64

# Maximum file size before rotation (1 GB)
_MAX_FILE_SIZE_BYTES = 1024 * 1024 * 1024

# Maximum file size to read during chain resume (100 MB)
# Prevents DoS if a very large file is placed at the log path
_MAX_RESUME_FILE_SIZE = 100 * 1024 * 1024


def _compute_entry_hash(
    seq: int,
    timestamp: str,
    prev_hash: str,
    event_json: str,
) -> str:
    """Compute SHA-256 hash for a log entry.

    The hash covers the sequence number, timestamp, previous hash,
    and the canonical JSON of the event. This ensures any change to
    any field in any entry breaks the chain.
    """
    payload = f"{seq}|{timestamp}|{prev_hash}|{event_json}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ImmutableLogExporter(SpanExporter):
    """Writes AITF events to an append-only, hash-chained log file.

    Each entry includes a SHA-256 hash linking it to the previous entry.
    The log file is opened in append-only mode with exclusive locking
    to prevent concurrent writes from corrupting the chain.

    Args:
        log_file: Path to the immutable log file.
        compliance_frameworks: Compliance frameworks for event enrichment.
        rotate_on_size: Enable automatic rotation when file exceeds 1 GB.
        file_permissions: UNIX file permissions (default: owner read/write).
    """

    def __init__(
        self,
        log_file: str = "/var/log/aitf/immutable_audit.jsonl",
        compliance_frameworks: list[str] | None = None,
        rotate_on_size: bool = True,
        file_permissions: int = 0o600,
    ) -> None:
        self._log_file = self._validate_log_path(log_file)
        self._rotate_on_size = rotate_on_size
        self._file_permissions = file_permissions
        self._mapper = OCSFMapper()
        self._compliance_mapper = ComplianceMapper(
            frameworks=compliance_frameworks
        )
        self._prev_hash = _GENESIS_HASH
        self._seq = 0
        self._lock = threading.Lock()
        self._event_count = 0

        # Create directory if needed
        self._log_file.parent.mkdir(parents=True, exist_ok=True)

        # Resume chain from existing log file
        self._resume_chain()

    @staticmethod
    def _validate_log_path(log_file: str) -> Path:
        """Validate the log file path to prevent path traversal.

        Rejects any path containing '..' components, which could be
        used to escape the intended directory.
        """
        raw_path = Path(log_file)

        if ".." in raw_path.parts:
            raise ValueError(
                f"Path traversal detected in log path: {log_file!r} "
                f"contains '..' component"
            )

        return raw_path.resolve()

    def _resume_chain(self) -> None:
        """Resume hash chain from existing log file if present."""
        if not self._log_file.exists():
            return

        # Guard against resuming from an excessively large file (DoS)
        file_size = self._log_file.stat().st_size
        if file_size > _MAX_RESUME_FILE_SIZE:
            logger.warning(
                "Log file %s is too large to resume (%d bytes > %d). "
                "Starting fresh chain.",
                self._log_file, file_size, _MAX_RESUME_FILE_SIZE,
            )
            return

        try:
            last_line = ""
            with open(self._log_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
                        self._seq += 1

            if last_line:
                entry = json.loads(last_line)
                self._prev_hash = entry.get("hash", _GENESIS_HASH)
                self._seq = entry.get("seq", self._seq) + 1
                logger.info(
                    "Resumed immutable log chain at seq=%d from %s",
                    self._seq, self._log_file,
                )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(
                "Could not resume chain from %s: %s. Starting fresh.",
                self._log_file, exc,
            )
            self._prev_hash = _GENESIS_HASH
            self._seq = 0

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        """Export spans as hash-chained log entries."""
        entries: list[str] = []

        for span in spans:
            ocsf_event = self._mapper.map_span(span)
            if ocsf_event is None:
                continue

            # Enrich with compliance metadata
            event_type = self._classify_event(ocsf_event)
            if event_type:
                self._compliance_mapper.enrich_event(ocsf_event, event_type)

            event_dict = ocsf_event.model_dump(exclude_none=True)
            event_json = json.dumps(event_dict, sort_keys=True, default=str)

            with self._lock:
                timestamp = datetime.now(timezone.utc).isoformat()
                entry_hash = _compute_entry_hash(
                    self._seq, timestamp, self._prev_hash, event_json
                )

                entry = {
                    "seq": self._seq,
                    "timestamp": timestamp,
                    "prev_hash": self._prev_hash,
                    "hash": entry_hash,
                    "event": event_dict,
                }

                entries.append(
                    json.dumps(entry, sort_keys=False, default=str)
                )
                self._prev_hash = entry_hash
                self._seq += 1
                self._event_count += 1

        if not entries:
            return SpanExportResult.SUCCESS

        try:
            self._write_entries(entries)
            return SpanExportResult.SUCCESS
        except Exception as exc:
            logger.error("Immutable log write failed: %s", exc)
            return SpanExportResult.FAILURE

    def _write_entries(self, entries: list[str]) -> None:
        """Write entries to log file with rotation check."""
        # Check for rotation
        if (
            self._rotate_on_size
            and self._log_file.exists()
            and self._log_file.stat().st_size > _MAX_FILE_SIZE_BYTES
        ):
            rotated = self._log_file.with_suffix(
                f".{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.jsonl"
            )
            self._log_file.rename(rotated)
            logger.info("Rotated immutable log to %s", rotated)

        # Open in append-only mode with restrictive permissions
        fd = os.open(
            str(self._log_file),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            self._file_permissions,
        )
        try:
            with os.fdopen(fd, "a") as f:
                for entry in entries:
                    f.write(entry + "\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            # fd is already closed by os.fdopen context manager on error
            raise

    def _classify_event(self, event: Any) -> str | None:
        class_uid = getattr(event, "class_uid", 0)
        mapping = {
            7001: "model_inference",
            7002: "agent_activity",
            7003: "tool_execution",
            7004: "data_retrieval",
            7005: "security_finding",
            7006: "supply_chain",
            7007: "governance",
            7008: "identity",
        }
        return mapping.get(class_uid)

    @property
    def event_count(self) -> int:
        with self._lock:
            return self._event_count

    @property
    def current_seq(self) -> int:
        with self._lock:
            return self._seq

    @property
    def current_hash(self) -> str:
        with self._lock:
            return self._prev_hash

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


class ImmutableLogVerifier:
    """Verifies the integrity of an AITF immutable log file.

    Replays the hash chain from the genesis entry and validates that
    every entry's hash matches its computed value and links correctly
    to the previous entry.

    Usage:
        verifier = ImmutableLogVerifier("/var/log/aitf/immutable_audit.jsonl")
        result = verifier.verify()
        if result.valid:
            print(f"Log integrity verified: {result.entries_checked} entries")
        else:
            print(f"TAMPER DETECTED at seq {result.first_invalid_seq}")
            print(f"  Expected: {result.expected_hash}")
            print(f"  Found:    {result.found_hash}")
    """

    def __init__(self, log_file: str) -> None:
        self._log_file = Path(log_file)

    def verify(self) -> VerificationResult:
        """Verify the entire hash chain.

        Returns:
            VerificationResult with validation details.
        """
        if not self._log_file.exists():
            return VerificationResult(
                valid=False,
                entries_checked=0,
                error="Log file does not exist",
            )

        prev_hash = _GENESIS_HASH
        entries_checked = 0

        try:
            with open(self._log_file, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError as exc:
                        return VerificationResult(
                            valid=False,
                            entries_checked=entries_checked,
                            first_invalid_seq=entries_checked,
                            error=f"Line {line_num}: invalid JSON: {exc}",
                        )

                    seq = entry.get("seq", -1)
                    timestamp = entry.get("timestamp", "")
                    stored_prev_hash = entry.get("prev_hash", "")
                    stored_hash = entry.get("hash", "")
                    event = entry.get("event", {})

                    # Check chain linkage
                    if stored_prev_hash != prev_hash:
                        return VerificationResult(
                            valid=False,
                            entries_checked=entries_checked,
                            first_invalid_seq=seq,
                            expected_hash=prev_hash,
                            found_hash=stored_prev_hash,
                            error=(
                                f"Chain break at seq {seq}: "
                                f"prev_hash mismatch"
                            ),
                        )

                    # Recompute hash
                    event_json = json.dumps(
                        event, sort_keys=True, default=str
                    )
                    computed_hash = _compute_entry_hash(
                        seq, timestamp, stored_prev_hash, event_json
                    )

                    if computed_hash != stored_hash:
                        return VerificationResult(
                            valid=False,
                            entries_checked=entries_checked,
                            first_invalid_seq=seq,
                            expected_hash=computed_hash,
                            found_hash=stored_hash,
                            error=(
                                f"Hash mismatch at seq {seq}: "
                                f"entry has been tampered with"
                            ),
                        )

                    prev_hash = stored_hash
                    entries_checked += 1

        except Exception as exc:
            return VerificationResult(
                valid=False,
                entries_checked=entries_checked,
                error=f"Verification failed: {exc}",
            )

        return VerificationResult(
            valid=True,
            entries_checked=entries_checked,
            final_hash=prev_hash,
        )


class VerificationResult:
    """Result of an immutable log verification."""

    def __init__(
        self,
        valid: bool,
        entries_checked: int = 0,
        first_invalid_seq: int | None = None,
        expected_hash: str | None = None,
        found_hash: str | None = None,
        final_hash: str | None = None,
        error: str | None = None,
    ) -> None:
        self.valid = valid
        self.entries_checked = entries_checked
        self.first_invalid_seq = first_invalid_seq
        self.expected_hash = expected_hash
        self.found_hash = found_hash
        self.final_hash = final_hash
        self.error = error

    def __repr__(self) -> str:
        if self.valid:
            return (
                f"VerificationResult(valid=True, "
                f"entries={self.entries_checked}, "
                f"final_hash={self.final_hash[:16]}...)"
            )
        return (
            f"VerificationResult(valid=False, "
            f"entries={self.entries_checked}, "
            f"error={self.error!r})"
        )
