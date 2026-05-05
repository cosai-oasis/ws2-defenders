"""AITF Vendor Mapper.

Loads vendor-supplied JSON mapping files and normalizes vendor-native
telemetry attributes to AITF semantic conventions before OCSF mapping.

Vendors (LangChain, CrewAI, etc.) supply JSON mapping files that declare:
  - span_name_patterns: regex patterns to classify span types
  - attribute_mappings: vendor attribute → AITF attribute translations
  - provider_detection: heuristics to detect the LLM provider
  - severity_mapping: vendor status values → OCSF severity IDs
  - defaults: fallback values when vendor attributes are missing

Usage:
    from aitf.ocsf.vendor_mapper import VendorMapper
    from aitf.ocsf.mapper import OCSFMapper

    vendor_mapper = VendorMapper()          # loads all built-in mappings
    ocsf_mapper = OCSFMapper()

    # In your SpanProcessor or Exporter:
    normalized = vendor_mapper.normalize_span(span)
    if normalized:
        event = ocsf_mapper.map_span(normalized)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from opentelemetry.sdk.trace import ReadableSpan

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAPPINGS_DIR = Path(__file__).parent / "vendor_mappings"

# Security limits for vendor-supplied regex patterns (ReDoS prevention)
_MAX_PATTERN_LENGTH = 500
_MAX_PATTERNS_PER_EVENT_TYPE = 50


# ---------------------------------------------------------------------------
# VendorMapping – in-memory representation of one JSON mapping file
# ---------------------------------------------------------------------------

class VendorMapping:
    """Parsed representation of a single vendor mapping JSON file."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.vendor: str = data["vendor"]
        self.version: str = data.get("version", "unknown")
        self.description: str = data.get("description", "")
        self.homepage: str = data.get("homepage", "")

        # Pre-compile span-name regexes with safety validation
        raw_patterns: dict[str, list[str]] = data.get("span_name_patterns", {})
        self.span_name_patterns: dict[str, list[re.Pattern[str]]] = {}
        for event_type, patterns in raw_patterns.items():
            compiled: list[re.Pattern[str]] = []
            for p in patterns[:_MAX_PATTERNS_PER_EVENT_TYPE]:
                if len(p) > _MAX_PATTERN_LENGTH:
                    logger.warning(
                        "Skipping oversized regex pattern (%d chars) in "
                        "vendor %s event type %s",
                        len(p), data.get("vendor", "?"), event_type,
                    )
                    continue
                try:
                    compiled.append(re.compile(p))
                except re.error as exc:
                    logger.warning(
                        "Skipping invalid regex pattern in vendor %s "
                        "event type %s: %s",
                        data.get("vendor", "?"), event_type, exc,
                    )
            self.span_name_patterns[event_type] = compiled

        self.attribute_mappings: dict[str, dict[str, Any]] = data.get(
            "attribute_mappings", {}
        )
        self.provider_detection: dict[str, Any] = data.get(
            "provider_detection", {}
        )
        self.severity_mapping: dict[str, dict[str, int]] = data.get(
            "severity_mapping", {}
        )
        self.metadata: dict[str, Any] = data.get("metadata", {})

    # -- classification -----------------------------------------------------

    def classify_span(self, span_name: str) -> str | None:
        """Return the event type for *span_name*, or ``None``."""
        for event_type, patterns in self.span_name_patterns.items():
            for pat in patterns:
                if pat.search(span_name):
                    return event_type
        return None

    # -- attribute translation ----------------------------------------------

    def translate_attributes(
        self,
        event_type: str,
        vendor_attrs: dict[str, Any],
    ) -> dict[str, Any]:
        """Translate vendor attributes to AITF semantic conventions.

        Returns a **new** dict containing only the mapped AITF attributes
        plus any defaults that were not already present.
        """
        mapping_block = self.attribute_mappings.get(event_type, {})
        vendor_to_aitf: dict[str, str] = mapping_block.get("vendor_to_aitf", {})
        defaults: dict[str, Any] = mapping_block.get("defaults", {})

        translated: dict[str, Any] = {}

        # 1. Map vendor keys → AITF keys
        for vendor_key, aitf_key in vendor_to_aitf.items():
            if vendor_key in vendor_attrs:
                translated[aitf_key] = vendor_attrs[vendor_key]

        # 2. Apply defaults for missing keys
        for key, value in defaults.items():
            translated.setdefault(key, value)

        # 3. Provider detection (infer gen_ai.system from model name)
        if "gen_ai.provider.name" not in translated:
            model = translated.get("gen_ai.request.model")
            if model:
                detected = self._detect_provider(str(model), vendor_attrs)
                if detected:
                    translated["gen_ai.provider.name"] = detected

        return translated

    # -- OCSF helpers -------------------------------------------------------

    def get_ocsf_class_uid(self, event_type: str) -> int | None:
        """Return the OCSF class_uid for *event_type*, or ``None``."""
        block = self.attribute_mappings.get(event_type, {})
        return block.get("ocsf_class_uid")

    def get_ocsf_activity_id(
        self, event_type: str, activity_hint: str | None = None
    ) -> int:
        """Return the OCSF activity_id for *event_type* and optional hint."""
        block = self.attribute_mappings.get(event_type, {})
        activity_map: dict[str, int] = block.get("ocsf_activity_id_map", {})
        if activity_hint and activity_hint in activity_map:
            return activity_map[activity_hint]
        return activity_map.get("default", 99)

    def get_severity_id(self, attr_key: str, attr_value: str) -> int | None:
        """Return the OCSF severity_id for a vendor status attribute."""
        sev_map = self.severity_mapping.get(attr_key, {})
        return sev_map.get(str(attr_value))

    # -- provider detection -------------------------------------------------

    def _detect_provider(
        self,
        model_name: str,
        vendor_attrs: dict[str, Any],
    ) -> str | None:
        """Detect the LLM provider from model name prefixes or attributes."""
        detection = self.provider_detection
        if not detection:
            return None

        # 1. Check explicit attribute keys first
        for key in detection.get("attribute_keys", []):
            if key in vendor_attrs:
                return str(vendor_attrs[key])

        # 2. Match model name prefix
        model_lower = model_name.lower()
        for prefix, provider in detection.get("model_prefix_to_provider", {}).items():
            if model_lower.startswith(prefix.lower()):
                return provider

        return None


# ---------------------------------------------------------------------------
# VendorMapper – the main public class
# ---------------------------------------------------------------------------

class VendorMapper:
    """Loads vendor mapping files and normalizes spans for OCSF mapping.

    Usage::

        mapper = VendorMapper()                        # all built-in vendors
        mapper = VendorMapper(vendors=["langchain"])    # specific vendors only
        mapper = VendorMapper(extra_dirs=[Path("/custom/mappings")])

        result = mapper.normalize_span(span)
        if result:
            vendor, event_type, aitf_attrs = result
    """

    def __init__(
        self,
        vendors: list[str] | None = None,
        extra_dirs: list[Path] | None = None,
    ) -> None:
        self._mappings: dict[str, VendorMapping] = {}
        self._load_builtin(vendors)
        for d in extra_dirs or []:
            self._load_dir(d, vendors)

    # -- public API ---------------------------------------------------------

    @property
    def vendors(self) -> list[str]:
        """Return the list of loaded vendor names."""
        return list(self._mappings.keys())

    def get_mapping(self, vendor: str) -> VendorMapping | None:
        """Return the mapping for *vendor*, or ``None``."""
        return self._mappings.get(vendor)

    def detect_vendor(self, span: ReadableSpan) -> tuple[str, str] | None:
        """Detect which vendor and event type a span belongs to.

        Returns ``(vendor_name, event_type)`` or ``None``.
        """
        name = span.name or ""
        attrs = dict(span.attributes or {})

        for vendor_name, mapping in self._mappings.items():
            # 1. Try span name patterns
            event_type = mapping.classify_span(name)
            if event_type:
                return (vendor_name, event_type)

            # 2. Try attribute-prefix heuristic (e.g. "crewai.*", "langchain.*")
            for attr_key in attrs:
                if attr_key.startswith(f"{vendor_name}."):
                    # Determine event type from the second segment
                    parts = attr_key.split(".")
                    if len(parts) >= 2:
                        segment = parts[1]
                        candidate = self._segment_to_event_type(
                            segment, mapping
                        )
                        if candidate:
                            return (vendor_name, candidate)

        return None

    def normalize_span(
        self,
        span: ReadableSpan,
    ) -> tuple[str, str, dict[str, Any]] | None:
        """Normalize a vendor span's attributes to AITF conventions.

        Returns ``(vendor_name, event_type, aitf_attrs)`` or ``None``
        if the span does not match any loaded vendor mapping.

        The returned *aitf_attrs* dict uses AITF semantic-convention keys
        and can be fed directly into :class:`OCSFMapper`.
        """
        detection = self.detect_vendor(span)
        if detection is None:
            return None

        vendor_name, event_type = detection
        mapping = self._mappings[vendor_name]
        vendor_attrs = dict(span.attributes or {})

        aitf_attrs = mapping.translate_attributes(event_type, vendor_attrs)
        return (vendor_name, event_type, aitf_attrs)

    def normalize_attributes(
        self,
        vendor: str,
        event_type: str,
        vendor_attrs: dict[str, Any],
    ) -> dict[str, Any]:
        """Translate raw vendor attributes to AITF conventions.

        Useful when you already know the vendor and event type
        (e.g. from a log record rather than a span).
        """
        mapping = self._mappings.get(vendor)
        if mapping is None:
            raise ValueError(f"Unknown vendor: {vendor!r}")
        return mapping.translate_attributes(event_type, vendor_attrs)

    def get_ocsf_class_uid(self, vendor: str, event_type: str) -> int | None:
        """Return the OCSF class_uid for a vendor event type."""
        mapping = self._mappings.get(vendor)
        if mapping:
            return mapping.get_ocsf_class_uid(event_type)
        return None

    def get_ocsf_activity_id(
        self,
        vendor: str,
        event_type: str,
        activity_hint: str | None = None,
    ) -> int:
        """Return the OCSF activity_id for a vendor event type."""
        mapping = self._mappings.get(vendor)
        if mapping:
            return mapping.get_ocsf_activity_id(event_type, activity_hint)
        return 99

    def list_supported_vendors(self) -> list[dict[str, str]]:
        """Return a summary of all loaded vendor mappings."""
        return [
            {
                "vendor": m.vendor,
                "version": m.version,
                "description": m.description,
                "homepage": m.homepage,
                "event_types": ", ".join(m.span_name_patterns.keys()),
            }
            for m in self._mappings.values()
        ]

    # -- loading ------------------------------------------------------------

    def _load_builtin(self, vendors: list[str] | None) -> None:
        """Load built-in mapping files from the package."""
        if _MAPPINGS_DIR.is_dir():
            self._load_dir(_MAPPINGS_DIR, vendors)

    def _load_dir(self, directory: Path, vendors: list[str] | None) -> None:
        """Load all .json mapping files from *directory*."""
        for path in sorted(directory.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning(
                    "Skipping invalid vendor mapping file %s: %s", path, exc
                )
                continue

            vendor_name = data.get("vendor")
            if not vendor_name:
                logger.warning(
                    "Skipping vendor mapping file %s: missing 'vendor' key",
                    path,
                )
                continue
            if vendors is not None and vendor_name not in vendors:
                continue

            self._mappings[vendor_name] = VendorMapping(data)

    def load_file(self, path: Path | str) -> VendorMapping:
        """Load a single vendor mapping file and register it.

        Returns the loaded :class:`VendorMapping`.
        """
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        mapping = VendorMapping(data)
        self._mappings[mapping.vendor] = mapping
        return mapping

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _segment_to_event_type(
        segment: str,
        mapping: VendorMapping,
    ) -> str | None:
        """Map an attribute segment (e.g. 'llm', 'agent') to an event type."""
        known = set(mapping.attribute_mappings.keys())
        # Direct match
        if segment in known:
            return segment
        # Common aliases
        aliases: dict[str, str] = {
            "llm": "inference",
            "model": "inference",
            "chat": "inference",
            "embedding": "inference",
            "crew": "agent",
            "task": "agent",
            "retriever": "retrieval",
            "rag": "retrieval",
        }
        candidate = aliases.get(segment)
        if candidate and candidate in known:
            return candidate
        return None
