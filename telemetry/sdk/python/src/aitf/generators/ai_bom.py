"""AITF AI-BOM Generator.

Automated AI Bill of Materials generator that collects component
information from OpenTelemetry telemetry spans and produces structured
AI-BOM documents in AITF, CycloneDX, and SPDX-compatible formats.

An AI-BOM captures the full inventory of models, datasets, frameworks,
tools, MCP servers, agents, guardrails, and other components that make
up an AI system — essential for supply chain security, compliance
auditing, and vulnerability management.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from aitf.semantic_conventions.attributes import (
    AIBOMAttributes,
    AgentAttributes,
    AssetInventoryAttributes,
    GenAIAttributes,
    MCPAttributes,
    ModelOpsAttributes,
    RAGAttributes,
    SkillAttributes,
    SupplyChainAttributes,
)

logger = logging.getLogger(__name__)

_GENERATOR_NAME = "aitf-ai-bom-generator"
_GENERATOR_VERSION = "1.0.0"
_AITF_BOM_SPEC_VERSION = "1.0"

# Maximum number of components to track (prevent unbounded memory)
_MAX_COMPONENTS = 10_000


@dataclass
class AIBOMComponent:
    """A single component in the AI Bill of Materials."""

    type: str
    name: str
    version: str | None = None
    provider: str | None = None
    hash: str | None = None
    license: str | None = None
    source: str | None = None
    description: str | None = None
    dependencies: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    occurrence_count: int = 1

    @property
    def component_id(self) -> str:
        """Unique identifier derived from type, name, and version."""
        key = f"{self.type}:{self.name}:{self.version or 'unknown'}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class AIBOMVulnerability:
    """A vulnerability associated with a component."""

    component_id: str
    vulnerability_id: str
    severity: str  # critical, high, medium, low
    description: str | None = None
    source: str | None = None


@dataclass
class AIBOMDocument:
    """A complete AI Bill of Materials document."""

    bom_id: str
    version: str = _AITF_BOM_SPEC_VERSION
    format: str = AIBOMAttributes.Format.AITF
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    generator: str = _GENERATOR_NAME
    generator_version: str = _GENERATOR_VERSION
    components: list[AIBOMComponent] = field(default_factory=list)
    vulnerabilities: list[AIBOMVulnerability] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def component_count(self) -> int:
        return len(self.components)

    @property
    def component_types(self) -> dict[str, int]:
        """Count of components by type."""
        counts: dict[str, int] = {}
        for comp in self.components:
            counts[comp.type] = counts.get(comp.type, 0) + 1
        return counts

    @property
    def vulnerability_summary(self) -> dict[str, int]:
        """Count of vulnerabilities by severity."""
        counts: dict[str, int] = {}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "bom_id": self.bom_id,
            "spec_version": self.version,
            "format": self.format,
            "generated_at": self.generated_at,
            "generator": {
                "name": self.generator,
                "version": self.generator_version,
            },
            "components": [
                _component_to_dict(c) for c in self.components
            ],
            "vulnerabilities": [
                {
                    "component_id": v.component_id,
                    "vulnerability_id": v.vulnerability_id,
                    "severity": v.severity,
                    "description": v.description,
                    "source": v.source,
                }
                for v in self.vulnerabilities
            ],
            "summary": {
                "total_components": self.component_count,
                "component_types": self.component_types,
                "total_vulnerabilities": len(self.vulnerabilities),
                "vulnerability_summary": self.vulnerability_summary,
            },
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_cyclonedx(self) -> dict[str, Any]:
        """Export in CycloneDX-compatible format."""
        components = []
        for comp in self.components:
            cdx_comp: dict[str, Any] = {
                "type": _map_type_to_cyclonedx(comp.type),
                "name": comp.name,
                "bom-ref": comp.component_id,
            }
            if comp.version:
                cdx_comp["version"] = comp.version
            if comp.provider:
                cdx_comp["supplier"] = {"name": comp.provider}
            if comp.hash:
                cdx_comp["hashes"] = [
                    {"alg": "SHA-256", "content": comp.hash}
                ]
            if comp.license:
                cdx_comp["licenses"] = [
                    {"license": {"id": comp.license}}
                ]
            if comp.description:
                cdx_comp["description"] = comp.description
            if comp.properties:
                cdx_comp["properties"] = [
                    {"name": k, "value": str(v)}
                    for k, v in comp.properties.items()
                ]
            components.append(cdx_comp)

        dependencies = []
        for comp in self.components:
            if comp.dependencies:
                dependencies.append({
                    "ref": comp.component_id,
                    "dependsOn": comp.dependencies,
                })

        vulnerabilities = []
        for vuln in self.vulnerabilities:
            vulnerabilities.append({
                "id": vuln.vulnerability_id,
                "ratings": [{"severity": vuln.severity}],
                "description": vuln.description or "",
                "affects": [{"ref": vuln.component_id}],
                "source": {"name": vuln.source} if vuln.source else None,
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "serialNumber": f"urn:uuid:{self.bom_id}",
            "metadata": {
                "timestamp": self.generated_at,
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": self.generator,
                            "version": self.generator_version,
                        }
                    ]
                },
                "component": {
                    "type": "machine-learning-model",
                    "name": self.metadata.get("system_name", "ai-system"),
                },
            },
            "components": components,
            "dependencies": dependencies,
            "vulnerabilities": vulnerabilities,
        }

    def to_spdx(self) -> dict[str, Any]:
        """Export in SPDX-compatible format."""
        packages = []
        for comp in self.components:
            pkg: dict[str, Any] = {
                "SPDXID": f"SPDXRef-{comp.component_id}",
                "name": comp.name,
                "downloadLocation": comp.source or "NOASSERTION",
                "primaryPackagePurpose": _map_type_to_spdx_purpose(comp.type),
            }
            if comp.version:
                pkg["versionInfo"] = comp.version
            if comp.provider:
                pkg["supplier"] = f"Organization: {comp.provider}"
            if comp.license:
                pkg["licenseConcluded"] = comp.license
            else:
                pkg["licenseConcluded"] = "NOASSERTION"
            pkg["licenseDeclared"] = pkg["licenseConcluded"]
            if comp.hash:
                pkg["checksums"] = [
                    {"algorithm": "SHA256", "checksumValue": comp.hash}
                ]
            if comp.description:
                pkg["description"] = comp.description
            packages.append(pkg)

        relationships = []
        for comp in self.components:
            for dep_id in comp.dependencies:
                relationships.append({
                    "spdxElementId": f"SPDXRef-{comp.component_id}",
                    "relatedSpdxElement": f"SPDXRef-{dep_id}",
                    "relationshipType": "DEPENDS_ON",
                })

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.metadata.get("system_name", "ai-system-bom"),
            "documentNamespace": f"https://aitf.dev/spdx/{self.bom_id}",
            "creationInfo": {
                "created": self.generated_at,
                "creators": [
                    f"Tool: {self.generator}-{self.generator_version}"
                ],
            },
            "packages": packages,
            "relationships": relationships,
        }


class AIBOMGenerator(SpanExporter):
    """Automated AI-BOM generator from OpenTelemetry telemetry data.

    Collects component information from traced AI operations and builds
    a comprehensive AI Bill of Materials. Can be used as an OTel
    SpanExporter to passively collect data, or components can be
    registered manually.

    Usage as SpanExporter (automatic collection):

        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from aitf.generators import AIBOMGenerator

        bom_generator = AIBOMGenerator(system_name="my-ai-app")
        provider = TracerProvider()
        provider.add_span_processor(BatchSpanProcessor(bom_generator))

        # ... run your AI workload ...

        bom = bom_generator.generate()
        print(bom.to_json())

    Manual registration:

        bom_generator = AIBOMGenerator(system_name="my-ai-app")
        bom_generator.add_component(
            component_type="model",
            name="gpt-4o",
            version="2024-08-06",
            provider="openai",
            license="proprietary",
        )
        bom = bom_generator.generate()
    """

    def __init__(
        self,
        system_name: str = "ai-system",
        system_version: str | None = None,
        auto_collect: bool = True,
    ):
        self._system_name = system_name
        self._system_version = system_version
        self._auto_collect = auto_collect
        self._components: dict[str, AIBOMComponent] = {}
        self._vulnerabilities: list[AIBOMVulnerability] = []
        self._lock = threading.Lock()
        self._span_count = 0

    # ── SpanExporter Interface ─────────────────────────────────────

    def export(self, spans: list[ReadableSpan] | tuple[ReadableSpan, ...]) -> SpanExportResult:
        """Process spans and extract AI component information."""
        if not self._auto_collect:
            return SpanExportResult.SUCCESS

        for span in spans:
            try:
                self._extract_components(span)
                with self._lock:
                    self._span_count += 1
            except Exception as exc:
                logger.debug("Failed to extract components from span: %s", exc)

        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True

    # ── Component Extraction from Spans ────────────────────────────

    def _extract_components(self, span: ReadableSpan) -> None:
        """Extract component information from a single span."""
        name = span.name or ""
        attrs = dict(span.attributes or {})

        # Extract model components from inference spans
        if GenAIAttributes.REQUEST_MODEL in attrs or GenAIAttributes.SYSTEM in attrs:
            self._extract_model_component(attrs)

        # Extract agent components
        if AgentAttributes.NAME in attrs:
            self._extract_agent_component(attrs)

        # Extract MCP server/tool components
        if MCPAttributes.SERVER_NAME in attrs or MCPAttributes.TOOL_NAME in attrs:
            self._extract_mcp_component(attrs)

        # Extract RAG/vector DB components
        if RAGAttributes.RETRIEVE_DATABASE in attrs:
            self._extract_rag_component(attrs)

        # Extract skill components
        if SkillAttributes.NAME in attrs:
            self._extract_skill_component(attrs)

        # Extract model ops components (training, deployment)
        if ModelOpsAttributes.TRAINING_BASE_MODEL in attrs:
            self._extract_training_component(attrs)
        if ModelOpsAttributes.DEPLOYMENT_MODEL_ID in attrs:
            self._extract_deployment_component(attrs)

        # Extract explicit supply chain/BOM data
        if SupplyChainAttributes.MODEL_SOURCE in attrs:
            self._extract_supply_chain_component(attrs)

        # Extract embedding model components from RAG spans
        if RAGAttributes.QUERY_EMBEDDING_MODEL in attrs:
            self._extract_embedding_component(attrs)

    def _extract_model_component(self, attrs: dict) -> None:
        model_id = str(attrs.get(GenAIAttributes.REQUEST_MODEL, ""))
        if not model_id:
            return

        provider = str(attrs.get(GenAIAttributes.SYSTEM, "unknown"))
        self._upsert_component(
            component_type=AIBOMAttributes.ComponentType.MODEL,
            name=model_id,
            provider=provider,
            properties=_extract_model_properties(attrs),
        )

    def _extract_agent_component(self, attrs: dict) -> None:
        agent_name = str(attrs.get(AgentAttributes.NAME, ""))
        if not agent_name:
            return

        self._upsert_component(
            component_type=AIBOMAttributes.ComponentType.AGENT,
            name=agent_name,
            version=_opt_str(attrs.get(AgentAttributes.VERSION)),
            properties={
                k: v for k, v in {
                    "agent_type": _opt_str(attrs.get(AgentAttributes.TYPE)),
                    "framework": _opt_str(attrs.get(AgentAttributes.FRAMEWORK)),
                }.items() if v is not None
            },
        )

    def _extract_mcp_component(self, attrs: dict) -> None:
        server_name = _opt_str(attrs.get(MCPAttributes.SERVER_NAME))
        if server_name:
            self._upsert_component(
                component_type=AIBOMAttributes.ComponentType.MCP_SERVER,
                name=server_name,
                version=_opt_str(attrs.get(MCPAttributes.SERVER_VERSION)),
                properties={
                    k: v for k, v in {
                        "transport": _opt_str(attrs.get(MCPAttributes.SERVER_TRANSPORT)),
                        "protocol_version": _opt_str(attrs.get(MCPAttributes.PROTOCOL_VERSION)),
                    }.items() if v is not None
                },
            )

        tool_name = _opt_str(attrs.get(MCPAttributes.TOOL_NAME))
        if tool_name:
            deps = []
            if server_name:
                server_comp = self._find_component(
                    AIBOMAttributes.ComponentType.MCP_SERVER, server_name
                )
                if server_comp:
                    deps.append(server_comp.component_id)

            self._upsert_component(
                component_type=AIBOMAttributes.ComponentType.TOOL,
                name=tool_name,
                provider=_opt_str(attrs.get(MCPAttributes.TOOL_SERVER)),
                dependencies=deps,
            )

    def _extract_rag_component(self, attrs: dict) -> None:
        db_name = str(attrs.get(RAGAttributes.RETRIEVE_DATABASE, ""))
        if not db_name:
            return

        self._upsert_component(
            component_type=AIBOMAttributes.ComponentType.VECTOR_DB,
            name=db_name,
            properties={
                k: v for k, v in {
                    "index": _opt_str(attrs.get(RAGAttributes.RETRIEVE_INDEX)),
                    "pipeline": _opt_str(attrs.get(RAGAttributes.PIPELINE_NAME)),
                }.items() if v is not None
            },
        )

    def _extract_skill_component(self, attrs: dict) -> None:
        skill_name = str(attrs.get(SkillAttributes.NAME, ""))
        if not skill_name:
            return

        self._upsert_component(
            component_type=AIBOMAttributes.ComponentType.PLUGIN,
            name=skill_name,
            version=_opt_str(attrs.get(SkillAttributes.VERSION)),
            provider=_opt_str(attrs.get(SkillAttributes.PROVIDER)),
            source=_opt_str(attrs.get(SkillAttributes.SOURCE)),
            properties={
                k: v for k, v in {
                    "category": _opt_str(attrs.get(SkillAttributes.CATEGORY)),
                }.items() if v is not None
            },
        )

    def _extract_training_component(self, attrs: dict) -> None:
        base_model = str(attrs.get(ModelOpsAttributes.TRAINING_BASE_MODEL, ""))
        if not base_model:
            return

        # The base model itself
        self._upsert_component(
            component_type=AIBOMAttributes.ComponentType.MODEL,
            name=base_model,
            properties={
                k: v for k, v in {
                    "training_type": _opt_str(attrs.get(ModelOpsAttributes.TRAINING_TYPE)),
                    "framework": _opt_str(attrs.get(ModelOpsAttributes.TRAINING_FRAMEWORK)),
                }.items() if v is not None
            },
        )

        # The training dataset
        dataset_id = _opt_str(attrs.get(ModelOpsAttributes.TRAINING_DATASET_ID))
        if dataset_id:
            self._upsert_component(
                component_type=AIBOMAttributes.ComponentType.DATASET,
                name=dataset_id,
                version=_opt_str(attrs.get(ModelOpsAttributes.TRAINING_DATASET_VERSION)),
            )

        # The output model (fine-tuned)
        output_model = _opt_str(attrs.get(ModelOpsAttributes.TRAINING_OUTPUT_MODEL_ID))
        if output_model:
            deps = []
            base_comp = self._find_component(
                AIBOMAttributes.ComponentType.MODEL, base_model
            )
            if base_comp:
                deps.append(base_comp.component_id)
            if dataset_id:
                ds_comp = self._find_component(
                    AIBOMAttributes.ComponentType.DATASET, dataset_id
                )
                if ds_comp:
                    deps.append(ds_comp.component_id)

            self._upsert_component(
                component_type=AIBOMAttributes.ComponentType.MODEL,
                name=output_model,
                hash=_opt_str(attrs.get(ModelOpsAttributes.TRAINING_OUTPUT_MODEL_HASH)),
                dependencies=deps,
                properties={"derived_from": base_model},
            )

    def _extract_deployment_component(self, attrs: dict) -> None:
        model_id = str(attrs.get(ModelOpsAttributes.DEPLOYMENT_MODEL_ID, ""))
        if not model_id:
            return

        self._upsert_component(
            component_type=AIBOMAttributes.ComponentType.MODEL,
            name=model_id,
            version=_opt_str(attrs.get(ModelOpsAttributes.DEPLOYMENT_MODEL_VERSION)),
            properties={
                k: v for k, v in {
                    "environment": _opt_str(attrs.get(ModelOpsAttributes.DEPLOYMENT_ENVIRONMENT)),
                    "endpoint": _opt_str(attrs.get(ModelOpsAttributes.DEPLOYMENT_ENDPOINT)),
                    "strategy": _opt_str(attrs.get(ModelOpsAttributes.DEPLOYMENT_STRATEGY)),
                }.items() if v is not None
            },
        )

    def _extract_supply_chain_component(self, attrs: dict) -> None:
        source = str(attrs.get(SupplyChainAttributes.MODEL_SOURCE, ""))
        if not source:
            return

        self._upsert_component(
            component_type=AIBOMAttributes.ComponentType.MODEL,
            name=source,
            hash=_opt_str(attrs.get(SupplyChainAttributes.MODEL_HASH)),
            license=_opt_str(attrs.get(SupplyChainAttributes.MODEL_LICENSE)),
            source=source,
            properties={
                k: v for k, v in {
                    "signed": attrs.get(SupplyChainAttributes.MODEL_SIGNED),
                    "signer": _opt_str(attrs.get(SupplyChainAttributes.MODEL_SIGNER)),
                    "training_data": _opt_str(attrs.get(SupplyChainAttributes.MODEL_TRAINING_DATA)),
                }.items() if v is not None
            },
        )

    def _extract_embedding_component(self, attrs: dict) -> None:
        model_name = str(attrs.get(RAGAttributes.QUERY_EMBEDDING_MODEL, ""))
        if not model_name:
            return

        self._upsert_component(
            component_type=AIBOMAttributes.ComponentType.EMBEDDING_MODEL,
            name=model_name,
            properties={
                k: v for k, v in {
                    "dimensions": attrs.get(RAGAttributes.QUERY_EMBEDDING_DIMENSIONS),
                }.items() if v is not None
            },
        )

    # ── Manual Component Management ───────────────────────────────

    def add_component(
        self,
        component_type: str,
        name: str,
        version: str | None = None,
        provider: str | None = None,
        hash: str | None = None,
        license: str | None = None,
        source: str | None = None,
        description: str | None = None,
        dependencies: list[str] | None = None,
        properties: dict[str, Any] | None = None,
    ) -> AIBOMComponent:
        """Manually add a component to the BOM."""
        return self._upsert_component(
            component_type=component_type,
            name=name,
            version=version,
            provider=provider,
            hash=hash,
            license=license,
            source=source,
            description=description,
            dependencies=dependencies or [],
            properties=properties or {},
        )

    def add_vulnerability(
        self,
        component_type: str,
        component_name: str,
        vulnerability_id: str,
        severity: str,
        description: str | None = None,
        source: str | None = None,
    ) -> AIBOMVulnerability | None:
        """Add a vulnerability associated with a component."""
        comp = self._find_component(component_type, component_name)
        if comp is None:
            logger.warning(
                "Component %s:%s not found, vulnerability not added",
                component_type,
                component_name,
            )
            return None

        vuln = AIBOMVulnerability(
            component_id=comp.component_id,
            vulnerability_id=vulnerability_id,
            severity=severity,
            description=description,
            source=source,
        )
        with self._lock:
            self._vulnerabilities.append(vuln)
        return vuln

    # ── BOM Generation ─────────────────────────────────────────────

    def generate(
        self,
        bom_id: str | None = None,
        output_format: str = AIBOMAttributes.Format.AITF,
    ) -> AIBOMDocument:
        """Generate the AI-BOM document from collected telemetry data.

        Args:
            bom_id: Optional unique identifier. Auto-generated if not provided.
            output_format: Target format (aitf, cyclonedx, spdx).

        Returns:
            AIBOMDocument with all collected components and vulnerabilities.
        """
        bom_id = bom_id or str(uuid.uuid4())

        with self._lock:
            components = list(self._components.values())
            vulnerabilities = list(self._vulnerabilities)

        return AIBOMDocument(
            bom_id=bom_id,
            format=output_format,
            components=components,
            vulnerabilities=vulnerabilities,
            metadata={
                "system_name": self._system_name,
                "system_version": self._system_version,
                "spans_processed": self._span_count,
                "auto_collected": self._auto_collect,
            },
        )

    def get_component_summary(self) -> dict[str, Any]:
        """Return a summary of collected components without generating full BOM."""
        with self._lock:
            components = list(self._components.values())

        type_counts: dict[str, int] = {}
        for comp in components:
            type_counts[comp.type] = type_counts.get(comp.type, 0) + 1

        return {
            "total_components": len(components),
            "component_types": type_counts,
            "total_vulnerabilities": len(self._vulnerabilities),
            "spans_processed": self._span_count,
        }

    @property
    def component_count(self) -> int:
        with self._lock:
            return len(self._components)

    @property
    def components(self) -> list[AIBOMComponent]:
        with self._lock:
            return list(self._components.values())

    def reset(self) -> None:
        """Clear all collected components and vulnerabilities."""
        with self._lock:
            self._components.clear()
            self._vulnerabilities.clear()
            self._span_count = 0

    # ── Internal Helpers ───────────────────────────────────────────

    def _upsert_component(
        self,
        component_type: str,
        name: str,
        version: str | None = None,
        provider: str | None = None,
        hash: str | None = None,
        license: str | None = None,
        source: str | None = None,
        description: str | None = None,
        dependencies: list[str] | None = None,
        properties: dict[str, Any] | None = None,
    ) -> AIBOMComponent:
        """Insert or update a component in the registry."""
        comp = AIBOMComponent(
            type=component_type,
            name=name,
            version=version,
            provider=provider,
            hash=hash,
            license=license,
            source=source,
            description=description,
            dependencies=dependencies or [],
            properties=properties or {},
        )
        key = comp.component_id

        with self._lock:
            if key in self._components:
                existing = self._components[key]
                existing.last_seen = datetime.now(timezone.utc).isoformat()
                existing.occurrence_count += 1
                # Merge new info into existing (non-None fields win)
                if version and not existing.version:
                    existing.version = version
                if provider and not existing.provider:
                    existing.provider = provider
                if hash and not existing.hash:
                    existing.hash = hash
                if license and not existing.license:
                    existing.license = license
                if source and not existing.source:
                    existing.source = source
                if description and not existing.description:
                    existing.description = description
                if dependencies:
                    for dep in dependencies:
                        if dep not in existing.dependencies:
                            existing.dependencies.append(dep)
                if properties:
                    existing.properties.update(properties)
                return existing
            else:
                if len(self._components) >= _MAX_COMPONENTS:
                    logger.warning(
                        "AI-BOM component limit (%d) reached, skipping %s:%s",
                        _MAX_COMPONENTS,
                        component_type,
                        name,
                    )
                    return comp
                self._components[key] = comp
                return comp

    def _find_component(self, component_type: str, name: str) -> AIBOMComponent | None:
        """Find a component by type and name."""
        key = f"{component_type}:{name}:unknown"
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        with self._lock:
            if key_hash in self._components:
                return self._components[key_hash]
            # Try with any version (scan all)
            for comp in self._components.values():
                if comp.type == component_type and comp.name == name:
                    return comp
        return None


# ── Module-level Utilities ─────────────────────────────────────────


def _component_to_dict(comp: AIBOMComponent) -> dict[str, Any]:
    """Serialize a component to dictionary."""
    d: dict[str, Any] = {
        "component_id": comp.component_id,
        "type": comp.type,
        "name": comp.name,
    }
    if comp.version:
        d["version"] = comp.version
    if comp.provider:
        d["provider"] = comp.provider
    if comp.hash:
        d["hash"] = comp.hash
    if comp.license:
        d["license"] = comp.license
    if comp.source:
        d["source"] = comp.source
    if comp.description:
        d["description"] = comp.description
    if comp.dependencies:
        d["dependencies"] = comp.dependencies
    if comp.properties:
        d["properties"] = comp.properties
    d["first_seen"] = comp.first_seen
    d["last_seen"] = comp.last_seen
    d["occurrence_count"] = comp.occurrence_count
    return d


def _extract_model_properties(attrs: dict) -> dict[str, Any]:
    """Extract model-specific properties from span attributes."""
    props: dict[str, Any] = {}
    if GenAIAttributes.REQUEST_TEMPERATURE in attrs:
        props["temperature"] = attrs[GenAIAttributes.REQUEST_TEMPERATURE]
    if GenAIAttributes.REQUEST_MAX_TOKENS in attrs:
        props["max_tokens"] = attrs[GenAIAttributes.REQUEST_MAX_TOKENS]
    if GenAIAttributes.REQUEST_STREAM in attrs:
        props["streaming"] = attrs[GenAIAttributes.REQUEST_STREAM]
    return props


def _opt_str(val: Any) -> str | None:
    return str(val) if val is not None else None


def _map_type_to_cyclonedx(comp_type: str) -> str:
    """Map AI-BOM component types to CycloneDX component types."""
    mapping = {
        "model": "machine-learning-model",
        "dataset": "data",
        "framework": "framework",
        "runtime": "platform",
        "tool": "application",
        "plugin": "library",
        "prompt_template": "file",
        "guardrail": "library",
        "vector_db": "platform",
        "embedding_model": "machine-learning-model",
        "mcp_server": "application",
        "agent": "application",
    }
    return mapping.get(comp_type, "library")


def _map_type_to_spdx_purpose(comp_type: str) -> str:
    """Map AI-BOM component types to SPDX primary package purposes."""
    mapping = {
        "model": "APPLICATION",
        "dataset": "SOURCE",
        "framework": "FRAMEWORK",
        "runtime": "OPERATING-SYSTEM",
        "tool": "APPLICATION",
        "plugin": "LIBRARY",
        "prompt_template": "FILE",
        "guardrail": "LIBRARY",
        "vector_db": "APPLICATION",
        "embedding_model": "APPLICATION",
        "mcp_server": "APPLICATION",
        "agent": "APPLICATION",
    }
    return mapping.get(comp_type, "APPLICATION")
