"""AITF OCSF Mapper.

Maps OpenTelemetry spans to OCSF Category 7 AI events (7001-7010).
Based on the OCSF mapper from the AITelemetry project, enhanced
for AITF with MCP, Skills, Identity, ModelOps, Asset Inventory,
and extended agent support.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from opentelemetry.sdk.trace import ReadableSpan

from aitf.ocsf.event_classes import (
    AIAgentActivityEvent,
    AIAssetInventoryEvent,
    AIDataRetrievalEvent,
    AIGovernanceEvent,
    AIIdentityEvent,
    AIModelInferenceEvent,
    AIModelOpsEvent,
    AISecurityFindingEvent,
    AISupplyChainEvent,
    AIToolExecutionEvent,
)
from aitf.ocsf.schema import (
    AIBaseEvent,
    AICostInfo,
    AILatencyMetrics,
    AIModelInfo,
    AISecurityFinding,
    AITokenUsage,
    OCSFActor,
    OCSFMetadata,
    OCSFSeverity,
    OCSFStatus,
)
from aitf.semantic_conventions.attributes import (
    AgentAttributes,
    AssetInventoryAttributes,
    ComplianceAttributes,
    CostAttributes,
    DriftDetectionAttributes,
    GenAIAttributes,
    IdentityAttributes,
    LatencyAttributes,
    MCPAttributes,
    ModelOpsAttributes,
    RAGAttributes,
    SecurityAttributes,
    SkillAttributes,
    SupplyChainAttributes,
)


class OCSFMapper:
    """Maps OTel spans to OCSF Category 7 AI events.

    Usage:
        mapper = OCSFMapper()
        ocsf_event = mapper.map_span(span)
        if ocsf_event:
            export_to_siem(ocsf_event.model_dump())
    """

    def map_span(self, span: ReadableSpan) -> AIBaseEvent | None:
        """Map an OTel span to an OCSF event.

        Returns the appropriate OCSF event class or None if the span
        is not an AI-related span.  Covers all 10 AITF OCSF classes
        (7001-7010).
        """
        name = span.name or ""
        attrs = dict(span.attributes or {})

        # Determine event type and map accordingly
        if self._is_inference_span(name, attrs):
            return self._map_inference(span, attrs)
        elif self._is_agent_span(name, attrs):
            return self._map_agent_activity(span, attrs)
        elif self._is_tool_span(name, attrs):
            return self._map_tool_execution(span, attrs)
        elif self._is_rag_span(name, attrs):
            return self._map_data_retrieval(span, attrs)
        elif self._is_security_span(name, attrs):
            return self._map_security_finding(span, attrs)
        elif self._is_supply_chain_span(name, attrs):
            return self._map_supply_chain(span, attrs)
        elif self._is_governance_span(name, attrs):
            return self._map_governance(span, attrs)
        elif self._is_identity_span(name, attrs):
            return self._map_identity(span, attrs)
        elif self._is_model_ops_span(name, attrs):
            return self._map_model_ops(span, attrs)
        elif self._is_asset_inventory_span(name, attrs):
            return self._map_asset_inventory(span, attrs)

        return None

    def _is_inference_span(self, name: str, attrs: dict) -> bool:
        return (
            name.startswith("chat ")
            or name.startswith("embeddings ")
            or name.startswith("text_completion ")
            or GenAIAttributes.PROVIDER_NAME in attrs
            or GenAIAttributes.SYSTEM in attrs
        )

    def _is_agent_span(self, name: str, attrs: dict) -> bool:
        return name.startswith("agent.") or GenAIAttributes.AGENT_NAME in attrs

    def _is_tool_span(self, name: str, attrs: dict) -> bool:
        return (
            name.startswith("mcp.tool.")
            or name.startswith("skill.invoke")
            or GenAIAttributes.TOOL_NAME in attrs
            or SkillAttributes.NAME in attrs
        )

    def _is_rag_span(self, name: str, attrs: dict) -> bool:
        return (
            name.startswith("rag.")
            or RAGAttributes.RETRIEVE_DATABASE in attrs
        )

    def _is_security_span(self, name: str, attrs: dict) -> bool:
        return SecurityAttributes.THREAT_DETECTED in attrs

    def _map_inference(self, span: ReadableSpan, attrs: dict) -> AIModelInferenceEvent:
        """Map inference span to OCSF 7001."""
        model_id = str(attrs.get(GenAIAttributes.REQUEST_MODEL, "unknown"))
        system = str(attrs.get(GenAIAttributes.PROVIDER_NAME) or attrs.get(GenAIAttributes.SYSTEM, "unknown"))
        operation = str(attrs.get(GenAIAttributes.OPERATION_NAME, "chat"))

        # Activity: 1=chat, 2=text_completion, 3=embeddings
        activity_map = {"chat": 1, "text_completion": 2, "embeddings": 3}
        activity_id = activity_map.get(operation, 99)

        model = AIModelInfo(
            model_id=model_id,
            name=model_id,
            provider=system,
            type="llm" if operation != "embeddings" else "embedding",
            parameters={
                k.replace("gen_ai.request.", ""): v
                for k, v in attrs.items()
                if k.startswith("gen_ai.request.") and k != GenAIAttributes.REQUEST_MODEL
            } or None,
        )

        token_usage = AITokenUsage(
            input_tokens=int(attrs.get(GenAIAttributes.USAGE_INPUT_TOKENS, 0)),
            output_tokens=int(attrs.get(GenAIAttributes.USAGE_OUTPUT_TOKENS, 0)),
            cached_tokens=int(attrs.get(GenAIAttributes.USAGE_CACHED_TOKENS, 0)),
            reasoning_tokens=int(attrs.get(GenAIAttributes.USAGE_REASONING_TOKENS, 0)),
        )

        latency = None
        if LatencyAttributes.TOTAL_MS in attrs:
            latency = AILatencyMetrics(
                total_ms=float(attrs.get(LatencyAttributes.TOTAL_MS, 0)),
                time_to_first_token_ms=_opt_float(attrs.get(LatencyAttributes.TIME_TO_FIRST_TOKEN_MS)),
                tokens_per_second=_opt_float(attrs.get(LatencyAttributes.TOKENS_PER_SECOND)),
            )

        cost = None
        if CostAttributes.TOTAL_COST in attrs:
            cost = AICostInfo(
                input_cost_usd=float(attrs.get(CostAttributes.INPUT_COST, 0)),
                output_cost_usd=float(attrs.get(CostAttributes.OUTPUT_COST, 0)),
                total_cost_usd=float(attrs.get(CostAttributes.TOTAL_COST, 0)),
            )

        finish_reasons = attrs.get(GenAIAttributes.RESPONSE_FINISH_REASONS, ["stop"])
        finish_reason = finish_reasons[0] if isinstance(finish_reasons, (list, tuple)) else str(finish_reasons)

        return AIModelInferenceEvent(
            activity_id=activity_id,
            model=model,
            token_usage=token_usage,
            latency=latency,
            cost=cost,
            finish_reason=finish_reason,
            streaming=bool(attrs.get(GenAIAttributes.REQUEST_STREAM, False)),
            message=f"{operation} {model_id}",
            time=_span_time(span),
        )

    def _map_agent_activity(self, span: ReadableSpan, attrs: dict) -> AIAgentActivityEvent:
        """Map agent span to OCSF 7002."""
        name = span.name or ""
        agent_name = str(attrs.get(GenAIAttributes.AGENT_NAME, "unknown"))
        agent_id = str(attrs.get(GenAIAttributes.AGENT_ID, "unknown"))
        session_id = str(attrs.get(GenAIAttributes.CONVERSATION_ID, "unknown"))

        # Determine activity from span name
        if "session" in name:
            activity_id = 1  # Session Start
        elif "delegation" in name or "delegate" in name:
            activity_id = 4  # Delegation
        elif "memory" in name:
            activity_id = 5  # Memory Access
        else:
            activity_id = 3  # Step Execute

        return AIAgentActivityEvent(
            activity_id=activity_id,
            agent_name=agent_name,
            agent_id=agent_id,
            agent_type=str(attrs.get(AgentAttributes.TYPE, "autonomous")),
            framework=_opt_str(attrs.get(AgentAttributes.FRAMEWORK)),
            session_id=session_id,
            step_type=_opt_str(attrs.get(AgentAttributes.STEP_TYPE)),
            step_index=_opt_int(attrs.get(AgentAttributes.STEP_INDEX)),
            thought=_opt_str(attrs.get(AgentAttributes.STEP_THOUGHT)),
            action=_opt_str(attrs.get(AgentAttributes.STEP_ACTION)),
            observation=_opt_str(attrs.get(AgentAttributes.STEP_OBSERVATION)),
            delegation_target=_opt_str(attrs.get(AgentAttributes.DELEGATION_TARGET_AGENT)),
            message=name,
            time=_span_time(span),
        )

    def _map_tool_execution(self, span: ReadableSpan, attrs: dict) -> AIToolExecutionEvent:
        """Map tool/MCP/skill span to OCSF 7003."""
        # Determine tool type
        if GenAIAttributes.TOOL_NAME in attrs:
            tool_name = str(attrs[GenAIAttributes.TOOL_NAME])
            tool_type = "mcp_tool"
            activity_id = 2  # MCP Tool Invoke
        elif SkillAttributes.NAME in attrs:
            tool_name = str(attrs[SkillAttributes.NAME])
            tool_type = "skill"
            activity_id = 3  # Skill Invoke
        else:
            tool_name = str(attrs.get("gen_ai.tool.name", "unknown"))
            tool_type = "function"
            activity_id = 1  # Function Call

        return AIToolExecutionEvent(
            activity_id=activity_id,
            tool_name=tool_name,
            tool_type=tool_type,
            tool_input=_opt_str(attrs.get(GenAIAttributes.TOOL_CALL_ARGUMENTS) or attrs.get(SkillAttributes.INPUT)),
            tool_output=_opt_str(attrs.get(GenAIAttributes.TOOL_CALL_RESULT) or attrs.get(SkillAttributes.OUTPUT)),
            is_error=bool(attrs.get(MCPAttributes.TOOL_IS_ERROR, False)),
            duration_ms=_opt_float(attrs.get(MCPAttributes.TOOL_DURATION_MS) or attrs.get(SkillAttributes.DURATION_MS)),
            mcp_server=_opt_str(attrs.get(MCPAttributes.TOOL_SERVER)),
            mcp_transport=_opt_str(attrs.get(MCPAttributes.SERVER_TRANSPORT)),
            skill_category=_opt_str(attrs.get(SkillAttributes.CATEGORY)),
            skill_version=_opt_str(attrs.get(SkillAttributes.VERSION)),
            approval_required=bool(attrs.get(MCPAttributes.TOOL_APPROVAL_REQUIRED, False)),
            approved=_opt_bool(attrs.get(MCPAttributes.TOOL_APPROVED)),
            message=span.name or f"tool.execute {tool_name}",
            time=_span_time(span),
        )

    def _map_data_retrieval(self, span: ReadableSpan, attrs: dict) -> AIDataRetrievalEvent:
        """Map RAG/retrieval span to OCSF 7004."""
        database = str(attrs.get(RAGAttributes.RETRIEVE_DATABASE, "unknown"))
        stage = str(attrs.get(RAGAttributes.PIPELINE_STAGE, "retrieve"))

        # Activity: 1=vector_search, 2=document_retrieval, 5=reranking
        activity_map = {"retrieve": 1, "rerank": 5, "generate": 99, "evaluate": 99}
        activity_id = activity_map.get(stage, 99)

        return AIDataRetrievalEvent(
            activity_id=activity_id,
            database_name=database,
            database_type=database,
            query=_opt_str(attrs.get(RAGAttributes.QUERY)),
            top_k=_opt_int(attrs.get(RAGAttributes.RETRIEVE_TOP_K)),
            results_count=int(attrs.get(RAGAttributes.RETRIEVE_RESULTS_COUNT, 0)),
            min_score=_opt_float(attrs.get(RAGAttributes.RETRIEVE_MIN_SCORE)),
            max_score=_opt_float(attrs.get(RAGAttributes.RETRIEVE_MAX_SCORE)),
            filter=_opt_str(attrs.get(RAGAttributes.RETRIEVE_FILTER)),
            embedding_model=_opt_str(attrs.get(RAGAttributes.QUERY_EMBEDDING_MODEL)),
            pipeline_name=_opt_str(attrs.get(RAGAttributes.PIPELINE_NAME)),
            pipeline_stage=stage,
            message=span.name or f"rag.{stage} {database}",
            time=_span_time(span),
        )

    def _map_security_finding(self, span: ReadableSpan, attrs: dict) -> AISecurityFindingEvent:
        """Map security span to OCSF 7005."""
        finding = AISecurityFinding(
            finding_type=str(attrs.get(SecurityAttributes.THREAT_TYPE, "unknown")),
            owasp_category=_opt_str(attrs.get(SecurityAttributes.OWASP_CATEGORY)),
            risk_level=str(attrs.get(SecurityAttributes.RISK_LEVEL, "medium")),
            risk_score=float(attrs.get(SecurityAttributes.RISK_SCORE, 50.0)),
            confidence=float(attrs.get(SecurityAttributes.CONFIDENCE, 0.5)),
            detection_method=str(attrs.get(SecurityAttributes.DETECTION_METHOD, "pattern")),
            blocked=bool(attrs.get(SecurityAttributes.BLOCKED, False)),
        )

        severity_map = {
            "critical": OCSFSeverity.CRITICAL,
            "high": OCSFSeverity.HIGH,
            "medium": OCSFSeverity.MEDIUM,
            "low": OCSFSeverity.LOW,
            "info": OCSFSeverity.INFORMATIONAL,
        }

        return AISecurityFindingEvent(
            activity_id=1,  # Threat Detection
            finding=finding,
            severity_id=severity_map.get(finding.risk_level, OCSFSeverity.MEDIUM),
            message=span.name or f"security.{finding.finding_type}",
            time=_span_time(span),
        )

    # ── Supply Chain (7006) ───────────────────────────────────────────

    def _is_supply_chain_span(self, name: str, attrs: dict) -> bool:
        return (
            name.startswith("supply_chain.")
            or SupplyChainAttributes.MODEL_SOURCE in attrs
        )

    def _map_supply_chain(self, span: ReadableSpan, attrs: dict) -> AISupplyChainEvent:
        """Map supply chain span to OCSF 7006."""
        name = span.name or ""

        # Activity: 1=verify, 2=audit, 3=sign, 4=validate
        if "verify" in name or "validate" in name:
            activity_id = 1
        elif "audit" in name:
            activity_id = 2
        elif "sign" in name:
            activity_id = 3
        else:
            activity_id = 99

        return AISupplyChainEvent(
            activity_id=activity_id,
            model_source=str(attrs.get(SupplyChainAttributes.MODEL_SOURCE, "unknown")),
            model_hash=_opt_str(attrs.get(SupplyChainAttributes.MODEL_HASH)),
            model_license=_opt_str(attrs.get(SupplyChainAttributes.MODEL_LICENSE)),
            model_signed=bool(attrs.get(SupplyChainAttributes.MODEL_SIGNED, False)),
            model_signer=_opt_str(attrs.get(SupplyChainAttributes.MODEL_SIGNER)),
            ai_bom_id=_opt_str(attrs.get(SupplyChainAttributes.AI_BOM_ID)),
            ai_bom_components=_opt_str(attrs.get(SupplyChainAttributes.AI_BOM_COMPONENTS)),
            message=name or "supply_chain.event",
            time=_span_time(span),
        )

    # ── Governance (7007) ─────────────────────────────────────────────

    def _is_governance_span(self, name: str, attrs: dict) -> bool:
        return (
            name.startswith("governance.")
            or name.startswith("compliance.")
            or ComplianceAttributes.FRAMEWORKS in attrs
        )

    def _map_governance(self, span: ReadableSpan, attrs: dict) -> AIGovernanceEvent:
        """Map governance/compliance span to OCSF 7007."""
        name = span.name or ""

        # Activity: 1=audit, 2=assessment, 3=violation, 4=remediation
        if "audit" in name:
            activity_id = 1
        elif "assess" in name or "check" in name:
            activity_id = 2
        elif "violat" in name:
            activity_id = 3
        elif "remedia" in name:
            activity_id = 4
        else:
            activity_id = 99

        frameworks_raw = attrs.get(ComplianceAttributes.FRAMEWORKS)
        frameworks: list[str] = []
        if isinstance(frameworks_raw, (list, tuple)):
            frameworks = [str(f) for f in frameworks_raw]
        elif frameworks_raw is not None:
            frameworks = [str(frameworks_raw)]

        return AIGovernanceEvent(
            activity_id=activity_id,
            frameworks=frameworks,
            event_type=name.split(".")[-1] if "." in name else name,
            message=name or "governance.event",
            time=_span_time(span),
        )

    # ── Identity (7008) ───────────────────────────────────────────────

    def _is_identity_span(self, name: str, attrs: dict) -> bool:
        return (
            name.startswith("identity.")
            or IdentityAttributes.AGENT_ID in attrs
        )

    def _map_identity(self, span: ReadableSpan, attrs: dict) -> AIIdentityEvent:
        """Map identity span to OCSF 7008."""
        name = span.name or ""

        # Activity: 1=authenticate, 2=authorize, 3=delegate, 4=trust, 5=lifecycle, 6=session
        if "auth " in name or ".auth " in name:
            activity_id = 1
        elif "authz" in name:
            activity_id = 2
        elif "delegate" in name:
            activity_id = 3
        elif "trust" in name:
            activity_id = 4
        elif "lifecycle" in name:
            activity_id = 5
        elif "session" in name:
            activity_id = 6
        else:
            activity_id = 99

        auth_method = str(attrs.get(IdentityAttributes.AUTH_METHOD, "unknown"))
        auth_result = str(attrs.get(IdentityAttributes.AUTH_RESULT, "unknown"))

        # Build delegation chain
        chain_raw = attrs.get(IdentityAttributes.DELEGATION_CHAIN)
        delegation_chain: list[str] = []
        if isinstance(chain_raw, (list, tuple)):
            delegation_chain = [str(c) for c in chain_raw]

        return AIIdentityEvent(
            activity_id=activity_id,
            agent_name=str(attrs.get(IdentityAttributes.AGENT_NAME, "unknown")),
            agent_id=str(attrs.get(IdentityAttributes.AGENT_ID, "unknown")),
            auth_method=auth_method,
            auth_result=auth_result,
            credential_type=_opt_str(attrs.get(IdentityAttributes.CREDENTIAL_TYPE)),
            delegation_chain=delegation_chain,
            scope=_opt_str(attrs.get(IdentityAttributes.SCOPE)),
            message=name or "identity.event",
            time=_span_time(span),
        )

    # ── Model Operations (7009) ───────────────────────────────────────

    def _is_model_ops_span(self, name: str, attrs: dict) -> bool:
        return (
            name.startswith("model_ops.")
            or name.startswith("drift.")
            or ModelOpsAttributes.TRAINING_RUN_ID in attrs
            or ModelOpsAttributes.EVALUATION_RUN_ID in attrs
            or ModelOpsAttributes.DEPLOYMENT_ID in attrs
            or DriftDetectionAttributes.MODEL_ID in attrs
        )

    def _map_model_ops(self, span: ReadableSpan, attrs: dict) -> AIModelOpsEvent:
        """Map model operations / drift detection span to OCSF 7009."""
        name = span.name or ""

        # Determine operation type and activity
        if name.startswith("model_ops.training") or ModelOpsAttributes.TRAINING_RUN_ID in attrs:
            operation_type = "training"
            activity_id = 1  # Train
        elif name.startswith("model_ops.evaluation") or ModelOpsAttributes.EVALUATION_RUN_ID in attrs:
            operation_type = "evaluation"
            activity_id = 2  # Evaluate
        elif name.startswith("model_ops.registry"):
            operation_type = "registry"
            activity_id = 3  # Register
        elif name.startswith("model_ops.deployment") or ModelOpsAttributes.DEPLOYMENT_ID in attrs:
            operation_type = "deployment"
            activity_id = 4  # Deploy
        elif name.startswith("model_ops.serving"):
            operation_type = "serving"
            activity_id = 5  # Serve
        elif name.startswith("model_ops.monitoring"):
            operation_type = "monitoring"
            activity_id = 6  # Monitor
        elif name.startswith("model_ops.prompt"):
            operation_type = "prompt"
            activity_id = 7  # Prompt Management
        elif name.startswith("drift.") or DriftDetectionAttributes.MODEL_ID in attrs:
            operation_type = "monitoring"
            activity_id = 6  # Monitor (drift is a monitoring concern)
        else:
            operation_type = "unknown"
            activity_id = 99

        # Extract model ID from various attribute sources
        model_id = _opt_str(
            attrs.get(ModelOpsAttributes.TRAINING_BASE_MODEL)
            or attrs.get(ModelOpsAttributes.EVALUATION_MODEL_ID)
            or attrs.get(ModelOpsAttributes.DEPLOYMENT_MODEL_ID)
            or attrs.get(ModelOpsAttributes.REGISTRY_MODEL_ID)
            or attrs.get(DriftDetectionAttributes.MODEL_ID)
        )

        # Extract run ID
        run_id = _opt_str(
            attrs.get(ModelOpsAttributes.TRAINING_RUN_ID)
            or attrs.get(ModelOpsAttributes.EVALUATION_RUN_ID)
        )

        return AIModelOpsEvent(
            activity_id=activity_id,
            operation_type=operation_type,
            model_id=model_id,
            run_id=run_id,
            status=_opt_str(attrs.get(ModelOpsAttributes.TRAINING_STATUS) or attrs.get(ModelOpsAttributes.DEPLOYMENT_STATUS)),
            # Training
            training_type=_opt_str(attrs.get(ModelOpsAttributes.TRAINING_TYPE)),
            base_model=_opt_str(attrs.get(ModelOpsAttributes.TRAINING_BASE_MODEL)),
            dataset_id=_opt_str(attrs.get(ModelOpsAttributes.TRAINING_DATASET_ID)),
            epochs=_opt_int(attrs.get(ModelOpsAttributes.TRAINING_EPOCHS)),
            loss_final=_opt_float(attrs.get(ModelOpsAttributes.TRAINING_LOSS_FINAL)),
            output_model_id=_opt_str(attrs.get(ModelOpsAttributes.TRAINING_OUTPUT_MODEL_ID)),
            # Evaluation
            evaluation_type=_opt_str(attrs.get(ModelOpsAttributes.EVALUATION_TYPE)),
            metrics=_opt_str(attrs.get(ModelOpsAttributes.EVALUATION_METRICS)),
            passed=_opt_bool(attrs.get(ModelOpsAttributes.EVALUATION_PASS)),
            # Deployment
            deployment_id=_opt_str(attrs.get(ModelOpsAttributes.DEPLOYMENT_ID)),
            strategy=_opt_str(attrs.get(ModelOpsAttributes.DEPLOYMENT_STRATEGY)),
            environment=_opt_str(attrs.get(ModelOpsAttributes.DEPLOYMENT_ENVIRONMENT)),
            endpoint=_opt_str(attrs.get(ModelOpsAttributes.DEPLOYMENT_ENDPOINT)),
            # Serving
            selected_model=_opt_str(attrs.get(ModelOpsAttributes.SERVING_ROUTE_SELECTED_MODEL)),
            fallback_chain=_opt_str(attrs.get(ModelOpsAttributes.SERVING_FALLBACK_CHAIN)),
            cache_hit=_opt_bool(attrs.get(ModelOpsAttributes.SERVING_CACHE_HIT)),
            # Monitoring / Drift
            check_type=_opt_str(attrs.get(ModelOpsAttributes.MONITORING_CHECK_TYPE) or attrs.get(DriftDetectionAttributes.TYPE)),
            drift_score=_opt_float(attrs.get(ModelOpsAttributes.MONITORING_DRIFT_SCORE) or attrs.get(DriftDetectionAttributes.SCORE)),
            drift_type=_opt_str(attrs.get(ModelOpsAttributes.MONITORING_DRIFT_TYPE) or attrs.get(DriftDetectionAttributes.TYPE)),
            action_triggered=_opt_str(attrs.get(ModelOpsAttributes.MONITORING_ACTION_TRIGGERED) or attrs.get(DriftDetectionAttributes.ACTION_TRIGGERED)),
            message=name or f"model_ops.{operation_type}",
            time=_span_time(span),
        )

    # ── Asset Inventory (7010) ────────────────────────────────────────

    def _is_asset_inventory_span(self, name: str, attrs: dict) -> bool:
        return (
            name.startswith("asset.")
            or AssetInventoryAttributes.ID in attrs
        )

    def _map_asset_inventory(self, span: ReadableSpan, attrs: dict) -> AIAssetInventoryEvent:
        """Map asset inventory span to OCSF 7010."""
        name = span.name or ""

        # Activity: 1=register, 2=discover, 3=audit, 4=classify, 5=decommission
        if "register" in name:
            operation_type = "register"
            activity_id = 1
        elif "discover" in name:
            operation_type = "discover"
            activity_id = 2
        elif "audit" in name:
            operation_type = "audit"
            activity_id = 3
        elif "classify" in name:
            operation_type = "classify"
            activity_id = 4
        elif "decommission" in name:
            operation_type = "decommission"
            activity_id = 5
        else:
            operation_type = "unknown"
            activity_id = 99

        return AIAssetInventoryEvent(
            activity_id=activity_id,
            operation_type=operation_type,
            asset_id=_opt_str(attrs.get(AssetInventoryAttributes.ID)),
            asset_name=_opt_str(attrs.get(AssetInventoryAttributes.NAME)),
            asset_type=_opt_str(attrs.get(AssetInventoryAttributes.TYPE)),
            asset_version=_opt_str(attrs.get(AssetInventoryAttributes.VERSION)),
            owner=_opt_str(attrs.get(AssetInventoryAttributes.OWNER)),
            deployment_environment=_opt_str(attrs.get(AssetInventoryAttributes.DEPLOYMENT_ENVIRONMENT)),
            risk_classification=_opt_str(attrs.get(AssetInventoryAttributes.RISK_CLASSIFICATION)),
            # Discovery
            discovery_scope=_opt_str(attrs.get(AssetInventoryAttributes.DISCOVERY_SCOPE)),
            discovery_method=_opt_str(attrs.get(AssetInventoryAttributes.DISCOVERY_METHOD)),
            assets_found=_opt_int(attrs.get(AssetInventoryAttributes.DISCOVERY_ASSETS_FOUND)),
            new_assets=_opt_int(attrs.get(AssetInventoryAttributes.DISCOVERY_NEW_ASSETS)),
            shadow_assets=_opt_int(attrs.get(AssetInventoryAttributes.DISCOVERY_SHADOW_ASSETS)),
            # Audit
            audit_type=_opt_str(attrs.get(AssetInventoryAttributes.AUDIT_TYPE)),
            audit_result=_opt_str(attrs.get(AssetInventoryAttributes.AUDIT_RESULT)),
            audit_framework=_opt_str(attrs.get(AssetInventoryAttributes.AUDIT_FRAMEWORK)),
            audit_findings=_opt_str(attrs.get(AssetInventoryAttributes.AUDIT_FINDINGS)),
            # Classification
            classification_framework=_opt_str(attrs.get(AssetInventoryAttributes.CLASSIFICATION_FRAMEWORK)),
            previous_classification=_opt_str(attrs.get(AssetInventoryAttributes.CLASSIFICATION_PREVIOUS)),
            classification_reason=_opt_str(attrs.get(AssetInventoryAttributes.CLASSIFICATION_REASON)),
            message=name or f"asset.{operation_type}",
            time=_span_time(span),
        )


# --- Utility Functions ---

def _span_time(span: ReadableSpan) -> str:
    if span.start_time:
        return datetime.fromtimestamp(
            span.start_time / 1e9, tz=timezone.utc
        ).isoformat()
    return datetime.now(timezone.utc).isoformat()


def _opt_str(val: Any) -> str | None:
    return str(val) if val is not None else None


def _opt_int(val: Any) -> int | None:
    return int(val) if val is not None else None


def _opt_float(val: Any) -> float | None:
    return float(val) if val is not None else None


def _opt_bool(val: Any) -> bool | None:
    return bool(val) if val is not None else None
