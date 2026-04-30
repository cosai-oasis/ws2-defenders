"""AITF Resource attributes for identifying AI system components."""


class AITFResource:
    """Resource attribute constants for AITF-instrumented services."""

    # Service identification
    SERVICE_NAME = "service.name"
    SERVICE_VERSION = "service.version"

    # AITF-specific resource attributes
    AITF_VERSION = "aitf.version"
    AITF_DEPLOYMENT = "aitf.deployment"

    # AI model resource
    AI_MODEL_ID = "ai.model.id"
    AI_MODEL_PROVIDER = "ai.model.provider"
    AI_MODEL_VERSION = "ai.model.version"

    # AI agent resource
    AI_AGENT_NAME = "ai.agent.name"
    AI_AGENT_FRAMEWORK = "ai.agent.framework"

    # AI platform resource
    AI_PLATFORM = "ai.platform"
    AI_PLATFORM_VERSION = "ai.platform.version"
