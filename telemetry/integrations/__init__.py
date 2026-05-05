"""AITF Third-Party Integrations.

Provides vendor-specific instrumentation modules that wrap popular AI/ML SDKs
with AITF telemetry. Each integration auto-instruments a vendor's SDK to emit
OpenTelemetry spans with AITF semantic conventions.

Vendor Categories:
    - LLM Providers: Anthropic, OpenAI, Google AI, Azure AI, Cohere, Mistral
    - Infrastructure: NVIDIA (NIM, NeMo, Triton)
    - Data Platforms: Databricks (MLflow, Mosaic ML, Unity Catalog),
                      Snowflake (Cortex AI, Snowpark ML)
    - Vector Databases: Pinecone, Weaviate, Milvus, Qdrant, ChromaDB, pgvector
    - Routing/Proxy: LiteLLM, OpenRouter
    - Guardrails: Guardrails AI, NVIDIA NeMo Guardrails, Lakera,
                  Robust Intelligence
    - Frameworks: LangGraph, CrewAI
"""

__all__ = [
    "anthropic",
    "openai",
    "google_ai",
    "azure_ai",
    "cohere",
    "mistral",
    "nvidia",
    "databricks",
    "snowflake",
    "vector_db",
    "litellm",
    "openrouter",
    "guardrails",
    "frameworks",
]
