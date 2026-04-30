# AITF Third-Party Integrations

> **Non-official, highly experimental.** These integrations are community proposals
> and have **not** been endorsed, reviewed, or certified by the vendors listed below.
> APIs, attribute mappings, and monkey-patching behaviour may break without notice.
> Use at your own risk — test thoroughly before deploying to production.

This directory contains vendor-specific instrumentation modules that wrap popular AI/ML SDKs with AITF telemetry. Each integration auto-instruments a vendor's SDK to emit OpenTelemetry spans enriched with AITF semantic conventions for observability, security, and compliance.

## Architecture

```
integrations/
├── anthropic/              # Anthropic
│   ├── claude-api/         #   Claude Messages API
│   └── claude-code/        #   Claude Code / Agent SDK
├── openai/                 # OpenAI
│   ├── gpt-api/            #   Chat Completions, Embeddings
│   └── assistants-api/     #   Assistants, Threads, Runs
├── google-ai/              # Google AI
│   ├── gemini/             #   Google Generative AI SDK
│   └── vertex-ai/          #   Vertex AI Platform
├── azure-ai/               # Microsoft Azure
│   ├── azure-openai/       #   Azure OpenAI Service
│   └── azure-ml/           #   Azure Machine Learning
├── cohere/                 # Cohere
│   ├── command/            #   Chat & Generate
│   ├── embed/              #   Embeddings
│   └── rerank/             #   Reranking
├── mistral/                # Mistral AI
│   ├── la-plateforme/      #   Mistral API (Chat, Embeddings, FIM)
│   └── le-chat/            #   Le Chat Agent
├── nvidia/                 # NVIDIA
│   ├── nim/                #   NIM Inference Microservices
│   ├── nemo/               #   NeMo Training Framework
│   └── triton/             #   Triton Inference Server
├── databricks/             # Databricks
│   ├── mlflow/             #   MLflow Experiment & Model Registry
│   ├── mosaic-ml/          #   MosaicML Training
│   └── unity-catalog/      #   Unity Catalog AI Assets
├── snowflake/              # Snowflake
│   ├── cortex-ai/          #   Cortex LLM Functions & Search
│   └── snowpark-ml/        #   Snowpark ML Pipelines
├── vector-db/              # Vector Databases
│   ├── pinecone/           #   Pinecone
│   ├── weaviate/           #   Weaviate
│   ├── milvus/             #   Milvus (PyMilvus)
│   ├── qdrant/             #   Qdrant
│   ├── chromadb/           #   ChromaDB
│   └── pgvector/           #   pgvector (PostgreSQL)
├── litellm/                # LiteLLM
│   ├── proxy/              #   LiteLLM Proxy Server
│   └── sdk/                #   LiteLLM SDK
├── openrouter/             # OpenRouter
│   └── api/                #   OpenRouter API
├── guardrails/             # Safety & Guardrails
│   ├── guardrails-ai/      #   Guardrails AI Framework
│   ├── nemo-guardrails/    #   NVIDIA NeMo Guardrails
│   ├── lakera/             #   Lakera Guard
│   └── robust-intelligence/#   Robust Intelligence (RIME)
└── frameworks/             # Agent Frameworks
    ├── langgraph/          #   LangGraph
    └── crewai/             #   CrewAI
```

## Quick Start

### Install

```bash
# Install AITF with specific vendor integrations
pip install aitf[anthropic]      # Anthropic Claude
pip install aitf[openai]         # OpenAI GPT
pip install aitf[google-ai]      # Google Gemini / Vertex AI
pip install aitf[all-integrations]  # Everything
```

### Basic Usage

```python
from aitf.integrations.anthropic.claude_api import AnthropicInstrumentor

# Auto-instrument the Anthropic SDK
instrumentor = AnthropicInstrumentor()
instrumentor.instrument()

# All anthropic.Anthropic().messages.create() calls are now traced
import anthropic
client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello!"}]
)
# ^ This automatically generates AITF spans with:
#   - gen_ai.system = "anthropic"
#   - gen_ai.request.model = "claude-sonnet-4-20250514"
#   - gen_ai.usage.input_tokens / output_tokens
#   - aitf.cost.total (auto-calculated)
#   - Security risk scoring
```

### Multi-Vendor Setup

```python
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

from aitf.processors import SecurityProcessor, PIIProcessor, CostProcessor
from aitf.integrations.anthropic.claude_api import AnthropicInstrumentor
from aitf.integrations.openai.gpt_api import OpenAIInstrumentor
from aitf.integrations.vector_db.pinecone import PineconeInstrumentor
from aitf.integrations.guardrails.lakera import LakeraInstrumentor

# Configure OTel with AITF processors
provider = TracerProvider()
provider.add_span_processor(SecurityProcessor())
provider.add_span_processor(PIIProcessor())
provider.add_span_processor(CostProcessor())
provider.add_span_processor(BatchSpanExporter(OTLPSpanExporter()))

# Instrument all vendors
AnthropicInstrumentor(tracer_provider=provider).instrument()
OpenAIInstrumentor(tracer_provider=provider).instrument()
PineconeInstrumentor(tracer_provider=provider).instrument()
LakeraInstrumentor(tracer_provider=provider).instrument()

# All SDK calls across vendors now produce unified AITF telemetry
```

## Integration Categories

### LLM Providers

| Vendor | Product | SDK | AITF Namespace | Key Features |
|--------|---------|-----|----------------|--------------|
| Anthropic | Claude API | `anthropic` | `gen_ai.*` | Messages, streaming, tool use, vision, caching |
| Anthropic | Claude Code | Agent SDK | `aitf.agent.*`, `aitf.mcp.*` | Agent sessions, MCP tools, file operations |
| OpenAI | GPT API | `openai` | `gen_ai.*` | Chat, embeddings, structured outputs, function calling |
| OpenAI | Assistants | `openai` | `aitf.agent.*` | Threads, runs, file search, code interpreter |
| Google AI | Gemini | `google-generativeai` | `gen_ai.*` | Multimodal, grounding, safety settings |
| Google AI | Vertex AI | `google-cloud-aiplatform` | `aitf.model_ops.*` | Deployment, batch prediction, evaluation |
| Azure | Azure OpenAI | `openai` | `gen_ai.*` | Content filtering, deployments, API versioning |
| Azure | Azure ML | `azure-ai-ml` | `aitf.model_ops.*` | Endpoints, model registry, managed compute |
| Cohere | Command | `cohere` | `gen_ai.*` | Chat, RAG connectors, citations |
| Cohere | Embed | `cohere` | `gen_ai.*` | Embeddings, input types, truncation |
| Cohere | Rerank | `cohere` | `aitf.rag.*` | Relevance scoring, document reranking |
| Mistral | La Plateforme | `mistralai` | `gen_ai.*` | Chat, embeddings, FIM, function calling |
| Mistral | Le Chat | Agent SDK | `aitf.agent.*` | Agent sessions, web search, code execution |

### Infrastructure & Platforms

| Vendor | Product | SDK | AITF Namespace | Key Features |
|--------|---------|-----|----------------|--------------|
| NVIDIA | NIM | NIM API | `gen_ai.*` | GPU inference, TensorRT-LLM, batching |
| NVIDIA | NeMo | NeMo SDK | `aitf.model_ops.*` | Training, fine-tuning, distributed training |
| NVIDIA | Triton | Triton Client | `aitf.model_ops.serving.*` | Model serving, dynamic batching, ensembles |
| Databricks | MLflow | `mlflow` | `aitf.model_ops.*` | Experiment tracking, model registry, serving |
| Databricks | Mosaic ML | Composer | `aitf.model_ops.training.*` | Distributed training, FSDP, checkpointing |
| Databricks | Unity Catalog | UC SDK | `aitf.asset.*` | AI asset registry, lineage, governance |
| Snowflake | Cortex AI | Snowflake SQL | `gen_ai.*` | LLM functions, search, fine-tuning |
| Snowflake | Snowpark ML | `snowpark-ml` | `aitf.model_ops.*` | ML pipelines, feature engineering |

### Vector Databases

| Vendor | SDK | AITF Namespace | Key Features |
|--------|-----|----------------|--------------|
| Pinecone | `pinecone` | `aitf.rag.*` | Upsert, query, namespaces, metadata filtering |
| Weaviate | `weaviate-client` | `aitf.rag.*` | Hybrid search, multi-tenancy, cross-references |
| Milvus | `pymilvus` | `aitf.rag.*` | IVF/HNSW indexes, partitions, GPU search |
| Qdrant | `qdrant-client` | `aitf.rag.*` | Payload filtering, quantization, snapshots |
| ChromaDB | `chromadb` | `aitf.rag.*` | Embedding functions, where filters, local/remote |
| pgvector | `pgvector` / SQLAlchemy | `aitf.rag.*` | PostgreSQL vectors, HNSW/IVFFlat indexes |

### Routing & Proxy

| Vendor | Product | SDK | AITF Namespace | Key Features |
|--------|---------|-----|----------------|--------------|
| LiteLLM | Proxy | LiteLLM Server | `aitf.model_ops.serving.*` | Model routing, fallbacks, load balancing, budgets |
| LiteLLM | SDK | `litellm` | `gen_ai.*` | Unified LLM API, provider mapping, cost tracking |
| OpenRouter | API | OpenRouter Client | `gen_ai.*` | Model routing, provider preferences, credits |

### Guardrails & Safety

| Vendor | SDK | AITF Namespace | Key Features |
|--------|-----|----------------|--------------|
| Guardrails AI | `guardrails-ai` | `aitf.guardrail.*` | Validators, reask loops, structured output |
| NeMo Guardrails | `nemoguardrails` | `aitf.guardrail.*` | Colang rails, jailbreak detection, fact-checking |
| Lakera | Lakera Guard API | `aitf.security.*` | Prompt injection, PII, content moderation |
| Robust Intelligence | RIME SDK | `aitf.security.*` | AI Firewall, stress testing, data integrity |

### Agent Frameworks

| Vendor | SDK | AITF Namespace | Key Features |
|--------|-----|----------------|--------------|
| LangGraph | `langgraph` | `aitf.agent.*` | Graph execution, nodes, edges, state, checkpoints |
| CrewAI | `crewai` | `aitf.agent.*` | Crew execution, agent delegation, task assignment |

## How Integrations Work

### Monkey-Patching Pattern

Each integration wraps the vendor SDK's key methods with AITF instrumentation:

```python
class VendorInstrumentor:
    def instrument(self):
        """Wrap vendor SDK methods with AITF spans."""
        import vendor_sdk
        self._original_method = vendor_sdk.Client.call
        vendor_sdk.Client.call = self._instrumented_call

    def uninstrument(self):
        """Restore original vendor SDK methods."""
        import vendor_sdk
        vendor_sdk.Client.call = self._original_method

    def _instrumented_call(self, *args, **kwargs):
        with self._tracer.start_as_current_span("gen_ai.inference") as span:
            span.set_attribute("gen_ai.system", "vendor")
            result = self._original_method(*args, **kwargs)
            span.set_attribute("gen_ai.usage.input_tokens", result.usage.input)
            return result
```

### Telemetry Flow

```
Vendor SDK Call
    │
    ▼
┌──────────────────────────────┐
│  AITF Integration Layer      │
│  (monkey-patched SDK method) │
│                              │
│  1. Create OTel span         │
│  2. Set gen_ai.* attributes  │
│  3. Call original SDK method  │
│  4. Set response attributes  │
│  5. Calculate cost            │
│  6. Close span                │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│  AITF Processors             │
│  - SecurityProcessor         │
│  - PIIProcessor              │
│  - ComplianceProcessor       │
│  - CostProcessor             │
│  - MemoryStateProcessor      │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│  OTel Exporters              │
│  - OTLP → Jaeger/Tempo       │
│  - OCSF → SIEM/XDR           │
│  - Console (debug)            │
└──────────────────────────────┘
```

## Writing a New Integration

To add a new vendor integration:

1. Create a directory under the appropriate category:
   ```
   integrations/<category>/<vendor>/
   ```

2. Create `__init__.py` and `instrumentor.py`

3. Implement the instrumentor class:

```python
"""AITF integration for <Vendor> <Product>."""

from __future__ import annotations

from typing import Any
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import GenAIAttributes, CostAttributes

_TRACER_NAME = "aitf.integration.<vendor>.<product>"


class VendorProductInstrumentor:
    """Auto-instruments the <vendor> <product> SDK with AITF telemetry."""

    def __init__(self, tracer_provider: TracerProvider | None = None):
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._original_methods: dict[str, Any] = {}
        self._instrumented = False

    def instrument(self) -> None:
        """Enable instrumentation by monkey-patching the SDK."""
        if self._instrumented:
            return
        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)
        self._patch_methods()
        self._instrumented = True

    def uninstrument(self) -> None:
        """Disable instrumentation by restoring original methods."""
        if not self._instrumented:
            return
        self._unpatch_methods()
        self._tracer = None
        self._instrumented = False

    def _patch_methods(self) -> None:
        # Save originals and replace with instrumented versions
        ...

    def _unpatch_methods(self) -> None:
        # Restore original methods
        ...
```

4. Register the integration in the category `__init__.py`

5. Add tests in `tests/integrations/<vendor>/`

## AITF Attribute Mapping

All integrations map vendor-specific concepts to standard AITF attributes:

| AITF Attribute | Description | Example |
|----------------|-------------|---------|
| `gen_ai.system` | Vendor identifier | `"anthropic"`, `"openai"`, `"cohere"` |
| `gen_ai.request.model` | Model name | `"claude-sonnet-4-20250514"`, `"gpt-4o"` |
| `gen_ai.usage.input_tokens` | Input token count | `150` |
| `gen_ai.usage.output_tokens` | Output token count | `500` |
| `gen_ai.response.id` | Response identifier | `"msg_abc123"` |
| `aitf.cost.total` | Total cost (USD) | `0.0045` |
| `aitf.cost.input` | Input cost (USD) | `0.0015` |
| `aitf.cost.output` | Output cost (USD) | `0.0030` |
| `aitf.agent.name` | Agent name | `"research-assistant"` |
| `aitf.rag.retrieve.source` | Vector DB source | `"pinecone"`, `"weaviate"` |
| `aitf.guardrail.result` | Guard result | `"pass"`, `"fail"`, `"fix"` |
| `aitf.security.risk_score` | Risk assessment | `0.85` |

## License

Apache 2.0 - See [LICENSE](../LICENSE) for details.
