"""AITF Example: RAG Pipeline Tracing — IT Knowledge-Base Q&A.

Demonstrates how AITF instruments a realistic RAG (Retrieval-Augmented
Generation) pipeline.  The simulated code mirrors what you would build
with LangChain, LlamaIndex, or a custom RAG stack:

    1. Chunk & embed documents   → text-embedding-3-small
    2. Vector search (Pinecone)  → top-k retrieval
    3. Rerank results            → cross-encoder
    4. Build prompt with context → assembled prompt
    5. Generate answer           → gpt-4o
    6. Evaluate quality          → faithfulness, relevance, groundedness

Every step produces OTel spans that can be exported as:
  - **OTLP** → Jaeger / Grafana Tempo / Datadog / Elastic Security (observability & security analytics)
  - **OCSF** → OCSF-native SIEM / XDR (7001 / 7004 events)
  - **Both** → via ``DualPipelineProvider`` (recommended)

See ``dual_pipeline_tracing.py`` for the full dual-pipeline setup.
This example uses OCSF-only for simplicity.

Run:
    pip install opentelemetry-sdk aitf
    python rag_pipeline_tracing.py
"""

from __future__ import annotations

import hashlib
import random
import time
from dataclasses import dataclass, field

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

from aitf.instrumentation.rag import RAGInstrumentor
from aitf.instrumentation.llm import LLMInstrumentor
from aitf.exporters.ocsf_exporter import OCSFExporter


# ────────────────────────────────────────────────────────────────────
# 1. Simulated knowledge-base documents
# ────────────────────────────────────────────────────────────────────

@dataclass
class Document:
    """A chunk from the knowledge base."""
    doc_id: str
    title: str
    content: str
    source: str
    embedding: list[float] = field(default_factory=list)
    score: float = 0.0


# Pre-loaded KB articles (in production these come from a document store)
KB_ARTICLES = [
    Document(
        doc_id="KB-001",
        title="VPN Setup Guide",
        content=(
            "To connect to the corporate VPN: 1) Open GlobalProtect, "
            "2) Enter gateway vpn.acme.corp, 3) Sign in with your SSO "
            "credentials, 4) Click Connect.  If MFA is required, approve "
            "the push notification on your authenticator app."
        ),
        source="it-wiki/vpn-setup",
    ),
    Document(
        doc_id="KB-002",
        title="VPN Troubleshooting",
        content=(
            "Common VPN issues: 'Gateway not found' — check DNS settings "
            "or try the IP fallback 10.0.1.5.  'Authentication failed' — "
            "reset your password at https://sso.acme.corp/reset.  'Slow "
            "connection' — switch to the split-tunnel profile in Settings."
        ),
        source="it-wiki/vpn-troubleshoot",
    ),
    Document(
        doc_id="KB-003",
        title="Password Reset Procedure",
        content=(
            "To reset your password: visit https://sso.acme.corp/reset, "
            "verify your identity with MFA, choose a new password (min 12 "
            "chars, 1 uppercase, 1 number, 1 special).  Passwords expire "
            "every 90 days."
        ),
        source="it-wiki/password-reset",
    ),
    Document(
        doc_id="KB-004",
        title="New Laptop Setup",
        content=(
            "When you receive your new laptop: 1) Power on and connect to "
            "Wi-Fi, 2) Sign in with your Acme SSO, 3) Run the IT bootstrap "
            "script from Software Center, 4) Install GlobalProtect VPN, "
            "5) Verify Endpoint Protection is active in System Tray."
        ),
        source="it-wiki/laptop-setup",
    ),
    Document(
        doc_id="KB-005",
        title="Multi-Factor Authentication (MFA)",
        content=(
            "All Acme employees must enroll in MFA.  Supported methods: "
            "Authenticator app (recommended), hardware security key (FIDO2), "
            "or SMS (backup only).  Enroll at https://sso.acme.corp/mfa.  "
            "Lost your device?  Contact IT Help Desk for a temporary bypass."
        ),
        source="it-wiki/mfa-enrollment",
    ),
]


# ────────────────────────────────────────────────────────────────────
# 2. Simulated RAG components
# ────────────────────────────────────────────────────────────────────

def embed_text(text: str) -> list[float]:
    """Simulate an embedding call — returns a deterministic 256-d vector."""
    seed = int(hashlib.md5(text.encode()).hexdigest()[:8], 16)
    rng = random.Random(seed)
    return [rng.gauss(0, 1) for _ in range(256)]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = sum(x * x for x in a) ** 0.5
    mag_b = sum(x * x for x in b) ** 0.5
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def vector_search(query_embedding: list[float], top_k: int = 5) -> list[Document]:
    """Search the KB by cosine similarity — mimics a Pinecone/Chroma query."""
    scored = []
    for doc in KB_ARTICLES:
        doc.embedding = embed_text(doc.content)
        doc.score = cosine_similarity(query_embedding, doc.embedding)
        scored.append(doc)
    scored.sort(key=lambda d: d.score, reverse=True)
    return scored[:top_k]


def rerank(docs: list[Document], query: str, top_n: int = 3) -> list[Document]:
    """Simulate a cross-encoder rerank pass (adjusts scores slightly)."""
    for doc in docs:
        # Boost docs whose title keywords overlap with the query
        query_words = set(query.lower().split())
        title_words = set(doc.title.lower().split())
        overlap = len(query_words & title_words)
        doc.score = min(1.0, doc.score + overlap * 0.08)
    docs.sort(key=lambda d: d.score, reverse=True)
    return docs[:top_n]


def build_prompt(query: str, context_docs: list[Document]) -> str:
    """Assemble the final prompt with retrieved context."""
    context_block = "\n\n".join(
        f"[{doc.doc_id}] {doc.title}\n{doc.content}" for doc in context_docs
    )
    return (
        "You are an IT help-desk assistant.  Answer the user's question "
        "using ONLY the context below.  If the context doesn't contain the "
        "answer, say so.\n\n"
        f"## Context\n{context_block}\n\n"
        f"## Question\n{query}\n\n"
        "## Answer"
    )


def generate_answer(prompt: str) -> str:
    """Simulate an LLM generation step."""
    # In production: openai.ChatCompletion.create(...)
    time.sleep(random.uniform(0.1, 0.3))
    return (
        "To connect to the corporate VPN, open GlobalProtect and enter "
        "the gateway vpn.acme.corp.  Sign in with your SSO credentials "
        "and approve the MFA push notification.  If you see 'Gateway not "
        "found', try the fallback IP 10.0.1.5 or check your DNS settings. "
        "For slow connections, enable the split-tunnel profile under "
        "Settings. [Sources: KB-001, KB-002]"
    )


# ────────────────────────────────────────────────────────────────────
# 3. AITF Setup
# ────────────────────────────────────────────────────────────────────

provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
ocsf_exporter = OCSFExporter(output_file="/tmp/aitf_rag_events.jsonl")
provider.add_span_processor(SimpleSpanProcessor(ocsf_exporter))
trace.set_tracer_provider(provider)

rag = RAGInstrumentor(tracer_provider=provider)
llm = LLMInstrumentor(tracer_provider=provider)


# ────────────────────────────────────────────────────────────────────
# 4. Run the RAG pipeline — every step is AITF-traced
# ────────────────────────────────────────────────────────────────────

query = "How do I connect to the corporate VPN and what should I do if it's slow?"

print("=" * 70)
print("  IT Help-Desk RAG Pipeline — with AITF Tracing")
print("=" * 70)
print(f"\n  User question: \"{query}\"\n")

with rag.trace_pipeline(
    pipeline_name="it-helpdesk-qa",
    query=query,
) as pipeline:

    # ── Step 1: Embed the query ──────────────────────────────────
    print("  Step 1: Embedding query …")
    with llm.trace_inference(
        model="text-embedding-3-small",
        system="openai",
        operation="embeddings",
    ) as embed_span:
        query_embedding = embed_text(query)
        embed_span.set_prompt(query)
        embed_span.set_usage(input_tokens=len(query.split()) * 2)
        embed_span.set_cost(input_cost=0.0000002)
    print(f"           Vector dimension: {len(query_embedding)}")

    # ── Step 2: Vector search ────────────────────────────────────
    print("  Step 2: Searching Pinecone …")
    with pipeline.retrieve(
        database="pinecone",
        top_k=5,
    ) as retrieval:
        retrieved_docs = vector_search(query_embedding, top_k=5)
        retrieval.set_results(
            count=len(retrieved_docs),
            min_score=min(d.score for d in retrieved_docs),
            max_score=max(d.score for d in retrieved_docs),
        )
    for doc in retrieved_docs:
        print(f"           [{doc.doc_id}] {doc.title}  (score={doc.score:.3f})")

    # ── Step 3: Rerank ───────────────────────────────────────────
    print("  Step 3: Reranking with cross-encoder …")
    with pipeline.rerank(model="cross-encoder/ms-marco-MiniLM-L-12-v2") as rerank_span:
        top_docs = rerank(retrieved_docs, query, top_n=3)
        rerank_span.set_results(
            input_count=len(retrieved_docs),
            output_count=len(top_docs),
        )
    for doc in top_docs:
        print(f"           [{doc.doc_id}] {doc.title}  (reranked={doc.score:.3f})")

    # ── Step 4: Build augmented prompt ───────────────────────────
    print("  Step 4: Assembling prompt with context …")
    augmented_prompt = build_prompt(query, top_docs)
    prompt_tokens = len(augmented_prompt.split()) * 2
    print(f"           Prompt length: {len(augmented_prompt)} chars, ~{prompt_tokens} tokens")

    # ── Step 5: LLM generation ───────────────────────────────────
    print("  Step 5: Generating answer with gpt-4o …")
    with llm.trace_inference(
        model="gpt-4o",
        system="openai",
        operation="chat",
        temperature=0.2,
        max_tokens=512,
    ) as gen_span:
        gen_span.set_prompt(augmented_prompt)
        answer = generate_answer(augmented_prompt)
        gen_span.set_completion(answer)
        output_tokens = len(answer.split()) * 2
        gen_span.set_response(
            response_id=f"chatcmpl-{random.randint(100000, 999999)}",
            model="gpt-4o",
            finish_reasons=["stop"],
        )
        gen_span.set_usage(input_tokens=prompt_tokens, output_tokens=output_tokens)
        gen_span.set_cost(
            input_cost=prompt_tokens * 2.50 / 1_000_000,
            output_cost=output_tokens * 10.00 / 1_000_000,
        )
        gen_span.set_latency(
            total_ms=random.uniform(600, 1200),
            tokens_per_second=random.uniform(80, 200),
        )

    # ── Step 6: Quality evaluation ───────────────────────────────
    print("  Step 6: Evaluating answer quality …")
    pipeline.set_quality(
        context_relevance=0.91,
        answer_relevance=0.88,
        faithfulness=0.95,
        groundedness=0.93,
    )


# ────────────────────────────────────────────────────────────────────
# 5. Display results
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Answer")
print("=" * 70)
print(f"\n  {answer}\n")

print("=" * 70)
print("  Pipeline Summary")
print("=" * 70)
print(f"  Documents in KB:     {len(KB_ARTICLES)}")
print(f"  Retrieved:           {len(retrieved_docs)}")
print(f"  After rerank:        {len(top_docs)}")
print(f"  Quality scores:      context=0.91, answer=0.88, faith=0.95, ground=0.93")
print(f"  OCSF events:         {ocsf_exporter.event_count}")
print(f"  Events written to:   /tmp/aitf_rag_events.jsonl")
print(f"\n  AITF captured: embedding call, vector search, rerank, generation,")
print(f"  and quality metrics — all as auditable OCSF 7001/7004 events.")
