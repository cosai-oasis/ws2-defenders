"""AITF Example: Skills Tracing — Enterprise Customer Support Automation.

Demonstrates AITF skill tracing in a realistic customer support scenario:

    A multilingual customer contacts support about a billing overcharge.
    The system orchestrates multiple skills: sentiment analysis to gauge
    urgency, knowledge-base search for relevant policies, a draft-response
    generator, language translation for the customer's preferred language,
    and ticket creation for audit — each skill traced with discovery,
    invocation, error handling, composition, and approval flows.

All spans are exportable as both OTel traces (OTLP → Jaeger/Tempo) and
OCSF security events (→ SIEM/XDR).  See ``dual_pipeline_tracing.py``
for dual-pipeline setup.

Run:
    pip install opentelemetry-sdk aitf
    python skills_tracing.py
"""

from __future__ import annotations

import json
import time

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

from aitf.instrumentation.skills import SkillInstrumentor
from aitf.instrumentation.llm import LLMInstrumentor
from aitf.exporters.ocsf_exporter import OCSFExporter


# ────────────────────────────────────────────────────────────────────
# 1. Simulated skill implementations
# ────────────────────────────────────────────────────────────────────

def analyze_sentiment(text: str) -> dict:
    """Simulate a sentiment analysis skill."""
    time.sleep(0.03)
    return {
        "sentiment": "negative",
        "confidence": 0.91,
        "emotions": {"frustration": 0.72, "urgency": 0.65, "anger": 0.28},
        "escalation_recommended": True,
    }


def search_knowledge_base(query: str, top_k: int = 5) -> list:
    """Simulate a knowledge base search."""
    time.sleep(0.05)
    return [
        {"doc_id": "POL-201", "title": "Refund Policy for Overcharges",
         "relevance": 0.94,
         "excerpt": "Customers overcharged due to system errors are entitled to a full refund "
                     "within 5 business days.  No restocking fee applies."},
        {"doc_id": "POL-105", "title": "Billing Dispute Resolution Process",
         "relevance": 0.88,
         "excerpt": "Disputes must be acknowledged within 24h.  Agent may issue immediate "
                     "credit for amounts under $500 without manager approval."},
        {"doc_id": "FAQ-042", "title": "How to request a refund",
         "relevance": 0.71,
         "excerpt": "Go to Account > Billing > Request Refund, or contact support."},
    ]


def draft_response(context: dict) -> str:
    """Simulate an AI response drafter."""
    time.sleep(0.04)
    return (
        f"Dear {context['customer_name']},\n\n"
        "Thank you for reaching out.  I can see that you were overcharged "
        f"${context['overcharge_amount']:.2f} on your February invoice due to a system "
        "error.  Per our refund policy (POL-201), you are entitled to a full refund.\n\n"
        f"I have initiated a credit of ${context['overcharge_amount']:.2f} to your account.  "
        "You should see it reflected within 3-5 business days.\n\n"
        "I sincerely apologize for the inconvenience.  Please let me know if there is "
        "anything else I can help with.\n\n"
        "Best regards,\nSupport Team"
    )


def translate_text(text: str, target_lang: str) -> dict:
    """Simulate translation (e.g., to French)."""
    time.sleep(0.04)
    if target_lang == "fr":
        translated = (
            f"Cher(e) client(e),\n\n"
            "Merci de nous avoir contactés.  Je constate que vous avez été surfacturé(e) "
            "de 47,99 $ sur votre facture de février en raison d'une erreur système.  "
            "Conformément à notre politique de remboursement (POL-201), vous avez droit "
            "à un remboursement intégral.\n\n"
            "J'ai initié un crédit de 47,99 $ sur votre compte.  Vous devriez le voir "
            "apparaître sous 3 à 5 jours ouvrables.\n\n"
            "Je vous présente mes sincères excuses pour ce désagrément.\n\n"
            "Cordialement,\nÉquipe Support"
        )
    else:
        translated = text  # Fallback
    return {"source_lang": "en", "target_lang": target_lang, "text": translated,
            "confidence": 0.96}


def create_ticket(data: dict) -> dict:
    """Simulate creating a support ticket in Zendesk/Jira."""
    time.sleep(0.03)
    return {
        "ticket_id": "SUP-20260226-4419",
        "status": "open",
        "priority": data.get("priority", "medium"),
        "assigned_to": "billing-team",
        "customer_id": data["customer_id"],
        "created_at": "2026-02-26T14:15:00Z",
    }


# ────────────────────────────────────────────────────────────────────
# 2. AITF Setup
# ────────────────────────────────────────────────────────────────────

provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
ocsf_exporter = OCSFExporter(
    output_file="/tmp/aitf_skills_events.jsonl",
    compliance_frameworks=["nist_ai_rmf", "eu_ai_act"],
)
provider.add_span_processor(SimpleSpanProcessor(ocsf_exporter))
trace.set_tracer_provider(provider)

skill_instr = SkillInstrumentor(tracer_provider=provider)
skill_instr.instrument()
llm = LLMInstrumentor(tracer_provider=provider)

# ── Incoming customer message ──
CUSTOMER = {
    "id": "cust-8832",
    "name": "Marie Dupont",
    "preferred_lang": "fr",
    "message": (
        "Bonjour, I was charged $47.99 twice on my February invoice. "
        "This is the third time this has happened!  I need this fixed immediately."
    ),
    "overcharge_amount": 47.99,
}


# ────────────────────────────────────────────────────────────────────
# 3. Customer Support Workflow
# ────────────────────────────────────────────────────────────────────

print("=" * 70)
print("  Customer Support Automation — Skills Tracing")
print("=" * 70)
print(f"\n  Customer: {CUSTOMER['name']} ({CUSTOMER['id']})")
print(f"  Language: {CUSTOMER['preferred_lang']}")
print(f"  Message:  {CUSTOMER['message'][:60]}…\n")


# ── Step 1: Discover available skills ─────────────────────────────

print("  Step 1: Discovering available skills from registry")
with skill_instr.trace_discover(
    source="mcp://skills-registry.internal:3001",
    filter_category="customer-support",
) as discovery:
    available_skills = [
        "sentiment-analysis", "kb-search", "response-drafter",
        "translator", "ticket-manager", "escalation-router",
    ]
    discovery.set_skills(available_skills)

print(f"    Found {len(available_skills)} skills: {', '.join(available_skills)}")


# ── Step 2: Analyze sentiment (urgency triage) ────────────────────

print("\n  Step 2: Analyzing customer sentiment")
with skill_instr.trace_invoke(
    skill_name="sentiment-analysis",
    version="3.2.0",
    skill_id="skill-sa-001",
    provider="builtin",
    category="nlp",
    description="Analyze customer message sentiment and urgency",
    skill_input=json.dumps({"text": CUSTOMER["message"]}),
    source="mcp://skills-registry.internal:3001",
    permissions=["text:read"],
) as invocation:
    sentiment = analyze_sentiment(CUSTOMER["message"])
    invocation.set_output(json.dumps(sentiment))

print(f"    Sentiment:  {sentiment['sentiment']} (confidence {sentiment['confidence']:.0%})")
print(f"    Emotions:   frustration={sentiment['emotions']['frustration']:.0%}, "
      f"urgency={sentiment['emotions']['urgency']:.0%}")
print(f"    Escalation: {'recommended' if sentiment['escalation_recommended'] else 'not needed'}")


# ── Step 3: Search knowledge base ─────────────────────────────────

print("\n  Step 3: Searching knowledge base for refund policies")
with skill_instr.trace_invoke(
    skill_name="kb-search",
    version="2.5.0",
    skill_id="skill-kb-001",
    provider="builtin",
    category="search",
    description="Search internal knowledge base for relevant policies and FAQs",
    skill_input=json.dumps({
        "query": "billing overcharge refund policy",
        "top_k": 5,
        "filters": {"category": ["billing", "refunds"]},
    }),
    source="mcp://skills-registry.internal:3001",
    permissions=["kb:read"],
) as invocation:
    kb_results = search_knowledge_base("billing overcharge refund policy")
    invocation.set_output(json.dumps(kb_results))

for r in kb_results:
    print(f"    [{r['doc_id']}] {r['title']} (relevance: {r['relevance']:.0%})")


# ── Step 4: Draft response + translate (sequential composition) ───

print(f"\n  Step 4: Draft response + translate to {CUSTOMER['preferred_lang']} (sequential workflow)")
with skill_instr.trace_compose(
    workflow_name="draft-and-translate",
    skills=["response-drafter", "translator"],
    pattern="sequential",
) as composition:

    # 4a: Draft the response in English
    with skill_instr.trace_invoke(
        skill_name="response-drafter",
        version="1.4.0",
        provider="builtin",
        category="generation",
        description="Draft a customer response based on sentiment and KB results",
        skill_input=json.dumps({
            "customer_name": CUSTOMER["name"],
            "overcharge_amount": CUSTOMER["overcharge_amount"],
            "sentiment": sentiment,
            "kb_results": [r["doc_id"] for r in kb_results[:2]],
        }),
        permissions=["llm:invoke"],
    ) as inv:
        # The drafter internally calls the LLM
        with llm.trace_inference(
            model="gpt-4o-mini",
            system="openai",
            operation="chat",
            temperature=0.3,
            max_tokens=512,
        ) as llm_span:
            llm_span.set_prompt(
                f"Draft a support response for {CUSTOMER['name']} about a "
                f"${CUSTOMER['overcharge_amount']} overcharge. Cite policies POL-201 and POL-105."
            )
            response_en = draft_response({
                "customer_name": CUSTOMER["name"],
                "overcharge_amount": CUSTOMER["overcharge_amount"],
            })
            llm_span.set_completion(response_en)
            llm_span.set_usage(input_tokens=95, output_tokens=140)

        inv.set_output(response_en)
    composition.mark_completed()

    print(f"    Drafted response ({len(response_en)} chars, EN)")

    # 4b: Translate to customer's preferred language
    with skill_instr.trace_invoke(
        skill_name="translator",
        version="4.1.0",
        provider="builtin",
        category="nlp",
        description="Translate text between languages",
        skill_input=json.dumps({
            "text": response_en,
            "target_lang": CUSTOMER["preferred_lang"],
        }),
        permissions=["llm:invoke"],
    ) as inv:
        translation = translate_text(response_en, CUSTOMER["preferred_lang"])
        inv.set_output(json.dumps(translation))
    composition.mark_completed()

    print(f"    Translated to {translation['target_lang']} "
          f"(confidence: {translation['confidence']:.0%})")

print(f"    Workflow completed: {composition.completed_count}/2 skills")


# ── Step 5: Create support ticket ─────────────────────────────────

print(f"\n  Step 5: Creating support ticket")
with skill_instr.trace_invoke(
    skill_name="ticket-manager",
    version="2.0.0",
    skill_id="skill-tm-001",
    provider="custom",
    category="workflow",
    description="Create and manage support tickets in Zendesk",
    skill_input=json.dumps({
        "action": "create",
        "customer_id": CUSTOMER["id"],
        "subject": "Billing overcharge — double charge $47.99",
        "priority": "high",
        "tags": ["billing", "overcharge", "refund", "repeat-issue"],
        "sentiment": sentiment["sentiment"],
    }),
    permissions=["zendesk:write"],
) as invocation:
    ticket = create_ticket({"customer_id": CUSTOMER["id"], "priority": "high"})
    invocation.set_output(json.dumps(ticket))

print(f"    Ticket: {ticket['ticket_id']} (priority: {ticket['priority']})")
print(f"    Assigned to: {ticket['assigned_to']}")


# ── Step 6: Parallel skill composition — background tasks ─────────

print(f"\n  Step 6: Background tasks (parallel workflow)")
with skill_instr.trace_compose(
    workflow_name="post-response-tasks",
    skills=["escalation-router", "ticket-manager", "sentiment-analysis"],
    pattern="parallel",
) as composition:

    # 6a: Route escalation notification
    with skill_instr.trace_invoke(
        skill_name="escalation-router",
        version="1.1.0",
        provider="builtin",
        category="workflow",
        description="Route high-priority cases to the right team",
        skill_input=json.dumps({
            "ticket_id": ticket["ticket_id"],
            "priority": "high",
            "reason": "repeat_issue + high_urgency_sentiment",
        }),
        permissions=["notifications:send"],
    ) as inv:
        inv.set_output(json.dumps({
            "routed_to": "billing-escalations",
            "notified": ["billing-lead@acme.corp", "cs-manager@acme.corp"],
        }))
    composition.mark_completed()

    # 6b: Update ticket with AI summary
    with skill_instr.trace_invoke(
        skill_name="ticket-manager",
        version="2.0.0",
        provider="custom",
        category="workflow",
        skill_input=json.dumps({
            "action": "update",
            "ticket_id": ticket["ticket_id"],
            "internal_note": "AI summary: repeat billing overcharge, refund initiated, "
                             "customer notified in French.",
        }),
        permissions=["zendesk:write"],
    ) as inv:
        inv.set_output(json.dumps({"updated": True}))
    composition.mark_completed()

    # 6c: Log interaction sentiment for analytics
    with skill_instr.trace_invoke(
        skill_name="sentiment-analysis",
        version="3.2.0",
        provider="builtin",
        category="nlp",
        skill_input=json.dumps({
            "text": response_en,
            "context": "agent_response",
        }),
        permissions=["text:read"],
    ) as inv:
        inv.set_output(json.dumps({"sentiment": "empathetic", "confidence": 0.88}))
    composition.mark_completed()

print(f"    Parallel workflow completed: {composition.completed_count}/3 skills")


# ── Step 7: Skill invocation with error and retry ─────────────────

print(f"\n{'=' * 70}")
print("  Example 2: Skill Error and Retry")
print("=" * 70)

print("\n  Simulating a transient database timeout on ticket update …")
with skill_instr.trace_invoke(
    skill_name="ticket-manager",
    version="2.0.0",
    provider="custom",
    category="workflow",
    description="Create and manage support tickets in Zendesk",
    skill_input=json.dumps({
        "action": "update",
        "ticket_id": ticket["ticket_id"],
        "status": "pending_refund",
    }),
    permissions=["zendesk:write"],
) as invocation:
    invocation.set_retry_count(1)
    invocation.set_error(
        error_type="ConnectionTimeout",
        message="Zendesk API timed out after 30s (first attempt)",
        retryable=True,
    )
    time.sleep(0.05)
    invocation.set_output(json.dumps({"updated": True, "status": "pending_refund"}))
    invocation.set_status("success")

print("  Attempt 1: ConnectionTimeout (retryable)")
print("  Attempt 2: Success — ticket updated to 'pending_refund'")


# ────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Summary")
print("=" * 70)
print(f"  Customer:            {CUSTOMER['name']} ({CUSTOMER['id']})")
print(f"  Issue:               Double charge of ${CUSTOMER['overcharge_amount']}")
print(f"  Skills used:         6 (sentiment, KB search, drafter, translator, ticket, escalation)")
print(f"  Skill invocations:   10")
print(f"  Compositions:        2 (1 sequential, 1 parallel)")
print(f"  Errors/retries:      1 (ConnectionTimeout → retry → success)")
print(f"  Ticket created:      {ticket['ticket_id']} (high priority)")
print(f"  Response language:   {CUSTOMER['preferred_lang']}")
print(f"  OCSF events:         {ocsf_exporter.event_count}")
print(f"  Events at:           /tmp/aitf_skills_events.jsonl")
print(f"\n  Every skill invocation is traced with input/output, permissions,")
print(f"  retry status, and composition context — full audit trail.")

provider.shutdown()
