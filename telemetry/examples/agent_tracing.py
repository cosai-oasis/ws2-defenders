"""AITF Example: Agent Tracing — Travel Booking Assistant.

Demonstrates how AITF instruments a realistic multi-step AI agent that:
  1. Thinks (plans an approach)
  2. Searches the web for flights
  3. Retrieves the user's travel preferences from memory
  4. Compares options and reasons about the best choice
  5. Books the flight via a tool call
  6. Sends a confirmation

Then shows a **multi-agent team** where a manager delegates to a
researcher and a writer.

All spans are exported as **both** OTel traces (for observability and
security analytics) and OCSF events (for OCSF-native SIEMs).  See ``dual_pipeline_tracing.py`` for the full
dual-pipeline setup.  This example uses OCSF-only for simplicity.

Run:
    pip install opentelemetry-sdk aitf
    python agent_tracing.py
"""

from __future__ import annotations

import json
import random
import time

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

from aitf.instrumentation.agent import AgentInstrumentor
from aitf.instrumentation.llm import LLMInstrumentor
from aitf.instrumentation.skills import SkillInstrumentor
from aitf.exporters.ocsf_exporter import OCSFExporter


# ────────────────────────────────────────────────────────────────────
# 1. Simulated tools & LLM (stand-ins for real APIs)
# ────────────────────────────────────────────────────────────────────

def search_flights(origin: str, destination: str, date: str) -> list[dict]:
    """Simulate a flight search API call."""
    time.sleep(0.1)
    return [
        {"airline": "United", "flight": "UA-412", "depart": "08:15",
         "arrive": "11:30", "price": 342, "stops": 0},
        {"airline": "Delta", "flight": "DL-789", "depart": "10:45",
         "arrive": "14:20", "price": 298, "stops": 1},
        {"airline": "JetBlue", "flight": "B6-1024", "depart": "14:00",
         "arrive": "17:15", "price": 275, "stops": 0},
    ]


def get_user_preferences(user_id: str) -> dict:
    """Simulate retrieving user travel preferences from a database."""
    time.sleep(0.05)
    return {
        "preferred_airlines": ["United", "JetBlue"],
        "seat_preference": "window",
        "max_budget": 400,
        "prefer_nonstop": True,
        "loyalty_program": "United MileagePlus",
    }


def book_flight(flight_id: str, passenger: str, seat_pref: str) -> dict:
    """Simulate booking a flight."""
    time.sleep(0.1)
    return {
        "confirmation": f"CONF-{random.randint(100000, 999999)}",
        "flight": flight_id,
        "passenger": passenger,
        "seat": f"12{random.choice('ABCDEF')}",
        "status": "confirmed",
    }


def llm_think(prompt: str) -> str:
    """Simulate an LLM reasoning step."""
    time.sleep(0.1)
    return prompt  # Content is predetermined for the demo


# ────────────────────────────────────────────────────────────────────
# 2. AITF Setup
# ────────────────────────────────────────────────────────────────────

provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
ocsf_exporter = OCSFExporter(
    output_file="/tmp/aitf_agent_events.jsonl",
    compliance_frameworks=["nist_ai_rmf", "eu_ai_act"],
)
provider.add_span_processor(SimpleSpanProcessor(ocsf_exporter))
trace.set_tracer_provider(provider)

agent_instr = AgentInstrumentor(tracer_provider=provider)
llm_instr = LLMInstrumentor(tracer_provider=provider)
skill_instr = SkillInstrumentor(tracer_provider=provider)


# ────────────────────────────────────────────────────────────────────
# 3. Single Agent Session — Travel Booking
# ────────────────────────────────────────────────────────────────────

print("=" * 70)
print("  Example 1: Travel Booking Agent (Single Agent)")
print("=" * 70)

user_request = "Book me a nonstop flight from SFO to JFK on March 15."

with agent_instr.trace_session(
    agent_name="travel-booking-agent",
    agent_type="autonomous",
    framework="custom",
    description="Books flights based on user preferences and constraints",
) as session:

    # ── Step 1: Planning ─────────────────────────────────────────
    print("\n  Step 1: Planning")
    with session.step("planning") as step:
        thought = (
            "The user wants a nonstop SFO→JFK flight on March 15.  "
            "I should: 1) fetch their preferences, 2) search flights, "
            "3) filter to nonstop + preferred airlines, 4) book the best."
        )
        step.set_thought(thought)
        step.set_action("plan_execution")

        with llm_instr.trace_inference(
            model="gpt-4o", system="openai", operation="chat"
        ) as llm_span:
            llm_think(thought)
            llm_span.set_prompt(f"User: {user_request}\nPlan the steps.")
            llm_span.set_completion(thought)
            llm_span.set_usage(input_tokens=45, output_tokens=60)

    print(f"    Thought: {thought[:80]}…")

    # ── Step 2: Retrieve user preferences from memory ────────────
    print("\n  Step 2: Memory Lookup — User Preferences")
    with session.memory_access(
        operation="retrieve",
        store="long_term",
        key="user_prefs:alice",
    ) as mem_span:
        prefs = get_user_preferences("alice")
        mem_span.set_attribute("memory.provenance", "user_profile_db")

    print(f"    Preferred airlines: {prefs['preferred_airlines']}")
    print(f"    Budget: ${prefs['max_budget']}, Nonstop: {prefs['prefer_nonstop']}")

    # ── Step 3: Search flights (tool call) ───────────────────────
    print("\n  Step 3: Tool Call — Flight Search")
    with session.step("tool_use") as step:
        step.set_action("search_flights(SFO, JFK, 2026-03-15)")

        with skill_instr.trace_invoke(
            skill_name="flight-search",
            version="3.0.0",
            category="travel",
            provider="amadeus",
            skill_input=json.dumps({
                "origin": "SFO", "destination": "JFK", "date": "2026-03-15"
            }),
        ) as skill:
            flights = search_flights("SFO", "JFK", "2026-03-15")
            skill.set_output(json.dumps(flights))

        step.set_observation(f"Found {len(flights)} flights")

    for f in flights:
        tag = " ✓ nonstop" if f["stops"] == 0 else ""
        print(f"    {f['airline']} {f['flight']}: ${f['price']} "
              f"({f['depart']}→{f['arrive']}){tag}")

    # ── Step 4: Reasoning — pick the best option ─────────────────
    print("\n  Step 4: Reasoning — Selecting Best Flight")
    with session.step("reasoning") as step:
        # Filter: nonstop + preferred airline + under budget
        candidates = [
            f for f in flights
            if f["stops"] == 0
            and f["airline"] in prefs["preferred_airlines"]
            and f["price"] <= prefs["max_budget"]
        ]
        best = min(candidates, key=lambda f: f["price"]) if candidates else flights[0]

        reasoning = (
            f"Filtered to {len(candidates)} nonstop flights on preferred airlines.  "
            f"Best option: {best['airline']} {best['flight']} at ${best['price']} "
            f"(within ${prefs['max_budget']} budget)."
        )
        step.set_thought(reasoning)

        with llm_instr.trace_inference(
            model="gpt-4o", system="openai", operation="chat"
        ) as llm_span:
            llm_think(reasoning)
            llm_span.set_prompt(f"Flights: {json.dumps(flights)}\nPrefs: {json.dumps(prefs)}\nPick the best.")
            llm_span.set_completion(reasoning)
            llm_span.set_usage(input_tokens=250, output_tokens=80)

    print(f"    {reasoning}")

    # ── Step 5: Book the flight (tool call) ──────────────────────
    print("\n  Step 5: Tool Call — Book Flight")
    with session.step("tool_use") as step:
        step.set_action(f"book_flight({best['flight']}, alice, window)")

        with skill_instr.trace_invoke(
            skill_name="flight-booking",
            version="2.1.0",
            category="travel",
            provider="amadeus",
            skill_input=json.dumps({
                "flight": best["flight"],
                "passenger": "alice",
                "seat_pref": prefs["seat_preference"],
            }),
        ) as skill:
            booking = book_flight(best["flight"], "alice", prefs["seat_preference"])
            skill.set_output(json.dumps(booking))

        step.set_observation(f"Booked!  Confirmation: {booking['confirmation']}")

    print(f"    Confirmation: {booking['confirmation']}")
    print(f"    Seat: {booking['seat']}")

    # ── Step 6: Store in memory + respond ────────────────────────
    print("\n  Step 6: Memory Store + Final Response")
    with session.memory_access(
        operation="store",
        store="short_term",
        key=f"booking:{booking['confirmation']}",
    ) as mem_span:
        mem_span.set_attribute("memory.provenance", "tool_result")

    with session.step("response") as step:
        reply = (
            f"All set!  I booked {best['airline']} {best['flight']} "
            f"(SFO→JFK on March 15, departing {best['depart']}) for ${best['price']}.  "
            f"Confirmation: {booking['confirmation']}, Seat: {booking['seat']}."
        )
        step.set_observation(reply)
        step.set_status("success")

    print(f"    Agent: {reply}")


# ────────────────────────────────────────────────────────────────────
# 4. Multi-Agent Team — Research & Writing Crew
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Example 2: Multi-Agent Team (CrewAI-style)")
print("=" * 70)
print("  Task: \"Write a 3-paragraph brief on AI supply-chain risks.\"")

with agent_instr.trace_team(
    team_name="research-writing-crew",
    topology="hierarchical",
    members=["manager", "researcher", "writer"],
    coordinator="manager",
) as team_span:

    # ── Manager delegates research ───────────────────────────────
    with agent_instr.trace_session(
        agent_name="manager",
        agent_type="autonomous",
        framework="crewai",
        team_name="research-writing-crew",
    ) as manager:

        with manager.step("planning") as step:
            step.set_thought(
                "This requires research first, then writing.  "
                "I'll delegate research to the researcher agent."
            )
        print(f"\n  Manager: Delegating research task …")

        with manager.delegate(
            target_agent="researcher",
            reason="Needs domain expertise on AI supply-chain security",
            strategy="capability",
            task="Research AI supply-chain risks: model poisoning, data provenance, dependency attacks",
        ):
            # ── Researcher agent works ───────────────────────────
            with agent_instr.trace_session(
                agent_name="researcher",
                framework="crewai",
                team_name="research-writing-crew",
            ) as researcher:
                with researcher.step("tool_use") as step:
                    step.set_action("web_search: AI supply chain security risks 2026")

                    with skill_instr.trace_invoke(
                        skill_name="web-search",
                        version="2.1.0",
                        category="search",
                        provider="builtin",
                        skill_input='{"query": "AI supply chain security risks 2026"}',
                    ) as skill:
                        time.sleep(0.08)
                        results = [
                            {"title": "NIST AI 100-2: Supply Chain Risks", "url": "https://nist.gov/ai"},
                            {"title": "MITRE ATLAS: ML Supply Chain Compromise", "url": "https://atlas.mitre.org"},
                            {"title": "OWASP LLM03: Training Data Poisoning", "url": "https://owasp.org/llm"},
                        ]
                        skill.set_output(json.dumps(results))
                    step.set_observation(f"Found {len(results)} authoritative sources.")

                print(f"  Researcher: Found {len(results)} sources")
                for r in results:
                    print(f"    - {r['title']}")

                with researcher.step("reasoning") as step:
                    step.set_thought(
                        "Key risks: 1) model poisoning via tainted training data, "
                        "2) dependency attacks on ML libraries, 3) lack of provenance "
                        "tracking for third-party models."
                    )

                    with llm_instr.trace_inference(
                        model="gpt-4o", system="openai", operation="chat"
                    ) as llm_span:
                        llm_span.set_usage(input_tokens=400, output_tokens=150)

        # ── Manager delegates writing ────────────────────────────
        print(f"\n  Manager: Delegating writing task …")
        with manager.delegate(
            target_agent="writer",
            reason="Needs professional writing skills",
            strategy="capability",
            task="Write a 3-paragraph executive brief on AI supply-chain risks",
        ):
            with agent_instr.trace_session(
                agent_name="writer",
                framework="crewai",
                team_name="research-writing-crew",
            ) as writer:
                with writer.step("response") as step:
                    with llm_instr.trace_inference(
                        model="gpt-4o", system="openai", operation="chat"
                    ) as llm_span:
                        time.sleep(0.15)
                        brief = (
                            "AI supply chains present three critical risks: model poisoning "
                            "through tainted training data, dependency attacks on ML libraries "
                            "like PyTorch and TensorFlow, and insufficient provenance tracking "
                            "for third-party model weights.  Organizations should adopt AI-BOM "
                            "(Bill of Materials) practices and implement SLSA-style attestation "
                            "for model artifacts."
                        )
                        llm_span.set_prompt("Write a brief on AI supply-chain risks using the research findings.")
                        llm_span.set_completion(brief)
                        llm_span.set_usage(input_tokens=600, output_tokens=350)

                    step.set_observation("Executive brief written.")

                print(f"  Writer: Brief complete ({len(brief.split())} words)")

    print(f"\n  Final output:\n    \"{brief[:120]}…\"")


# ────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Summary")
print("=" * 70)
print(f"  Agent sessions:       2 (travel-booking + research-writing-crew)")
print(f"  Total agent steps:    11")
print(f"  Tool invocations:     4 (flight-search, flight-booking, web-search x1)")
print(f"  LLM calls:            5")
print(f"  Memory operations:    2 (1 retrieve, 1 store)")
print(f"  Delegations:          2 (manager→researcher, manager→writer)")
print(f"  OCSF events:          {ocsf_exporter.event_count}")
print(f"  Events at:            /tmp/aitf_agent_events.jsonl")
