"""AITF Example: Agentic Log Tracing — DevOps Incident Response Agent.

Demonstrates structured agentic log entries (Table 10.1 minimal fields)
in the context of a realistic DevOps incident-response scenario:

    A production alert fires for high CPU on the payments service.
    An autonomous agent investigates, identifies the root cause (a
    runaway database query), applies a fix, and verifies recovery —
    each action logged with goal, tool, outcome, confidence, anomaly
    score, and policy evaluation for full security audit.

All spans are exportable as both OTel traces (OTLP → Jaeger/Tempo) and
OCSF security events (→ SIEM/XDR).  See ``dual_pipeline_tracing.py``
for dual-pipeline setup.

Run:
    pip install opentelemetry-sdk aitf
    python agentic_log_tracing.py
"""

from __future__ import annotations

import json
import random
import time

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

from aitf.instrumentation.agentic_log import AgenticLogInstrumentor
from aitf.instrumentation.agent import AgentInstrumentor
from aitf.exporters.ocsf_exporter import OCSFExporter


# ────────────────────────────────────────────────────────────────────
# 1. Simulated DevOps tools
# ────────────────────────────────────────────────────────────────────

def check_service_health(service: str) -> dict:
    """Simulate a health check against Kubernetes."""
    time.sleep(0.05)
    return {
        "service": service,
        "status": "degraded",
        "cpu_pct": 94.2,
        "memory_pct": 67.1,
        "error_rate": 12.4,
        "p99_latency_ms": 3400,
        "replicas": {"desired": 3, "ready": 2},
    }


def query_logs(service: str, window: str = "15m") -> list[dict]:
    """Simulate a log query (Datadog / Splunk style)."""
    time.sleep(0.05)
    return [
        {"ts": "2026-02-26T14:32:01Z", "level": "ERROR",
         "msg": "QueryTimeout: SELECT * FROM transactions WHERE status='pending' exceeded 30s"},
        {"ts": "2026-02-26T14:32:15Z", "level": "ERROR",
         "msg": "ConnectionPool exhausted: 50/50 connections in use"},
        {"ts": "2026-02-26T14:32:30Z", "level": "WARN",
         "msg": "CPU throttling detected on pod payments-7b4f9c-xk2p"},
    ]


def run_db_explain(query: str) -> dict:
    """Simulate running EXPLAIN on a slow query."""
    time.sleep(0.05)
    return {
        "query": query,
        "plan": "Seq Scan on transactions (rows=2.4M, cost=184200)",
        "suggestion": "Add index on (status, created_at) to avoid full table scan",
        "estimated_improvement": "~98% reduction in query time",
    }


def apply_hotfix(action: str, params: dict) -> dict:
    """Simulate applying an operational hotfix."""
    time.sleep(0.1)
    return {"action": action, "params": params, "result": "applied", "rollback_id": "rb-20260226-001"}


def verify_recovery(service: str) -> dict:
    """Simulate a post-fix health check."""
    time.sleep(0.05)
    return {
        "service": service,
        "status": "healthy",
        "cpu_pct": 28.5,
        "error_rate": 0.1,
        "p99_latency_ms": 180,
        "replicas": {"desired": 3, "ready": 3},
    }


# ────────────────────────────────────────────────────────────────────
# 2. AITF Setup
# ────────────────────────────────────────────────────────────────────

provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
ocsf_exporter = OCSFExporter(
    output_file="/tmp/aitf_agentic_log_events.jsonl",
    compliance_frameworks=["nist_ai_rmf", "eu_ai_act"],
)
provider.add_span_processor(SimpleSpanProcessor(ocsf_exporter))
trace.set_tracer_provider(provider)

agentic_log = AgenticLogInstrumentor(tracer_provider=provider)
agent_instr = AgentInstrumentor(tracer_provider=provider)

AGENT_ID = "agent-devops-responder-prod-001"
SESSION_ID = f"sess-{random.randint(100000, 999999)}"
GOAL_ID = "goal-resolve-payments-cpu-alert"


# ────────────────────────────────────────────────────────────────────
# 3. Incident Response Scenario
# ────────────────────────────────────────────────────────────────────

print("=" * 70)
print("  DevOps Incident Response Agent — with Agentic Log Tracing")
print("=" * 70)
print(f"\n  ALERT: payments-service CPU at 94% — error rate 12.4%")
print(f"  Agent: {AGENT_ID}")
print(f"  Session: {SESSION_ID}")
print(f"  Goal: {GOAL_ID}\n")

with agent_instr.trace_session(
    agent_name="devops-responder",
    agent_id=AGENT_ID,
    framework="custom",
    description="Autonomous incident response for production alerts",
) as session:

    # ── Action 1: Check service health ───────────────────────────
    print("  Action 1: Checking service health …")
    with session.step("tool_use") as step:
        step.set_action("check_service_health(payments-service)")

        with agentic_log.log_action(
            agent_id=AGENT_ID,
            session_id=SESSION_ID,
            goal_id=GOAL_ID,
            sub_task_id="task-check-health",
            tool_used="k8s.health_check",
            tool_parameters={"service": "payments-service", "namespace": "production"},
            confidence_score=0.95,
        ) as entry:
            health = check_service_health("payments-service")
            entry.set_outcome("SUCCESS")
            entry.set_anomaly_score(0.10)
            entry.set_policy_evaluation({
                "policy": "read_only_monitoring",
                "result": "PASS",
            })

        step.set_observation(
            f"CPU={health['cpu_pct']}%, errors={health['error_rate']}%, "
            f"p99={health['p99_latency_ms']}ms, replicas={health['replicas']}"
        )

    print(f"    Status: {health['status']}, CPU: {health['cpu_pct']}%")
    print(f"    Error rate: {health['error_rate']}%, P99: {health['p99_latency_ms']}ms")

    # ── Action 2: Query recent logs ──────────────────────────────
    print("\n  Action 2: Querying recent logs …")
    with session.step("tool_use") as step:
        step.set_action("query_logs(payments-service, 15m)")

        with agentic_log.log_action(
            agent_id=AGENT_ID,
            session_id=SESSION_ID,
            goal_id=GOAL_ID,
            sub_task_id="task-query-logs",
            tool_used="datadog.logs.query",
            tool_parameters={
                "service": "payments-service",
                "window": "15m",
                "level": "ERROR,WARN",
            },
            confidence_score=0.90,
        ) as entry:
            logs = query_logs("payments-service")
            entry.set_outcome("SUCCESS")
            entry.set_anomaly_score(0.08)
            entry.set_policy_evaluation({
                "policy": "log_read_access",
                "result": "PASS",
            })

        step.set_observation(f"Found {len(logs)} relevant log entries")

    for log in logs:
        print(f"    [{log['level']}] {log['msg'][:70]}…")

    # ── Action 3: Analyze the slow query ─────────────────────────
    print("\n  Action 3: Running EXPLAIN on slow query …")
    with session.step("reasoning") as step:
        step.set_thought(
            "Logs show a QueryTimeout on `SELECT * FROM transactions WHERE "
            "status='pending'`.  This is likely a full table scan on the "
            "2.4M-row transactions table.  Let me run EXPLAIN to confirm."
        )

        with agentic_log.log_action(
            agent_id=AGENT_ID,
            session_id=SESSION_ID,
            goal_id=GOAL_ID,
            sub_task_id="task-explain-query",
            tool_used="postgres.explain",
            tool_parameters={
                "query": "SELECT * FROM transactions WHERE status='pending'",
                "database": "payments_prod",
            },
            confidence_score=0.85,
        ) as entry:
            explain = run_db_explain("SELECT * FROM transactions WHERE status='pending'")
            entry.set_outcome("SUCCESS")
            # Slightly elevated anomaly: running EXPLAIN on prod is unusual
            entry.set_anomaly_score(0.25)
            entry.set_policy_evaluation({
                "policy": "db_read_access",
                "result": "PASS",
                "note": "EXPLAIN is read-only, allowed",
            })

    print(f"    Plan: {explain['plan']}")
    print(f"    Fix:  {explain['suggestion']}")

    # ── Action 4: Apply hotfix — kill slow queries + add index ───
    print("\n  Action 4: Applying hotfix (kill slow queries) …")
    with session.step("tool_use") as step:
        step.set_action("apply_hotfix: kill_slow_queries + create_index")

        # Sub-action 4a: Kill running slow queries
        with agentic_log.log_action(
            agent_id=AGENT_ID,
            session_id=SESSION_ID,
            goal_id=GOAL_ID,
            sub_task_id="task-kill-slow-queries",
            tool_used="postgres.pg_terminate_backend",
            tool_parameters={
                "query_pattern": "SELECT * FROM transactions WHERE status='pending'",
                "min_duration": "30s",
            },
            confidence_score=0.78,
        ) as entry:
            fix1 = apply_hotfix("kill_slow_queries", {"min_duration": "30s"})
            entry.set_outcome("SUCCESS")
            # Higher anomaly: this is a write operation on production
            entry.set_anomaly_score(0.55)
            entry.set_policy_evaluation({
                "policy": "prod_write_access",
                "result": "WARN",
                "reason": "Write action on production DB — requires incident ticket",
                "incident_ticket": "INC-2026-4421",
            })

        print(f"    Killed slow queries (rollback: {fix1['rollback_id']})")

        # Sub-action 4b: Create missing index
        with agentic_log.log_action(
            agent_id=AGENT_ID,
            session_id=SESSION_ID,
            goal_id=GOAL_ID,
            sub_task_id="task-create-index",
            tool_used="postgres.create_index",
            tool_parameters={
                "table": "transactions",
                "columns": ["status", "created_at"],
                "concurrently": True,
            },
            confidence_score=0.72,
        ) as entry:
            fix2 = apply_hotfix("create_index", {
                "table": "transactions",
                "columns": ["status", "created_at"],
            })
            entry.set_outcome("SUCCESS")
            # High anomaly: DDL on production
            entry.set_anomaly_score(0.70)
            entry.set_policy_evaluation({
                "policy": "prod_ddl_access",
                "result": "WARN",
                "reason": "DDL change on production — requires approval within 15min",
                "approval_deadline": "2026-02-26T14:50:00Z",
            })

        step.set_observation("Hotfix applied: slow queries killed + index created")
        print(f"    Created index on transactions(status, created_at)")

    # ── Action 5: Verify recovery ────────────────────────────────
    print("\n  Action 5: Verifying recovery …")
    with session.step("tool_use") as step:
        step.set_action("verify_recovery(payments-service)")

        with agentic_log.log_action(
            agent_id=AGENT_ID,
            session_id=SESSION_ID,
            goal_id=GOAL_ID,
            sub_task_id="task-verify-recovery",
            tool_used="k8s.health_check",
            tool_parameters={"service": "payments-service", "post_fix": True},
            confidence_score=0.98,
        ) as entry:
            recovery = verify_recovery("payments-service")
            entry.set_outcome("SUCCESS")
            entry.set_anomaly_score(0.02)
            entry.set_policy_evaluation({
                "policy": "read_only_monitoring",
                "result": "PASS",
            })

        step.set_observation(
            f"Service healthy: CPU={recovery['cpu_pct']}%, "
            f"errors={recovery['error_rate']}%, p99={recovery['p99_latency_ms']}ms"
        )
        step.set_status("success")

    print(f"    Status: {recovery['status']}")
    print(f"    CPU: {recovery['cpu_pct']}% (was {health['cpu_pct']}%)")
    print(f"    Error rate: {recovery['error_rate']}% (was {health['error_rate']}%)")
    print(f"    P99 latency: {recovery['p99_latency_ms']}ms (was {health['p99_latency_ms']}ms)")


# ────────────────────────────────────────────────────────────────────
# 4. Example: Blocked action (agent tries something it shouldn't)
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Example 2: Policy-Blocked Action")
print("=" * 70)

print("\n  Agent attempts to drop the slow-query cache table …")

with agentic_log.log_action(
    agent_id=AGENT_ID,
    session_id=SESSION_ID,
    goal_id=GOAL_ID,
    sub_task_id="task-drop-cache-table",
    tool_used="postgres.drop_table",
    tool_parameters={"table": "query_cache", "cascade": True},
) as entry:
    entry.set_outcome("DENIED")
    entry.set_confidence_score(0.40)
    entry.set_anomaly_score(0.92)
    entry.set_policy_evaluation({
        "policy": "destructive_operations",
        "result": "FAIL",
        "reason": "DROP TABLE is permanently destructive — requires human approval",
        "escalated_to": "oncall@acme.corp",
    })

print(f"  Outcome: DENIED")
print(f"  Anomaly: 0.92 (would trigger SIEM alert)")
print(f"  Policy:  destructive_operations → FAIL")
print(f"  Action:  Escalated to oncall@acme.corp")


# ────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Summary")
print("=" * 70)
print(f"  Incident:          payments-service CPU spike")
print(f"  Root cause:        Missing index → full table scan → connection pool exhaustion")
print(f"  Resolution:        Killed slow queries + created index")
print(f"  Recovery:          CPU {health['cpu_pct']}% → {recovery['cpu_pct']}%")
print(f"  Agentic log entries: 7 (6 SUCCESS + 1 DENIED)")
print(f"  Policy evaluations:  7 (5 PASS + 1 WARN + 1 FAIL)")
print(f"  OCSF events:         {ocsf_exporter.event_count}")
print(f"  Events at:           /tmp/aitf_agentic_log_events.jsonl")
print(f"\n  Every action is logged with goal_id, tool, outcome, confidence,")
print(f"  anomaly score, and policy evaluation — ready for SIEM correlation.")
