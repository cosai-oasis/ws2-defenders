"""AITF Example: MCP Protocol Tracing — AI Code Review Assistant.

Demonstrates MCP (Model Context Protocol) tracing in a realistic scenario:

    An AI-powered code review assistant connects to three MCP servers
    (GitHub, filesystem, Postgres) to review a pull request.  It fetches
    the PR diff from GitHub, reads related source files from the local
    filesystem, looks up related tickets in the issue database, then
    generates a review and posts comments — with every MCP operation
    fully traced for security audit.

All spans are exportable as both OTel traces (OTLP → Jaeger/Tempo) and
OCSF security events (→ SIEM/XDR).  See ``dual_pipeline_tracing.py``
for dual-pipeline setup.

Run:
    pip install opentelemetry-sdk aitf
    python mcp_tracing.py
"""

from __future__ import annotations

import json
import time

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter

from aitf.instrumentation.mcp import MCPInstrumentor
from aitf.instrumentation.llm import LLMInstrumentor
from aitf.exporters.ocsf_exporter import OCSFExporter


# ────────────────────────────────────────────────────────────────────
# 1. Simulated MCP tool implementations
# ────────────────────────────────────────────────────────────────────

def github_get_pr_diff(owner: str, repo: str, pr_number: int) -> dict:
    """Simulate fetching a PR diff from GitHub."""
    time.sleep(0.05)
    return {
        "pr_number": pr_number,
        "title": "feat: add rate limiting to /api/payments endpoint",
        "author": "alice",
        "files_changed": 3,
        "additions": 87,
        "deletions": 12,
        "diff": (
            "--- a/src/api/payments.py\n"
            "+++ b/src/api/payments.py\n"
            "@@ -45,6 +45,18 @@\n"
            "+from redis import Redis\n"
            "+from ratelimit import RateLimiter\n"
            "+\n"
            "+limiter = RateLimiter(Redis(), max_calls=100, period=60)\n"
            "+\n"
            " @app.post('/api/payments')\n"
            "+@limiter.limit\n"
            " def create_payment(request: PaymentRequest):\n"
            "+    # FIXME: should we also limit by IP?\n"
            "     validate_payment(request)\n"
        ),
    }


def github_list_pr_comments(owner: str, repo: str, pr_number: int) -> list:
    """Simulate listing existing PR comments."""
    time.sleep(0.03)
    return [
        {"author": "bob", "body": "Looks good overall, but can we add tests?", "created_at": "2026-02-25T10:30:00Z"},
    ]


def fs_read_file(path: str) -> str:
    """Simulate reading a local file via the filesystem MCP server."""
    time.sleep(0.02)
    if "payments.py" in path:
        return (
            "from fastapi import FastAPI, HTTPException\n"
            "from pydantic import BaseModel\n\n"
            "app = FastAPI()\n\n"
            "class PaymentRequest(BaseModel):\n"
            "    amount: float\n"
            "    currency: str\n"
            "    recipient: str\n\n"
            "def validate_payment(req: PaymentRequest):\n"
            "    if req.amount <= 0:\n"
            "        raise HTTPException(400, 'Invalid amount')\n"
            "    if req.amount > 10000:\n"
            "        raise HTTPException(400, 'Amount exceeds limit')\n"
        )
    return "# file not found in simulation"


def fs_list_directory(path: str) -> list:
    """Simulate listing a directory."""
    time.sleep(0.02)
    return ["payments.py", "auth.py", "models.py", "config.py", "__init__.py"]


def db_query_related_tickets(component: str) -> list:
    """Simulate querying the Postgres issue tracker for related tickets."""
    time.sleep(0.04)
    return [
        {"ticket_id": "PAY-1023", "title": "Rate limit abuse on payments endpoint",
         "status": "open", "priority": "high", "reporter": "security-team"},
        {"ticket_id": "PAY-987", "title": "Add Redis caching for payment validation",
         "status": "closed", "priority": "medium", "reporter": "alice"},
    ]


def github_post_review(owner: str, repo: str, pr_number: int, body: str, event: str) -> dict:
    """Simulate posting a PR review on GitHub."""
    time.sleep(0.05)
    return {"review_id": 42, "state": event, "body": body[:80] + "..."}


# ────────────────────────────────────────────────────────────────────
# 2. AITF Setup
# ────────────────────────────────────────────────────────────────────

provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
ocsf_exporter = OCSFExporter(
    output_file="/tmp/aitf_mcp_events.jsonl",
    compliance_frameworks=["nist_ai_rmf", "mitre_atlas", "eu_ai_act"],
)
provider.add_span_processor(SimpleSpanProcessor(ocsf_exporter))
trace.set_tracer_provider(provider)

mcp = MCPInstrumentor(tracer_provider=provider)
llm = LLMInstrumentor(tracer_provider=provider)

PR_OWNER, PR_REPO, PR_NUMBER = "acme", "payments-service", 142


# ────────────────────────────────────────────────────────────────────
# 3. Code Review Scenario
# ────────────────────────────────────────────────────────────────────

print("=" * 70)
print("  AI Code Review Assistant — MCP Protocol Tracing")
print("=" * 70)
print(f"\n  Reviewing PR #{PR_NUMBER} in {PR_OWNER}/{PR_REPO}")
print(f"  MCP servers: github, filesystem, postgres\n")


# ── Step 1: Connect to GitHub MCP server ──────────────────────────

print("  Step 1: Connect to GitHub MCP server")
with mcp.trace_server_connect(
    server_name="github",
    transport="stdio",
    protocol_version="2025-03-26",
) as conn:
    conn.set_capabilities(tools=True, resources=True, prompts=False, sampling=False)

    with conn.discover_tools() as discovery:
        discovery.set_tools([
            "get_pr_diff", "list_pr_comments", "post_review",
            "create_issue", "list_issues", "get_file_contents",
        ])

    # Fetch the PR diff
    print("  Step 2: Fetch PR diff from GitHub")
    with mcp.trace_tool_invoke(
        tool_name="get_pr_diff",
        server_name="github",
        tool_input=json.dumps({"owner": PR_OWNER, "repo": PR_REPO, "pr_number": PR_NUMBER}),
    ) as invocation:
        pr_diff = github_get_pr_diff(PR_OWNER, PR_REPO, PR_NUMBER)
        invocation.set_output(json.dumps(pr_diff), "application/json")

    print(f"    PR: {pr_diff['title']}")
    print(f"    Changes: +{pr_diff['additions']} -{pr_diff['deletions']} in {pr_diff['files_changed']} files")

    # List existing comments
    print("\n  Step 3: Check existing review comments")
    with mcp.trace_tool_invoke(
        tool_name="list_pr_comments",
        server_name="github",
        tool_input=json.dumps({"owner": PR_OWNER, "repo": PR_REPO, "pr_number": PR_NUMBER}),
    ) as invocation:
        comments = github_list_pr_comments(PR_OWNER, PR_REPO, PR_NUMBER)
        invocation.set_output(json.dumps(comments), "application/json")

    for c in comments:
        print(f"    [{c['author']}]: {c['body']}")


# ── Step 4: Connect to filesystem MCP server ─────────────────────

print("\n  Step 4: Connect to filesystem MCP server")
with mcp.trace_server_connect(
    server_name="filesystem",
    transport="stdio",
    protocol_version="2025-03-26",
) as conn:
    conn.set_capabilities(tools=True, resources=True, prompts=False, sampling=False)

    # List the source directory
    with mcp.trace_tool_invoke(
        tool_name="list_directory",
        server_name="filesystem",
        tool_input=json.dumps({"path": "src/api/"}),
    ) as invocation:
        files = fs_list_directory("src/api/")
        invocation.set_output(json.dumps(files), "application/json")

    print(f"    Files in src/api/: {', '.join(files)}")

    # Read the full source file for context
    print("\n  Step 5: Read full source of payments.py")
    with mcp.trace_resource_read(
        resource_uri="file:///workspace/src/api/payments.py",
        server_name="filesystem",
        resource_name="payments.py",
        mime_type="text/x-python",
    ) as span:
        source_code = fs_read_file("payments.py")
        span.set_attribute("mcp.resource.size_bytes", len(source_code))

    print(f"    Read {len(source_code)} bytes")


# ── Step 6: Connect to Postgres MCP server (issue tracker) ───────

print("\n  Step 6: Query related tickets from Postgres")
with mcp.trace_server_connect(
    server_name="postgres-issues",
    transport="streamable_http",
    server_url="http://localhost:3001/mcp",
) as conn:
    conn.set_capabilities(tools=True, resources=True)

    with mcp.trace_tool_invoke(
        tool_name="query",
        server_name="postgres-issues",
        tool_input=json.dumps({
            "sql": "SELECT * FROM tickets WHERE component='payments' AND status='open' ORDER BY priority",
        }),
    ) as invocation:
        tickets = db_query_related_tickets("payments")
        invocation.set_output(json.dumps(tickets), "application/json")

    for t in tickets:
        print(f"    [{t['ticket_id']}] {t['title']} ({t['status']}, {t['priority']})")


# ── Step 7: Generate review using LLM (MCP sampling) ─────────────

print("\n  Step 7: Generate AI review (Claude via MCP sampling)")
with mcp.trace_sampling_request(
    server_name="github",
    model="claude-sonnet-4-5-20250929",
    max_tokens=1024,
) as span:
    with llm.trace_inference(
        model="claude-sonnet-4-5-20250929",
        system="anthropic",
        operation="chat",
        temperature=0.1,
        max_tokens=1024,
    ) as llm_span:
        llm_span.set_prompt(
            f"Review this PR diff for security, correctness, and best practices:\n\n"
            f"PR: {pr_diff['title']}\n"
            f"Diff:\n{pr_diff['diff']}\n\n"
            f"Related source:\n{source_code[:500]}\n\n"
            f"Related tickets:\n{json.dumps(tickets, indent=2)}\n\n"
            f"Existing comments: {json.dumps(comments)}"
        )

        review_text = (
            "## AI Code Review — PR #142\n\n"
            "### Security\n"
            "- **Rate limiter uses default Redis connection** — ensure TLS is "
            "enabled for the Redis connection in production (`rediss://`).\n"
            "- The `FIXME` comment about IP-based limiting is valid — consider "
            "adding `X-Forwarded-For` rate limiting for defense in depth.\n\n"
            "### Correctness\n"
            "- Rate limit of 100/min seems reasonable, but verify with PAY-1023 "
            "(the rate limit abuse ticket) to match the security team's requirements.\n\n"
            "### Tests\n"
            "- Agree with @bob — please add tests for rate-limited and non-rate-limited paths.\n\n"
            "**Verdict: APPROVE with suggestions**"
        )

        llm_span.set_completion(review_text)
        llm_span.set_usage(input_tokens=680, output_tokens=195)

    print(f"    Generated review ({195} tokens)")


# ── Step 8: Post the review (requires approval) ──────────────────

print("\n  Step 8: Post review to GitHub (approval required)")
with mcp.trace_tool_invoke(
    tool_name="post_review",
    server_name="github",
    tool_input=json.dumps({
        "owner": PR_OWNER,
        "repo": PR_REPO,
        "pr_number": PR_NUMBER,
        "body": review_text,
        "event": "APPROVE",
    }),
    approval_required=True,
) as invocation:
    invocation.set_approved(approved=True, approver="devops-lead@acme.corp")
    result = github_post_review(PR_OWNER, PR_REPO, PR_NUMBER, review_text, "APPROVE")
    invocation.set_output(json.dumps(result), "application/json")

print(f"    Posted review #{result['review_id']} (state: {result['state']})")
print(f"    Approved by: devops-lead@acme.corp")


# ── Step 9: Example — blocked destructive action ─────────────────

print(f"\n{'=' * 70}")
print("  Example 2: Policy-Blocked MCP Tool Invocation")
print("=" * 70)

print("\n  Agent attempts to delete a branch via GitHub MCP …")
with mcp.trace_tool_invoke(
    tool_name="delete_branch",
    server_name="github",
    tool_input=json.dumps({"owner": PR_OWNER, "repo": PR_REPO, "branch": "main"}),
    approval_required=True,
) as invocation:
    invocation.set_approved(approved=False, approver="system")
    invocation.set_output("DENIED: delete_branch on protected branch 'main' is not allowed", "text")

print("  Outcome: DENIED — protected branch policy blocked deletion")


# ────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────

print(f"\n{'=' * 70}")
print("  Summary")
print("=" * 70)
print(f"  MCP servers connected:   3 (github, filesystem, postgres-issues)")
print(f"  Tools discovered:        6 (on github server)")
print(f"  Tool invocations:        6 (5 approved + 1 denied)")
print(f"  Resources read:          1 (payments.py)")
print(f"  Sampling requests:       1 (Claude code review)")
print(f"  OCSF events:             {ocsf_exporter.event_count}")
print(f"  Events at:               /tmp/aitf_mcp_events.jsonl")
print(f"\n  Every MCP operation is traced with server identity, tool I/O,")
print(f"  approval status, and resource URIs — ready for security audit.")

provider.shutdown()
