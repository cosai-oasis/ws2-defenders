# AgentDR — macOS Test Plan / Demo Script

> Target platform: macOS 14+ on Apple Silicon or Intel.
> Estimated runtime: 25 min walkthrough, 45 min full plan.
> Prerequisites: Homebrew, an installed coding agent (Claude Code, Cursor,
> or Codex CLI), Python 3, `curl`, `jq`.

## Setup

```bash
# 0.1 Install
brew tap girdav01/agentdr
brew install agentdr

# 0.2 Confirm version + rule-pack integrity
adr-agent --version
adr-agent verify

# 0.3 Pick a clean root for this demo so multiple runs don't bleed events
export DEMO_ROOT="$HOME/agentdr-demo"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
```

Expect: `adr-agent 0.2.0` and a green `✓  All rule files verified successfully.`

---

## Tier 1 — local agent telemetry

### STEP T1.1 — install runtime hooks for every supported agent

```bash
adr-agent hooks install all --endpoint http://127.0.0.1:4318
```

**expect**:
```
✓ claude-code: wrote /Users/<u>/.claude/settings.json
✓ cursor: wrote /Users/<u>/.cursor/mcp.json
✓ codex: wrote /Users/<u>/.codex/config.toml
✓ aider: wrote /Users/<u>/.aider.conf.yml
```

> DEMO NARRATION: *"AgentDR doesn't sniff at the network and guess what
> agents are doing — we install OpenTelemetry hooks in every supported
> agent so we capture prompt, tool-call, and approval events with
> **semantic certainty**."*

### STEP T1.2 — start the agent in the foreground

```bash
adr-agent --root "$DEMO_ROOT" start --watch ~/Documents --watch ~/Desktop &
AGENT_PID=$!
```

**expect** within 1 second:
```
INFO policy: loaded 8 rule(s) from cosai-community/policies/policies.yaml
INFO OTLP ingest listening on http://127.0.0.1:4318 (traces, logs, metrics)
INFO Starting CoSAI ADR Agent Engine (Rust)
```

### STEP T1.3 — send a synthetic OTel gen_ai span

```bash
curl -s -X POST -H 'Content-Type: application/json' --data @- http://127.0.0.1:4318/v1/traces <<'JSON'
{"resourceSpans":[{"resource":{"attributes":[
  {"key":"service.name","value":{"stringValue":"claude-code"}},
  {"key":"host.name","value":{"stringValue":"laptop-david"}},
  {"key":"user.name","value":{"stringValue":"david"}}]},
"scopeSpans":[{"spans":[
  {"traceId":"9b7f0c8d2e1a4f5b6c7d8e9f0a1b2c3d","spanId":"1a2b3c4d5e6f7a8b","name":"chat claude-sonnet-4-5","kind":3,
   "attributes":[
     {"key":"gen_ai.system","value":{"stringValue":"anthropic"}},
     {"key":"gen_ai.request.model","value":{"stringValue":"claude-sonnet-4-5"}},
     {"key":"gen_ai.usage.input_tokens","value":{"intValue":"1240"}},
     {"key":"gen_ai.usage.output_tokens","value":{"intValue":"318"}}]},
  {"traceId":"9b7f0c8d2e1a4f5b6c7d8e9f0a1b2c3d","spanId":"2a2b3c4d5e6f7a8b","name":"tools/call read_file",
   "attributes":[{"key":"gen_ai.tool.name","value":{"stringValue":"read_file"}}]}]
}]}]}
JSON
```

**emits**:

| class_uid | ai_operation | event_type | meaning |
|---|---|---|---|
| 6003 | `inference` | `gen_ai.inference` | LLM call, token usage populated |
| 6003 | `tool_execution` | `gen_ai.tool` | tool_name=read_file |

```bash
tail -2 "$DEMO_ROOT/logs/events.jsonl" | jq '{class_uid, ai_operation, event_type, tool_name, token_usage}'
```

### STEP T1.4 — MCP server inventory

```bash
adr-agent mcp inventory --jsonl | jq '. | {runtime: .details.runtime, name: .details.name, transport: .details.transport}'
```

> DEMO NARRATION: *"Comparable telemetry-only projects in this space
> generally skip MCP configuration inventory. We do it across every
> coding agent's config in one shot, and we'll proxy the JSON-RPC on
> the next slide."*

### STEP T1.5 — wrap a real MCP server

```bash
adr-agent --root "$DEMO_ROOT" mcp wrap --name github -- npx -y @modelcontextprotocol/server-github &
MCP_PID=$!
sleep 1
# In another terminal: point Cursor at this wrapped server and trigger a tools/call.
# For automated demos:
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_issue","arguments":{}}}' > /dev/tcp/...  # or pipe stdin
```

**emits**: `class_uid=6003` (`ai_operation="mcp_operation"`) events for every JSON-RPC message; `tool_name="tools/call"` carries risk=medium.

---

## Tier 2 — fleet deployment

### STEP T2.1 — show the installed LaunchDaemon

```bash
sudo launchctl print system/com.cosai.agentdr | grep -E 'state|user|program'
```

**expect**: `state = running` under user `_agentdr`.

### STEP T2.2 — Jamf profile preview (no live MDM needed)

```bash
cat /usr/local/etc/agentdr/jamf/agentdr.mobileconfig | xmllint --format - | head -40
```

> DEMO NARRATION: *"In an MDM environment that .mobileconfig is what an
> admin uploads. It pre-grants Full Disk Access for the agent binary so
> the file monitor sees user-space paths without prompting users."*

---

## Tier 3 — vendor exporters

For each demo configure one exporter. The smallest visual demo is **syslog**
because anyone can `nc -lu 514`.

### STEP T3.1 — start a syslog receiver

```bash
nc -kluv 0.0.0.0 5514 &  NC_PID=$!
```

### STEP T3.2 — enable the AgentDR syslog exporter

```bash
cat >> "$DEMO_ROOT/config.toml" <<EOF

[exporters.syslog]
enabled  = true
protocol = "udp"
address  = "127.0.0.1:5514"
appname  = "agentdr-demo"
EOF
kill -HUP $AGENT_PID || (kill $AGENT_PID; adr-agent --root "$DEMO_ROOT" start --quiet &)
```

### STEP T3.3 — trigger an event and watch syslog

Re-run STEP T1.3. Within ~5 seconds the syslog receiver shows:

```
<109>1 2026-05-17T... laptop-david agentdr-demo 12345 - [aitf@53595 class_uid="6003" ai_operation="inference" risk="low" provider="anthropic" model="claude-sonnet-4-5" trace_id="9b7f0c8d..."] {...full event JSON...}
```

> DEMO NARRATION: *"That structured-data block — `[aitf@53595 ...]` — is
> RFC 5424. Any SIEM that speaks syslog can index those fields without
> parsing the JSON body. We ship the same shape to Splunk HEC, Datadog,
> Elastic, Chronicle, XSIAM, Snowflake, Sentinel, Wazuh and a generic
> OCSF webhook."*

---

## Tier 4 — UEBA / multi-host correlation

(Requires the Next.js dashboard. Skip if doing a CLI-only demo.)

```bash
# In the dashboard checkout:
yarn dev &   # http://localhost:3000
adr-agent --root "$DEMO_ROOT" config set server_push.enabled true
adr-agent --root "$DEMO_ROOT" config set server_push.endpoint http://localhost:3000/api/sync
```

### STEP T4.1 — generate a multi-trace session

Re-fire STEP T1.3 with three different `traceId` values. Open
`http://localhost:3000/sessions` — three rows appear, each with its event
count and the agents/hosts/providers it touched.

### STEP T4.2 — recompute baselines

`http://localhost:3000/ueba` → click **Recompute (last 14 days)**.

**expect**: rows appear keyed by (host, user, agent) with `n`, `μ`, `σ`,
`p50`/`p95`/`p99` filled in.

### STEP T4.3 — kill-chain replay

`http://localhost:3000/sessions/<traceId>` shows the full timeline of
events plus a "kill-chain phases" strip mapping every class_uid to a
MITRE-style phase.

---

## Tier 5 — governance (live block)

### STEP T5.1 — show the policy pack

```bash
adr-agent policy list
adr-agent policy test <<'JSON'
{"timestamp":"2026-05-17T00:00:00Z","event_type":"file_read",
 "details":{"path":"/Users/david/.aws/credentials"},"risk_level":"low",
 "trace_id":"deadbeefcafef00d","span_id":"1234567890abcdef"}
JSON
```

**expect**: `action: "block"` referencing `AGENTDR-POL-001`.

### STEP T5.2 — turn on the inline proxy

```bash
cat >> "$DEMO_ROOT/config.toml" <<EOF

[proxy]
enabled  = true
bind     = "127.0.0.1:18080"
allowlist = ["anthropic.com"]
EOF
# restart agent (kill + start), then in another terminal:
export HTTPS_PROXY=http://127.0.0.1:18080
```

### STEP T5.3 — denied egress

```bash
curl -sv https://api.openai.com/v1/models --max-time 5 2>&1 | grep -E 'HTTP/|403'
```

**expect**: `HTTP/1.1 403 Forbidden` from `Proxy-Agent: AgentDR`.

```bash
tail -1 "$DEMO_ROOT/logs/events.jsonl" | jq '{class_uid, event_type, message, risk_level}'
```

**emits**: `class_uid=2003`, `ai_operation="compliance_violation"`, `event_type="proxy_block"`, `risk_level="high"`.

### STEP T5.4 — allowed egress

```bash
curl -s https://api.anthropic.com/v1/messages -o /dev/null -w 'HTTP %{http_code}\n' --max-time 5
```

**emits**: `class_uid=6003`, `ai_operation="inference"`, `event_type="proxy_allow"`, `provider="anthropic"`.

### STEP T5.5 — approval-flow capture

Push a synthetic OTel span with `gen_ai.approval.decision=deny`:

```bash
curl -s -X POST -H 'Content-Type: application/json' http://127.0.0.1:4318/v1/traces --data @- <<'JSON'
{"resourceSpans":[{"resource":{"attributes":[
  {"key":"service.name","value":{"stringValue":"claude-code"}}]},
 "scopeSpans":[{"spans":[
   {"traceId":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","spanId":"b1b1b1b1b1b1b1b1","name":"approval","attributes":[
    {"key":"gen_ai.system","value":{"stringValue":"anthropic"}},
    {"key":"gen_ai.approval.decision","value":{"stringValue":"deny"}},
    {"key":"gen_ai.approval.scope","value":{"stringValue":"shell:rm -rf /"}},
    {"key":"gen_ai.approval.actor","value":{"stringValue":"david"}}]}]}]}]}
JSON
```

**emits**: `class_uid=2004`, `ai_operation="permission_escalation"`, `risk_level=high`, `status_id=3 (BLOCKED)`,
`details.decision="deny"`.

---

## Tier 6 — kernel / shell / browser / attribution

### STEP T6.1 — kernel telemetry (EndpointSecurity note)

```bash
adr-agent --root "$DEMO_ROOT" start 2>&1 | grep kernel_monitor_warning
```

**expect**:
```
macOS EndpointSecurity requires a signed entitled sidecar.
Deploy the AgentDR-ES sidecar via MDM and forward its events to the file monitor.
```

> DEMO NARRATION: *"On macOS, Apple gates EndpointSecurity behind an
> entitlement and a signed binary. AgentDR ships a sidecar (separate
> Developer ID-signed package); for this demo we'll show Linux kernel
> telemetry working out of the box in the next plan."*

### STEP T6.2 — shell wrap

```bash
printf 'ls /etc/hostname\necho done\n' | \
  adr-agent --root "$DEMO_ROOT" shell wrap --name claude-bash -- bash
```

**emits**: 5 events — `shell_wrap_start`, 2× `shell_input` (risk=medium),
2× `shell_stdout` (risk=low), `shell_wrap_end`.

```bash
tail -5 "$DEMO_ROOT/logs/events.jsonl" | jq '{event_type, risk_level, line: .details.line}'
```

### STEP T6.3 — browser CDP attach

```bash
# Launch Chrome with the standard browser-use debugging port
open -na "Google Chrome" --args --remote-debugging-port=9222
cat >> "$DEMO_ROOT/config.toml" <<EOF

[browser]
enabled = true
cdp_endpoint = "http://127.0.0.1:9222"
poll_seconds = 3
EOF
# Restart agent. Navigate to https://news.ycombinator.com → see:
```

**emits**: `browser_attached` once, then `browser_page_navigated` with
`details.url="https://news.ycombinator.com"`.

### STEP T6.4 — credential-use attribution

Trigger a credential read while a known agent process is alive:

```bash
adr-agent --version &    # any process matched by agent-signatures will do for the demo
cat ~/.aws/credentials > /dev/null 2>&1   # safe: file may not exist
```

**expect**: the `AITF-DET-018` alert now contains a `candidate_agents`
array listing every live agent process inside the 10-minute attribution
window — `pid`, `agent_name`, `framework`, `user`, `exe`, `age_seconds`.

```bash
grep alert_credential_access "$DEMO_ROOT/logs/events.jsonl" | tail -1 | jq '.details.candidate_agents'
```

---

## RESET

```bash
kill $AGENT_PID $MCP_PID $NC_PID 2>/dev/null
adr-agent hooks uninstall all
rm -rf "$DEMO_ROOT"
unset HTTPS_PROXY
```

---

## Failure modes & quick fixes

| Symptom | Cause | Fix |
|---|---|---|
| `OTLP server failed to bind` | another process on :4318 | `lsof -i :4318` then `kill <pid>` |
| `policy: no policy pack found` | wrong cwd | `cd adr_system` or set `[policy].path` |
| `proxy: 502 Bad Gateway` | upstream unreachable | normal on a dev laptop; demo doesn't depend on reachability |
| Hooks not picked up by Claude Code | the editor was already running | restart Claude Code; OTel env is read at launch |
| Browser monitor silent | Chrome not started with `--remote-debugging-port` | use `--args --remote-debugging-port=9222` |
