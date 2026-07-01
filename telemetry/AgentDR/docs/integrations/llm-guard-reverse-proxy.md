# LLM Guard reverse proxy & forward-proxy enrichment

AgentDR ships **two** complementary proxies under `src/proxy/`. They protect
traffic in opposite directions and are configured independently.

| | Forward CONNECT proxy | LLM Guard reverse proxy |
|---|---|---|
| Module | `src/proxy/mod.rs` (`InlineProxy`) | `src/proxy/reverse.rs` (`Guard`) |
| Config | `[proxy]` | `[llm_guard]` |
| Direction | Agent → **remote** LLM/API hosts (egress) | Client → **local** model backend (ingress) |
| Sees bodies? | No (HTTPS tunnelled via `CONNECT`) | Yes (terminates HTTP, inspects req/resp) |
| Default | disabled | disabled |

Both are opt-in (`enabled = false`) and emit the same OCSF / AITF events as the
rest of AgentDR via the shared event bus.

---

## Quick start

Get the LLM Guard reverse proxy in front of a local Ollama in three steps.

**1. Enable it in `config.toml`** (minimal — observe-only, no auth):

```toml
[llm_guard]
enabled = true
listen_address = "127.0.0.1:8011"

[[llm_guard.backends]]
name = "ollama"
kind = "ollama"
url = "http://127.0.0.1:11434"
route_prefix = "/ollama"
health_path = "/api/tags"

[llm_guard.monitoring]
enabled = true              # inspect prompts for injection / PII, track tokens
```

> Config locations: Linux & macOS `/etc/agentdr/config.toml`, Windows
> `C:\ProgramData\AgentDR\config.toml`. When running from a checkout, the agent
> reads `<root>/config.toml` (override with `--config`). The shipped
> Windows `default-config.toml` includes a fully-commented `[llm_guard]` block.

**2. Start the agent** — the guard spawns automatically when `enabled = true`:

```
adr-agent start
# guard now listening on http://127.0.0.1:8011
```

Or run **just the guard**, standalone, without the rest of the agent — handy
for a dedicated model-gateway host. It reads the same `[llm_guard]` block
(force-enabled for the run) and writes events as JSONL to the configured
events path:

```
adr-agent llm-guard                       # uses [llm_guard].listen_address
adr-agent llm-guard --listen 0.0.0.0:8011 # override the bind address
```

**3. Point your client at the guard instead of the backend.** The
`route_prefix` selects the backend and is stripped before forwarding, so
`/ollama/api/generate` → `http://127.0.0.1:11434/api/generate`:

```
curl http://127.0.0.1:8011/ollama/api/generate \
  -d '{"model":"llama3","prompt":"Hello"}'

# liveness of every configured backend:
curl http://127.0.0.1:8011/healthz
```

Open the dashboard's **LLM Guard** page to watch requests, findings, token
usage and backend health in real time (see
[Dashboard UI](#3-dashboard-ui-monitoring--configuration) below).

### Common use cases

| Goal | What to set |
|---|---|
| **Just observe** local LLM traffic (default) | `[llm_guard] enabled = true`, `monitoring.enabled = true`, leave `block_on_* = false` |
| **Block prompt-injection / PII** at the edge | `monitoring.block_on_injection = true` and/or `block_on_pii = true` |
| **Require an API key** from callers | `llm_guard.auth_tokens = ["<key>"]` → callers send `Authorization: Bearer <key>` |
| **Verify JWTs** instead of static keys | `[llm_guard.jwt] enabled = true`, `secret = "<hs256>"` |
| **Throttle abusive callers** | `[llm_guard.rate_limits] enabled = true`, tune `requests_per_minute` / `burst` |
| **Restrict which processes may call** the models | `[llm_guard.process_acl] enabled = true` — apply a [preset](#process-access-control) or set `allow` / `deny` patterns |
| **Front several backends** (Ollama + LM Studio + llama.cpp) | add one `[[llm_guard.backends]]` block per backend with distinct `route_prefix` |
| **Guard outbound agent egress** too | enable the separate `[proxy]` forward proxy (section 1) |

---

## 1. Forward CONNECT proxy enrichment (`[proxy]`)

The existing inline blocking proxy still does host allow-listing + policy-engine
decisions on every `CONNECT`. It now additionally records **caller
provenance**, can **authenticate** callers, and can **rate-limit** them. Because
the connection is an opaque TLS tunnel, enrichment works on connection metadata
and proxy headers — never on request bodies.

```toml
[proxy]
enabled = false
bind = "127.0.0.1:8080"
allowlist = []          # substring host allow-list (case-insensitive)
provenance = true       # resolve PID / exe / known-agent for each connection

# Optional auth. Empty tokens + jwt.enabled=false  =>  observe-only (no creds
# required), so it stays a drop-in for existing HTTPS_PROXY clients.
auth_tokens = []        # Proxy-Authorization: Bearer <key>  OR  X-API-Key: <key>

[proxy.jwt]
enabled = false
secret  = ""            # HS256 shared secret
issuer  = ""            # optional expected iss
audience = ""           # optional expected aud

# OFF by default so it never throttles chatty browser/agent clients.
[proxy.rate_limits]
enabled = false
requests_per_minute = 120
burst = 30
```

Behaviour:

1. **Provenance** — when `provenance = true`, AgentDR resolves the local process
   that opened the connection (PID / executable / command line, Linux via
   `/proc`) and attributes it to a known AI agent from the signature table.
   Emitted events gain an `actor` object plus `agent_name` / `agent_framework`.
2. **Auth** — if any `auth_tokens` are set or `jwt.enabled = true`, a missing /
   invalid credential is rejected with **`407 Proxy Authentication Required`**
   and a `proxy_auth_denied` event (`ai_operation = identity`).
3. **Rate limit** — when enabled, a per-caller sliding window (keyed by auth
   subject, else PID/peer) returns **`429`** and a `proxy_rate_limited`
   guardrail event on breach.
4. **Policy + allow-list** — unchanged; a denied host is blocked and a
   `compliance_violation` finding is emitted.

Run standalone:

```
adr-agent proxy --allow anthropic.com     # CLI overrides bind/allowlist on [proxy]
```

---

## 2. LLM Guard reverse proxy (`[llm_guard]`)

Put the guard **in front of** your local model servers and point clients at it
instead of the backend. Because it terminates HTTP, it can inspect prompts and
responses.

```toml
[llm_guard]
enabled = false
listen_address = "127.0.0.1:8011"
auth_tokens = []                      # Authorization: Bearer <key>  OR  X-API-Key
health_check_interval_seconds = 30    # 0 disables the background poller
max_body_bytes = 8388608             # 8 MiB request-body cap (413 over limit)
upstream_timeout_seconds = 120

# Requests route by route_prefix (longest match wins); the matched prefix is
# stripped before forwarding. An empty prefix is the default backend.
[[llm_guard.backends]]
name = "ollama"
kind = "ollama"
url = "http://127.0.0.1:11434"
route_prefix = "/ollama"
health_path = "/api/tags"

[[llm_guard.backends]]
name = "lmstudio"
kind = "lmstudio"
url = "http://127.0.0.1:1234"
route_prefix = "/lmstudio"
health_path = "/v1/models"

[[llm_guard.backends]]
name = "llamacpp"
kind = "llamacpp"
url = "http://127.0.0.1:8080"
route_prefix = "/llamacpp"
health_path = "/health"

[llm_guard.jwt]
enabled = false
secret = ""
issuer = ""
audience = ""

[llm_guard.rate_limits]
enabled = true
requests_per_minute = 120
burst = 30

[llm_guard.monitoring]
enabled = true
detect_prompt_injection = true
detect_pii = true
track_tokens = true
block_on_injection = false   # alert-only by default (still forwarded)
block_on_pii = false
max_prompt_chars = 512       # prompt chars retained in events (never the full prompt)
```

### Request lifecycle

```
client ─▶ [provenance] ─▶ [process ACL 403] ─▶ [auth 401] ─▶ [rate-limit 429] ─▶ [route 502]
       ─▶ [read body ≤max 413] ─▶ [inspect prompt → 403 if block_on_*]
       ─▶ forward to backend ─▶ [read response] ─▶ [extract token usage]
       ─▶ emit observation ─▶ relay response to client
```

- **Routing** — e.g. `POST /ollama/api/generate` → `http://127.0.0.1:11434/api/generate`.
- **Process ACL** — gate on *which local process* (or attributed AI agent) is
  calling, before auth. A denied caller gets **`403`** and an `identity`
  Detection Finding. See [Process access control](#process-access-control) below.
- **Auth** — missing/invalid credential → **`401 Unauthorized`**. Empty
  `auth_tokens` + `jwt.enabled = false` ⇒ observe-only (nothing rejected).
- **Rate limit** — per-key sliding window → **`429`**.
- **Content inspection** — prompts are extracted from common shapes
  (OpenAI `messages[]`, Ollama `prompt`, plain `input`). Injection / PII matches
  emit an OCSF Detection Finding (`class_uid 2004`, `ai_operation`
  `prompt_injection` / `data_exfiltration`). With `block_on_* = true` the
  request is rejected with **`403`** before reaching the backend; otherwise it is
  forwarded and only a finding is raised (alert-only).
- **Token usage** — parsed from the upstream response (OpenAI
  `usage.{prompt,completion,total}_tokens`, Ollama `prompt_eval_count` /
  `eval_count`) and attached to an `inference` observation event.

### Process access control

The guard resolves the **local process** behind every request — PID, executable
path, command line — and attributes it to a known AI agent (reusing the same
`agent-signatures` matching as the rest of AgentDR). With `[llm_guard.process_acl]`
you can turn that into an access decision, so only the processes you trust may
reach your local models:

```toml
[llm_guard.process_acl]
enabled = true
default = "deny"            # "deny" = allowlist, "allow" = denylist
block_unresolved = false    # reject callers with no resolvable PID (Linux-only resolution)
allow = ["claude-code", "cursor", "ollama"]
deny  = ["curl", "wget", "python"]
```

- Patterns are **case-insensitive substrings** matched against a haystack of
  `name + exe + cmdline + agent_name`.
- **`deny` always wins** over `allow`. When neither matches, `default` decides.
- A blocked caller gets **`403`** plus an `ai_operation = identity` Detection
  Finding (`status_id` BLOCKED) in the event stream / dashboard.
- **Linux-only enforcement today.** Process resolution parses `/proc`; on
  macOS/Windows the caller is peer-address-only, so keep `block_unresolved = false`
  there (an allowlist would otherwise reject everything). This is defence in
  depth — pair it with `auth_tokens`, since `name`/`cmdline` are spoofable
  (the `exe` symlink is sturdier).

**Curated presets.** The dashboard's LLM Guard settings page ships ready-made
rule profiles you can apply and then fine-tune (see
`adr_dashboard/nextjs_space/lib/llm-guard-presets.ts`):

| Preset | Kind | What it does |
|--------|------|--------------|
| Observe only | off | Record provenance, never block (baseline). |
| Allow known AI coding agents only | allowlist | Claude Code, Cursor, Codex, Aider, Continue, Cline, … |
| Allow first-party LLM apps | allowlist | Ollama, LM Studio, llama.cpp, Open WebUI, Jan, Msty, … |
| Developer workstation | allowlist | Union of coding agents + LLM apps (recommended). |
| Block scripting interpreters | denylist | python, node, ruby, bash, powershell, … |
| Block data-transfer tooling | denylist | curl, wget, netcat, socat, scp, rsync, … |
| Block browsers | denylist | Chrome, Firefox, Edge, Safari, Brave, … |
| Strict lockdown | allowlist | default-deny + block unresolved; edit the allowlist. |

### Health checks

A background task polls each backend's `health_path` every
`health_check_interval_seconds` (skip with `0`). The current status of every
backend is always available on demand:

```
curl http://127.0.0.1:8011/healthz
```

### Notes & limitations

- The guard **buffers** responses (bounded by `max_body_bytes`) so it can parse
  token usage; streaming responses are therefore delivered in a single shot
  rather than incrementally.
- Hop-by-hop headers are stripped on forward.
- Content inspection is signature/heuristic based — tune
  `detect_*` / `block_on_*` to your tolerance for false positives before
  enabling hard blocking.

---

## 3. Dashboard UI (monitoring & configuration)

The Next.js analyst dashboard ships two LLM Guard surfaces. Both require sign-in;
editing configuration additionally requires an **admin** or **owner** role.

### Monitoring — `/llm-guard`

The **LLM Guard** item in the sidebar opens a live monitoring view. Pick a time
window (1h / 24h / 7d); the page auto-refreshes and shows:

- **Stat cards** — healthy backends, total requests, blocked requests,
  rate-limited requests, prompt-injection findings, PII findings, total tokens.
- **Backend health** — per-backend status (healthy / unhealthy), last HTTP
  status and latency. Powered by `GET /api/llm-guard/health`, which probes each
  backend's `health_path` directly.
- **Token usage trend** — hourly token consumption (Recharts area chart).
- **Recent security findings** — prompt-injection / PII detections, auth
  denials, rate-limit hits and upstream errors, each with provider, agent and
  host attribution.
- **Active sessions** — distinct callers (subjects) with request counts and last
  seen time.

Findings come from `GET /api/llm-guard/findings`, which aggregates `Event` rows
where `source = 'llm-guard'` (the events emitted by the reverse proxy and
relayed to the dashboard via `/api/sync`). If the database is unreachable the
page degrades gracefully and renders an empty-but-valid view rather than
erroring.

### Configuration — `/settings/llm-guard`

Admins/owners can manage the guard from the UI instead of hand-editing TOML:

- **General** — enable/disable, listen address, health-check interval, upstream
  timeout, max request-body size.
- **Backends** — add / edit / remove backends (name, kind, URL, route prefix,
  health path).
- **Authentication** — static API keys (masked on display) and optional HS256
  JWT (secret, issuer, audience).
- **Rate limits** — enable/disable, requests-per-minute, burst.
- **Monitoring** — content inspection, prompt-injection detection, PII
  detection, token tracking, `block_on_*` behaviour, and `max_prompt_chars`.

Secrets (API keys, JWT secret) are **masked** when fetched and only overwritten
when you submit a new value, so saving the form never clobbers existing
credentials. Settings persist to `data/llm-guard-config.json` via
`GET`/`POST /api/llm-guard/config`. Non-admins see the page read-only.
