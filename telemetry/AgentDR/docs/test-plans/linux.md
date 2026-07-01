# AgentDR — Linux Test Plan / Demo Script

> Target platform: Ubuntu 22.04 / Debian 12 / RHEL 9, x86_64 or aarch64.
> Estimated runtime: 20 min walkthrough, 40 min full plan.
> **Strength of this platform:** native kernel telemetry via NETLINK_AUDIT
> works out of the box — best demo for the Tier 6 "things current OSS
> AI-telemetry projects skip" story.

## Setup

```bash
# 0.1 Install
curl -fsSL https://github.com/girdav01/agentdr/releases/latest/download/agentdr_0.2.0_amd64.deb -o /tmp/agentdr.deb
sudo apt-get install -y /tmp/agentdr.deb     # or `dnf install agentdr-*.rpm` on RHEL
sudo systemctl status agentdr | head -8

# 0.2 Verify
adr-agent --version
adr-agent verify

# 0.3 Clean demo root (the systemd unit uses /var/lib/agentdr; for live demos
# we keep that running and use a per-demo root in the user's home).
export DEMO_ROOT="$HOME/agentdr-demo"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
```

Expect `Active: active (running)` on the systemd unit.

---

## Tier 1 — local agent telemetry

### STEP T1.1 — runtime hooks

```bash
adr-agent hooks install all --endpoint http://127.0.0.1:4318
adr-agent hooks status | jq '{claude: .claude_code.installed, cursor: .cursor.installed, codex: .codex.installed, aider: .aider.installed}'
```

**expect**: all four `true`.

### STEP T1.2 — start in foreground

```bash
adr-agent --root "$DEMO_ROOT" start --watch ~ &
AGENT_PID=$!
sleep 1
```

### STEP T1.3 — fire an OTel span (same payload as macOS T1.3)

See `macos.md` STEP T1.3 — the JSON payload is identical. Confirm:

```bash
tail -2 "$DEMO_ROOT/logs/events.jsonl" | jq '{class_uid, event_type, provider, tool_name}'
```

### STEP T1.4 — MCP inventory + wrap

Same as macOS T1.4 / T1.5.

---

## Tier 2 — fleet deployment (systemd)

### STEP T2.1 — confirm hardened unit

```bash
systemctl cat agentdr | grep -E 'ProtectSystem|NoNewPrivileges|MemoryDenyWriteExecute'
```

**expect**:
```
ProtectSystem=strict
NoNewPrivileges=true
MemoryDenyWriteExecute=true
```

> DEMO NARRATION: *"The systemd unit drops every privilege the agent
> doesn't strictly need — write-only to its own data dir, no
> namespacing, no new privileges, no executable heap. That's what
> production endpoint software should look like."*

### STEP T2.2 — show packaging artefacts

```bash
ls /usr/bin/adr-agent /etc/agentdr/config.toml /var/lib/agentdr /var/log/agentdr
dpkg -V agentdr   # or `rpm -V agentdr`
```

**expect**: no output (no integrity drift).

---

## Tier 3 — vendor exporters (Datadog + syslog combo)

Linux is the best platform for showing **multiple destinations in parallel**
because UDP syslog and a Datadog Agent both run cleanly here.

### STEP T3.1 — set up both backends

```bash
# UDP syslog receiver
sudo nc -kluv 0.0.0.0 5514 &  NC_PID=$!

# Datadog API key (optional — comment out if you don't want a live key)
export DD_KEY="$DD_KEY"
```

### STEP T3.2 — enable both exporters

```bash
sudo tee -a /etc/agentdr/config.toml <<EOF

[exporters.syslog]
enabled  = true
protocol = "udp"
address  = "127.0.0.1:5514"

[exporters.datadog]
enabled  = ${DD_KEY:+true}${DD_KEY:-false}
api_key  = "$DD_KEY"
site     = "datadoghq.com"
tags     = ["env:demo", "team:secops"]
EOF
sudo systemctl restart agentdr
journalctl -u agentdr -n 15 --no-pager | grep -E 'exporters|policy'
```

**expect**: `vendor exporters active: ["syslog", "datadog"]` (or just
`["syslog"]` if you skipped DD).

### STEP T3.3 — fire an event

Re-run T1.3. Within ~5 s the syslog receiver shows the RFC 5424 line and
(if enabled) the event appears in Datadog Logs filterable by
`service:agentdr`.

---

## Tier 4 — UEBA / dashboard

(Same as macos.md Tier 4 — the dashboard is platform-agnostic.)

---

## Tier 5 — governance

### STEP T5.1 — policy decision (same as macOS)

```bash
adr-agent policy test <<'JSON'
{"timestamp":"2026-05-17T00:00:00Z","event_type":"file_read",
 "details":{"path":"/home/david/.aws/credentials"},"risk_level":"low",
 "trace_id":"deadbeefcafef00d","span_id":"1234567890abcdef"}
JSON
```

### STEP T5.2 — block egress at the proxy level

```bash
sudo tee -a /etc/agentdr/config.toml <<EOF

[proxy]
enabled   = true
bind      = "127.0.0.1:18080"
allowlist = ["anthropic.com"]
EOF
sudo systemctl restart agentdr
HTTPS_PROXY=http://127.0.0.1:18080 curl -s -o /dev/null -w 'HTTP %{http_code}\n' https://api.openai.com/v1/models --max-time 5
```

**expect**: `HTTP 000` (curl reports failed CONNECT because the proxy
returned 403 and closed). Verify the block event was emitted:

```bash
sudo grep proxy_block /var/log/agentdr/stdout.log /var/lib/agentdr/logs/events.jsonl 2>/dev/null | tail -1
```

### STEP T5.3 — approval-flow capture

Same as macOS T5.5.

---

## Tier 6 — kernel / shell / browser / attribution **(showcase platform)**

### STEP T6.1 — enable kernel auditing

```bash
sudo tee -a /etc/agentdr/config.toml <<EOF

[kernel]
enabled = true
EOF
sudo systemctl restart agentdr
journalctl -u agentdr -n 50 --no-pager | grep -E 'NETLINK_AUDIT|kernel_monitor'
```

**expect**:
```
INFO kernel: subscribed to NETLINK_AUDIT multicast
```

> DEMO NARRATION: *"That's it — no eBPF program to compile, no
> kernel-module install, no dependency. Just plain Linux audit on a
> multicast netlink group. This is what runs in production."*

### STEP T6.2 — generate kernel activity

```bash
sudo auditctl -w /tmp/secret -p rwa -k demo
echo touched > /tmp/secret
sudo auditctl -W /tmp/secret -k demo
```

**emits**: `kernel_audit` events arrive within ~1 s. View:

```bash
sudo grep kernel_audit /var/lib/agentdr/logs/events.jsonl | tail -3 | jq '.details.record'
```

### STEP T6.3 — shell wrap (CI / agent shell-exec use case)

```bash
adr-agent --root "$DEMO_ROOT" shell wrap --name ci-bash -- bash -c 'whoami; uname -a; pwd'
tail -6 "$DEMO_ROOT/logs/events.jsonl" | jq '{event_type, risk_level, line: .details.line}'
```

### STEP T6.4 — browser CDP (headless Chromium)

```bash
google-chrome --headless --remote-debugging-port=9222 https://example.com &
CHROME_PID=$!
sudo tee -a /etc/agentdr/config.toml <<EOF

[browser]
enabled      = true
cdp_endpoint = "http://127.0.0.1:9222"
poll_seconds = 3
EOF
sudo systemctl restart agentdr
sleep 6
sudo grep browser_ /var/lib/agentdr/logs/events.jsonl | tail -3 | jq '{event_type, url: .details.url}'
```

### STEP T6.5 — credential attribution

```bash
# Spawn a "claude" process so the detector adds it to its attribution window
sleep 600 &  AGENT_LIKE=$!; rename_pid "$AGENT_LIKE" "claude"  # or just have Claude Code open
cat /home/$USER/.aws/credentials 2>/dev/null || echo "fake_aws_key" | sudo tee /tmp/agentdr-demo.aws > /dev/null
# Trigger the credential file pattern via the file_monitor
ln -sf /tmp/agentdr-demo.aws /tmp/aws-credentials
sudo cp /tmp/agentdr-demo.aws /var/lib/agentdr/watch/test.aws 2>/dev/null || true
sudo grep alert_credential_access /var/lib/agentdr/logs/events.jsonl | tail -1 | jq '.details.candidate_agents'
```

> DEMO NARRATION: *"Most AI-telemetry tools stop at 'a credential file
> was read'. AgentDR joins that read with every agent process running
> inside a 10-minute window so the analyst gets the suspect list, not
> just the finding."*

---

## RESET

```bash
kill $AGENT_PID $NC_PID $CHROME_PID $AGENT_LIKE 2>/dev/null
sudo systemctl restart agentdr
adr-agent hooks uninstall all
rm -rf "$DEMO_ROOT"
sudo auditctl -W /tmp/secret 2>/dev/null
unset HTTPS_PROXY
```

---

## Failure modes & quick fixes

| Symptom | Cause | Fix |
|---|---|---|
| `netlink audit: cannot open` | missing `CAP_AUDIT_READ` | unit ships with the capability bracket; if running ad-hoc, prepend `sudo` |
| `journalctl: No journal files` | machine is `/init`-less | check `/var/log/agentdr/stdout.log` instead |
| Audit events not flowing | another auditd subscriber is set to `exclusive` | `sudo auditctl -l` then change rules so multicast group 1 is shared |
| `apt: package not found` | repo not configured | use the direct .deb URL in the setup section |
