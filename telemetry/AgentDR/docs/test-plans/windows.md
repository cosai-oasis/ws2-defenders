# AgentDR — Windows Test Plan / Demo Script

> Target platform: Windows 10 22H2 / 11 23H2 / Windows Server 2022.
> Estimated runtime: 20 min walkthrough, 35 min full plan.
> **Strength of this platform:** the MSI / Intune story for enterprise
> fleets. The kernel-telemetry segment is a "show the ETW gap and how we
> address it via the syslog exporter" rather than live netlink.

## Setup (PowerShell, run as Administrator)

```powershell
# 0.1 Install via Scoop (single-line install)
scoop bucket add agentdr https://github.com/girdav01/agentdr
scoop install agentdr

# 0.2 — or — install the signed MSI (enterprise distribution path)
msiexec /i agentdr-0.2.0.msi /qn

# 0.3 Confirm the service is registered and started
Get-Service AgentDR | Format-Table -AutoSize
adr-agent --version
adr-agent verify

# 0.4 Per-demo root
$env:DEMO_ROOT = "$env:USERPROFILE\agentdr-demo"
Remove-Item -Recurse -Force $env:DEMO_ROOT -ErrorAction Ignore
New-Item -ItemType Directory -Force $env:DEMO_ROOT | Out-Null
```

Expect `Status: Running` and `adr-agent 0.2.0`.

---

## Tier 1 — local agent telemetry

### STEP T1.1 — hooks for each installed agent

```powershell
adr-agent hooks install all --endpoint http://127.0.0.1:4318
adr-agent hooks status | ConvertFrom-Json | Format-List
```

**expect**: a managed config file under `$env:APPDATA\.claude\`,
`$env:USERPROFILE\.cursor\`, etc., depending on which agents are
installed.

### STEP T1.2 — start a foreground agent (separate from the service)

```powershell
Start-Process adr-agent -ArgumentList '--root', $env:DEMO_ROOT, 'start' -NoNewWindow -PassThru
```

### STEP T1.3 — send the synthetic OTel span

```powershell
$payload = @'
{"resourceSpans":[{"resource":{"attributes":[
  {"key":"service.name","value":{"stringValue":"claude-code"}},
  {"key":"host.name","value":{"stringValue":"laptop-w11"}},
  {"key":"user.name","value":{"stringValue":"admin"}}]},
 "scopeSpans":[{"spans":[
   {"traceId":"9b7f0c8d2e1a4f5b6c7d8e9f0a1b2c3d","spanId":"1a2b3c4d5e6f7a8b","name":"chat",
    "attributes":[
      {"key":"gen_ai.system","value":{"stringValue":"anthropic"}},
      {"key":"gen_ai.request.model","value":{"stringValue":"claude-sonnet-4-5"}},
      {"key":"gen_ai.usage.input_tokens","value":{"intValue":"1240"}}]}]}]}]}
'@
Invoke-RestMethod -Uri http://127.0.0.1:4318/v1/traces -Method Post -ContentType application/json -Body $payload
Get-Content "$env:DEMO_ROOT\logs\events.jsonl" -Tail 1 | ConvertFrom-Json | Format-List class_uid, ai_operation, event_type, provider
```

### STEP T1.4 — MCP inventory (catches Windows-specific config paths)

```powershell
adr-agent mcp inventory --jsonl | ForEach-Object { $_ | ConvertFrom-Json | Format-List details.runtime, details.name, details.transport }
```

Watch for the Claude Desktop config path under `$env:APPDATA\Claude\`.

---

## Tier 2 — enterprise distribution

### STEP T2.1 — show the service installed by the MSI

```powershell
Get-WmiObject win32_service | Where-Object Name -EQ AgentDR | Select-Object Name, State, StartMode, StartName
```

**expect**: `Running`, `Auto`, `LocalSystem`.

### STEP T2.2 — Intune policy preview (no live tenant required)

```powershell
Get-Content .\mdm\intune\agentdr-windows-policy.json | ConvertFrom-Json | Select-Object -ExpandProperty settings | Format-Table id, settingInstance.settingDefinitionId -AutoSize
```

> DEMO NARRATION: *"This JSON is what an Intune admin imports as a
> Custom Settings Catalog policy. It delivers a managed config.toml to
> every device and restarts the AgentDR service to pick it up. No
> reimaging required."*

### STEP T2.3 — verify the MSI doesn't overwrite operator-edited config

```powershell
Add-Content C:\ProgramData\AgentDR\config.toml "`n# operator change"
msiexec /i agentdr-0.2.0.msi /qn /norestart REINSTALL=ALL REINSTALLMODE=vomus
Get-Content C:\ProgramData\AgentDR\config.toml | Select-String 'operator change'
```

**expect**: the comment is still present (the `NeverOverwrite="yes"` flag
on the config component does its job).

---

## Tier 3 — vendor exporters (Splunk + Sentinel combo)

Windows is the right platform for showing **Sentinel** because that's
where Azure-shop SOCs actually run.

### STEP T3.1 — enable Sentinel + Splunk

```powershell
@"

[exporters.splunk]
enabled    = true
endpoint   = "https://splunk.example.com:8088"
token      = "$env:SPLUNK_HEC_TOKEN"
sourcetype = "agentdr:aitf"

[exporters.sentinel]
enabled       = true
workspace_id  = "$env:SENTINEL_WS_ID"
shared_key    = "$env:SENTINEL_SHARED_KEY"
log_type      = "AgentDR_AITF"
"@ | Add-Content C:\ProgramData\AgentDR\config.toml

Restart-Service AgentDR
Get-Content C:\ProgramData\AgentDR\logs\agent_runtime.log -Tail 20 | Select-String 'exporters'
```

**expect**: `vendor exporters active: ["splunk", "sentinel"]`.

### STEP T3.2 — fire an event, verify both backends ingested

Re-run STEP T1.3. In Splunk run `index=* sourcetype=agentdr:aitf`. In
Sentinel run `AgentDR_AITF_CL | take 5`. Both should show the event
within ~30 seconds.

---

## Tier 4 — dashboard

(Same as macos.md.)

---

## Tier 5 — governance

### STEP T5.1 — same policy CLI test

```powershell
$ev = @'
{"timestamp":"2026-05-17T00:00:00Z","event_type":"file_read",
 "details":{"path":"C:\\Users\\admin\\.aws\\credentials"},
 "risk_level":"low",
 "trace_id":"deadbeefcafef00d","span_id":"1234567890abcdef"}
'@
$ev | adr-agent policy test
```

### STEP T5.2 — inline proxy

```powershell
@"

[proxy]
enabled   = true
bind      = "127.0.0.1:18080"
allowlist = ["anthropic.com"]
"@ | Add-Content C:\ProgramData\AgentDR\config.toml
Restart-Service AgentDR

$env:HTTPS_PROXY = 'http://127.0.0.1:18080'
Invoke-WebRequest https://api.openai.com/v1/models -UseBasicParsing -TimeoutSec 5 -ErrorAction Continue
```

**expect**: `(403) Forbidden` from `Proxy-Agent: AgentDR`.

---

## Tier 6 — kernel / shell / browser / attribution

### STEP T6.1 — kernel telemetry (ETW posture note)

```powershell
adr-agent --root $env:DEMO_ROOT start 2>&1 | Select-String 'kernel_monitor_warning' | Select-Object -First 1
```

**expect** (verbatim):
```
Windows ETW requires Administrator. Enable the
Microsoft-Windows-Kernel-Process and Microsoft-Windows-Audit providers
with wevtutil and forward to AgentDR via the syslog exporter.
```

> DEMO NARRATION: *"On Windows we don't reinvent ETW — we tell admins to
> turn on the kernel providers they're already audited against, and we
> consume the resulting events through our syslog exporter. The SOC
> story stays the same; the plumbing is native."*

### STEP T6.2 — minimal ETW pipeline (optional — needs wevtutil)

```powershell
# Enable the kernel-process channel
wevtutil sl Microsoft-Windows-Kernel-Process/Analytic /e:true /q:true
# Forward to AgentDR's syslog port (set up an Event Log Subscription
# that writes selected events to a file the file_monitor watches).
```

### STEP T6.3 — shell wrap

```powershell
'whoami','pwd','dir C:\Windows\Temp' | adr-agent --root $env:DEMO_ROOT shell wrap --name win-shell -- cmd /q
Get-Content "$env:DEMO_ROOT\logs\events.jsonl" -Tail 10 | ForEach-Object { $_ | ConvertFrom-Json } | Format-Table event_type, risk_level
```

### STEP T6.4 — Edge browser CDP attach

```powershell
Start-Process msedge -ArgumentList '--remote-debugging-port=9222','https://example.com'
@"

[browser]
enabled      = true
cdp_endpoint = "http://127.0.0.1:9222"
poll_seconds = 3
"@ | Add-Content C:\ProgramData\AgentDR\config.toml
Restart-Service AgentDR
Start-Sleep 6
Get-Content C:\ProgramData\AgentDR\logs\events.jsonl | Select-String 'browser_' | Select-Object -Last 3
```

### STEP T6.5 — credential attribution

```powershell
# Triggering AWS credentials path on Windows
Get-Content "$env:USERPROFILE\.aws\credentials" -ErrorAction Ignore
Get-Content C:\ProgramData\AgentDR\logs\events.jsonl | Select-String 'alert_credential_access' | Select-Object -Last 1
```

---

## RESET

```powershell
Stop-Service AgentDR
adr-agent hooks uninstall all
Remove-Item -Recurse -Force $env:DEMO_ROOT -ErrorAction Ignore
Remove-Item Env:HTTPS_PROXY -ErrorAction Ignore
Start-Service AgentDR
```

---

## Failure modes & quick fixes

| Symptom | Cause | Fix |
|---|---|---|
| Service won't start | port 4318 already bound by another app | `netstat -ano | findstr 4318` then kill, or set `[otlp].bind` |
| Edge CDP unreachable | profile is using IE-mode | start with `--user-data-dir=C:\Temp\edge-cdp` to force a fresh profile |
| Sentinel HMAC errors | `shared_key` decoded incorrectly | confirm the key is the base64 string from the workspace settings page, not the workspace GUID |
| `Test-AgentDR ... Access denied` | running PowerShell as user instead of Admin | re-launch as Administrator (most steps require it for the service-level operations) |
