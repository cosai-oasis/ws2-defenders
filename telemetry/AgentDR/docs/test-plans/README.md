# AgentDR Test Plans / Demo Scripts

This directory contains **reusable test plans** for each supported endpoint
platform. They serve three audiences:

1. **QA** — repeatable, idempotent verification of every Tier 1–6 capability.
2. **Sales / SE demos** — turn-key 10-, 20- or 45-minute walkthroughs with
   expected output captured inline so you know when a demo has drifted.
3. **Conference talks** — DEF CON AI Village (see
   `../presentations/defcon-ai-village-2026.md`) uses the macOS plan as the
   live-demo backbone.

## Files

| Plan | When to use |
|---|---|
| [`macos.md`](macos.md)     | Default demo platform. Most coding-agent installs are on Macs. |
| [`linux.md`](linux.md)     | Cloud / container / CI runners. Best for the kernel-telemetry demo (NETLINK_AUDIT). |
| [`windows.md`](windows.md) | Enterprise endpoint demo. Best for the MSI / Intune story. |

Every plan follows the same shape:

```
SETUP   →   T1 (telemetry)  →  T2 (deploy)  →  T3 (exporters)
        →   T4 (UEBA)       →  T5 (govern)  →  T6 (kernel/shell/browser)
        →   RESET
```

so the same audience expectations transfer between platforms.

## Reset between runs

Every demo writes events to `<root>/logs/events.jsonl`. To get back to a
clean slate:

```bash
adr-agent hooks uninstall all
pkill -f adr-agent     # or `Stop-Service AgentDR` on Windows
rm -rf <root>          # the entire data directory
```

Reset takes < 5 seconds and is safe between back-to-back demos.

## Convention

Each step is labelled `STEP N` and shows:

* **what** — one-line description
* **command** — exact shell invocation (copy-paste)
* **expect** — the line of output that signals success
* **emits** — the AgentDR event class_uid the audience should see in the
  dashboard

Anywhere you see `# DEMO NARRATION:` is a sentence the presenter can read
aloud — it's calibrated to match the on-screen output so the explanation
arrives at the same time as the result.
