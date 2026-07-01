# Contributing to CoSAI Community Detection Rules

Thank you for helping improve AI agent detection coverage! This guide explains how to add new agent signatures, endpoint patterns, and detection rules.

## Adding a New Agent Signature

1. Open `rules/agent-signatures.json`
2. Add a new entry to the `signatures` array:

```json
{
  "id": "my-agent",
  "name": "My Agent",
  "framework": "Agent Framework",
  "category": "coding|general|workflow|enterprise|browser",
  "risk": "low|medium|high",
  "process_patterns": ["myagent", "my-agent", "myagent.exe"]
}
```

### Field Definitions

| Field | Required | Description |
|-------|----------|-------------|
| `id` | ✅ | Unique kebab-case identifier |
| `name` | ✅ | Human-readable display name |
| `framework` | ✅ | Underlying framework or vendor |
| `category` | ✅ | One of: `coding`, `general`, `workflow`, `enterprise`, `browser` |
| `risk` | ✅ | Default risk level: `low`, `medium`, or `high` |
| `process_patterns` | ✅ | Array of lowercase substrings to match in process name/cmdline |

### Guidelines

- **Process patterns** should be lowercase and as specific as possible to avoid false positives
- If the agent has multiple executables or aliases, include all of them in `process_patterns`
- Choose the risk level based on the agent's default capabilities (file access, code execution, network access)
- Test your patterns against known process lists before submitting

## Adding a New AI Endpoint

1. Open `rules/ai-endpoints.json`
2. Add a new entry to the `endpoints` array:

```json
{
  "patterns": ["api.newprovider.com"],
  "provider": "New Provider",
  "model": "default-model"
}
```

## Adding a New Detection Rule

1. Open `policies/detection-rules.json`
2. Add a new entry using the next available `AITF-DET-XXX` ID
3. Choose an appropriate `ai_operation` profile and its reused OCSF class

## Pull Request Checklist

- [ ] JSON is valid (use `jq . < filename.json`)
- [ ] No duplicate `id` values
- [ ] Process patterns tested against real process names
- [ ] Risk level justified in PR description
- [ ] Version number bumped in the modified file
