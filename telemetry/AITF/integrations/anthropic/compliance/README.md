# Anthropic Claude Compliance API → AITF

Ingest the [Claude Compliance API](https://platform.claude.com/docs/en/manage-claude/compliance-api)
**Activity Feed** (`GET /v1/compliance/activities`) and normalize each audit
activity into AITF / OCSF telemetry for SIEM/XDR correlation.

The Activity Feed records every authentication, chat, file, project,
administrative, and platform action in a Claude Enterprise org (per-event,
retained 6 years). This integration turns those records into OCSF events using
AITF's **class-reuse** model — no bespoke AI category.

## Mapping

Activities are classified by keyword (forward-compatible: unknown types are
mapped, never dropped) onto the OCSF class they reuse:

| Activity (examples) | OCSF category | OCSF class | `class_uid` |
|---|---|---|---|
| `sso_login_initiated`, `*_sign_out`, mfa/session | 3 IAM | Authentication | 3002 |
| `user_added/removed`, `*_invite`, SCIM/directory | 3 IAM | Account Change | 3001 |
| `role_*`, `group_member_*`, permission/privilege | 3 IAM | User Access Management | 3005 |
| `claude_chat_*`, `claude_file_*`, project/content/settings | 6 Application | Web Resources Activity | 6001 |
| `compliance_*`, `*_export`, api key / workspace | 6 Application | API Activity | 6003 |
| anything unrecognized | 6 Application | API Activity | 6003 (Other) |

The `actor` union (`user_actor`, `api_actor`, `admin_api_key_actor`,
`unauthenticated_user_actor`, `anthropic_actor`, `scim_directory_sync_actor`)
maps to the OCSF `actor`; IP → `device.ip`; email/IP/user id become
`observables`; activity/resource ids (`claude_chat_id`, `claude_project_id`,
`claude_file_id`, …) become `enrichments` under the
`claude.compliance.*` semantic conventions.

## Usage

```python
from integrations.anthropic.compliance import ClaudeComplianceMapper, iter_activities

mapper = ClaudeComplianceMapper()

# Poll the feed (stdlib only) and normalize to OCSF:
for activity in iter_activities(
    api_key=os.environ["ANTHROPIC_COMPLIANCE_ACCESS_KEY"],
    activity_types=["claude_chat_created", "claude_file_uploaded"],
    created_at_gte="2026-04-01T00:00:00Z",
):
    event = mapper.map_activity(activity)
    forward_to_siem(event.model_dump(exclude_none=True))
```

`iter_activities` follows the documented cursor contract (`after_id` /
`last_id` / `has_more`); pass a persisted `after_id` to resume. If you already
have Activity dicts (e.g. from your own poller), call `mapper.map_activity(...)`
directly — the mapper has no network dependency.

## Notes

- Requires a Compliance Access Key (or Admin API key for the Activity Feed
  only) with the `read:compliance_activities` scope.
- The mapper depends only on the `aitf` package; the poller uses only the
  Python standard library.
- Content endpoints (chats/files/projects bodies) are out of scope here — this
  integration covers the audit **Activity Feed**.
