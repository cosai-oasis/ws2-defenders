"""Minimal, dependency-free poller for the Claude Compliance Activity Feed.

Pages through ``GET /v1/compliance/activities`` using the documented cursor
contract (``after_id`` / ``last_id`` / ``has_more``) with only the Python
standard library, yielding raw Activity dicts. Pair with
:class:`~integrations.anthropic.compliance.mapper.ClaudeComplianceMapper` to
normalize them to OCSF.

Docs: https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed

Example::

    from integrations.anthropic.compliance import iter_activities, ClaudeComplianceMapper

    mapper = ClaudeComplianceMapper()
    for activity in iter_activities(api_key, activity_types=["claude_chat_created"]):
        event = mapper.map_activity(activity)
        ...
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any

_BASE_URL = "https://api.anthropic.com/v1/compliance/activities"
_MAX_LIMIT = 5000


def iter_activities(
    api_key: str,
    *,
    activity_types: list[str] | None = None,
    organization_ids: list[str] | None = None,
    actor_ids: list[str] | None = None,
    created_at_gte: str | None = None,
    created_at_lt: str | None = None,
    after_id: str | None = None,
    limit: int = 100,
    base_url: str = _BASE_URL,
    timeout: float = 30.0,
) -> Iterator[dict[str, Any]]:
    """Yield Activity records from the feed, following pagination to the end.

    ``after_id`` lets a caller resume from a previously persisted cursor.
    Repeatable filters use array-bracket syntax (``activity_types[]=...``).
    """
    if not 1 <= limit <= _MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {_MAX_LIMIT}")

    base_params: list[tuple[str, str]] = [("limit", str(limit))]
    for value in activity_types or []:
        base_params.append(("activity_types[]", value))
    for value in organization_ids or []:
        base_params.append(("organization_ids[]", value))
    for value in actor_ids or []:
        base_params.append(("actor_ids[]", value))
    if created_at_gte:
        base_params.append(("created_at.gte", created_at_gte))
    if created_at_lt:
        base_params.append(("created_at.lt", created_at_lt))

    cursor = after_id
    while True:
        params = list(base_params)
        if cursor:
            params.append(("after_id", cursor))
        url = f"{base_url}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers={"x-api-key": api_key})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted host)
            payload = json.loads(resp.read().decode("utf-8"))

        for activity in payload.get("data", []):
            yield activity

        if not payload.get("has_more"):
            break
        cursor = payload.get("last_id")
        if not cursor:
            break
