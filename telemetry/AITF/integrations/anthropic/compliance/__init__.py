"""AITF integration for the Anthropic Claude Compliance API.

Maps the Compliance API Activity Feed to AITF / OCSF telemetry and provides a
small stdlib-only poller to page through the feed.

Docs: https://platform.claude.com/docs/en/manage-claude/compliance-api
"""

from integrations.anthropic.compliance.mapper import (
    ClaudeComplianceMapper,
    classify,
)
from integrations.anthropic.compliance.client import iter_activities

__all__ = [
    "ClaudeComplianceMapper",
    "classify",
    "iter_activities",
]
