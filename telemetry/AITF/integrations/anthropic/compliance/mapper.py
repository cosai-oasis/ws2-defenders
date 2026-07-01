"""AITF integration for the Anthropic Claude Compliance API.

Normalizes records from the Compliance API **Activity Feed**
(``GET /v1/compliance/activities``) into AITF / OCSF telemetry so Claude
Enterprise audit activity can be correlated alongside the rest of an
organization's AI telemetry and forwarded to a SIEM/XDR.

Docs: https://platform.claude.com/docs/en/manage-claude/compliance-api

The feed produces *hundreds* of forward-compatible activity types. Rather than
enumerate them, this mapper classifies each activity by keyword into the
existing OCSF class it reuses (per OCSF's "reuse objects and profiles" model):

    authentication / sso / session   -> IAM Authentication (3002)
    user / member / invite / scim    -> IAM Account Change (3001)
    role / group / permission        -> IAM User Access Management (3005)
    chat / file / project / content  -> Application Web Resources Activity (6001)
    compliance / export / api key    -> Application API Activity (6003)
    everything else (unknown types)  -> Application API Activity (6003), activity Other

Unknown / future activity and actor types are passed through (Anthropic's
forward-compatibility guidance) rather than dropped.

Usage::

    from integrations.anthropic.compliance import ClaudeComplianceMapper

    mapper = ClaudeComplianceMapper()
    for activity in feed:                 # dicts from the Activity Feed
        event = mapper.map_activity(activity)
        export_to_siem(event.model_dump(exclude_none=True))
"""

from __future__ import annotations

from typing import Any

from aitf.ocsf.schema import (
    AIBaseEvent,
    OCSFActor,
    OCSFClassUID,
    OCSFDevice,
    OCSFEnrichment,
    OCSFMetadata,
    OCSFObservable,
    OCSFSeverity,
    OCSFStatus,
)
from aitf.semantic_conventions.attributes import ClaudeComplianceAttributes as C


# --- classification --------------------------------------------------------

# (category_uid, class_uid, category_label) keyed by ordered keyword groups.
# First matching group wins; order matters (auth before account, etc.).
_KEYWORD_CLASS: list[tuple[tuple[str, ...], int, int, str]] = [
    (("login", "logout", "signin", "sign_in", "sign_out", "sso", "mfa",
      "session", "authenticat", "password"), 3, OCSFClassUID.AUTHENTICATION, "authentication"),
    (("role", "permission", "privilege", "group", "access_grant"), 3,
     OCSFClassUID.USER_ACCESS_MANAGEMENT, "access_management"),
    (("user", "member", "invite", "scim", "directory", "provision", "seat"), 3,
     OCSFClassUID.ACCOUNT_CHANGE, "account_change"),
    (("chat", "file", "project", "attachment", "message", "document",
      "artifact", "content", "setting", "policy"), 6,
     OCSFClassUID.WEB_RESOURCES_ACTIVITY, "content"),
    (("compliance", "api_key", "export", "workspace"), 6,
     OCSFClassUID.API_ACTIVITY, "administration"),
]

# verb keyword -> generic activity_id (Create/Read/Update/Delete/Other style).
_VERB_ACTIVITY: list[tuple[tuple[str, ...], int]] = [
    (("created", "added", "uploaded", "invited", "granted", "enabled",
      "started", "initiated"), 1),   # Create / Logon
    (("deleted", "removed", "revoked", "disabled", "ended", "completed"), 4),  # Delete
    (("updated", "edited", "changed", "renamed", "modified"), 3),  # Update
    (("viewed", "read", "downloaded", "exported", "listed", "accessed"), 2),  # Read
]


def classify(activity_type: str) -> tuple[int, int, int, str]:
    """Map a Compliance activity ``type`` to (category_uid, class_uid, activity_id, category)."""
    t = (activity_type or "").lower()

    category_uid, class_uid, category = 6, int(OCSFClassUID.API_ACTIVITY), "other"
    for keywords, cat, cls, label in _KEYWORD_CLASS:
        if any(k in t for k in keywords):
            category_uid, class_uid, category = cat, int(cls), label
            break

    # Authentication uses Logon(1)/Logoff(2) semantics.
    if class_uid == OCSFClassUID.AUTHENTICATION:
        if any(k in t for k in ("logout", "sign_out", "signout")):
            activity_id = 2
        elif any(k in t for k in ("login", "sign_in", "signin", "sso")):
            activity_id = 1
        else:
            activity_id = 99
        return category_uid, class_uid, activity_id, category

    activity_id = 99
    for verbs, aid in _VERB_ACTIVITY:
        if any(v in t for v in verbs):
            activity_id = aid
            break
    return category_uid, class_uid, activity_id, category


# --- actor -----------------------------------------------------------------

def _build_actor(actor: dict[str, Any]) -> OCSFActor:
    """Translate the Compliance actor union into an OCSF actor."""
    actor = actor or {}
    uid = (
        actor.get("user_id")
        or actor.get("api_key_id")
        or actor.get("admin_api_key_id")
        or actor.get("directory_id")
    )
    user: dict[str, Any] = {"type": actor.get("type")}
    if uid is not None:
        user["uid"] = str(uid)
    email = actor.get("email_address") or actor.get("unauthenticated_email_address")
    if email:
        user["email_addr"] = email
        user["name"] = email
    return OCSFActor(user=user)


# --- mapper ----------------------------------------------------------------

class ClaudeComplianceMapper:
    """Maps Claude Compliance Activity records to OCSF events (reuse model)."""

    PRODUCT = {
        "name": "Anthropic Claude Compliance API",
        "vendor_name": "Anthropic",
        "version": "v1",
    }

    def map_activity(self, activity: dict[str, Any]) -> AIBaseEvent:
        """Map a single Activity Feed record to an OCSF event."""
        activity_type = str(activity.get("type", "unknown"))
        category_uid, class_uid, activity_id, category = classify(activity_type)

        actor_raw = activity.get("actor") or {}
        device = None
        ip = actor_raw.get("ip_address")
        user_agent = actor_raw.get("user_agent")
        if ip:
            device = OCSFDevice(ip=str(ip))

        # Carry the activity-specific fields as enrichments + observables.
        enrichments: list[OCSFEnrichment] = [
            OCSFEnrichment(name=C.ACTIVITY_TYPE, value=activity_type, provider="claude_compliance"),
            OCSFEnrichment(name=C.ACTIVITY_CATEGORY, value=category, provider="claude_compliance"),
        ]
        for key, attr in (
            ("id", C.ACTIVITY_ID),
            ("organization_id", C.ORGANIZATION_ID),
            ("organization_uuid", C.ORGANIZATION_UUID),
            ("claude_chat_id", C.CHAT_ID),
            ("claude_project_id", C.PROJECT_ID),
            ("claude_file_id", C.FILE_ID),
            ("filename", C.FILENAME),
        ):
            if activity.get(key) is not None:
                enrichments.append(OCSFEnrichment(name=attr, value=str(activity[key])))
        if actor_raw.get("type"):
            enrichments.append(OCSFEnrichment(name=C.ACTOR_TYPE, value=str(actor_raw["type"])))
        if user_agent:
            enrichments.append(OCSFEnrichment(name=C.ACTOR_USER_AGENT, value=str(user_agent)))

        observables: list[OCSFObservable] = []
        email = actor_raw.get("email_address") or actor_raw.get("unauthenticated_email_address")
        if email:
            observables.append(OCSFObservable(name=C.ACTOR_EMAIL, type="Email Address", value=str(email)))
        if ip:
            observables.append(OCSFObservable(name=C.ACTOR_IP, type="IP Address", value=str(ip)))
        if actor_raw.get("user_id"):
            observables.append(OCSFObservable(name=C.ACTOR_USER_ID, type="User", value=str(actor_raw["user_id"])))

        # Failures are encoded in the type for most events; default Success.
        status_id = OCSFStatus.FAILURE if any(
            k in activity_type.lower() for k in ("failed", "denied", "rejected", "error")
        ) else OCSFStatus.SUCCESS

        kwargs: dict[str, Any] = dict(
            category_uid=category_uid,
            class_uid=class_uid,
            activity_id=activity_id,
            severity_id=OCSFSeverity.INFORMATIONAL,
            status_id=status_id,
            message=activity_type,
            metadata=OCSFMetadata(product=self.PRODUCT),
            actor=_build_actor(actor_raw),
            device=device,
            enrichments=enrichments,
            observables=observables,
        )
        if activity.get("created_at"):
            kwargs["time"] = str(activity["created_at"])
        return AIBaseEvent(**kwargs)

    def map_activities(self, activities: list[dict[str, Any]]) -> list[AIBaseEvent]:
        """Map a page of Activity records to OCSF events."""
        return [self.map_activity(a) for a in activities]
