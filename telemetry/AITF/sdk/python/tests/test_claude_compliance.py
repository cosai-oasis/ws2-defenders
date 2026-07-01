"""Tests for the Anthropic Claude Compliance API integration mapper."""

import importlib.util
from pathlib import Path

# Load the mapper module directly from the repo-root integrations tree so the
# test does not trigger integrations.anthropic.__init__ (which imports SDK
# instrumentors that require optional vendor packages).
_REPO_ROOT = Path(__file__).resolve().parents[3]
_MAPPER_PATH = _REPO_ROOT / "integrations" / "anthropic" / "compliance" / "mapper.py"
_spec = importlib.util.spec_from_file_location("claude_compliance_mapper", _MAPPER_PATH)
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)


class TestClassify:
    def test_authentication(self):
        assert cc.classify("sso_login_initiated") == (3, 3002, 1, "authentication")
        assert cc.classify("user_sign_out") == (3, 3002, 2, "authentication")

    def test_account_change(self):
        assert cc.classify("user_added")[:2] == (3, 3001)
        assert cc.classify("user_removed") == (3, 3001, 4, "account_change")

    def test_access_management(self):
        assert cc.classify("role_permission_granted") == (3, 3005, 1, "access_management")
        assert cc.classify("group_member_added")[:2] == (3, 3005)

    def test_content(self):
        assert cc.classify("claude_chat_created") == (6, 6001, 1, "content")
        assert cc.classify("claude_file_uploaded") == (6, 6001, 1, "content")
        assert cc.classify("chat_message_viewed") == (6, 6001, 2, "content")

    def test_unknown_is_forward_compatible(self):
        # New/unknown types fall back to API Activity / Other, never dropped.
        assert cc.classify("some_brand_new_future_event") == (6, 6003, 99, "other")


class TestMapActivity:
    def setup_method(self):
        self.mapper = cc.ClaudeComplianceMapper()

    def test_chat_created_maps_to_web_resources(self):
        event = self.mapper.map_activity({
            "id": "activity_1",
            "created_at": "2026-04-10T08:09:10Z",
            "organization_id": "org_1",
            "actor": {
                "type": "user_actor",
                "email_address": "u@example.com",
                "user_id": "user_1",
                "ip_address": "192.0.2.34",
                "user_agent": "Mozilla/5.0",
            },
            "type": "claude_chat_created",
            "claude_chat_id": "chat_1",
            "claude_project_id": "proj_1",
        })
        assert event.category_uid == 6
        assert event.class_uid == 6001
        assert event.type_uid == 600101
        assert event.time == "2026-04-10T08:09:10Z"
        assert event.actor.user["uid"] == "user_1"
        assert event.actor.user["email_addr"] == "u@example.com"
        assert event.device.ip == "192.0.2.34"
        names = {e.name: e.value for e in event.enrichments}
        assert names["claude.compliance.chat.id"] == "chat_1"
        assert names["claude.compliance.activity.type"] == "claude_chat_created"
        obs = {o.value for o in event.observables}
        assert "192.0.2.34" in obs and "u@example.com" in obs

    def test_login_maps_to_authentication(self):
        event = self.mapper.map_activity({
            "id": "a2",
            "created_at": "2026-04-10T09:00:00Z",
            "actor": {"type": "unauthenticated_user_actor",
                      "unauthenticated_email_address": "x@example.com",
                      "ip_address": "10.0.0.1"},
            "type": "sso_login_initiated",
        })
        assert (event.category_uid, event.class_uid, event.activity_id) == (3, 3002, 1)
        assert event.metadata.product["vendor_name"] == "Anthropic"

    def test_scim_user_added_maps_to_account_change(self):
        event = self.mapper.map_activity({
            "id": "a3",
            "actor": {"type": "scim_directory_sync_actor", "directory_id": "dir_1"},
            "type": "user_added",
        })
        assert (event.category_uid, event.class_uid) == (3, 3001)
        assert event.actor.user["uid"] == "dir_1"
        # No created_at -> falls back to a generated timestamp (non-empty).
        assert event.time

    def test_failure_status_detected(self):
        event = self.mapper.map_activity({"id": "a4", "actor": {"type": "api_actor"},
                                          "type": "sso_login_failed"})
        assert event.status_id == 2  # Failure

    def test_map_activities_batch(self):
        events = self.mapper.map_activities([
            {"id": "x1", "actor": {"type": "api_actor"}, "type": "claude_file_uploaded"},
            {"id": "x2", "actor": {"type": "api_actor"}, "type": "compliance_export_created"},
        ])
        assert [e.class_uid for e in events] == [6001, 6003]
