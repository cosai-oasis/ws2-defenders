package ocsf

import "testing"

func TestClaudeClassifyAuthentication(t *testing.T) {
	cat, cls, aid, label := Classify("sso_login_initiated")
	if cat != 3 || cls != 3002 || aid != 1 || label != "authentication" {
		t.Fatalf("sso_login_initiated => (%d, %d, %d, %q), want (3, 3002, 1, authentication)", cat, cls, aid, label)
	}
	cat, cls, aid, label = Classify("user_sign_out")
	if cat != 3 || cls != 3002 || aid != 2 || label != "authentication" {
		t.Fatalf("user_sign_out => (%d, %d, %d, %q), want (3, 3002, 2, authentication)", cat, cls, aid, label)
	}
}

func TestClaudeClassifyAccountChange(t *testing.T) {
	cat, cls, _, _ := Classify("user_added")
	if cat != 3 || cls != 3001 {
		t.Fatalf("user_added => (%d, %d), want (3, 3001)", cat, cls)
	}
	cat, cls, aid, label := Classify("user_removed")
	if cat != 3 || cls != 3001 || aid != 4 || label != "account_change" {
		t.Fatalf("user_removed => (%d, %d, %d, %q), want (3, 3001, 4, account_change)", cat, cls, aid, label)
	}
}

func TestClaudeClassifyAccessManagement(t *testing.T) {
	cat, cls, aid, label := Classify("role_permission_granted")
	if cat != 3 || cls != 3005 || aid != 1 || label != "access_management" {
		t.Fatalf("role_permission_granted => (%d, %d, %d, %q), want (3, 3005, 1, access_management)", cat, cls, aid, label)
	}
	cat, cls, _, _ = Classify("group_member_added")
	if cat != 3 || cls != 3005 {
		t.Fatalf("group_member_added => (%d, %d), want (3, 3005)", cat, cls)
	}
}

func TestClaudeClassifyContent(t *testing.T) {
	cat, cls, aid, label := Classify("claude_chat_created")
	if cat != 6 || cls != 6001 || aid != 1 || label != "content" {
		t.Fatalf("claude_chat_created => (%d, %d, %d, %q), want (6, 6001, 1, content)", cat, cls, aid, label)
	}
	cat, cls, aid, label = Classify("claude_file_uploaded")
	if cat != 6 || cls != 6001 || aid != 1 || label != "content" {
		t.Fatalf("claude_file_uploaded => (%d, %d, %d, %q), want (6, 6001, 1, content)", cat, cls, aid, label)
	}
	cat, cls, aid, label = Classify("chat_message_viewed")
	if cat != 6 || cls != 6001 || aid != 2 || label != "content" {
		t.Fatalf("chat_message_viewed => (%d, %d, %d, %q), want (6, 6001, 2, content)", cat, cls, aid, label)
	}
}

func TestClaudeClassifyUnknownIsForwardCompatible(t *testing.T) {
	cat, cls, aid, label := Classify("some_brand_new_future_event")
	if cat != 6 || cls != 6003 || aid != 99 || label != "other" {
		t.Fatalf("unknown => (%d, %d, %d, %q), want (6, 6003, 99, other)", cat, cls, aid, label)
	}
}

func TestClaudeMapChatCreatedMapsToWebResources(t *testing.T) {
	m := NewClaudeComplianceMapper()
	event := m.MapActivity(map[string]interface{}{
		"id":              "activity_1",
		"created_at":      "2026-04-10T08:09:10Z",
		"organization_id": "org_1",
		"actor": map[string]interface{}{
			"type":          "user_actor",
			"email_address": "u@example.com",
			"user_id":       "user_1",
			"ip_address":    "192.0.2.34",
			"user_agent":    "Mozilla/5.0",
		},
		"type":              "claude_chat_created",
		"claude_chat_id":    "chat_1",
		"claude_project_id": "proj_1",
	})
	if event.CategoryUID != 6 {
		t.Fatalf("category_uid = %d, want 6", event.CategoryUID)
	}
	if event.ClassUID != 6001 {
		t.Fatalf("class_uid = %d, want 6001", event.ClassUID)
	}
	if event.TypeUID != 600101 {
		t.Fatalf("type_uid = %d, want 600101", event.TypeUID)
	}
	if event.Time != "2026-04-10T08:09:10Z" {
		t.Fatalf("time = %q, want 2026-04-10T08:09:10Z", event.Time)
	}
	if event.Actor.User["uid"] != "user_1" {
		t.Fatalf("actor uid = %v, want user_1", event.Actor.User["uid"])
	}
	if event.Actor.User["email_addr"] != "u@example.com" {
		t.Fatalf("actor email_addr = %v, want u@example.com", event.Actor.User["email_addr"])
	}
	if event.Device == nil || event.Device.IP != "192.0.2.34" {
		t.Fatalf("device ip = %v, want 192.0.2.34", event.Device)
	}
	names := map[string]string{}
	for _, e := range event.Enrichments {
		names[e.Name] = e.Value
	}
	if names["claude.compliance.chat.id"] != "chat_1" {
		t.Fatalf("chat.id enrichment = %q, want chat_1", names["claude.compliance.chat.id"])
	}
	if names["claude.compliance.activity.type"] != "claude_chat_created" {
		t.Fatalf("activity.type enrichment = %q, want claude_chat_created", names["claude.compliance.activity.type"])
	}
	obs := map[string]bool{}
	for _, o := range event.Observables {
		obs[o.Value] = true
	}
	if !obs["192.0.2.34"] || !obs["u@example.com"] {
		t.Fatalf("observables missing ip/email: %v", obs)
	}
}

func TestClaudeMapLoginMapsToAuthentication(t *testing.T) {
	m := NewClaudeComplianceMapper()
	event := m.MapActivity(map[string]interface{}{
		"id":         "a2",
		"created_at": "2026-04-10T09:00:00Z",
		"actor": map[string]interface{}{
			"type":                          "unauthenticated_user_actor",
			"unauthenticated_email_address": "x@example.com",
			"ip_address":                    "10.0.0.1",
		},
		"type": "sso_login_initiated",
	})
	if event.CategoryUID != 3 || event.ClassUID != 3002 || event.ActivityID != 1 {
		t.Fatalf("(%d, %d, %d), want (3, 3002, 1)", event.CategoryUID, event.ClassUID, event.ActivityID)
	}
	if event.Metadata.Product["vendor_name"] != "Anthropic" {
		t.Fatalf("vendor_name = %q, want Anthropic", event.Metadata.Product["vendor_name"])
	}
}

func TestClaudeMapScimUserAddedMapsToAccountChange(t *testing.T) {
	m := NewClaudeComplianceMapper()
	event := m.MapActivity(map[string]interface{}{
		"id": "a3",
		"actor": map[string]interface{}{
			"type":         "scim_directory_sync_actor",
			"directory_id": "dir_1",
		},
		"type": "user_added",
	})
	if event.CategoryUID != 3 || event.ClassUID != 3001 {
		t.Fatalf("(%d, %d), want (3, 3001)", event.CategoryUID, event.ClassUID)
	}
	if event.Actor.User["uid"] != "dir_1" {
		t.Fatalf("actor uid = %v, want dir_1", event.Actor.User["uid"])
	}
	// No created_at -> falls back to a generated timestamp (non-empty).
	if event.Time == "" {
		t.Fatalf("time is empty, want generated timestamp")
	}
}

func TestClaudeMapFailureStatusDetected(t *testing.T) {
	m := NewClaudeComplianceMapper()
	event := m.MapActivity(map[string]interface{}{
		"id":    "a4",
		"actor": map[string]interface{}{"type": "api_actor"},
		"type":  "sso_login_failed",
	})
	if event.StatusID != 2 {
		t.Fatalf("status_id = %d, want 2 (Failure)", event.StatusID)
	}
}

func TestClaudeMapActivitiesBatch(t *testing.T) {
	m := NewClaudeComplianceMapper()
	events := m.MapActivities([]map[string]interface{}{
		{"id": "x1", "actor": map[string]interface{}{"type": "api_actor"}, "type": "claude_file_uploaded"},
		{"id": "x2", "actor": map[string]interface{}{"type": "api_actor"}, "type": "compliance_export_created"},
	})
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].ClassUID != 6001 || events[1].ClassUID != 6003 {
		t.Fatalf("class_uids = [%d, %d], want [6001, 6003]", events[0].ClassUID, events[1].ClassUID)
	}
}
