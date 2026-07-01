// AITF integration for the Anthropic Claude Compliance API.
//
// Normalizes records from the Compliance API Activity Feed
// (GET /v1/compliance/activities) into AITF / OCSF telemetry so Claude
// Enterprise audit activity can be correlated alongside the rest of an
// organization's AI telemetry and forwarded to a SIEM/XDR.
//
// Docs: https://platform.claude.com/docs/en/manage-claude/compliance-api
//
// The feed produces hundreds of forward-compatible activity types. Rather than
// enumerate them, this mapper classifies each activity by keyword into the
// existing OCSF class it reuses (per OCSF's "reuse objects and profiles" model):
//
//	authentication / sso / session   -> IAM Authentication (3002)
//	user / member / invite / scim    -> IAM Account Change (3001)
//	role / group / permission        -> IAM User Access Management (3005)
//	chat / file / project / content  -> Application Web Resources Activity (6001)
//	compliance / export / api key    -> Application API Activity (6003)
//	everything else (unknown types)  -> Application API Activity (6003), activity Other
//
// Unknown / future activity and actor types are passed through (Anthropic's
// forward-compatibility guidance) rather than dropped.
package ocsf

import (
	"fmt"
	"strings"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

// strFromAny renders an arbitrary value as a string. Strings pass through
// unchanged; everything else uses fmt's default formatting.
func strFromAny(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// --- classification --------------------------------------------------------

// keywordClass maps ordered keyword groups to (category_uid, class_uid,
// category_label). First matching group wins; order matters (auth before
// account, etc.).
type keywordClass struct {
	keywords    []string
	categoryUID int
	classUID    int
	category    string
}

var claudeKeywordClass = []keywordClass{
	{[]string{"login", "logout", "signin", "sign_in", "sign_out", "sso", "mfa",
		"session", "authenticat", "password"}, 3, ClassUIDAuthentication, "authentication"},
	{[]string{"role", "permission", "privilege", "group", "access_grant"}, 3,
		ClassUIDUserAccessManagement, "access_management"},
	{[]string{"user", "member", "invite", "scim", "directory", "provision", "seat"}, 3,
		ClassUIDAccountChange, "account_change"},
	{[]string{"chat", "file", "project", "attachment", "message", "document",
		"artifact", "content", "setting", "policy"}, 6,
		ClassUIDWebResourcesActivity, "content"},
	{[]string{"compliance", "api_key", "export", "workspace"}, 6,
		ClassUIDAPIActivity, "administration"},
}

// verbActivity maps verb keyword groups to a generic activity_id
// (Create/Read/Update/Delete/Other style).
type verbActivity struct {
	verbs      []string
	activityID int
}

var claudeVerbActivity = []verbActivity{
	{[]string{"created", "added", "uploaded", "invited", "granted", "enabled",
		"started", "initiated"}, 1}, // Create / Logon
	{[]string{"deleted", "removed", "revoked", "disabled", "ended", "completed"}, 4}, // Delete
	{[]string{"updated", "edited", "changed", "renamed", "modified"}, 3},             // Update
	{[]string{"viewed", "read", "downloaded", "exported", "listed", "accessed"}, 2}, // Read
}

func anyContains(s string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// Classify maps a Compliance activity type to
// (categoryUID, classUID, activityID, category).
func Classify(activityType string) (int, int, int, string) {
	t := strings.ToLower(activityType)

	categoryUID, classUID, category := 6, ClassUIDAPIActivity, "other"
	for _, kc := range claudeKeywordClass {
		if anyContains(t, kc.keywords) {
			categoryUID, classUID, category = kc.categoryUID, kc.classUID, kc.category
			break
		}
	}

	// Authentication uses Logon(1)/Logoff(2) semantics.
	if classUID == ClassUIDAuthentication {
		var activityID int
		switch {
		case anyContains(t, []string{"logout", "sign_out", "signout"}):
			activityID = 2
		case anyContains(t, []string{"login", "sign_in", "signin", "sso"}):
			activityID = 1
		default:
			activityID = 99
		}
		return categoryUID, classUID, activityID, category
	}

	activityID := 99
	for _, va := range claudeVerbActivity {
		if anyContains(t, va.verbs) {
			activityID = va.activityID
			break
		}
	}
	return categoryUID, classUID, activityID, category
}

// --- actor -----------------------------------------------------------------

// asString returns the string form of a map value, or "" if absent/nil.
func asString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
		return strFromAny(v)
	}
	return ""
}

// buildActor translates the Compliance actor union into an OCSF actor.
func buildActor(actor map[string]interface{}) *OCSFActor {
	if actor == nil {
		actor = map[string]interface{}{}
	}
	uid := firstNonEmpty(
		asString(actor, "user_id"),
		asString(actor, "api_key_id"),
		asString(actor, "admin_api_key_id"),
		asString(actor, "directory_id"),
	)
	user := map[string]interface{}{"type": actor["type"]}
	if uid != "" {
		user["uid"] = uid
	}
	email := firstNonEmpty(asString(actor, "email_address"), asString(actor, "unauthenticated_email_address"))
	if email != "" {
		user["email_addr"] = email
		user["name"] = email
	}
	return &OCSFActor{User: user}
}

// --- mapper ----------------------------------------------------------------

// ClaudeComplianceMapper maps Claude Compliance Activity records to OCSF events
// (reuse model).
type ClaudeComplianceMapper struct{}

// claudeComplianceProduct is the OCSF metadata product for Claude Compliance events.
var claudeComplianceProduct = map[string]string{
	"name":        "Anthropic Claude Compliance API",
	"vendor_name": "Anthropic",
	"version":     "v1",
}

// NewClaudeComplianceMapper creates a ClaudeComplianceMapper.
func NewClaudeComplianceMapper() *ClaudeComplianceMapper {
	return &ClaudeComplianceMapper{}
}

// MapActivity maps a single Activity Feed record to an OCSF event.
func (m *ClaudeComplianceMapper) MapActivity(activity map[string]interface{}) *AIBaseEvent {
	activityType := "unknown"
	if v := asString(activity, "type"); v != "" {
		activityType = v
	}
	categoryUID, classUID, activityID, category := Classify(activityType)

	actorRaw, _ := activity["actor"].(map[string]interface{})
	if actorRaw == nil {
		actorRaw = map[string]interface{}{}
	}
	ip := asString(actorRaw, "ip_address")
	userAgent := asString(actorRaw, "user_agent")
	var device *OCSFDevice
	if ip != "" {
		device = &OCSFDevice{IP: ip}
	}

	// Carry the activity-specific fields as enrichments + observables.
	enrichments := []OCSFEnrichment{
		{Name: semconv.ClaudeComplianceActivityType, Value: activityType, Provider: "claude_compliance"},
		{Name: semconv.ClaudeComplianceActivityCategory, Value: category, Provider: "claude_compliance"},
	}
	fieldAttrs := []struct {
		key  string
		attr string
	}{
		{"id", semconv.ClaudeComplianceActivityID},
		{"organization_id", semconv.ClaudeComplianceOrganizationID},
		{"organization_uuid", semconv.ClaudeComplianceOrganizationUUID},
		{"claude_chat_id", semconv.ClaudeComplianceChatID},
		{"claude_project_id", semconv.ClaudeComplianceProjectID},
		{"claude_file_id", semconv.ClaudeComplianceFileID},
		{"filename", semconv.ClaudeComplianceFilename},
	}
	for _, fa := range fieldAttrs {
		if v, ok := activity[fa.key]; ok && v != nil {
			enrichments = append(enrichments, OCSFEnrichment{Name: fa.attr, Value: strFromAny(v)})
		}
	}
	if at := asString(actorRaw, "type"); at != "" {
		enrichments = append(enrichments, OCSFEnrichment{Name: semconv.ClaudeComplianceActorType, Value: at})
	}
	if userAgent != "" {
		enrichments = append(enrichments, OCSFEnrichment{Name: semconv.ClaudeComplianceActorUserAgent, Value: userAgent})
	}

	observables := []OCSFObservable{}
	email := firstNonEmpty(asString(actorRaw, "email_address"), asString(actorRaw, "unauthenticated_email_address"))
	if email != "" {
		observables = append(observables, OCSFObservable{Name: semconv.ClaudeComplianceActorEmail, Type: "Email Address", Value: email})
	}
	if ip != "" {
		observables = append(observables, OCSFObservable{Name: semconv.ClaudeComplianceActorIP, Type: "IP Address", Value: ip})
	}
	if uid := asString(actorRaw, "user_id"); uid != "" {
		observables = append(observables, OCSFObservable{Name: semconv.ClaudeComplianceActorUserID, Type: "User", Value: uid})
	}

	// Failures are encoded in the type for most events; default Success.
	statusID := StatusSuccess
	if anyContains(strings.ToLower(activityType), []string{"failed", "denied", "rejected", "error"}) {
		statusID = StatusFailure
	}

	event := NewAIBaseEvent(categoryUID, classUID, activityID)
	event.SeverityID = SeverityInformational
	event.StatusID = statusID
	event.Message = activityType
	event.Metadata = NewOCSFMetadata()
	event.Metadata.Product = claudeComplianceProduct
	event.Actor = buildActor(actorRaw)
	event.Device = device
	event.Enrichments = enrichments
	event.Observables = observables
	if ca := asString(activity, "created_at"); ca != "" {
		event.Time = ca
	}
	return &event
}

// MapActivities maps a page of Activity records to OCSF events.
func (m *ClaudeComplianceMapper) MapActivities(activities []map[string]interface{}) []*AIBaseEvent {
	events := make([]*AIBaseEvent, 0, len(activities))
	for _, a := range activities {
		events = append(events, m.MapActivity(a))
	}
	return events
}
