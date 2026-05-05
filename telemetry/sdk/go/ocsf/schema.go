// Package ocsf provides AITF OCSF Category 7 AI event schema for Go.
//
// OCSF v1.1.0 base objects and AI-specific extension models.
// Based on the OCSF schema from the AITelemetry project, enhanced
// for AITF Category 7 AI events.
package ocsf

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// version is the AITF SDK version used in OCSF metadata.
const version = "1.0.0"

// --- OCSF Enumerations ---

// OCSFSeverity represents OCSF event severity levels.
const (
	SeverityUnknown       = 0
	SeverityInformational = 1
	SeverityLow           = 2
	SeverityMedium        = 3
	SeverityHigh          = 4
	SeverityCritical      = 5
	SeverityFatal         = 6
)

// OCSFStatus represents OCSF event status codes.
const (
	StatusUnknown = 0
	StatusSuccess = 1
	StatusFailure = 2
	StatusOther   = 99
)

// OCSFActivity represents OCSF event activity codes.
const (
	ActivityUnknown = 0
	ActivityCreate  = 1
	ActivityRead    = 2
	ActivityUpdate  = 3
	ActivityDelete  = 4
	ActivityOther   = 99
)

// AIClassUID represents AITF OCSF Category 7 class UIDs.
const (
	ClassUIDModelInference  = 7001
	ClassUIDAgentActivity   = 7002
	ClassUIDToolExecution   = 7003
	ClassUIDDataRetrieval   = 7004
	ClassUIDSecurityFinding = 7005
	ClassUIDSupplyChain     = 7006
	ClassUIDGovernance      = 7007
	ClassUIDIdentity        = 7008
	ClassUIDModelOps        = 7009
	ClassUIDAssetInventory  = 7010
)

// --- OCSF Base Objects ---

// OCSFMetadata holds OCSF event metadata.
type OCSFMetadata struct {
	Version        string            `json:"version"`
	Product        map[string]string `json:"product"`
	UID            string            `json:"uid"`
	CorrelationUID string            `json:"correlation_uid,omitempty"`
	OriginalTime   string            `json:"original_time,omitempty"`
	LoggedTime     string            `json:"logged_time"`
}

// NewOCSFMetadata creates metadata with default values.
func NewOCSFMetadata() OCSFMetadata {
	return OCSFMetadata{
		Version: "1.1.0",
		Product: map[string]string{
			"name":        "AITF",
			"vendor_name": "AITF",
			"version":     version,
		},
		UID:        generateUID(),
		LoggedTime: time.Now().UTC().Format(time.RFC3339),
	}
}

// OCSFActor holds OCSF actor information.
type OCSFActor struct {
	User    map[string]interface{} `json:"user,omitempty"`
	Session map[string]interface{} `json:"session,omitempty"`
	AppName string                 `json:"app_name,omitempty"`
}

// OCSFDevice holds OCSF device/host information.
type OCSFDevice struct {
	Hostname  string            `json:"hostname,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Type      string            `json:"type,omitempty"`
	OS        map[string]string `json:"os,omitempty"`
	Cloud     map[string]string `json:"cloud,omitempty"`
	Container map[string]string `json:"container,omitempty"`
}

// OCSFEnrichment holds OCSF enrichment data.
type OCSFEnrichment struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Type     string `json:"type,omitempty"`
	Provider string `json:"provider,omitempty"`
}

// OCSFObservable holds OCSF observable values.
type OCSFObservable struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// --- AI-Specific Extension Models ---

// AIModelInfo holds AI model information.
type AIModelInfo struct {
	ModelID    string                 `json:"model_id"`
	Name       string                 `json:"name,omitempty"`
	Version    string                 `json:"version,omitempty"`
	Provider   string                 `json:"provider,omitempty"`
	Type       string                 `json:"type,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// AITokenUsage holds AI token usage statistics.
type AITokenUsage struct {
	InputTokens     int      `json:"input_tokens"`
	OutputTokens    int      `json:"output_tokens"`
	TotalTokens     int      `json:"total_tokens"`
	CachedTokens    int      `json:"cached_tokens,omitempty"`
	ReasoningTokens int      `json:"reasoning_tokens,omitempty"`
	EstimatedCostUSD *float64 `json:"estimated_cost_usd,omitempty"`
}

// ComputeTotal sets TotalTokens to InputTokens + OutputTokens if it is zero.
func (t *AITokenUsage) ComputeTotal() {
	if t.TotalTokens == 0 {
		t.TotalTokens = t.InputTokens + t.OutputTokens
	}
}

// AILatencyMetrics holds AI operation latency metrics.
type AILatencyMetrics struct {
	TotalMs            float64  `json:"total_ms"`
	TimeToFirstTokenMs *float64 `json:"time_to_first_token_ms,omitempty"`
	TokensPerSecond    *float64 `json:"tokens_per_second,omitempty"`
	QueueTimeMs        *float64 `json:"queue_time_ms,omitempty"`
	InferenceTimeMs    *float64 `json:"inference_time_ms,omitempty"`
}

// AICostInfo holds AI operation cost information.
type AICostInfo struct {
	InputCostUSD  float64 `json:"input_cost_usd"`
	OutputCostUSD float64 `json:"output_cost_usd"`
	TotalCostUSD  float64 `json:"total_cost_usd"`
	Currency      string  `json:"currency"`
}

// AITeamInfo holds multi-agent team information.
type AITeamInfo struct {
	TeamName    string   `json:"team_name"`
	TeamID      string   `json:"team_id,omitempty"`
	Topology    string   `json:"topology,omitempty"`
	Members     []string `json:"members,omitempty"`
	Coordinator string   `json:"coordinator,omitempty"`
}

// AISecurityFinding holds security finding details.
type AISecurityFinding struct {
	FindingType     string   `json:"finding_type"`
	OWASPCategory   string   `json:"owasp_category,omitempty"`
	RiskLevel       string   `json:"risk_level"`
	RiskScore       float64  `json:"risk_score"`
	Confidence      float64  `json:"confidence"`
	DetectionMethod string   `json:"detection_method"`
	Blocked         bool     `json:"blocked"`
	Details         string   `json:"details,omitempty"`
	PIITypes        []string `json:"pii_types,omitempty"`
	MatchedPatterns []string `json:"matched_patterns,omitempty"`
	Remediation     string   `json:"remediation,omitempty"`
}

// ComplianceMetadata holds compliance framework mappings.
type ComplianceMetadata struct {
	NISTAIMRMF map[string]interface{} `json:"nist_ai_rmf,omitempty"`
	MITREAtlas map[string]interface{} `json:"mitre_atlas,omitempty"`
	ISO42001   map[string]interface{} `json:"iso_42001,omitempty"`
	EUAIAct    map[string]interface{} `json:"eu_ai_act,omitempty"`
	SOC2       map[string]interface{} `json:"soc2,omitempty"`
	GDPR       map[string]interface{} `json:"gdpr,omitempty"`
	CCPA       map[string]interface{} `json:"ccpa,omitempty"`
	CSAAICM    map[string]interface{} `json:"csa_aicm,omitempty"`
}

// --- OCSF Base Event ---

// AIBaseEvent is the base OCSF event for all AITF Category 7 events.
type AIBaseEvent struct {
	ActivityID  int                `json:"activity_id"`
	CategoryUID int               `json:"category_uid"`
	ClassUID    int                `json:"class_uid"`
	TypeUID     int                `json:"type_uid"`
	Time        string             `json:"time"`
	SeverityID  int                `json:"severity_id"`
	StatusID    int                `json:"status_id"`
	Message     string             `json:"message"`
	Metadata    OCSFMetadata       `json:"metadata"`
	Actor       *OCSFActor         `json:"actor,omitempty"`
	Device      *OCSFDevice        `json:"device,omitempty"`
	Compliance  *ComplianceMetadata `json:"compliance,omitempty"`
	Observables []OCSFObservable   `json:"observables,omitempty"`
	Enrichments []OCSFEnrichment   `json:"enrichments,omitempty"`
}

// ComputeTypeUID computes the type_uid as class_uid * 100 + activity_id.
func (e *AIBaseEvent) ComputeTypeUID() int {
	return e.ClassUID*100 + e.ActivityID
}

// NewAIBaseEvent creates a base event with default values.
func NewAIBaseEvent(classUID, activityID int) AIBaseEvent {
	e := AIBaseEvent{
		ActivityID:  activityID,
		CategoryUID: 7, // AI System Activity
		ClassUID:    classUID,
		Time:        time.Now().UTC().Format(time.RFC3339),
		SeverityID:  SeverityInformational,
		StatusID:    StatusSuccess,
		Metadata:    NewOCSFMetadata(),
	}
	e.TypeUID = e.ComputeTypeUID()
	return e
}

// ToJSON serializes the event to JSON bytes.
func (e *AIBaseEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// generateUID creates a cryptographically random unique identifier.
// Uses 16 bytes of randomness (128-bit) for unpredictable UIDs.
func generateUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is a critical system-level issue;
		// use a less predictable fallback combining timestamp and PID.
		return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	}
	return hex.EncodeToString(b)
}
