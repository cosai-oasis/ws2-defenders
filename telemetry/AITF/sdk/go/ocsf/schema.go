// Package ocsf provides AITF OCSF AI event schema for Go.
//
// OCSF v1.1.0 base objects and AI-specific extension models. Following OCSF's
// "reuse existing objects and profiles" approach (OCSF PR #1641 / issue #1640),
// AITF emits AI telemetry under existing OCSF classes enriched with the
// ai_operation profile, using the proposed "ai" category (uid 9) only for the
// genuinely new agent / delegation control-plane classes.
package ocsf

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

// AgentTypeID represents OCSF ai_agent.type_id (normalized agent framework).
//
// Mirrors the enum introduced by OCSF PR #1641 (objects/ai_agent.json) so AITF
// telemetry maps cleanly onto the upstream OCSF ai_agent object.
const (
	AgentTypeIDUnknown   = 0
	AgentTypeIDNative    = 1
	AgentTypeIDLangChain = 2
	AgentTypeIDAutoGen   = 3
	AgentTypeIDCrewAI    = 4
	AgentTypeIDOther     = 99
)

// AgentTypeLabels maps AgentTypeID values to their OCSF captions (PR #1641).
var AgentTypeLabels = map[int]string{
	AgentTypeIDUnknown:   "Unknown",
	AgentTypeIDNative:    "Native",
	AgentTypeIDLangChain: "LangChain",
	AgentTypeIDAutoGen:   "AutoGen",
	AgentTypeIDCrewAI:    "CrewAI",
	AgentTypeIDOther:     "Other",
}

// frameworkToTypeID maps AITF framework values to OCSF ai_agent.type_id.
// Frameworks without a dedicated OCSF enum member (langgraph aside,
// semantic_kernel, custom, ...) normalize to Other (99) per OCSF open-enum
// guidance.
var frameworkToTypeID = map[string]int{
	"native":    AgentTypeIDNative,
	"langchain": AgentTypeIDLangChain,
	"langgraph": AgentTypeIDLangChain,
	"autogen":   AgentTypeIDAutoGen,
	"crewai":    AgentTypeIDCrewAI,
}

// NormalizeAgentTypeID maps an AITF framework string to an OCSF
// ai_agent.type_id value. Empty -> Unknown (0); known frameworks -> their enum
// member; any other non-empty value -> Other (99).
func NormalizeAgentTypeID(framework string) int {
	if framework == "" {
		return AgentTypeIDUnknown
	}
	if id, ok := frameworkToTypeID[strings.ToLower(strings.TrimSpace(framework))]; ok {
		return id
	}
	return AgentTypeIDOther
}

// OCSFAICategoryUID is the proposed "AI Activity" category (OCSF issue #1640).
const OCSFAICategoryUID = 9

// OCSFCategoryUID values are the OCSF category UIDs that AITF AI events map
// onto. Following OCSF's "reuse existing objects and profiles" approach (OCSF
// PR #1641 / issue #1640), data-plane AI activity is emitted under existing
// OCSF categories enriched with the ai_operation profile; only agent /
// delegation control-plane lifecycle uses the proposed "ai" category (uid 9).
const (
	OCSFCategoryUIDFindings    = 2
	OCSFCategoryUIDIAM         = 3
	OCSFCategoryUIDDiscovery   = 5
	OCSFCategoryUIDApplication = 6
	OCSFCategoryUIDAI          = 9 // proposed "AI Activity" category (OCSF issue #1640)
)

// OCSFClassUID values are the OCSF event class UIDs that AITF AI events map
// onto. Data-plane AI activity reuses existing OCSF classes; only the agent and
// delegation control-plane lifecycle use the proposed "ai" category (uid 9).
//
// Inference and tool execution intentionally share API Activity (6003); they
// are distinguished by activity_id and the ai_operation profile.
const (
	// Reused existing OCSF classes (verified against the OCSF schema).
	ClassUIDVulnerabilityFinding = 2002
	ClassUIDComplianceFinding    = 2003
	ClassUIDDetectionFinding     = 2004
	ClassUIDAccountChange        = 3001
	ClassUIDAuthentication       = 3002
	ClassUIDEntityManagement     = 3004
	ClassUIDUserAccessManagement = 3005
	ClassUIDInventoryInfo        = 5001
	ClassUIDWebResourcesActivity = 6001
	ClassUIDApplicationLifecycle = 6002
	ClassUIDAPIActivity          = 6003
	ClassUIDDatastoreActivity    = 6005
	// New control-plane classes in the proposed "ai" category (uid 9). UIDs are
	// provisional pending OCSF issue #1640 ratification.
	ClassUIDAgentActivity      = 9001
	ClassUIDDelegationActivity = 9002
	ClassUIDAgentCommunication = 9003
)

// AgentProtocolID represents the agent-to-agent communication protocol (OCSF
// agent_message.protocol_id). One generic discriminator across agentic
// protocols rather than a dedicated OCSF object per protocol — protocol-specific
// detail stays in the per-protocol OTel namespaces.
const (
	AgentProtocolIDUnknown = 0
	AgentProtocolIDA2A     = 1
	AgentProtocolIDACP     = 2
	AgentProtocolIDANP     = 3
	AgentProtocolIDMCP     = 4
	AgentProtocolIDOther   = 99
)

// AgentProtocolLabels maps AgentProtocolID values to their captions.
var AgentProtocolLabels = map[int]string{
	AgentProtocolIDUnknown: "Unknown",
	AgentProtocolIDA2A:     "A2A",
	AgentProtocolIDACP:     "ACP",
	AgentProtocolIDANP:     "ANP",
	AgentProtocolIDMCP:     "MCP",
	AgentProtocolIDOther:   "Other",
}

// protocolToID maps a protocol string to an OCSF agent_message.protocol_id.
var protocolToID = map[string]int{
	"a2a": AgentProtocolIDA2A,
	"acp": AgentProtocolIDACP,
	"anp": AgentProtocolIDANP,
	"mcp": AgentProtocolIDMCP,
}

// NormalizeAgentProtocolID maps a protocol string to an OCSF
// agent_message.protocol_id. Empty -> Unknown (0); known protocols -> their
// enum member; any other non-empty value -> Other (99).
func NormalizeAgentProtocolID(protocol string) int {
	if protocol == "" {
		return AgentProtocolIDUnknown
	}
	if id, ok := protocolToID[strings.ToLower(strings.TrimSpace(protocol))]; ok {
		return id
	}
	return AgentProtocolIDOther
}

// Backward-compatible aliases. AITF previously defined a bespoke Category 7
// with classes 7001-7010; events now reuse the OCSF classes above per OCSF's
// object/profile-reuse model. Kept so existing references keep working.
const (
	ClassUIDModelInference = ClassUIDAPIActivity          // was 7001 -> API Activity (6003)
	ClassUIDToolExecution  = ClassUIDAPIActivity          // was 7003 -> API Activity (6003)
	ClassUIDDataRetrieval  = ClassUIDDatastoreActivity    // was 7004 -> Datastore Activity (6005)
	ClassUIDSecurityFinding = ClassUIDDetectionFinding    // was 7005 -> Detection Finding (2004)
	ClassUIDSupplyChain    = ClassUIDVulnerabilityFinding // was 7006 -> Vulnerability Finding (2002)
	ClassUIDGovernance     = ClassUIDComplianceFinding    // was 7007 -> Compliance Finding (2003)
	ClassUIDIdentity       = ClassUIDAuthentication       // was 7008 -> Authentication (3002)
	ClassUIDModelOps       = ClassUIDApplicationLifecycle // was 7009 -> Application Lifecycle (6002)
	ClassUIDAssetInventory = ClassUIDInventoryInfo        // was 7010 -> Inventory Info (5001)
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

// OCSFAIAgent is the OCSF ai_agent object (OCSF PR #1641).
//
// An autonomous AI agent operating under delegated authority. Distinct from the
// OCSF agent object (which models security sensors such as EDR/DLP) and from
// human principals. Attached to events via the ai_operation profile so any
// activity can be attributed to the agent that performed it.
type OCSFAIAgent struct {
	UID         string `json:"uid"`                    // required: stable logical identifier
	InstanceUID string `json:"instance_uid,omitempty"` // restart-sensitive running instance id
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"` // caption of type_id (Native, LangChain, ...)
	TypeID      int    `json:"type_id,omitempty"`
	AIModel     string `json:"ai_model,omitempty"` // model backing the agent at event time
	Version     string `json:"version,omitempty"`  // agent code/configuration revision
	Charter     string `json:"charter,omitempty"`  // role / operating-boundary reference
}

// OCSFDelegation is the OCSF delegation object (OCSF issue #1640).
//
// A durable authorization context that persists independently of any single
// trace or session. uid/parent_uid/issuer_uid provide the OCSF core; the
// remaining fields preserve AITF's richer delegation telemetry.
type OCSFDelegation struct {
	UID        string   `json:"uid"`                  // required: stable delegation identifier
	ParentUID  string   `json:"parent_uid,omitempty"` // parent delegation (lineage)
	IssuerUID  string   `json:"issuer_uid,omitempty"` // trusted issuer that minted the delegation
	Delegator  string   `json:"delegator,omitempty"`
	Delegatee  string   `json:"delegatee,omitempty"`
	Type       string   `json:"type,omitempty"` // on_behalf_of, token_exchange, capability_grant, ...
	Scope      []string `json:"scope,omitempty"`
	ProofType  string   `json:"proof_type,omitempty"` // dpop, mtls_binding, signed_assertion
	TTLSeconds *int     `json:"ttl_seconds,omitempty"`
}

// OCSFDelegationNode is a single node in an OCSF delegation_lineage graph
// (OCSF issue #1640).
type OCSFDelegationNode struct {
	UID       string `json:"uid"`
	ParentUID string `json:"parent_uid,omitempty"`
	AgentUID  string `json:"agent_uid,omitempty"`
	Depth     int    `json:"depth"`
}

// OCSFDelegationLineage is the OCSF delegation_lineage directed graph for
// ancestry queries (OCSF issue #1640).
type OCSFDelegationLineage struct {
	Nodes []OCSFDelegationNode `json:"nodes,omitempty"`
}

// OCSFAgentMessage is the OCSF agent_message object — one generic
// representation of an agent-to-agent communication across A2A / ACP / ANP /
// MCP.
//
// Proposed addition (see ocsf-mapping/ocsf-pr-draft.md). Carries the wire
// protocol_id discriminator plus the shared core (peer agents, unit of work +
// lifecycle status, transport, trust); protocol-specific extras live in
// metadata.
type OCSFAgentMessage struct {
	ProtocolID      int                    `json:"protocol_id"`
	Protocol        string                 `json:"protocol,omitempty"`
	ProtocolVersion string                 `json:"protocol_version,omitempty"`
	Direction       string                 `json:"direction,omitempty"` // request | response | stream | notification
	Role            string                 `json:"role,omitempty"`      // client | server
	Operation       string                 `json:"operation,omitempty"`
	UnitUID         string                 `json:"unit_uid,omitempty"`
	UnitType        string                 `json:"unit_type,omitempty"` // task | run | message
	Status          string                 `json:"status,omitempty"`    // canonical lifecycle status
	PreviousStatus  string                 `json:"previous_status,omitempty"`
	SrcAgent        *OCSFAIAgent           `json:"src_agent,omitempty"`
	DstAgent        *OCSFAIAgent           `json:"dst_agent,omitempty"`
	Delegation      *OCSFDelegation        `json:"delegation,omitempty"`
	PartsCount      *int                   `json:"parts_count,omitempty"`
	PartTypes       []string               `json:"part_types,omitempty"`
	ArtifactsCount  *int                   `json:"artifacts_count,omitempty"`
	Transport       string                 `json:"transport,omitempty"`
	Endpoint        string                 `json:"endpoint,omitempty"`
	PeerEndpoint    string                 `json:"peer_endpoint,omitempty"`
	TrustDomain     string                 `json:"trust_domain,omitempty"`
	PeerTrustDomain string                 `json:"peer_trust_domain,omitempty"`
	CrossDomain     *bool                  `json:"cross_domain,omitempty"`
	PeerDID         string                 `json:"peer_did,omitempty"`
	ErrorCode       string                 `json:"error_code,omitempty"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	DurationMs      *float64               `json:"duration_ms,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
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

// AIBaseEvent is the base OCSF event for AITF AI events.
//
// Constructors set category_uid and class_uid to the OCSF class they reuse
// (OCSF PR #1641 / issue #1640). AI-specific context is carried on the
// ai_operation profile (ai_agent, ai_model, delegation).
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

	// OCSF ai_operation profile (OCSF PR #1641) + delegation context
	// (OCSF issue #1640). Populated by the crosswalk so every AITF event can be
	// attributed to the AI agent and delegation that produced it.
	AIAgent           *OCSFAIAgent           `json:"ai_agent,omitempty"`
	AIModel           string                 `json:"ai_model,omitempty"`
	Delegation        *OCSFDelegation        `json:"delegation,omitempty"`
	DelegationLineage *OCSFDelegationLineage `json:"delegation_lineage,omitempty"`
}

// ComputeTypeUID computes the type_uid as class_uid * 100 + activity_id.
func (e *AIBaseEvent) ComputeTypeUID() int {
	return e.ClassUID*100 + e.ActivityID
}

// NewAIBaseEvent creates a base event with default values. The event reuses the
// given OCSF category_uid and class_uid (OCSF PR #1641 / issue #1640).
func NewAIBaseEvent(categoryUID, classUID, activityID int) AIBaseEvent {
	e := AIBaseEvent{
		ActivityID:  activityID,
		CategoryUID: categoryUID,
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
