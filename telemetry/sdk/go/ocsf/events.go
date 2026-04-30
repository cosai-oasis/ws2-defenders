package ocsf

import "encoding/json"

// AIModelInferenceEvent represents OCSF Class 7001: AI Model Inference.
// An AI model inference operation (request + response).
type AIModelInferenceEvent struct {
	AIBaseEvent
	Model          AIModelInfo       `json:"model"`
	TokenUsage     AITokenUsage      `json:"token_usage"`
	Latency        *AILatencyMetrics `json:"latency,omitempty"`
	RequestContent string            `json:"request_content,omitempty"`
	ResponseContent string           `json:"response_content,omitempty"`
	Streaming      bool              `json:"streaming"`
	ToolsProvided  int               `json:"tools_provided,omitempty"`
	FinishReason   string            `json:"finish_reason"`
	Cost           *AICostInfo       `json:"cost,omitempty"`
	Error          map[string]interface{} `json:"error,omitempty"`
}

// NewAIModelInferenceEvent creates a new model inference event.
func NewAIModelInferenceEvent(model AIModelInfo, activityID int) *AIModelInferenceEvent {
	e := &AIModelInferenceEvent{
		AIBaseEvent:  NewAIBaseEvent(ClassUIDModelInference, activityID),
		Model:        model,
		FinishReason: "stop",
	}
	e.TokenUsage.ComputeTotal()
	return e
}

// ToJSON serializes the event to JSON bytes.
func (e *AIModelInferenceEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// AIAgentActivityEvent represents OCSF Class 7002: AI Agent Activity.
// An AI agent lifecycle event (session, step, delegation).
type AIAgentActivityEvent struct {
	AIBaseEvent
	AgentName        string     `json:"agent_name"`
	AgentID          string     `json:"agent_id"`
	AgentType        string     `json:"agent_type"`
	Framework        string     `json:"framework,omitempty"`
	SessionID        string     `json:"session_id"`
	StepType         string     `json:"step_type,omitempty"`
	StepIndex        *int       `json:"step_index,omitempty"`
	Thought          string     `json:"thought,omitempty"`
	Action           string     `json:"action,omitempty"`
	Observation      string     `json:"observation,omitempty"`
	DelegationTarget string     `json:"delegation_target,omitempty"`
	TeamInfo         *AITeamInfo `json:"team_info,omitempty"`
}

// NewAIAgentActivityEvent creates a new agent activity event.
func NewAIAgentActivityEvent(agentName, agentID, sessionID string, activityID int) *AIAgentActivityEvent {
	return &AIAgentActivityEvent{
		AIBaseEvent: NewAIBaseEvent(ClassUIDAgentActivity, activityID),
		AgentName:   agentName,
		AgentID:     agentID,
		AgentType:   "autonomous",
		SessionID:   sessionID,
	}
}

// ToJSON serializes the event to JSON bytes.
func (e *AIAgentActivityEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// AIToolExecutionEvent represents OCSF Class 7003: AI Tool Execution.
// A tool/function execution, including MCP tools and skills.
type AIToolExecutionEvent struct {
	AIBaseEvent
	ToolName         string   `json:"tool_name"`
	ToolType         string   `json:"tool_type"`
	ToolInput        string   `json:"tool_input,omitempty"`
	ToolOutput       string   `json:"tool_output,omitempty"`
	IsError          bool     `json:"is_error"`
	DurationMs       *float64 `json:"duration_ms,omitempty"`
	MCPServer        string   `json:"mcp_server,omitempty"`
	MCPTransport     string   `json:"mcp_transport,omitempty"`
	SkillCategory    string   `json:"skill_category,omitempty"`
	SkillVersion     string   `json:"skill_version,omitempty"`
	ApprovalRequired bool     `json:"approval_required"`
	Approved         *bool    `json:"approved,omitempty"`
}

// NewAIToolExecutionEvent creates a new tool execution event.
func NewAIToolExecutionEvent(toolName, toolType string, activityID int) *AIToolExecutionEvent {
	return &AIToolExecutionEvent{
		AIBaseEvent: NewAIBaseEvent(ClassUIDToolExecution, activityID),
		ToolName:    toolName,
		ToolType:    toolType,
	}
}

// ToJSON serializes the event to JSON bytes.
func (e *AIToolExecutionEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// AIDataRetrievalEvent represents OCSF Class 7004: AI Data Retrieval.
// RAG and vector search operations.
type AIDataRetrievalEvent struct {
	AIBaseEvent
	DatabaseName        string             `json:"database_name"`
	DatabaseType        string             `json:"database_type"`
	Query               string             `json:"query,omitempty"`
	TopK                *int               `json:"top_k,omitempty"`
	ResultsCount        int                `json:"results_count"`
	MinScore            *float64           `json:"min_score,omitempty"`
	MaxScore            *float64           `json:"max_score,omitempty"`
	Filter              string             `json:"filter,omitempty"`
	EmbeddingModel      string             `json:"embedding_model,omitempty"`
	EmbeddingDimensions *int               `json:"embedding_dimensions,omitempty"`
	PipelineName        string             `json:"pipeline_name,omitempty"`
	PipelineStage       string             `json:"pipeline_stage,omitempty"`
	QualityScores       map[string]float64 `json:"quality_scores,omitempty"`
}

// NewAIDataRetrievalEvent creates a new data retrieval event.
func NewAIDataRetrievalEvent(databaseName, databaseType string, activityID int) *AIDataRetrievalEvent {
	return &AIDataRetrievalEvent{
		AIBaseEvent:  NewAIBaseEvent(ClassUIDDataRetrieval, activityID),
		DatabaseName: databaseName,
		DatabaseType: databaseType,
	}
}

// ToJSON serializes the event to JSON bytes.
func (e *AIDataRetrievalEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// AISecurityFindingEvent represents OCSF Class 7005: AI Security Finding.
// A security finding in AI operations.
type AISecurityFindingEvent struct {
	AIBaseEvent
	Finding AISecurityFinding `json:"finding"`
}

// NewAISecurityFindingEvent creates a new security finding event.
func NewAISecurityFindingEvent(finding AISecurityFinding, activityID int) *AISecurityFindingEvent {
	return &AISecurityFindingEvent{
		AIBaseEvent: NewAIBaseEvent(ClassUIDSecurityFinding, activityID),
		Finding:     finding,
	}
}

// ToJSON serializes the event to JSON bytes.
func (e *AISecurityFindingEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// AISupplyChainEvent represents OCSF Class 7006: AI Supply Chain.
// AI supply chain events (model provenance, integrity).
type AISupplyChainEvent struct {
	AIBaseEvent
	ModelSource        string `json:"model_source"`
	ModelHash          string `json:"model_hash,omitempty"`
	ModelLicense       string `json:"model_license,omitempty"`
	ModelSigned        bool   `json:"model_signed"`
	ModelSigner        string `json:"model_signer,omitempty"`
	VerificationResult string `json:"verification_result,omitempty"`
	AIBomID            string `json:"ai_bom_id,omitempty"`
	AIBomComponents    string `json:"ai_bom_components,omitempty"`
}

// NewAISupplyChainEvent creates a new supply chain event.
func NewAISupplyChainEvent(modelSource string, activityID int) *AISupplyChainEvent {
	return &AISupplyChainEvent{
		AIBaseEvent: NewAIBaseEvent(ClassUIDSupplyChain, activityID),
		ModelSource: modelSource,
	}
}

// ToJSON serializes the event to JSON bytes.
func (e *AISupplyChainEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// AIGovernanceEvent represents OCSF Class 7007: AI Governance.
// Compliance and governance events.
type AIGovernanceEvent struct {
	AIBaseEvent
	Frameworks        []string `json:"frameworks,omitempty"`
	Controls          string   `json:"controls,omitempty"`
	EventType         string   `json:"event_type"`
	ViolationDetected bool     `json:"violation_detected"`
	ViolationSeverity string   `json:"violation_severity,omitempty"`
	Remediation       string   `json:"remediation,omitempty"`
	AuditID           string   `json:"audit_id,omitempty"`
}

// NewAIGovernanceEvent creates a new governance event.
func NewAIGovernanceEvent(eventType string, activityID int) *AIGovernanceEvent {
	return &AIGovernanceEvent{
		AIBaseEvent: NewAIBaseEvent(ClassUIDGovernance, activityID),
		EventType:   eventType,
	}
}

// ToJSON serializes the event to JSON bytes.
func (e *AIGovernanceEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// AIIdentityEvent represents OCSF Class 7008: AI Identity.
// Agent identity and authentication events.
type AIIdentityEvent struct {
	AIBaseEvent
	AgentName       string   `json:"agent_name"`
	AgentID         string   `json:"agent_id"`
	AuthMethod      string   `json:"auth_method"`
	AuthResult      string   `json:"auth_result"`
	Permissions     []string `json:"permissions,omitempty"`
	CredentialType  string   `json:"credential_type,omitempty"`
	DelegationChain []string `json:"delegation_chain,omitempty"`
	Scope           string   `json:"scope,omitempty"`
}

// NewAIIdentityEvent creates a new identity event.
func NewAIIdentityEvent(agentName, agentID, authMethod, authResult string, activityID int) *AIIdentityEvent {
	return &AIIdentityEvent{
		AIBaseEvent: NewAIBaseEvent(ClassUIDIdentity, activityID),
		AgentName:   agentName,
		AgentID:     agentID,
		AuthMethod:  authMethod,
		AuthResult:  authResult,
	}
}

// ToJSON serializes the event to JSON bytes.
func (e *AIIdentityEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// AIModelOpsEvent represents OCSF Class 7009: AI Model Operations.
// Model lifecycle operations: training, evaluation, deployment, serving, monitoring.
type AIModelOpsEvent struct {
	AIBaseEvent
	OperationType string   `json:"operation_type"`
	ModelID       string   `json:"model_id,omitempty"`
	RunID         string   `json:"run_id,omitempty"`
	Framework     string   `json:"framework,omitempty"`
	Status        string   `json:"status,omitempty"`
	TrainingType  string   `json:"training_type,omitempty"`
	BaseModel     string   `json:"base_model,omitempty"`
	DatasetID     string   `json:"dataset_id,omitempty"`
	Epochs        *int     `json:"epochs,omitempty"`
	LossFinal     *float64 `json:"loss_final,omitempty"`
	OutputModelID string   `json:"output_model_id,omitempty"`
	EvalType      string   `json:"evaluation_type,omitempty"`
	Metrics       string   `json:"metrics,omitempty"`
	Passed        *bool    `json:"passed,omitempty"`
	DeploymentID  string   `json:"deployment_id,omitempty"`
	Strategy      string   `json:"strategy,omitempty"`
	Environment   string   `json:"environment,omitempty"`
	Endpoint      string   `json:"endpoint,omitempty"`
	SelectedModel string   `json:"selected_model,omitempty"`
	FallbackChain string   `json:"fallback_chain,omitempty"`
	CacheHit      *bool    `json:"cache_hit,omitempty"`
	CheckType     string   `json:"check_type,omitempty"`
	DriftScore    *float64 `json:"drift_score,omitempty"`
	DriftType     string   `json:"drift_type,omitempty"`
	ActionTriggered string `json:"action_triggered,omitempty"`
}

// NewAIModelOpsEvent creates a new model operations event.
func NewAIModelOpsEvent(operationType string, activityID int) *AIModelOpsEvent {
	return &AIModelOpsEvent{
		AIBaseEvent:   NewAIBaseEvent(ClassUIDModelOps, activityID),
		OperationType: operationType,
	}
}

// ToJSON serializes the event to JSON bytes.
func (e *AIModelOpsEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// AIAssetInventoryEvent represents OCSF Class 7010: AI Asset Inventory.
// AI asset lifecycle events: registration, discovery, audit, classification.
type AIAssetInventoryEvent struct {
	AIBaseEvent
	OperationType         string `json:"operation_type"`
	AssetID               string `json:"asset_id,omitempty"`
	AssetName             string `json:"asset_name,omitempty"`
	AssetType             string `json:"asset_type,omitempty"`
	AssetVersion          string `json:"asset_version,omitempty"`
	Owner                 string `json:"owner,omitempty"`
	DeploymentEnvironment string `json:"deployment_environment,omitempty"`
	RiskClassification    string `json:"risk_classification,omitempty"`
	DiscoveryScope        string `json:"discovery_scope,omitempty"`
	DiscoveryMethod       string `json:"discovery_method,omitempty"`
	AssetsFound           *int   `json:"assets_found,omitempty"`
	NewAssets             *int   `json:"new_assets,omitempty"`
	ShadowAssets          *int   `json:"shadow_assets,omitempty"`
	AuditType             string `json:"audit_type,omitempty"`
	AuditResult           string `json:"audit_result,omitempty"`
	AuditFramework        string `json:"audit_framework,omitempty"`
	AuditFindings         string `json:"audit_findings,omitempty"`
	ClassificationFramework  string `json:"classification_framework,omitempty"`
	PreviousClassification   string `json:"previous_classification,omitempty"`
	ClassificationReason     string `json:"classification_reason,omitempty"`
}

// NewAIAssetInventoryEvent creates a new asset inventory event.
func NewAIAssetInventoryEvent(operationType string, activityID int) *AIAssetInventoryEvent {
	return &AIAssetInventoryEvent{
		AIBaseEvent:   NewAIBaseEvent(ClassUIDAssetInventory, activityID),
		OperationType: operationType,
	}
}

// ToJSON serializes the event to JSON bytes.
func (e *AIAssetInventoryEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}
