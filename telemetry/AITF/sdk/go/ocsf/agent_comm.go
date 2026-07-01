package ocsf

// Agent-to-agent communication normalization (A2A / ACP / ANP).
//
// One generic OCSF agent_message object with a protocol_id discriminator rather
// than a per-protocol object. Per-protocol lifecycle states are normalized to a
// single canonical status set, mirroring the Python SDK implementation.

import (
	"strings"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

// a2aStatus maps A2A task.state values to the canonical status set.
var a2aStatus = map[string]string{
	"submitted":      semconv.AgentCommStatusSubmitted,
	"working":        semconv.AgentCommStatusWorking,
	"input-required": semconv.AgentCommStatusInputRequired,
	"auth-required":  semconv.AgentCommStatusInputRequired,
	"completed":      semconv.AgentCommStatusCompleted,
	"failed":         semconv.AgentCommStatusFailed,
	"rejected":       semconv.AgentCommStatusFailed,
	"canceled":       semconv.AgentCommStatusCanceled,
}

// acpStatus maps ACP run.status values to the canonical status set.
var acpStatus = map[string]string{
	"created":     semconv.AgentCommStatusSubmitted,
	"in-progress": semconv.AgentCommStatusWorking,
	"awaiting":    semconv.AgentCommStatusInputRequired,
	"completed":   semconv.AgentCommStatusCompleted,
	"failed":      semconv.AgentCommStatusFailed,
	"cancelling":  semconv.AgentCommStatusCanceling,
	"cancelled":   semconv.AgentCommStatusCanceled,
}

// statusTables maps a protocol id to its per-protocol status table.
var statusTables = map[int]map[string]string{
	AgentProtocolIDA2A: a2aStatus,
	AgentProtocolIDACP: acpStatus,
}

// CanonicalCommStatus normalizes a protocol-specific lifecycle state to the
// canonical status set. Unknown values pass through unchanged; an empty status
// returns "".
func CanonicalCommStatus(protocolID int, status string) string {
	if status == "" {
		return ""
	}
	if table, ok := statusTables[protocolID]; ok {
		if canonical, ok := table[status]; ok {
			return canonical
		}
	}
	return status
}

// detectProtocol detects the agent-comm protocol from attribute namespaces.
func detectProtocol(attrs map[string]interface{}) int {
	if explicit := attrStr(attrs, string(semconv.AgentCommProtocolKey), ""); explicit != "" {
		return NormalizeAgentProtocolID(explicit)
	}
	if anyKeyHasPrefix(attrs, "a2a.") {
		return AgentProtocolIDA2A
	}
	if anyKeyHasPrefix(attrs, "acp.") {
		return AgentProtocolIDACP
	}
	if anyKeyHasPrefix(attrs, "anp.") {
		return AgentProtocolIDANP
	}
	return AgentProtocolIDUnknown
}

// anyKeyHasPrefix reports whether any attribute key starts with prefix.
func anyKeyHasPrefix(attrs map[string]interface{}, prefix string) bool {
	for k := range attrs {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// hasAttr reports whether a non-nil attribute is present for key.
func hasAttr(attrs map[string]interface{}, key string) bool {
	v, ok := attrs[key]
	return ok && v != nil
}

// firstAttrAny returns the first present non-nil string attribute among keys.
func firstAttrAny(attrs map[string]interface{}, keys ...string) string {
	return firstAttrStr(attrs, keys...)
}

func intPtrFrom(attrs map[string]interface{}, key string) *int {
	if hasAttr(attrs, key) {
		v := toInt(attrs[key])
		return &v
	}
	return nil
}

func floatPtrFrom(attrs map[string]interface{}, key string) *float64 {
	if hasAttr(attrs, key) {
		v := toFloat64(attrs[key])
		return &v
	}
	return nil
}

func boolPtrFrom(attrs map[string]interface{}, key string) *bool {
	if hasAttr(attrs, key) {
		v := toBool(attrs[key])
		return &v
	}
	return nil
}

// BuildAgentMessage builds a generic OCSF agent_message from A2A/ACP/ANP and
// canonical agent.comm.* attributes. Returns nil when the span carries no
// agent-communication context.
func BuildAgentMessage(attrs map[string]interface{}) *OCSFAgentMessage {
	protocolID := detectProtocol(attrs)
	if protocolID == AgentProtocolIDUnknown && !hasAttr(attrs, string(semconv.AgentCommUnitIDKey)) {
		return nil
	}

	msg := &OCSFAgentMessage{
		ProtocolID: protocolID,
		Protocol:   attrStr(attrs, string(semconv.AgentCommProtocolKey), ""),
	}

	switch protocolID {
	case AgentProtocolIDA2A:
		msg.ProtocolVersion = attrStr(attrs, string(semconv.A2AProtocolVersionKey), "")
		msg.Transport = attrStr(attrs, string(semconv.A2ATransportKey), "")
		msg.Operation = attrStr(attrs, string(semconv.A2AMethodKey), "")
		if hasAttr(attrs, string(semconv.A2ATaskIDKey)) {
			msg.UnitUID = attrStr(attrs, string(semconv.A2ATaskIDKey), "")
			msg.UnitType = "task"
			msg.Status = CanonicalCommStatus(protocolID, attrStr(attrs, string(semconv.A2ATaskStateKey), ""))
			msg.PreviousStatus = CanonicalCommStatus(protocolID, attrStr(attrs, string(semconv.A2ATaskPreviousStateKey), ""))
		} else {
			msg.UnitUID = attrStr(attrs, string(semconv.A2AMessageIDKey), "")
			msg.UnitType = "message"
		}
		mode := strings.ToLower(attrStr(attrs, string(semconv.A2AInteractionModeKey), ""))
		switch mode {
		case "stream":
			msg.Direction = "stream"
		case "push":
			msg.Direction = "notification"
		default:
			msg.Direction = "request"
		}
		msg.PartsCount = intPtrFrom(attrs, string(semconv.A2AMessagePartsCountKey))
		msg.PartTypes = attrStrList(attrs, string(semconv.A2AMessagePartTypesKey))
		msg.ArtifactsCount = intPtrFrom(attrs, string(semconv.A2ATaskArtifactsCountKey))
		msg.PeerEndpoint = attrStr(attrs, string(semconv.A2AAgentURLKey), "")
		msg.ErrorCode = attrStr(attrs, string(semconv.A2AJSONRPCErrorCodeKey), "")
		msg.ErrorMessage = attrStr(attrs, string(semconv.A2AJSONRPCErrorMessageKey), "")
		if name := attrStr(attrs, string(semconv.A2AAgentNameKey), ""); name != "" {
			msg.DstAgent = &OCSFAIAgent{
				UID:     name,
				Name:    name,
				Version: attrStr(attrs, string(semconv.A2AAgentVersionKey), ""),
			}
		}

	case AgentProtocolIDACP:
		msg.Operation = firstAttrAny(attrs, string(semconv.ACPOperationKey), string(semconv.ACPRunModeKey))
		msg.UnitUID = attrStr(attrs, string(semconv.ACPRunIDKey), "")
		msg.UnitType = "run"
		msg.Status = CanonicalCommStatus(protocolID, attrStr(attrs, string(semconv.ACPRunStatusKey), ""))
		msg.PreviousStatus = CanonicalCommStatus(protocolID, attrStr(attrs, string(semconv.ACPRunPreviousStatusKey), ""))
		mode := strings.ToLower(attrStr(attrs, string(semconv.ACPRunModeKey), ""))
		if mode == "stream" {
			msg.Direction = "stream"
		} else {
			msg.Direction = "request"
		}
		msg.Transport = "http"
		msg.Endpoint = attrStr(attrs, string(semconv.ACPHTTPURLKey), "")
		msg.PartsCount = intPtrFrom(attrs, string(semconv.ACPMessagePartsCountKey))
		msg.PartTypes = attrStrList(attrs, string(semconv.ACPMessageContentTypesKey))
		msg.DurationMs = floatPtrFrom(attrs, string(semconv.ACPRunDurationMsKey))
		msg.ErrorCode = attrStr(attrs, string(semconv.ACPRunErrorCodeKey), "")
		msg.ErrorMessage = attrStr(attrs, string(semconv.ACPRunErrorMessageKey), "")
		if name := attrStr(attrs, string(semconv.ACPAgentNameKey), ""); name != "" {
			msg.DstAgent = &OCSFAIAgent{UID: name, Name: name}
		}

	case AgentProtocolIDANP:
		msg.ProtocolVersion = attrStr(attrs, string(semconv.ANPProtocolVersionKey), "")
		msg.Transport = attrStr(attrs, string(semconv.ANPTransportKey), "")
		msg.Operation = firstAttrAny(attrs, string(semconv.ANPMetaProtocolNameKey), string(semconv.ANPMessageTypeKey))
		msg.UnitUID = attrStr(attrs, string(semconv.ANPMessageIDKey), "")
		msg.UnitType = "message"
		msg.PartsCount = intPtrFrom(attrs, string(semconv.ANPMessagePartsCountKey))
		msg.PeerDID = attrStr(attrs, string(semconv.ANPPeerDIDKey), "")
		msg.TrustDomain = attrStr(attrs, string(semconv.ANPTrustDomainKey), "")
		msg.PeerTrustDomain = attrStr(attrs, string(semconv.ANPPeerTrustDomainKey), "")
		msg.CrossDomain = boolPtrFrom(attrs, string(semconv.ANPCrossDomainKey))
		msg.ErrorCode = attrStr(attrs, string(semconv.ANPErrorCodeKey), "")
		msg.ErrorMessage = attrStr(attrs, string(semconv.ANPErrorMessageKey), "")
	}

	// Canonical agent.comm.* attributes override / fill in any protocol.
	applyCanonical(msg, attrs)

	// Source agent from gen_ai.agent.* / canonical, if present.
	if msg.SrcAgent == nil {
		msg.SrcAgent = BuildAIAgent(attrs)
	}

	// Delegation context (issue #1640) rides on the comms event when present.
	msg.Delegation = BuildDelegation(attrs)
	return msg
}

// applyCanonical overlays explicit canonical agent.comm.* attributes onto msg.
func applyCanonical(msg *OCSFAgentMessage, attrs map[string]interface{}) {
	strOverrides := []struct {
		field *string
		key   string
	}{
		{&msg.ProtocolVersion, string(semconv.AgentCommProtocolVersionKey)},
		{&msg.Direction, string(semconv.AgentCommDirectionKey)},
		{&msg.Role, string(semconv.AgentCommRoleKey)},
		{&msg.Operation, string(semconv.AgentCommOperationKey)},
		{&msg.UnitUID, string(semconv.AgentCommUnitIDKey)},
		{&msg.UnitType, string(semconv.AgentCommUnitTypeKey)},
		{&msg.Status, string(semconv.AgentCommStatusKey)},
		{&msg.PreviousStatus, string(semconv.AgentCommPreviousStatusKey)},
		{&msg.Transport, string(semconv.AgentCommTransportKey)},
		{&msg.Endpoint, string(semconv.AgentCommEndpointKey)},
		{&msg.PeerEndpoint, string(semconv.AgentCommPeerEndpointKey)},
		{&msg.TrustDomain, string(semconv.AgentCommTrustDomainKey)},
		{&msg.PeerTrustDomain, string(semconv.AgentCommPeerTrustDomainKey)},
		{&msg.PeerDID, string(semconv.AgentCommPeerDIDKey)},
		{&msg.ErrorCode, string(semconv.AgentCommErrorCodeKey)},
		{&msg.ErrorMessage, string(semconv.AgentCommErrorMessageKey)},
	}
	for _, o := range strOverrides {
		if hasAttr(attrs, o.key) {
			*o.field = attrStr(attrs, o.key, "")
		}
	}

	if p := intPtrFrom(attrs, string(semconv.AgentCommPartsCountKey)); p != nil {
		msg.PartsCount = p
	}
	if p := intPtrFrom(attrs, string(semconv.AgentCommArtifactsCountKey)); p != nil {
		msg.ArtifactsCount = p
	}
	if hasAttr(attrs, string(semconv.AgentCommPartTypesKey)) {
		msg.PartTypes = attrStrList(attrs, string(semconv.AgentCommPartTypesKey))
	}
	if p := boolPtrFrom(attrs, string(semconv.AgentCommCrossDomainKey)); p != nil {
		msg.CrossDomain = p
	}
	if p := floatPtrFrom(attrs, string(semconv.AgentCommDurationMsKey)); p != nil {
		msg.DurationMs = p
	}

	peerID := attrStr(attrs, string(semconv.AgentCommPeerAgentIDKey), "")
	peerName := attrStr(attrs, string(semconv.AgentCommPeerAgentNameKey), "")
	if peerID != "" || peerName != "" {
		uid := peerID
		if uid == "" {
			uid = peerName
		}
		msg.DstAgent = &OCSFAIAgent{UID: uid, Name: peerName}
	}
}
