// Package processors provides AITF span processors for Go.
package processors

import (
	"strings"

	"github.com/girdav01/AITF/sdk/go/semconv"
	"go.opentelemetry.io/otel/attribute"
)

// ComplianceFrameworkMapping holds the control mapping for a single framework
// applied to a single event type.
type ComplianceFrameworkMapping struct {
	Controls   []string // NIST, ISO, SOC2, CSA AICM
	Techniques []string // MITRE ATLAS
	Articles   []string // EU AI Act, GDPR
	Sections   []string // CCPA
	Function   string   // NIST function (MAP, GOVERN, MANAGE)
	Tactic     string   // MITRE tactic
	Clause     string   // ISO clause
	RiskLevel  string   // EU AI Act risk level
	Criteria   string   // SOC2 criteria
	LawfulBasis string  // GDPR lawful basis
	Category   string   // CCPA category
	Domain     string   // CSA AICM domain
}

// PrimaryControls returns the primary control list for this mapping.
func (m *ComplianceFrameworkMapping) PrimaryControls() []string {
	if len(m.Controls) > 0 {
		return m.Controls
	}
	if len(m.Techniques) > 0 {
		return m.Techniques
	}
	if len(m.Articles) > 0 {
		return m.Articles
	}
	if len(m.Sections) > 0 {
		return m.Sections
	}
	return nil
}

// ComplianceMappings maps event types to framework mappings.
// Key structure: ComplianceMappings[eventType][framework] -> ComplianceFrameworkMapping
var ComplianceMappings = map[string]map[string]ComplianceFrameworkMapping{
	"model_inference": {
		"nist_ai_rmf": {Controls: []string{"MAP-1.1", "MEASURE-2.5"}, Function: "MAP"},
		"mitre_atlas":  {Techniques: []string{"AML.T0040"}, Tactic: "ML Attack Staging"},
		"iso_42001":    {Controls: []string{"6.1.4", "8.4"}, Clause: "Operation"},
		"eu_ai_act":    {Articles: []string{"Article 13", "Article 15"}, RiskLevel: "high"},
		"soc2":         {Controls: []string{"CC6.1"}, Criteria: "Common Criteria"},
		"gdpr":         {Articles: []string{"Article 5", "Article 22"}, LawfulBasis: "legitimate_interest"},
		"ccpa":         {Sections: []string{"1798.100"}, Category: "personal_information"},
		"csa_aicm": {Controls: []string{
			"MDS-01", "MDS-02", "MDS-03", "MDS-04", "MDS-05", "MDS-06",
			"MDS-07", "MDS-08", "MDS-09", "MDS-10", "MDS-11", "MDS-13",
			"AIS-03", "AIS-04", "AIS-05", "AIS-06", "AIS-07", "AIS-08",
			"AIS-09", "AIS-12", "AIS-14", "AIS-15", "LOG-07", "LOG-08",
			"LOG-13", "LOG-14", "LOG-15", "GRC-13", "GRC-14", "GRC-15",
			"TVM-11", "DSP-07",
		}, Domain: "Model Security"},
	},
	"agent_activity": {
		"nist_ai_rmf": {Controls: []string{"GOVERN-1.2", "MANAGE-3.1"}, Function: "GOVERN"},
		"mitre_atlas":  {Techniques: []string{"AML.T0048"}, Tactic: "ML Attack Staging"},
		"iso_42001":    {Controls: []string{"8.2", "A.6.2.5"}, Clause: "Operation"},
		"eu_ai_act":    {Articles: []string{"Article 14", "Article 52"}, RiskLevel: "high"},
		"soc2":         {Controls: []string{"CC7.2"}, Criteria: "Common Criteria"},
		"gdpr":         {Articles: []string{"Article 22"}, LawfulBasis: "legitimate_interest"},
		"csa_aicm": {Controls: []string{
			"AIS-02", "AIS-11", "AIS-13", "IAM-04", "IAM-05", "IAM-16",
			"IAM-19", "GRC-09", "GRC-10", "GRC-15", "LOG-05", "LOG-11",
			"MDS-10",
		}, Domain: "Application & Interface Security"},
	},
	"tool_execution": {
		"nist_ai_rmf": {Controls: []string{"MAP-3.5", "MANAGE-4.2"}, Function: "MANAGE"},
		"mitre_atlas":  {Techniques: []string{"AML.T0043"}, Tactic: "ML Attack Staging"},
		"iso_42001":    {Controls: []string{"A.6.2.7"}, Clause: "Annex A"},
		"eu_ai_act":    {Articles: []string{"Article 9"}, RiskLevel: "high"},
		"soc2":         {Controls: []string{"CC6.3"}, Criteria: "Common Criteria"},
		"gdpr":         {Articles: []string{"Article 25"}, LawfulBasis: "legitimate_interest"},
		"csa_aicm": {Controls: []string{
			"AIS-01", "AIS-04", "AIS-08", "AIS-09", "AIS-10", "AIS-13",
			"IAM-05", "IAM-16", "LOG-05", "LOG-11", "TVM-05", "TVM-11",
		}, Domain: "Application & Interface Security"},
	},
	"data_retrieval": {
		"nist_ai_rmf": {Controls: []string{"MAP-1.5", "MEASURE-2.7"}, Function: "MAP"},
		"mitre_atlas":  {Techniques: []string{"AML.T0025"}, Tactic: "Exfiltration"},
		"iso_42001":    {Controls: []string{"A.7.4"}, Clause: "Annex A"},
		"eu_ai_act":    {Articles: []string{"Article 10"}, RiskLevel: "high"},
		"soc2":         {Controls: []string{"CC6.1"}, Criteria: "Common Criteria"},
		"gdpr":         {Articles: []string{"Article 5", "Article 6"}, LawfulBasis: "legitimate_interest"},
		"ccpa":         {Sections: []string{"1798.100"}, Category: "personal_information"},
		"csa_aicm": {Controls: []string{
			"DSP-01", "DSP-02", "DSP-03", "DSP-04", "DSP-05", "DSP-06",
			"DSP-07", "DSP-08", "DSP-09", "DSP-10", "DSP-11", "DSP-12",
			"DSP-13", "DSP-14", "DSP-15", "DSP-16", "DSP-17", "DSP-18",
			"DSP-19", "DSP-20", "DSP-21", "DSP-22", "DSP-23", "DSP-24",
			"CEK-03", "LOG-07", "LOG-10",
		}, Domain: "Data Security & Privacy"},
	},
	"security_finding": {
		"nist_ai_rmf": {Controls: []string{"MANAGE-2.4", "MANAGE-4.1"}, Function: "MANAGE"},
		"mitre_atlas":  {Techniques: []string{"AML.T0051"}, Tactic: "Initial Access"},
		"iso_42001":    {Controls: []string{"6.1.2", "A.6.2.4"}, Clause: "Planning"},
		"eu_ai_act":    {Articles: []string{"Article 9", "Article 62"}, RiskLevel: "high"},
		"soc2":         {Controls: []string{"CC7.2", "CC7.3"}, Criteria: "Common Criteria"},
		"gdpr":         {Articles: []string{"Article 32", "Article 33"}, LawfulBasis: "legal_obligation"},
		"ccpa":         {Sections: []string{"1798.150"}, Category: "breach"},
		"csa_aicm": {Controls: []string{
			"SEF-01", "SEF-02", "SEF-03", "SEF-04", "SEF-05", "SEF-06",
			"SEF-07", "SEF-08", "SEF-09", "TVM-01", "TVM-02", "TVM-03",
			"TVM-04", "TVM-06", "TVM-07", "TVM-08", "TVM-09", "TVM-10",
			"TVM-11", "TVM-12", "TVM-13", "LOG-02", "LOG-03", "LOG-04",
			"LOG-12", "MDS-06", "MDS-07",
		}, Domain: "Security Incident Management"},
	},
	"supply_chain": {
		"nist_ai_rmf": {Controls: []string{"MAP-5.2", "GOVERN-6.1"}, Function: "GOVERN"},
		"mitre_atlas":  {Techniques: []string{"AML.T0010"}, Tactic: "Resource Development"},
		"iso_42001":    {Controls: []string{"A.6.2.3"}, Clause: "Annex A"},
		"eu_ai_act":    {Articles: []string{"Article 15", "Article 28"}, RiskLevel: "high"},
		"soc2":         {Controls: []string{"CC9.2"}, Criteria: "Common Criteria"},
		"gdpr":         {Articles: []string{"Article 28"}, LawfulBasis: "contractual"},
		"csa_aicm": {Controls: []string{
			"STA-01", "STA-02", "STA-03", "STA-04", "STA-05", "STA-06",
			"STA-07", "STA-08", "STA-09", "STA-10", "STA-11", "STA-12",
			"STA-13", "STA-14", "STA-15", "STA-16", "CCC-01", "CCC-02",
			"CCC-03", "CCC-04", "CCC-05", "CCC-06", "CCC-07", "CCC-08",
			"CCC-09", "MDS-08", "MDS-09", "MDS-12", "MDS-13",
			"DCS-01", "DCS-02", "DCS-03", "DCS-04", "DCS-05", "DCS-06",
			"DCS-07", "DCS-08", "DCS-09", "DCS-10", "DCS-11", "DCS-12",
			"DCS-13", "DCS-14", "DCS-15",
			"IPY-01", "IPY-02", "IPY-03", "IPY-04",
			"I&S-01", "I&S-02", "I&S-03", "I&S-04", "I&S-05",
			"I&S-06", "I&S-07", "I&S-08", "I&S-09",
		}, Domain: "Supply Chain Management"},
	},
	"governance": {
		"nist_ai_rmf": {Controls: []string{"GOVERN-1.1", "MANAGE-1.3"}, Function: "GOVERN"},
		"iso_42001":    {Controls: []string{"5.1", "9.1"}, Clause: "Leadership"},
		"eu_ai_act":    {Articles: []string{"Article 9", "Article 61"}, RiskLevel: "high"},
		"soc2":         {Controls: []string{"CC1.2"}, Criteria: "Common Criteria"},
		"gdpr":         {Articles: []string{"Article 5"}, LawfulBasis: "legal_obligation"},
		"ccpa":         {Sections: []string{"1798.185"}, Category: "rulemaking"},
		"csa_aicm": {Controls: []string{
			"GRC-01", "GRC-02", "GRC-03", "GRC-04", "GRC-05", "GRC-06",
			"GRC-07", "GRC-08", "GRC-09", "GRC-10", "GRC-11", "GRC-12",
			"GRC-13", "GRC-14", "GRC-15", "A&A-01", "A&A-02", "A&A-03",
			"A&A-04", "A&A-05", "A&A-06", "BCR-01", "BCR-02", "BCR-03",
			"BCR-04", "BCR-05", "BCR-06", "BCR-07", "BCR-08", "BCR-09",
			"BCR-10", "BCR-11", "HRS-01", "HRS-02", "HRS-03", "HRS-04",
			"HRS-05", "HRS-06", "HRS-07", "HRS-08", "HRS-09", "HRS-10",
			"HRS-11", "HRS-12", "HRS-13", "HRS-14", "HRS-15",
			"LOG-01", "LOG-06", "DSP-01",
		}, Domain: "Governance, Risk & Compliance"},
	},
	"identity": {
		"nist_ai_rmf": {Controls: []string{"GOVERN-1.5", "MANAGE-2.1"}, Function: "GOVERN"},
		"mitre_atlas":  {Techniques: []string{"AML.T0052"}, Tactic: "Initial Access"},
		"iso_42001":    {Controls: []string{"A.6.2.6"}, Clause: "Annex A"},
		"eu_ai_act":    {Articles: []string{"Article 9"}, RiskLevel: "high"},
		"soc2":         {Controls: []string{"CC6.1", "CC6.2"}, Criteria: "Common Criteria"},
		"gdpr":         {Articles: []string{"Article 32"}, LawfulBasis: "legal_obligation"},
		"ccpa":         {Sections: []string{"1798.140"}, Category: "personal_information"},
		"csa_aicm": {Controls: []string{
			"IAM-01", "IAM-02", "IAM-03", "IAM-04", "IAM-05", "IAM-06",
			"IAM-07", "IAM-08", "IAM-09", "IAM-10", "IAM-11", "IAM-12",
			"IAM-13", "IAM-14", "IAM-15", "IAM-16", "IAM-17", "IAM-18",
			"IAM-19", "CEK-01", "CEK-02", "CEK-03", "CEK-04", "CEK-05",
			"CEK-06", "CEK-07", "CEK-08", "CEK-09", "CEK-10", "CEK-11",
			"CEK-12", "CEK-13", "CEK-14", "CEK-15", "CEK-16", "CEK-17",
			"CEK-18", "CEK-19", "CEK-20", "CEK-21", "LOG-04", "LOG-09",
			"UEM-01", "UEM-02", "UEM-03", "UEM-04", "UEM-05", "UEM-06",
			"UEM-07", "UEM-08", "UEM-09", "UEM-10", "UEM-11", "UEM-12",
			"UEM-13", "UEM-14",
		}, Domain: "Identity & Access Management"},
	},
}

// allFrameworks lists all supported compliance frameworks.
var allFrameworks = []string{
	"nist_ai_rmf", "mitre_atlas", "iso_42001",
	"eu_ai_act", "soc2", "gdpr", "ccpa", "csa_aicm",
}

// ComplianceProcessor maps AI telemetry events to compliance framework controls.
type ComplianceProcessor struct {
	frameworks []string
}

// NewComplianceProcessor creates a new compliance processor.
// If frameworks is nil or empty, all 8 frameworks are enabled.
func NewComplianceProcessor(frameworks []string) *ComplianceProcessor {
	if len(frameworks) == 0 {
		frameworks = append([]string{}, allFrameworks...)
	}
	return &ComplianceProcessor{frameworks: frameworks}
}

// GetComplianceMapping returns the compliance mapping for a given event type,
// filtered to only the configured frameworks.
func (c *ComplianceProcessor) GetComplianceMapping(eventType string) map[string]ComplianceFrameworkMapping {
	fullMapping, ok := ComplianceMappings[eventType]
	if !ok {
		return nil
	}

	result := make(map[string]ComplianceFrameworkMapping)
	for _, framework := range c.frameworks {
		if m, ok := fullMapping[framework]; ok {
			result[framework] = m
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// GetComplianceAttributes returns compliance data as OTel-compatible attributes
// suitable for span attributes.
func (c *ComplianceProcessor) GetComplianceAttributes(eventType string) []attribute.KeyValue {
	mapping := c.GetComplianceMapping(eventType)
	if mapping == nil {
		return nil
	}

	var attrs []attribute.KeyValue

	for framework, m := range mapping {
		switch framework {
		case "nist_ai_rmf":
			if len(m.Controls) > 0 {
				attrs = append(attrs, semconv.ComplianceNISTControlsKey.String(strings.Join(m.Controls, ",")))
			}
		case "mitre_atlas":
			if len(m.Techniques) > 0 {
				attrs = append(attrs, semconv.ComplianceMITRETechniquesKey.String(strings.Join(m.Techniques, ",")))
			}
		case "iso_42001":
			if len(m.Controls) > 0 {
				attrs = append(attrs, semconv.ComplianceISOControlsKey.String(strings.Join(m.Controls, ",")))
			}
		case "eu_ai_act":
			if len(m.Articles) > 0 {
				attrs = append(attrs, semconv.ComplianceEUArticlesKey.String(strings.Join(m.Articles, ",")))
			}
		case "soc2":
			if len(m.Controls) > 0 {
				attrs = append(attrs, semconv.ComplianceSOC2ControlsKey.String(strings.Join(m.Controls, ",")))
			}
		case "gdpr":
			if len(m.Articles) > 0 {
				attrs = append(attrs, semconv.ComplianceGDPRArticlesKey.String(strings.Join(m.Articles, ",")))
			}
		case "ccpa":
			if len(m.Sections) > 0 {
				attrs = append(attrs, semconv.ComplianceCCPASectionsKey.String(strings.Join(m.Sections, ",")))
			}
		case "csa_aicm":
			if len(m.Controls) > 0 {
				attrs = append(attrs, semconv.ComplianceCSAAICMControlsKey.String(strings.Join(m.Controls, ",")))
			}
		}
	}

	return attrs
}

// GetCoverageMatrix generates a coverage matrix showing which controls are
// mapped per event type for the configured frameworks.
func (c *ComplianceProcessor) GetCoverageMatrix() map[string]map[string][]string {
	matrix := make(map[string]map[string][]string)

	for eventType, frameworkMap := range ComplianceMappings {
		matrix[eventType] = make(map[string][]string)
		for _, framework := range c.frameworks {
			if m, ok := frameworkMap[framework]; ok {
				controls := m.PrimaryControls()
				if len(controls) > 0 {
					matrix[eventType][framework] = controls
				}
			}
		}
	}

	return matrix
}

// ClassifySpanName classifies a span name into an AI event type.
// Returns empty string if the span is not an AI-related span.
func ClassifySpanName(name string, attrKeys []string) string {
	if strings.HasPrefix(name, "chat ") || strings.HasPrefix(name, "embeddings ") {
		return "model_inference"
	}
	for _, k := range attrKeys {
		if k == string(semconv.GenAISystemKey) {
			return "model_inference"
		}
	}
	if strings.HasPrefix(name, "agent.") {
		return "agent_activity"
	}
	if strings.HasPrefix(name, "mcp.tool.") || strings.HasPrefix(name, "skill.invoke") {
		return "tool_execution"
	}
	if strings.HasPrefix(name, "rag.") || strings.HasPrefix(name, "mcp.resource.") {
		return "data_retrieval"
	}
	for _, k := range attrKeys {
		if strings.HasPrefix(k, "security.") {
			return "security_finding"
		}
	}
	return ""
}
