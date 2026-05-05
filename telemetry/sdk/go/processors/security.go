// Package processors provides AITF span processors for Go.
package processors

import (
	"log"
	"regexp"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

// maxContentLength is the maximum content length to analyze (prevent unbounded CPU usage).
const maxContentLength = 100000

// SecurityFinding represents a detected security threat.
type SecurityFinding struct {
	ThreatType      string
	OWASPCategory   string
	RiskLevel       string
	RiskScore       float64
	Confidence      float64
	DetectionMethod string
	Details         string
	Blocked         bool
}

// SecurityProcessor detects security threats in AI content.
type SecurityProcessor struct {
	promptInjectionPatterns  []*regexp.Regexp
	jailbreakPatterns        []*regexp.Regexp
	systemPromptLeakPatterns []*regexp.Regexp
	dataExfilPatterns        []*regexp.Regexp
	commandInjectionPatterns []*regexp.Regexp
}

// NewSecurityProcessor creates a new security processor.
func NewSecurityProcessor() *SecurityProcessor {
	return &SecurityProcessor{
		promptInjectionPatterns: compilePatterns([]string{
			`(?i)ignore\s+(all\s+)?previous\s+instructions`,
			`(?i)ignore\s+(all\s+)?above\s+instructions`,
			`(?i)disregard\s+(all\s+)?previous`,
			`(?i)forget\s+(all\s+)?(your|previous)\s+instructions`,
			`(?i)you\s+are\s+now\s+(a|an|the)\s+`,
			`(?i)new\s+instructions?:\s*`,
			`(?i)system\s*:\s*you\s+are`,
			`(?i)\[SYSTEM\]`,
			`(?i)override\s+(your\s+)?instructions`,
		}),
		jailbreakPatterns: compilePatterns([]string{
			`(?i)DAN\s+mode`,
			`(?i)developer\s+mode\s+enabled`,
			`(?i)jailbreak`,
			`(?i)bypass\s+(safety|content|filter)`,
			`(?i)without\s+(any\s+)?restrictions`,
			`(?i)unfiltered\s+(mode|response)`,
		}),
		systemPromptLeakPatterns: compilePatterns([]string{
			`(?i)(show|reveal|display|print|repeat)\s+(your\s+)?(system\s+)?prompt`,
			`(?i)what\s+(are|is)\s+your\s+(system\s+)?(instructions|prompt|rules)`,
		}),
		dataExfilPatterns: compilePatterns([]string{
			// Bounded quantifier to prevent ReDoS (was: .* which causes catastrophic backtracking)
			`(?i)(send|post|transmit|upload)\s+[^\n]{0,200}(to|at)\s+https?://`,
			`(?i)(curl|wget|fetch)\s+`,
			`(?i)exfiltrat`,
		}),
		commandInjectionPatterns: compilePatterns([]string{
			`(?i);\s*(rm|del|drop|shutdown|kill)\s+`,
			`(?i)\|\s*(bash|sh|cmd|powershell)`,
		}),
	}
}

// AnalyzeText checks text for security threats.
func (s *SecurityProcessor) AnalyzeText(text string) []SecurityFinding {
	// Truncate content to prevent excessive CPU usage
	if len(text) > maxContentLength {
		text = text[:maxContentLength]
	}

	var findings []SecurityFinding

	if matchesAny(s.promptInjectionPatterns, text) {
		findings = append(findings, SecurityFinding{
			ThreatType:      semconv.ThreatTypePromptInjection,
			OWASPCategory:   semconv.OWASPLICM01,
			RiskLevel:       semconv.RiskLevelHigh,
			RiskScore:       80.0,
			Confidence:      0.85,
			DetectionMethod: "pattern",
			Details:         "Prompt injection pattern detected",
		})
	}

	if matchesAny(s.jailbreakPatterns, text) {
		findings = append(findings, SecurityFinding{
			ThreatType:      semconv.ThreatTypeJailbreak,
			OWASPCategory:   semconv.OWASPLICM01,
			RiskLevel:       semconv.RiskLevelCritical,
			RiskScore:       95.0,
			Confidence:      0.90,
			DetectionMethod: "pattern",
			Details:         "Jailbreak attempt detected",
		})
	}

	if matchesAny(s.systemPromptLeakPatterns, text) {
		findings = append(findings, SecurityFinding{
			ThreatType:      semconv.ThreatTypeSystemPromptLeak,
			OWASPCategory:   semconv.OWASPLICM07,
			RiskLevel:       semconv.RiskLevelMedium,
			RiskScore:       60.0,
			Confidence:      0.75,
			DetectionMethod: "pattern",
			Details:         "System prompt leak attempt detected",
		})
	}

	if matchesAny(s.dataExfilPatterns, text) {
		findings = append(findings, SecurityFinding{
			ThreatType:      semconv.ThreatTypeDataExfil,
			OWASPCategory:   semconv.OWASPLICM02,
			RiskLevel:       semconv.RiskLevelHigh,
			RiskScore:       85.0,
			Confidence:      0.70,
			DetectionMethod: "pattern",
			Details:         "Data exfiltration pattern detected",
		})
	}

	if matchesAny(s.commandInjectionPatterns, text) {
		findings = append(findings, SecurityFinding{
			ThreatType:      "command_injection",
			OWASPCategory:   semconv.OWASPLICM05,
			RiskLevel:       semconv.RiskLevelCritical,
			RiskScore:       90.0,
			Confidence:      0.80,
			DetectionMethod: "pattern",
			Details:         "Command injection pattern detected",
		})
	}

	return findings
}

func compilePatterns(patterns []string) []*regexp.Regexp {
	result := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			log.Printf("WARNING: dropping invalid security pattern %q: %v", p, err)
			continue
		}
		result = append(result, re)
	}
	return result
}

func matchesAny(patterns []*regexp.Regexp, text string) bool {
	for _, p := range patterns {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}
