package processors

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// PIIDetection represents a PII detection result.
type PIIDetection struct {
	Type  string
	Count int
}

// PIIProcessor detects and optionally redacts PII in text.
type PIIProcessor struct {
	patterns map[string]*regexp.Regexp
	action   string // "flag", "redact", "hash"
}

// NewPIIProcessor creates a new PII processor.
// action can be "flag", "redact", or "hash".
func NewPIIProcessor(action string, types []string) *PIIProcessor {
	allPatterns := map[string]*regexp.Regexp{
		"email":       regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
		"phone":       regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
		"ssn":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		"credit_card": regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),
		"api_key":     regexp.MustCompile(`\b(?:sk-|pk-|ak-|key-)[A-Za-z0-9]{20,}\b`),
		"jwt":         regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`),
		"ip_address":  regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
		"aws_key":     regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	}

	selected := make(map[string]*regexp.Regexp)
	if len(types) == 0 {
		selected = allPatterns
	} else {
		for _, t := range types {
			if p, ok := allPatterns[t]; ok {
				selected[t] = p
			}
		}
	}

	switch action {
	case "flag", "redact", "hash":
		// valid
	case "":
		action = "flag"
	default:
		log.Printf("WARNING: invalid PII action %q, defaulting to \"flag\"", action)
		action = "flag"
	}

	return &PIIProcessor{patterns: selected, action: action}
}

// DetectPII finds PII in text and returns detections.
func (p *PIIProcessor) DetectPII(text string) []PIIDetection {
	var detections []PIIDetection
	for piiType, pattern := range p.patterns {
		matches := pattern.FindAllString(text, -1)
		if len(matches) > 0 {
			detections = append(detections, PIIDetection{
				Type:  piiType,
				Count: len(matches),
			})
		}
	}
	return detections
}

// RedactPII replaces PII in text with redaction markers.
func (p *PIIProcessor) RedactPII(text string) (string, []PIIDetection) {
	detections := p.DetectPII(text)
	if len(detections) == 0 {
		return text, nil
	}

	result := text
	for piiType, pattern := range p.patterns {
		replacement := fmt.Sprintf("[%s_REDACTED]", strings.ToUpper(piiType))
		result = pattern.ReplaceAllString(result, replacement)
	}
	return result, detections
}

// HasPII returns true if text contains any PII.
func (p *PIIProcessor) HasPII(text string) bool {
	for _, pattern := range p.patterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}
