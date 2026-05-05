// Package processors provides AITF span processors for Go.
package processors

import (
	"context"
	"fmt"
	"sync"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// MemorySnapshot captures the state of a memory entry before and after a mutation.
type MemorySnapshot struct {
	Key               string
	Store             string
	Operation         string
	ContentHashBefore string
	ContentHashAfter  string
	SizeBefore        int
	SizeAfter         int
	Provenance        string
	SessionID         string
	Timestamp         time.Time
}

// MemorySecurityEvent represents a security event detected by the memory processor.
type MemorySecurityEvent struct {
	EventType string
	Severity  string
	Details   string
	SpanID    string
	SessionID string
	MemoryKey string
	Timestamp time.Time
}

// MemorySessionStats holds memory statistics for a given session.
type MemorySessionStats struct {
	EntryCount     int
	TotalSizeBytes int
	ActiveKeys     []string
	EventCount     int
}

// MemoryStateOption configures a MemoryStateProcessor.
type MemoryStateOption func(*MemoryStateProcessor)

// WithMaxMemoryEntries sets the per-session entry count alert threshold.
func WithMaxMemoryEntries(n int) MemoryStateOption {
	return func(p *MemoryStateProcessor) {
		p.maxEntries = n
	}
}

// WithMaxMemorySize sets the per-session total size alert threshold in bytes.
func WithMaxMemorySize(n int) MemoryStateOption {
	return func(p *MemoryStateProcessor) {
		p.maxSize = n
	}
}

// WithAllowedProvenances sets the trusted provenance sources. Any write from a
// provenance not in this set triggers a security event.
func WithAllowedProvenances(provenances []string) MemoryStateOption {
	return func(p *MemoryStateProcessor) {
		p.allowedProvenances = make(map[string]struct{}, len(provenances))
		for _, prov := range provenances {
			p.allowedProvenances[prov] = struct{}{}
		}
	}
}

// WithPoisoningThreshold sets the score threshold (0-1) for poisoning detection.
func WithPoisoningThreshold(threshold float64) MemoryStateOption {
	return func(p *MemoryStateProcessor) {
		p.poisoningThreshold = threshold
	}
}

// WithSnapshotsEnabled controls whether before/after snapshots are captured.
func WithSnapshotsEnabled(enabled bool) MemoryStateOption {
	return func(p *MemoryStateProcessor) {
		p.enableSnapshots = enabled
	}
}

// WithCrossSessionAlert controls whether cross-session memory access alerts are emitted.
func WithCrossSessionAlert(enabled bool) MemoryStateOption {
	return func(p *MemoryStateProcessor) {
		p.crossSessionAlert = enabled
	}
}

// WithMaxEvents sets the maximum number of retained security events.
func WithMaxEvents(n int) MemoryStateOption {
	return func(p *MemoryStateProcessor) {
		p.maxEvents = n
	}
}

// WithMaxSnapshots sets the maximum number of retained memory snapshots.
func WithMaxSnapshots(n int) MemoryStateOption {
	return func(p *MemoryStateProcessor) {
		p.maxSnapshots = n
	}
}

// Compile-time assertion that MemoryStateProcessor implements sdktrace.SpanProcessor.
var _ sdktrace.SpanProcessor = (*MemoryStateProcessor)(nil)

// MemoryStateProcessor is an OTel SpanProcessor that monitors agent memory
// mutations for security-relevant patterns. It tracks memory writes, updates,
// and deletes with before/after snapshots, detects memory poisoning (unexpected
// content injection), verifies session memory isolation, monitors long-term
// memory growth anomalies, and emits security events for suspicious memory
// operations.
//
// Usage:
//
//	processor := processors.NewMemoryStateProcessor(
//	    processors.WithMaxMemoryEntries(500),
//	    processors.WithAllowedProvenances([]string{"conversation", "tool_result", "system"}),
//	)
//	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(processor))
type MemoryStateProcessor struct {
	maxEntries          int
	maxSize             int
	allowedProvenances  map[string]struct{}
	poisoningThreshold  float64
	enableSnapshots     bool
	crossSessionAlert   bool
	maxEvents           int
	maxSnapshots        int

	// mu protects all mutable state below.
	mu                 sync.RWMutex
	sessionMemory      map[string]map[string]*MemorySnapshot // sessionID -> key -> snapshot
	sessionEntryCounts map[string]int
	sessionTotalSize   map[string]int
	memoryHashes       map[string]string // "sessionID:key" -> hash
	events             []MemorySecurityEvent
	snapshots          []MemorySnapshot
}

// NewMemoryStateProcessor creates a new MemoryStateProcessor with the given options.
func NewMemoryStateProcessor(opts ...MemoryStateOption) *MemoryStateProcessor {
	p := &MemoryStateProcessor{
		maxEntries:         1000,
		maxSize:            50 * 1024 * 1024, // 50 MB
		poisoningThreshold: 0.7,
		enableSnapshots:    true,
		crossSessionAlert:  true,
		maxEvents:          10000,
		maxSnapshots:       1000,
		allowedProvenances: map[string]struct{}{
			"conversation": {},
			"tool_result":  {},
			"system":       {},
			"imported":     {},
		},
		sessionMemory:      make(map[string]map[string]*MemorySnapshot),
		sessionEntryCounts: make(map[string]int),
		sessionTotalSize:   make(map[string]int),
		memoryHashes:       make(map[string]string),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// OnStart is called when a span starts. No processing is needed at start time.
func (p *MemoryStateProcessor) OnStart(_ context.Context, _ sdktrace.ReadWriteSpan) {
	// Processing happens in OnEnd when all attributes are available.
}

// OnEnd processes completed memory operation spans.
func (p *MemoryStateProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	attrs := span.Attributes()

	// Build a lookup map for attributes.
	attrMap := make(map[string]interface{}, len(attrs))
	for _, kv := range attrs {
		attrMap[string(kv.Key)] = kv.Value.Emit()
	}

	// Only process memory-related spans.
	operationRaw, ok := attrMap["memory.operation"]
	if !ok {
		return
	}
	operation, _ := operationRaw.(string)
	if operation == "" {
		return
	}

	memoryKey := attrString(attrMap, "memory.key", "")
	store := attrString(attrMap, "memory.store", "unknown")
	provenance := attrString(attrMap, "memory.provenance", "unknown")
	sessionID := attrString(attrMap, "gen_ai.conversation.id", "unknown")
	contentHash := attrString(attrMap, "memory.security.content_hash", "")
	contentSize := attrInt(attrMap, "memory.security.content_size", 0)
	poisoningScore := attrFloat(attrMap, "memory.security.poisoning_score")
	crossSession := attrBool(attrMap, "memory.security.cross_session")
	integrityHash := attrString(attrMap, "memory.security.integrity_hash", "")

	spanID := "unknown"
	if span.SpanContext().HasSpanID() {
		spanID = span.SpanContext().SpanID().String()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// 1. Capture snapshot
	if p.enableSnapshots && (operation == "store" || operation == "update" || operation == "delete") {
		hashKey := sessionID + ":" + memoryKey
		previousHash, _ := p.memoryHashes[hashKey]

		var sizeBefore int
		if sessionMem, exists := p.sessionMemory[sessionID]; exists {
			if prev, exists := sessionMem[memoryKey]; exists {
				sizeBefore = prev.SizeAfter
			}
		}

		afterHash := contentHash
		sizeAfter := contentSize
		if operation == "delete" {
			afterHash = ""
			sizeAfter = 0
		}

		snapshot := MemorySnapshot{
			Key:               memoryKey,
			Store:             store,
			Operation:         operation,
			ContentHashBefore: previousHash,
			ContentHashAfter:  afterHash,
			SizeBefore:        sizeBefore,
			SizeAfter:         sizeAfter,
			Provenance:        provenance,
			SessionID:         sessionID,
			Timestamp:         time.Now(),
		}
		p.snapshots = append(p.snapshots, snapshot)

		// Enforce max_snapshots bound.
		if len(p.snapshots) > p.maxSnapshots {
			p.snapshots = p.snapshots[len(p.snapshots)-p.maxSnapshots:]
		}

		// Update tracked hash.
		if operation == "delete" {
			delete(p.memoryHashes, hashKey)
		} else if contentHash != "" {
			p.memoryHashes[hashKey] = contentHash
		}
	}

	// 2. Provenance check -- detect untrusted sources.
	if _, trusted := p.allowedProvenances[provenance]; !trusted {
		p.emitEvent(MemorySecurityEvent{
			EventType: "untrusted_provenance",
			Severity:  "high",
			Details: fmt.Sprintf(
				"Memory write from untrusted provenance '%s' for key '%s' in store '%s'",
				provenance, memoryKey, store,
			),
			SpanID:    spanID,
			SessionID: sessionID,
			MemoryKey: memoryKey,
			Timestamp: time.Now(),
		})
	}

	// 3. Poisoning detection.
	if poisoningScore != nil && *poisoningScore >= p.poisoningThreshold {
		p.emitEvent(MemorySecurityEvent{
			EventType: "memory_poisoning_detected",
			Severity:  "critical",
			Details: fmt.Sprintf(
				"Memory poisoning detected for key '%s' (score=%.2f, threshold=%.2f). Provenance: %s",
				memoryKey, *poisoningScore, p.poisoningThreshold, provenance,
			),
			SpanID:    spanID,
			SessionID: sessionID,
			MemoryKey: memoryKey,
			Timestamp: time.Now(),
		})
	}

	// 4. Integrity verification.
	if integrityHash != "" && contentHash != "" && integrityHash != contentHash {
		p.emitEvent(MemorySecurityEvent{
			EventType: "memory_integrity_violation",
			Severity:  "critical",
			Details: fmt.Sprintf(
				"Memory integrity hash mismatch for key '%s'. Expected: %s, Got: %s",
				memoryKey, integrityHash, contentHash,
			),
			SpanID:    spanID,
			SessionID: sessionID,
			MemoryKey: memoryKey,
			Timestamp: time.Now(),
		})
	}

	// 5. Cross-session isolation check.
	if p.crossSessionAlert && crossSession {
		p.emitEvent(MemorySecurityEvent{
			EventType: "cross_session_memory_access",
			Severity:  "high",
			Details: fmt.Sprintf(
				"Cross-session memory access detected for key '%s'. Session '%s' accessed memory belonging to another session.",
				memoryKey, sessionID,
			),
			SpanID:    spanID,
			SessionID: sessionID,
			MemoryKey: memoryKey,
			Timestamp: time.Now(),
		})
	}

	// 6. Memory growth anomaly detection.
	if operation == "store" || operation == "update" {
		if operation == "store" {
			p.sessionEntryCounts[sessionID]++
		}
		p.sessionTotalSize[sessionID] += contentSize

		entryCount := p.sessionEntryCounts[sessionID]
		totalSize := p.sessionTotalSize[sessionID]

		if entryCount > p.maxEntries {
			p.emitEvent(MemorySecurityEvent{
				EventType: "memory_growth_anomaly",
				Severity:  "medium",
				Details: fmt.Sprintf(
					"Session '%s' exceeded max memory entries: %d > %d",
					sessionID, entryCount, p.maxEntries,
				),
				SpanID:    spanID,
				SessionID: sessionID,
				Timestamp: time.Now(),
			})
		}

		if totalSize > p.maxSize {
			p.emitEvent(MemorySecurityEvent{
				EventType: "memory_size_anomaly",
				Severity:  "high",
				Details: fmt.Sprintf(
					"Session '%s' exceeded max memory size: %d bytes > %d bytes",
					sessionID, totalSize, p.maxSize,
				),
				SpanID:    spanID,
				SessionID: sessionID,
				Timestamp: time.Now(),
			})
		}
	}

	// 7. Update tracking state.
	if operation == "delete" {
		if sessionMem, exists := p.sessionMemory[sessionID]; exists {
			delete(sessionMem, memoryKey)
		}
	} else {
		if _, exists := p.sessionMemory[sessionID]; !exists {
			p.sessionMemory[sessionID] = make(map[string]*MemorySnapshot)
		}
		p.sessionMemory[sessionID][memoryKey] = &MemorySnapshot{
			Key:              memoryKey,
			Store:            store,
			Operation:        operation,
			ContentHashAfter: contentHash,
			SizeAfter:        contentSize,
			Provenance:       provenance,
			SessionID:        sessionID,
		}
	}
}

// emitEvent appends a security event, enforcing the max_events bound.
// Must be called while holding p.mu.
func (p *MemoryStateProcessor) emitEvent(event MemorySecurityEvent) {
	p.events = append(p.events, event)
	if len(p.events) > p.maxEvents {
		p.events = p.events[len(p.events)-p.maxEvents:]
	}
}

// Shutdown shuts down the processor.
func (p *MemoryStateProcessor) Shutdown(_ context.Context) error {
	return nil
}

// ForceFlush flushes any pending state.
func (p *MemoryStateProcessor) ForceFlush(_ context.Context) error {
	return nil
}

// ── Public API ──────────────────────────────────────────────────────────────

// severityOrder maps severity strings to numeric levels for filtering.
var severityOrder = map[string]int{
	"informational": 0,
	"low":           1,
	"medium":        2,
	"high":          3,
	"critical":      4,
}

// GetEvents returns security events at or above the given severity level.
func (p *MemoryStateProcessor) GetEvents(minSeverity string) []MemorySecurityEvent {
	minLevel, ok := severityOrder[minSeverity]
	if !ok {
		minLevel = 0
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	var result []MemorySecurityEvent
	for _, e := range p.events {
		if severityOrder[e.Severity] >= minLevel {
			result = append(result, e)
		}
	}
	return result
}

// GetSnapshots returns memory mutation snapshots, optionally filtered by session.
func (p *MemoryStateProcessor) GetSnapshots(sessionID string) []MemorySnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if sessionID != "" {
		var result []MemorySnapshot
		for _, s := range p.snapshots {
			if s.SessionID == sessionID {
				result = append(result, s)
			}
		}
		return result
	}

	result := make([]MemorySnapshot, len(p.snapshots))
	copy(result, p.snapshots)
	return result
}

// GetSessionStats returns memory statistics for the given session.
func (p *MemoryStateProcessor) GetSessionStats(sessionID string) MemorySessionStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var activeKeys []string
	if sessionMem, exists := p.sessionMemory[sessionID]; exists {
		activeKeys = make([]string, 0, len(sessionMem))
		for k := range sessionMem {
			activeKeys = append(activeKeys, k)
		}
	}

	var eventCount int
	for _, e := range p.events {
		if e.SessionID == sessionID {
			eventCount++
		}
	}

	return MemorySessionStats{
		EntryCount:     p.sessionEntryCounts[sessionID],
		TotalSizeBytes: p.sessionTotalSize[sessionID],
		ActiveKeys:     activeKeys,
		EventCount:     eventCount,
	}
}

// ClearSession removes all tracking state for the given session.
func (p *MemoryStateProcessor) ClearSession(sessionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.sessionMemory, sessionID)
	delete(p.sessionEntryCounts, sessionID)
	delete(p.sessionTotalSize, sessionID)

	// Clean up hashes for this session.
	prefix := sessionID + ":"
	for k := range p.memoryHashes {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(p.memoryHashes, k)
		}
	}
}

// ── Attribute extraction helpers ────────────────────────────────────────────

func attrString(m map[string]interface{}, key, fallback string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return fallback
}

func attrInt(m map[string]interface{}, key string, fallback int) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int64:
			return int(n)
		case int:
			return n
		case float64:
			return int(n)
		}
	}
	return fallback
}

func attrFloat(m map[string]interface{}, key string) *float64 {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return &n
		case int64:
			f := float64(n)
			return &f
		}
	}
	return nil
}

func attrBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
