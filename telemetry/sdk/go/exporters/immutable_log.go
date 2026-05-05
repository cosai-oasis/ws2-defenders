// Package exporters provides AITF span exporters for Go.
//
// ImmutableLogExporter writes AI telemetry events to an append-only,
// hash-chained log file providing cryptographic tamper evidence.
//
// Each log entry includes a SHA-256 hash of the previous entry, creating
// an unbroken chain. Any modification to a historical entry invalidates
// all subsequent hashes, making tampering detectable.
//
// Satisfies audit requirements for:
//   - EU AI Act Article 12 (record-keeping)
//   - NIST AI RMF GOVERN-1.5 (audit trail)
//   - SOC 2 CC8.1 (integrity)
//   - ISO/IEC 42001 (AI management records)
package exporters

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/girdav01/AITF/sdk/go/ocsf"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const (
	genesisHash    = "0000000000000000000000000000000000000000000000000000000000000000"
	maxLogFileSize = 1024 * 1024 * 1024 // 1 GB
)

// computeEntryHash computes the SHA-256 hash for a log entry.
func computeEntryHash(seq int, timestamp, prevHash, eventJSON string) string {
	payload := fmt.Sprintf("%d|%s|%s|%s", seq, timestamp, prevHash, eventJSON)
	h := sha256.Sum256([]byte(payload))
	return fmt.Sprintf("%x", h)
}

// ImmutableLogEntry represents a single entry in the hash-chained log.
type ImmutableLogEntry struct {
	Seq       int                    `json:"seq"`
	Timestamp string                 `json:"timestamp"`
	PrevHash  string                 `json:"prev_hash"`
	Hash      string                 `json:"hash"`
	Event     map[string]interface{} `json:"event"`
}

// ImmutableLogExporter writes hash-chained log entries for tamper evidence.
type ImmutableLogExporter struct {
	logFile    string
	mapper     *ocsf.OCSFMapper
	compliance *ocsf.ComplianceMapper
	prevHash   string
	seq        int
	eventCount int
	mu         sync.Mutex
}

// ImmutableLogOption configures the ImmutableLogExporter.
type ImmutableLogOption func(*ImmutableLogExporter)

// WithImmutableLogFile sets the log file path.
func WithImmutableLogFile(path string) ImmutableLogOption {
	return func(e *ImmutableLogExporter) { e.logFile = path }
}

// WithImmutableComplianceFrameworks sets compliance frameworks for enrichment.
func WithImmutableComplianceFrameworks(frameworks []string) ImmutableLogOption {
	return func(e *ImmutableLogExporter) {
		e.compliance = ocsf.NewComplianceMapper(frameworks)
	}
}

// NewImmutableLogExporter creates a new immutable log exporter.
func NewImmutableLogExporter(opts ...ImmutableLogOption) (*ImmutableLogExporter, error) {
	e := &ImmutableLogExporter{
		logFile:    "/var/log/aitf/immutable_audit.jsonl",
		mapper:     ocsf.NewOCSFMapper(),
		compliance: ocsf.NewComplianceMapper(nil),
		prevHash:   genesisHash,
		seq:        0,
	}
	for _, opt := range opts {
		opt(e)
	}

	// Create directory
	dir := filepath.Dir(e.logFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", dir, err)
	}

	// Resume chain from existing log
	e.resumeChain()

	return e, nil
}

func (e *ImmutableLogExporter) resumeChain() {
	f, err := os.Open(e.logFile)
	if err != nil {
		return // File doesn't exist yet
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB max line

	var lastLine string
	lineCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lastLine = line
			lineCount++
		}
	}

	if lastLine != "" {
		var entry ImmutableLogEntry
		if err := json.Unmarshal([]byte(lastLine), &entry); err == nil {
			e.prevHash = entry.Hash
			e.seq = entry.Seq + 1
			log.Printf("immutable_log: resumed chain at seq=%d from %s", e.seq, e.logFile)
		}
	}
}

// ExportSpans converts spans to hash-chained log entries.
func (e *ImmutableLogExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	var entries []string

	for _, span := range spans {
		ocsfEvent := e.mapper.MapSpan(span)
		if ocsfEvent == nil {
			continue
		}

		eventBytes, err := json.Marshal(ocsfEvent)
		if err != nil {
			continue
		}

		var eventMap map[string]interface{}
		if err := json.Unmarshal(eventBytes, &eventMap); err != nil {
			continue
		}

		// Canonical JSON for deterministic hashing
		canonicalBytes, err := json.Marshal(eventMap)
		if err != nil {
			continue
		}
		eventJSON := string(canonicalBytes)

		e.mu.Lock()
		timestamp := time.Now().UTC().Format(time.RFC3339Nano)
		entryHash := computeEntryHash(e.seq, timestamp, e.prevHash, eventJSON)

		entry := ImmutableLogEntry{
			Seq:       e.seq,
			Timestamp: timestamp,
			PrevHash:  e.prevHash,
			Hash:      entryHash,
			Event:     eventMap,
		}

		entryBytes, err := json.Marshal(entry)
		if err != nil {
			e.mu.Unlock()
			continue
		}

		entries = append(entries, string(entryBytes))
		e.prevHash = entryHash
		e.seq++
		e.eventCount++
		e.mu.Unlock()
	}

	if len(entries) == 0 {
		return nil
	}

	return e.writeEntries(entries)
}

func (e *ImmutableLogExporter) writeEntries(entries []string) error {
	// Check rotation
	if info, err := os.Stat(e.logFile); err == nil && info.Size() > maxLogFileSize {
		rotated := e.logFile + "." + time.Now().UTC().Format("20060102T150405")
		if err := os.Rename(e.logFile, rotated); err == nil {
			log.Printf("immutable_log: rotated to %s", rotated)
		}
	}

	// Open in append-only mode with restrictive permissions
	f, err := os.OpenFile(e.logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("immutable_log: open failed: %w", err)
	}
	defer f.Close()

	for _, entry := range entries {
		if _, err := f.WriteString(entry + "\n"); err != nil {
			return fmt.Errorf("immutable_log: write failed: %w", err)
		}
	}

	return f.Sync()
}

// Shutdown is a no-op.
func (e *ImmutableLogExporter) Shutdown(ctx context.Context) error {
	return nil
}

// EventCount returns the total number of events written.
func (e *ImmutableLogExporter) EventCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.eventCount
}

// CurrentSeq returns the current sequence number.
func (e *ImmutableLogExporter) CurrentSeq() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.seq
}

// CurrentHash returns the hash of the last written entry.
func (e *ImmutableLogExporter) CurrentHash() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.prevHash
}

// VerificationResult holds the result of a log integrity check.
type VerificationResult struct {
	Valid           bool   `json:"valid"`
	EntriesChecked  int    `json:"entries_checked"`
	FirstInvalidSeq *int   `json:"first_invalid_seq,omitempty"`
	ExpectedHash    string `json:"expected_hash,omitempty"`
	FoundHash       string `json:"found_hash,omitempty"`
	FinalHash       string `json:"final_hash,omitempty"`
	Error           string `json:"error,omitempty"`
}

// VerifyImmutableLog verifies the integrity of an immutable log file
// by replaying the entire hash chain from genesis.
func VerifyImmutableLog(logFile string) (*VerificationResult, error) {
	f, err := os.Open(logFile)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Sprintf("cannot open file: %v", err)}, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	prevHash := genesisHash
	entriesChecked := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry ImmutableLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			seq := entriesChecked
			return &VerificationResult{
				Valid:           false,
				EntriesChecked:  entriesChecked,
				FirstInvalidSeq: &seq,
				Error:           fmt.Sprintf("invalid JSON at seq %d: %v", entriesChecked, err),
			}, nil
		}

		// Check chain linkage
		if entry.PrevHash != prevHash {
			return &VerificationResult{
				Valid:           false,
				EntriesChecked:  entriesChecked,
				FirstInvalidSeq: &entry.Seq,
				ExpectedHash:    prevHash,
				FoundHash:       entry.PrevHash,
				Error:           fmt.Sprintf("chain break at seq %d: prev_hash mismatch", entry.Seq),
			}, nil
		}

		// Recompute hash
		eventJSON, _ := json.Marshal(entry.Event)
		computedHash := computeEntryHash(entry.Seq, entry.Timestamp, entry.PrevHash, string(eventJSON))

		if computedHash != entry.Hash {
			return &VerificationResult{
				Valid:           false,
				EntriesChecked:  entriesChecked,
				FirstInvalidSeq: &entry.Seq,
				ExpectedHash:    computedHash,
				FoundHash:       entry.Hash,
				Error:           fmt.Sprintf("hash mismatch at seq %d: entry tampered", entry.Seq),
			}, nil
		}

		prevHash = entry.Hash
		entriesChecked++
	}

	return &VerificationResult{
		Valid:          true,
		EntriesChecked: entriesChecked,
		FinalHash:     prevHash,
	}, nil
}

// Compile-time check that ImmutableLogExporter implements SpanExporter.
var _ sdktrace.SpanExporter = (*ImmutableLogExporter)(nil)
