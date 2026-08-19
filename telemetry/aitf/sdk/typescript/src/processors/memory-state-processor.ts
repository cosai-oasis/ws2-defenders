/**
 * AITF Memory State Tracking Processor.
 *
 * An OTel SpanProcessor that monitors agent memory mutations for security-relevant
 * patterns. Aligned with CoSAI AI Incident Response requirement for memory state
 * change logging in agentic systems.
 *
 * Capabilities:
 *   - Tracks memory writes/updates/deletes with before/after snapshots
 *   - Detects memory poisoning (unexpected content injection)
 *   - Verifies session memory isolation
 *   - Monitors long-term memory growth anomalies
 *   - Emits security events for suspicious memory operations
 */

import { Context, Span } from "@opentelemetry/api";
import { ReadableSpan, SpanProcessor } from "@opentelemetry/sdk-trace-base";

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/** Snapshot of a memory entry before/after a mutation. */
export interface MemorySnapshot {
  /** The memory key that was mutated. */
  key: string;
  /** The memory store (e.g. "short_term", "long_term"). */
  store: string;
  /** The operation performed ("store", "update", "delete"). */
  operation: string;
  /** Content hash before the mutation, if available. */
  contentHashBefore: string | null;
  /** Content hash after the mutation, if available. */
  contentHashAfter: string | null;
  /** Content size before the mutation, if available. */
  sizeBefore: number | null;
  /** Content size after the mutation, if available. */
  sizeAfter: number | null;
  /** Provenance label (e.g. "conversation", "tool_result"). */
  provenance: string | null;
  /** Session that performed the mutation. */
  sessionId: string | null;
  /** Unix timestamp of the snapshot. */
  timestamp: number;
}

/** A security event detected by the memory processor. */
export interface MemorySecurityEvent {
  /** Type of security event (e.g. "memory_poisoning_detected"). */
  eventType: string;
  /** Severity level: "informational" | "low" | "medium" | "high" | "critical". */
  severity: string;
  /** Human-readable event details. */
  details: string;
  /** The span ID associated with this event. */
  spanId: string;
  /** Session ID associated with this event, if applicable. */
  sessionId: string | null;
  /** Memory key associated with this event, if applicable. */
  memoryKey: string | null;
  /** Unix timestamp of the event. */
  timestamp: number;
}

/** Configuration options for the MemoryStateProcessor. */
export interface MemoryStateProcessorOptions {
  /** Alert threshold for memory entry count per session. Default: 1000. */
  maxMemoryEntriesPerSession?: number;
  /** Alert threshold for total memory size in bytes per session. Default: 50MB. */
  maxMemorySizeBytes?: number;
  /** Set of trusted provenance sources. Default: {"conversation", "tool_result", "system", "imported"}. */
  allowedProvenances?: Set<string>;
  /** Threshold (0-1) for poisoning detection. Default: 0.7. */
  poisoningScoreThreshold?: number;
  /** Whether to capture before/after snapshots. Default: true. */
  enableSnapshots?: boolean;
  /** Whether to alert on cross-session memory access. Default: true. */
  crossSessionAlert?: boolean;
  /** Maximum number of events to retain. Default: 10000. */
  maxEvents?: number;
  /** Maximum number of snapshots to retain. Default: 1000. */
  maxSnapshots?: number;
}

/** Statistics for a specific session's memory usage. */
export interface SessionStats {
  /** Number of memory entries created in this session. */
  entryCount: number;
  /** Total memory size in bytes for this session. */
  totalSizeBytes: number;
  /** List of active memory keys in this session. */
  activeKeys: string[];
  /** Number of security events associated with this session. */
  events: number;
}

// ---------------------------------------------------------------------------
// Internal tracking state per-session
// ---------------------------------------------------------------------------

interface SessionMemoryEntry {
  key: string;
  store: string;
  operation: string;
  contentHashAfter: string | null;
  sizeAfter: number | null;
  provenance: string | null;
  sessionId: string | null;
}

// ---------------------------------------------------------------------------
// Severity ordering
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<string, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// ---------------------------------------------------------------------------
// Processor
// ---------------------------------------------------------------------------

/**
 * OTel SpanProcessor that tracks memory state changes and detects anomalies.
 *
 * Usage:
 *   ```ts
 *   import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
 *   import { MemoryStateProcessor } from "@aitf/sdk";
 *
 *   const processor = new MemoryStateProcessor({
 *     maxMemoryEntriesPerSession: 500,
 *     allowedProvenances: new Set(["conversation", "tool_result", "system"]),
 *   });
 *   const provider = new NodeTracerProvider();
 *   provider.addSpanProcessor(processor);
 *   ```
 */
export class MemoryStateProcessor implements SpanProcessor {
  private readonly _maxEntries: number;
  private readonly _maxSize: number;
  private readonly _allowedProvenances: Set<string>;
  private readonly _poisoningThreshold: number;
  private readonly _enableSnapshots: boolean;
  private readonly _crossSessionAlert: boolean;
  private readonly _maxEvents: number;
  private readonly _maxSnapshots: number;

  // State tracking
  private _sessionMemory: Map<string, Map<string, SessionMemoryEntry>> = new Map();
  private _sessionEntryCounts: Map<string, number> = new Map();
  private _sessionTotalSize: Map<string, number> = new Map();
  private _memoryHashes: Map<string, string> = new Map();
  private _events: MemorySecurityEvent[] = [];
  private _snapshots: MemorySnapshot[] = [];

  constructor(options: MemoryStateProcessorOptions = {}) {
    this._maxEntries = options.maxMemoryEntriesPerSession ?? 1000;
    this._maxSize = options.maxMemorySizeBytes ?? 50 * 1024 * 1024;
    this._allowedProvenances = options.allowedProvenances ?? new Set([
      "conversation", "tool_result", "system", "imported",
    ]);
    this._poisoningThreshold = options.poisoningScoreThreshold ?? 0.7;
    this._enableSnapshots = options.enableSnapshots ?? true;
    this._crossSessionAlert = options.crossSessionAlert ?? true;
    this._maxEvents = options.maxEvents ?? 10000;
    this._maxSnapshots = options.maxSnapshots ?? 1000;
  }

  onStart(_span: Span, _parentContext: Context): void {
    // We process on_end when all attributes are available.
  }

  onEnd(span: ReadableSpan): void {
    const attrs = span.attributes ?? {};

    // Only process memory-related spans
    const operation = attrs["memory.operation"];
    if (!operation) {
      return;
    }

    const operationStr = String(operation);
    const memoryKey = String(attrs["memory.key"] ?? "");
    const store = String(attrs["memory.store"] ?? "unknown");
    const provenance = String(attrs["memory.provenance"] ?? "unknown");
    const sessionId = String(attrs["gen_ai.conversation.id"] ?? "unknown");
    const contentHash = attrs["memory.security.content_hash"]
      ? String(attrs["memory.security.content_hash"])
      : null;
    const contentSize = typeof attrs["memory.security.content_size"] === "number"
      ? attrs["memory.security.content_size"]
      : 0;
    const poisoningScore = typeof attrs["memory.security.poisoning_score"] === "number"
      ? attrs["memory.security.poisoning_score"]
      : null;
    const crossSession = attrs["memory.security.cross_session"] === true;
    const integrityHash = attrs["memory.security.integrity_hash"]
      ? String(attrs["memory.security.integrity_hash"])
      : null;

    const spanId = span.spanContext()
      ? span.spanContext().spanId
      : "unknown";

    // -- 1. Capture snapshot --

    if (this._enableSnapshots && (operationStr === "store" || operationStr === "update" || operationStr === "delete")) {
      const previousHash = this._memoryHashes.get(`${sessionId}:${memoryKey}`) ?? null;
      const sessionEntries = this._sessionMemory.get(sessionId);
      const existingEntry = sessionEntries?.get(memoryKey);

      const snapshot: MemorySnapshot = {
        key: memoryKey,
        store,
        operation: operationStr,
        contentHashBefore: previousHash,
        contentHashAfter: operationStr !== "delete" ? contentHash : null,
        sizeBefore: existingEntry?.sizeAfter ?? null,
        sizeAfter: operationStr !== "delete" ? contentSize : 0,
        provenance,
        sessionId,
        timestamp: Date.now() / 1000,
      };
      this._snapshots.push(snapshot);

      // Enforce max_snapshots bound
      if (this._snapshots.length > this._maxSnapshots) {
        this._snapshots = this._snapshots.slice(-this._maxSnapshots);
      }

      // Update tracked hash
      if (operationStr === "delete") {
        this._memoryHashes.delete(`${sessionId}:${memoryKey}`);
      } else if (contentHash !== null) {
        this._memoryHashes.set(`${sessionId}:${memoryKey}`, contentHash);
      }
    }

    // -- 2. Provenance check -- detect untrusted sources --

    if (!this._allowedProvenances.has(provenance)) {
      this._emitEvent({
        eventType: "untrusted_provenance",
        severity: "high",
        details:
          `Memory write from untrusted provenance '${provenance}' ` +
          `for key '${memoryKey}' in store '${store}'`,
        spanId,
        sessionId,
        memoryKey,
        timestamp: Date.now() / 1000,
      });
    }

    // -- 3. Poisoning detection --

    if (poisoningScore !== null && poisoningScore >= this._poisoningThreshold) {
      this._emitEvent({
        eventType: "memory_poisoning_detected",
        severity: "critical",
        details:
          `Memory poisoning detected for key '${memoryKey}' ` +
          `(score=${poisoningScore.toFixed(2)}, threshold=${this._poisoningThreshold}). ` +
          `Provenance: ${provenance}`,
        spanId,
        sessionId,
        memoryKey,
        timestamp: Date.now() / 1000,
      });
    }

    // -- 4. Integrity verification --

    if (integrityHash !== null && contentHash !== null && integrityHash !== contentHash) {
      this._emitEvent({
        eventType: "memory_integrity_violation",
        severity: "critical",
        details:
          `Memory integrity hash mismatch for key '${memoryKey}'. ` +
          `Expected: ${integrityHash}, Got: ${contentHash}`,
        spanId,
        sessionId,
        memoryKey,
        timestamp: Date.now() / 1000,
      });
    }

    // -- 5. Cross-session isolation check --

    if (this._crossSessionAlert && crossSession) {
      this._emitEvent({
        eventType: "cross_session_memory_access",
        severity: "high",
        details:
          `Cross-session memory access detected for key '${memoryKey}'. ` +
          `Session '${sessionId}' accessed memory belonging to another session.`,
        spanId,
        sessionId,
        memoryKey,
        timestamp: Date.now() / 1000,
      });
    }

    // -- 6. Memory growth anomaly detection --

    if (operationStr === "store" || operationStr === "update") {
      const currentEntryCount = this._sessionEntryCounts.get(sessionId) ?? 0;
      const currentTotalSize = this._sessionTotalSize.get(sessionId) ?? 0;

      const newEntryCount = operationStr === "store"
        ? currentEntryCount + 1
        : currentEntryCount;
      const newTotalSize = currentTotalSize + contentSize;

      this._sessionEntryCounts.set(sessionId, newEntryCount);
      this._sessionTotalSize.set(sessionId, newTotalSize);

      if (newEntryCount > this._maxEntries) {
        this._emitEvent({
          eventType: "memory_growth_anomaly",
          severity: "medium",
          details:
            `Session '${sessionId}' exceeded max memory entries: ` +
            `${newEntryCount} > ${this._maxEntries}`,
          spanId,
          sessionId,
          memoryKey: null,
          timestamp: Date.now() / 1000,
        });
      }

      if (newTotalSize > this._maxSize) {
        this._emitEvent({
          eventType: "memory_size_anomaly",
          severity: "high",
          details:
            `Session '${sessionId}' exceeded max memory size: ` +
            `${newTotalSize} bytes > ${this._maxSize} bytes`,
          spanId,
          sessionId,
          memoryKey: null,
          timestamp: Date.now() / 1000,
        });
      }
    }

    // -- 7. Update tracking state --

    if (operationStr === "delete") {
      const sessionEntries = this._sessionMemory.get(sessionId);
      if (sessionEntries) {
        sessionEntries.delete(memoryKey);
      }
    } else {
      let sessionEntries = this._sessionMemory.get(sessionId);
      if (!sessionEntries) {
        sessionEntries = new Map();
        this._sessionMemory.set(sessionId, sessionEntries);
      }
      sessionEntries.set(memoryKey, {
        key: memoryKey,
        store,
        operation: operationStr,
        contentHashAfter: contentHash,
        sizeAfter: contentSize,
        provenance,
        sessionId,
      });
    }
  }

  private _emitEvent(event: MemorySecurityEvent): void {
    this._events.push(event);
    if (this._events.length > this._maxEvents) {
      this._events = this._events.slice(-this._maxEvents);
    }
  }

  async shutdown(): Promise<void> {
    // No-op
  }

  async forceFlush(): Promise<void> {
    // No-op
  }

  // -- Public API -----------------------------------------------------------

  /**
   * Get security events at or above a severity level.
   *
   * @param minSeverity - Minimum severity to include. Default: "low".
   */
  getEvents(minSeverity: string = "low"): MemorySecurityEvent[] {
    const minLevel = SEVERITY_ORDER[minSeverity] ?? 0;
    return this._events.filter(
      (e) => (SEVERITY_ORDER[e.severity] ?? 0) >= minLevel,
    );
  }

  /**
   * Get memory mutation snapshots, optionally filtered by session.
   *
   * @param sessionId - If provided, only return snapshots for this session.
   */
  getSnapshots(sessionId?: string): MemorySnapshot[] {
    if (sessionId !== undefined) {
      return this._snapshots.filter((s) => s.sessionId === sessionId);
    }
    return [...this._snapshots];
  }

  /**
   * Get memory statistics for a session.
   *
   * @param sessionId - The session to get stats for.
   */
  getSessionStats(sessionId: string): SessionStats {
    const sessionEntries = this._sessionMemory.get(sessionId);
    return {
      entryCount: this._sessionEntryCounts.get(sessionId) ?? 0,
      totalSizeBytes: this._sessionTotalSize.get(sessionId) ?? 0,
      activeKeys: sessionEntries ? [...sessionEntries.keys()] : [],
      events: this._events.filter((e) => e.sessionId === sessionId).length,
    };
  }

  /**
   * Clear tracking state for a session (e.g., on session end).
   *
   * @param sessionId - The session to clear.
   */
  clearSession(sessionId: string): void {
    this._sessionMemory.delete(sessionId);
    this._sessionEntryCounts.delete(sessionId);
    this._sessionTotalSize.delete(sessionId);

    // Clean up hashes for this session
    const prefix = `${sessionId}:`;
    for (const key of [...this._memoryHashes.keys()]) {
      if (key.startsWith(prefix)) {
        this._memoryHashes.delete(key);
      }
    }
  }
}
