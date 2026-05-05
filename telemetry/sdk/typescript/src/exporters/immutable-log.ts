/**
 * AITF Immutable Log Exporter.
 *
 * OTel SpanExporter that writes AI telemetry events to an append-only,
 * hash-chained log file providing cryptographic tamper evidence.
 *
 * Each log entry includes a SHA-256 hash of the previous entry, creating
 * an unbroken chain. Any modification to a historical entry invalidates
 * all subsequent hashes, making tampering detectable.
 *
 * Satisfies audit requirements for:
 *   - EU AI Act Article 12 (record-keeping)
 *   - NIST AI RMF GOVERN-1.5 (audit trail)
 *   - SOC 2 CC8.1 (integrity)
 *   - ISO/IEC 42001 (AI management records)
 *
 * Usage:
 *   import { ImmutableLogExporter } from "@aitf/sdk";
 *   const exporter = new ImmutableLogExporter({
 *     logFile: "/var/log/aitf/immutable_audit.jsonl",
 *   });
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { ReadableSpan, SpanExporter } from "@opentelemetry/sdk-trace-base";
import { ExportResult, ExportResultCode } from "@opentelemetry/core";
import { OCSFMapper } from "../ocsf/mapper";
import { ComplianceMapper } from "../ocsf/compliance-mapper";
import { AIBaseEvent, stripNulls } from "../ocsf/schema";

const GENESIS_HASH =
  "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1 GB

/** Compute SHA-256 hash for a log entry. */
function computeEntryHash(
  seq: number,
  timestamp: string,
  prevHash: string,
  eventJSON: string
): string {
  const payload = `${seq}|${timestamp}|${prevHash}|${eventJSON}`;
  return crypto.createHash("sha256").update(payload, "utf-8").digest("hex");
}

/** A single entry in the hash-chained log. */
interface ImmutableLogEntry {
  seq: number;
  timestamp: string;
  prev_hash: string;
  hash: string;
  event: Record<string, unknown>;
}

/** Options for ImmutableLogExporter. */
export interface ImmutableLogExporterOptions {
  logFile?: string;
  complianceFrameworks?: string[];
  rotateOnSize?: boolean;
  filePermissions?: number;
}

/**
 * Writes AITF events to an append-only, hash-chained log file.
 */
export class ImmutableLogExporter implements SpanExporter {
  private readonly _logFile: string;
  private readonly _rotateOnSize: boolean;
  private readonly _filePermissions: number;
  private readonly _mapper: OCSFMapper;
  private readonly _complianceMapper: ComplianceMapper;
  private _prevHash: string;
  private _seq: number;
  private _eventCount: number;

  constructor(options: ImmutableLogExporterOptions = {}) {
    this._logFile = path.resolve(
      options.logFile ?? "/var/log/aitf/immutable_audit.jsonl"
    );
    this._rotateOnSize = options.rotateOnSize ?? true;
    this._filePermissions = options.filePermissions ?? 0o600;
    this._mapper = new OCSFMapper();
    this._complianceMapper = new ComplianceMapper({
      frameworks: options.complianceFrameworks,
    });
    this._prevHash = GENESIS_HASH;
    this._seq = 0;
    this._eventCount = 0;

    // Create directory
    const dir = path.dirname(this._logFile);
    fs.mkdirSync(dir, { recursive: true });

    // Resume chain
    this._resumeChain();
  }

  private _resumeChain(): void {
    if (!fs.existsSync(this._logFile)) return;

    try {
      const content = fs.readFileSync(this._logFile, "utf-8");
      const lines = content.trim().split("\n").filter(Boolean);
      if (lines.length === 0) return;

      const lastLine = lines[lines.length - 1];
      const entry: ImmutableLogEntry = JSON.parse(lastLine);
      this._prevHash = entry.hash;
      this._seq = entry.seq + 1;
      console.log(
        `immutable_log: resumed chain at seq=${this._seq} from ${this._logFile}`
      );
    } catch {
      this._prevHash = GENESIS_HASH;
      this._seq = 0;
    }
  }

  export(
    spans: ReadableSpan[],
    resultCallback: (result: ExportResult) => void
  ): void {
    const entries: string[] = [];

    for (const span of spans) {
      const ocsfEvent = this._mapper.mapSpan(span);
      if (!ocsfEvent) continue;

      // Enrich with compliance metadata
      const eventType = this._classifyEvent(ocsfEvent);
      if (eventType) {
        this._complianceMapper.enrichEvent(ocsfEvent, eventType);
      }

      if (
        typeof ocsfEvent !== "object" ||
        ocsfEvent === null ||
        Array.isArray(ocsfEvent)
      ) {
        continue;
      }
      const eventDict = stripNulls(
        ocsfEvent as unknown as Record<string, unknown>
      );

      const eventJSON = JSON.stringify(eventDict, Object.keys(eventDict).sort());
      const timestamp = new Date().toISOString();
      const entryHash = computeEntryHash(
        this._seq,
        timestamp,
        this._prevHash,
        eventJSON
      );

      const entry: ImmutableLogEntry = {
        seq: this._seq,
        timestamp,
        prev_hash: this._prevHash,
        hash: entryHash,
        event: eventDict,
      };

      entries.push(JSON.stringify(entry));
      this._prevHash = entryHash;
      this._seq++;
      this._eventCount++;
    }

    if (entries.length === 0) {
      resultCallback({ code: ExportResultCode.SUCCESS });
      return;
    }

    try {
      this._writeEntries(entries);
      resultCallback({ code: ExportResultCode.SUCCESS });
    } catch (err) {
      console.error("immutable_log: write failed:", err);
      resultCallback({ code: ExportResultCode.FAILED });
    }
  }

  private _writeEntries(entries: string[]): void {
    // Check rotation
    if (this._rotateOnSize && fs.existsSync(this._logFile)) {
      const stats = fs.statSync(this._logFile);
      if (stats.size > MAX_FILE_SIZE) {
        const rotated =
          this._logFile +
          "." +
          new Date().toISOString().replace(/[:.]/g, "");
        fs.renameSync(this._logFile, rotated);
      }
    }

    // Append with restrictive permissions
    const content = entries.join("\n") + "\n";
    fs.appendFileSync(this._logFile, content, {
      encoding: "utf-8",
      mode: this._filePermissions,
    });
  }

  private _classifyEvent(event: AIBaseEvent): string | null {
    const classUid = event.class_uid;
    const mapping: Record<number, string> = {
      7001: "model_inference",
      7002: "agent_activity",
      7003: "tool_execution",
      7004: "data_retrieval",
      7005: "security_finding",
      7006: "supply_chain",
      7007: "governance",
      7008: "identity",
    };
    return mapping[classUid] ?? null;
  }

  get eventCount(): number {
    return this._eventCount;
  }

  get currentSeq(): number {
    return this._seq;
  }

  get currentHash(): string {
    return this._prevHash;
  }

  async shutdown(): Promise<void> {
    // No-op
  }

  async forceFlush(): Promise<void> {
    // No-op
  }
}

/** Result of an immutable log verification. */
export interface VerificationResult {
  valid: boolean;
  entriesChecked: number;
  firstInvalidSeq?: number;
  expectedHash?: string;
  foundHash?: string;
  finalHash?: string;
  error?: string;
}

/**
 * Verify the integrity of an AITF immutable log file
 * by replaying the entire hash chain from genesis.
 */
export function verifyImmutableLog(logFile: string): VerificationResult {
  if (!fs.existsSync(logFile)) {
    return {
      valid: false,
      entriesChecked: 0,
      error: "Log file does not exist",
    };
  }

  const content = fs.readFileSync(logFile, "utf-8");
  const lines = content.trim().split("\n").filter(Boolean);

  let prevHash = GENESIS_HASH;
  let entriesChecked = 0;

  for (const line of lines) {
    let entry: ImmutableLogEntry;
    try {
      entry = JSON.parse(line);
    } catch (err) {
      return {
        valid: false,
        entriesChecked,
        firstInvalidSeq: entriesChecked,
        error: `Invalid JSON at seq ${entriesChecked}: ${err}`,
      };
    }

    // Check chain linkage
    if (entry.prev_hash !== prevHash) {
      return {
        valid: false,
        entriesChecked,
        firstInvalidSeq: entry.seq,
        expectedHash: prevHash,
        foundHash: entry.prev_hash,
        error: `Chain break at seq ${entry.seq}: prev_hash mismatch`,
      };
    }

    // Recompute hash
    const eventJSON = JSON.stringify(
      entry.event,
      Object.keys(entry.event).sort()
    );
    const computedHash = computeEntryHash(
      entry.seq,
      entry.timestamp,
      entry.prev_hash,
      eventJSON
    );

    if (computedHash !== entry.hash) {
      return {
        valid: false,
        entriesChecked,
        firstInvalidSeq: entry.seq,
        expectedHash: computedHash,
        foundHash: entry.hash,
        error: `Hash mismatch at seq ${entry.seq}: entry tampered`,
      };
    }

    prevHash = entry.hash;
    entriesChecked++;
  }

  return {
    valid: true,
    entriesChecked,
    finalHash: prevHash,
  };
}
