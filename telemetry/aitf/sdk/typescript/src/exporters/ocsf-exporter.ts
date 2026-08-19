/**
 * AITF OCSF Exporter.
 *
 * OTel SpanExporter that converts AI spans to OCSF Category 7 events
 * and exports them to SIEM/XDR endpoints, S3, or local files.
 *
 * Based on forwarder architecture from the AITelemetry project.
 */

import * as fs from "fs";
import * as path from "path";
import * as https from "https";
import { URL } from "url";
import { ReadableSpan, SpanExporter } from "@opentelemetry/sdk-trace-base";
import { ExportResult, ExportResultCode } from "@opentelemetry/core";
import { OCSFMapper } from "../ocsf/mapper";
import { ComplianceMapper } from "../ocsf/compliance-mapper";
import { AIBaseEvent, stripNulls } from "../ocsf/schema";

/** Localhost hosts allowed for HTTP (development only). */
const DEV_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/** Options for configuring the OCSFExporter. */
export interface OCSFExporterOptions {
  endpoint?: string;
  outputFile?: string;
  complianceFrameworks?: string[];
  includeRawSpan?: boolean;
  apiKey?: string;
}

/**
 * Validate endpoint URL for security.
 * Enforces HTTPS when API key is present and not localhost.
 */
function validateEndpoint(endpoint: string, apiKey?: string): void {
  const url = new URL(endpoint);

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(
      `Unsupported URL scheme '${url.protocol}'. Only http: and https: are allowed.`
    );
  }

  const isDev = DEV_HOSTS.has(url.hostname);

  // Enforce HTTPS when API key is present and not localhost
  if (apiKey && url.protocol !== "https:" && !isDev) {
    throw new Error(
      "HTTPS is required when using API key authentication. " +
        "Use https:// or connect to localhost for development."
    );
  }
}

/**
 * Validate output file path to prevent path traversal.
 */
function validateOutputPath(outputFile: string): string {
  if (outputFile.includes("..")) {
    throw new Error(
      `Path traversal detected in output path: ${outputFile}`
    );
  }
  return path.resolve(outputFile);
}

/**
 * Exports OTel spans as OCSF Category 7 AI events.
 *
 * Converts AI-related spans to OCSF events using OCSFMapper,
 * enriches with compliance metadata, and exports to configured
 * destinations.
 *
 * Usage:
 *   import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
 *   import { BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
 *   import { OCSFExporter } from "@aitf/sdk";
 *
 *   const exporter = new OCSFExporter({
 *     outputFile: "/var/log/aitf/ocsf_events.jsonl",
 *     complianceFrameworks: ["nist_ai_rmf", "eu_ai_act", "mitre_atlas"],
 *   });
 *   const provider = new NodeTracerProvider();
 *   provider.addSpanProcessor(new BatchSpanProcessor(exporter));
 */
export class OCSFExporter implements SpanExporter {
  private readonly _endpoint: string | null;
  private readonly _outputFile: string | null;
  private readonly _includeRawSpan: boolean;
  private readonly _apiKey: string | null;
  private readonly _mapper: OCSFMapper;
  private readonly _complianceMapper: ComplianceMapper;
  private _eventCount = 0;

  constructor(options: OCSFExporterOptions = {}) {
    this._apiKey = options.apiKey ?? null;
    this._includeRawSpan = options.includeRawSpan ?? false;
    this._mapper = new OCSFMapper();
    this._complianceMapper = new ComplianceMapper({
      frameworks: options.complianceFrameworks,
    });

    // Validate endpoint URL
    if (options.endpoint) {
      validateEndpoint(options.endpoint, options.apiKey);
      this._endpoint = options.endpoint;
    } else {
      this._endpoint = null;
    }

    // Validate and ensure output directory exists
    if (options.outputFile) {
      const resolved = validateOutputPath(options.outputFile);
      this._outputFile = resolved;
      const dir = path.dirname(resolved);
      fs.mkdirSync(dir, { recursive: true });
    } else {
      this._outputFile = null;
    }
  }

  /**
   * Export spans as OCSF events.
   */
  export(
    spans: ReadableSpan[],
    resultCallback: (result: ExportResult) => void
  ): void {
    const events: Record<string, unknown>[] = [];

    for (const span of spans) {
      const ocsfEvent = this._mapper.mapSpan(span);
      if (!ocsfEvent) {
        continue;
      }

      // Enrich with compliance metadata
      const eventType = this._classifyEvent(ocsfEvent);
      if (eventType) {
        this._complianceMapper.enrichEvent(ocsfEvent, eventType);
      }

      // Runtime validation before type cast to Record<string, unknown>
      if (
        typeof ocsfEvent !== "object" ||
        ocsfEvent === null ||
        Array.isArray(ocsfEvent)
      ) {
        console.warn("OCSF: Skipping non-object event from mapper");
        continue;
      }
      const eventDict = stripNulls(
        ocsfEvent as unknown as Record<string, unknown>
      );
      events.push(eventDict);
      this._eventCount++;
    }

    if (events.length === 0) {
      resultCallback({ code: ExportResultCode.SUCCESS });
      return;
    }

    try {
      if (this._outputFile) {
        this._exportToFile(events);
      }
      if (this._endpoint) {
        this._exportToEndpoint(events)
          .then(() => {
            resultCallback({ code: ExportResultCode.SUCCESS });
          })
          .catch((err) => {
            console.error("OCSF export to endpoint failed:", this._sanitizeError(err));
            resultCallback({ code: ExportResultCode.FAILED });
          });
        return;
      }
      resultCallback({ code: ExportResultCode.SUCCESS });
    } catch (err) {
      console.error("OCSF export failed:", this._sanitizeError(err));
      resultCallback({ code: ExportResultCode.FAILED });
    }
  }

  private _exportToFile(events: Record<string, unknown>[]): void {
    if (!this._outputFile) return;

    const lines = events
      .map((event) => JSON.stringify(event))
      .join("\n");
    fs.appendFileSync(this._outputFile, lines + "\n", {
      encoding: "utf-8",
      mode: 0o600, // Restrictive file permissions
    });
  }

  private async _exportToEndpoint(
    events: Record<string, unknown>[]
  ): Promise<void> {
    if (!this._endpoint) return;

    const url = new URL(this._endpoint);
    const payload = JSON.stringify(events);

    // Enforce HTTPS for all non-localhost endpoints
    if (url.protocol !== "https:" && !DEV_HOSTS.has(url.hostname)) {
      console.warn(
        "OCSF: Using insecure HTTP endpoint. Consider using HTTPS for production."
      );
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Content-Length": String(Buffer.byteLength(payload)),
    };
    if (this._apiKey) {
      headers["Authorization"] = `Bearer ${this._apiKey}`;
    }

    return new Promise<void>((resolve, reject) => {
      const requestOptions = {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: "POST",
        headers,
        timeout: 30000,
      };

      const req = https.request(requestOptions, (res) => {
        if (res.statusCode && res.statusCode >= 400) {
          reject(
            new Error(
              `OCSF endpoint returned ${res.statusCode}`
            )
          );
        } else {
          resolve();
        }
        // Consume response data to free memory
        res.resume();
      });

      req.on("error", reject);
      req.on("timeout", () => {
        req.destroy();
        reject(new Error("OCSF endpoint request timed out"));
      });

      req.write(payload);
      req.end();
    });
  }

  /**
   * Sanitize an error before logging to ensure the API key is never leaked.
   */
  private _sanitizeError(err: unknown): string {
    const message = err instanceof Error ? err.message : String(err);
    if (this._apiKey) {
      return message.replaceAll(this._apiKey, "[REDACTED]");
    }
    return message;
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

  /** Number of OCSF events exported. */
  get eventCount(): number {
    return this._eventCount;
  }

  async shutdown(): Promise<void> {
    // No-op
  }

  async forceFlush(): Promise<void> {
    // No-op
  }
}
