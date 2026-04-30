/**
 * AITF CEF Syslog Exporter.
 *
 * OTel SpanExporter that converts AI spans to CEF (Common Event Format)
 * syslog messages and sends them to any SIEM that supports CEF ingestion,
 * including vendors that do not support OCSF natively.
 *
 * Supported destinations:
 *   - ArcSight (Micro Focus / OpenText)
 *   - QRadar (IBM)
 *   - LogRhythm
 *   - Trend Vision One (Service Gateway)
 *   - Splunk (via syslog input)
 *   - Elastic Security (via Filebeat CEF module)
 *   - Any syslog-compatible receiver
 *
 * Usage:
 *   import { CEFSyslogExporter } from "@aitf/sdk";
 *   const exporter = new CEFSyslogExporter({
 *     host: "siem.example.com",
 *     port: 6514,
 *     protocol: "tcp",
 *     tls: true,
 *   });
 */

import * as net from "net";
import * as tls from "tls";
import { ReadableSpan, SpanExporter } from "@opentelemetry/sdk-trace-base";
import { ExportResult, ExportResultCode } from "@opentelemetry/core";
import { OCSFMapper } from "../ocsf/mapper";
import { stripNulls } from "../ocsf/schema";

/** CEF severity mapping from OCSF severity_id. */
const OCSF_TO_CEF_SEVERITY: Record<number, number> = {
  0: 0,  // Unknown
  1: 1,  // Informational
  2: 3,  // Low
  3: 5,  // Medium
  4: 7,  // High
  5: 9,  // Critical
  6: 10, // Fatal
};

const CLASS_UID_TO_NAME: Record<number, string> = {
  7001: "AI Model Inference",
  7002: "AI Agent Activity",
  7003: "AI Tool Execution",
  7004: "AI Data Retrieval",
  7005: "AI Security Finding",
  7006: "AI Supply Chain Event",
  7007: "AI Governance Event",
  7008: "AI Identity Event",
  7009: "AI Model Operations Event",
  7010: "AI Asset Inventory Event",
};

function sanitizeCEFValue(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/\|/g, "\\|")
    .replace(/=/g, "\\=")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r");
}

function sanitizeCEFHeader(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\|/g, "\\|");
}

/** Convert an OCSF event to a CEF syslog message string. */
export function ocsfEventToCEF(
  event: Record<string, unknown>,
  vendor = "AITF",
  product = "AI-Telemetry-Framework",
  version = "1.0.0"
): string {
  const classUid = (event.class_uid as number) ?? 0;
  const activityId = (event.activity_id as number) ?? 0;
  const typeUid =
    (event.type_uid as number) ?? classUid * 100 + activityId;
  const severityId = (event.severity_id as number) ?? 1;

  const signatureId = String(typeUid);
  const name = sanitizeCEFHeader(
    CLASS_UID_TO_NAME[classUid] ?? `OCSF-${classUid}`
  );
  const cefSeverity = OCSF_TO_CEF_SEVERITY[severityId] ?? 1;

  const ext: string[] = [];

  // Timestamp
  const eventTime =
    (event.time as string) ?? new Date().toISOString();
  ext.push(`rt=${sanitizeCEFValue(eventTime)}`);

  // Message
  const message = event.message as string;
  if (message) {
    ext.push(`msg=${sanitizeCEFValue(message)}`);
  }

  // OCSF identifiers
  ext.push(`cs1=${classUid}`, "cs1Label=ocsf_class_uid");
  ext.push(`cs2=${activityId}`, "cs2Label=ocsf_activity_id");
  ext.push(
    `cs3=${(event.category_uid as number) ?? 7}`,
    "cs3Label=ocsf_category_uid"
  );

  // Model information
  const modelInfo = event.model as Record<string, unknown> | undefined;
  if (modelInfo) {
    if (modelInfo.model_id) {
      ext.push(
        `cs4=${sanitizeCEFValue(String(modelInfo.model_id))}`,
        "cs4Label=ai_model_id"
      );
    }
    if (modelInfo.provider) {
      ext.push(
        `cs5=${sanitizeCEFValue(String(modelInfo.provider))}`,
        "cs5Label=ai_provider"
      );
    }
  }

  // Agent name
  if (event.agent_name) {
    ext.push(`suser=${sanitizeCEFValue(String(event.agent_name))}`);
  }

  // Tool name
  if (event.tool_name) {
    ext.push(
      `cs6=${sanitizeCEFValue(String(event.tool_name))}`,
      "cs6Label=ai_tool_name"
    );
  }

  // Security finding
  const finding = event.finding as Record<string, unknown> | undefined;
  if (finding) {
    if (finding.finding_type) {
      ext.push(`cat=${sanitizeCEFValue(String(finding.finding_type))}`);
    }
    if (finding.risk_score != null) {
      ext.push(`cn1=${finding.risk_score}`, "cn1Label=risk_score");
    }
    if (finding.owasp_category) {
      ext.push(
        `flexString1=${sanitizeCEFValue(String(finding.owasp_category))}`,
        "flexString1Label=owasp_category"
      );
    }
  }

  // Token usage
  const usage = event.usage as Record<string, unknown> | undefined;
  if (usage) {
    if (usage.input_tokens != null) {
      ext.push(`cn2=${usage.input_tokens}`, "cn2Label=input_tokens");
    }
    if (usage.output_tokens != null) {
      ext.push(`cn3=${usage.output_tokens}`, "cn3Label=output_tokens");
    }
  }

  // Cost
  const cost = event.cost as Record<string, unknown> | undefined;
  if (cost?.total_cost_usd != null) {
    ext.push(`cfp1=${cost.total_cost_usd}`, "cfp1Label=total_cost_usd");
  }

  const extensionStr = ext.join(" ");

  return `CEF:0|${sanitizeCEFHeader(vendor)}|${sanitizeCEFHeader(product)}|${sanitizeCEFHeader(version)}|${signatureId}|${name}|${cefSeverity}|${extensionStr}`;
}

/** Options for CEFSyslogExporter. */
export interface CEFSyslogExporterOptions {
  host: string;
  port?: number;
  protocol?: "tcp" | "udp";
  tls?: boolean;
  tlsCACert?: string;
  tlsRejectUnauthorized?: boolean;
  vendor?: string;
  product?: string;
  version?: string;
}

/**
 * Exports AITF telemetry as CEF syslog messages to any SIEM.
 */
export class CEFSyslogExporter implements SpanExporter {
  private readonly _host: string;
  private readonly _port: number;
  private readonly _protocol: "tcp" | "udp";
  private readonly _useTLS: boolean;
  private readonly _tlsCACert?: string;
  private readonly _tlsRejectUnauthorized: boolean;
  private readonly _vendor: string;
  private readonly _product: string;
  private readonly _version: string;
  private readonly _mapper: OCSFMapper;
  private _socket: net.Socket | null = null;
  private _connected = false;
  private _totalExported = 0;

  constructor(options: CEFSyslogExporterOptions) {
    this._host = options.host;
    this._port = options.port ?? 514;
    this._protocol = options.protocol ?? "tcp";
    this._useTLS = options.tls ?? true;
    this._tlsCACert = options.tlsCACert;
    this._tlsRejectUnauthorized = options.tlsRejectUnauthorized ?? true;
    this._vendor = options.vendor ?? "AITF";
    this._product = options.product ?? "AI-Telemetry-Framework";
    this._version = options.version ?? "1.0.0";
    this._mapper = new OCSFMapper();
  }

  private async _connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this._protocol === "tcp") {
        if (this._useTLS) {
          const tlsOptions: tls.ConnectionOptions = {
            host: this._host,
            port: this._port,
            rejectUnauthorized: this._tlsRejectUnauthorized,
            ca: this._tlsCACert ? [this._tlsCACert] : undefined,
          };
          this._socket = tls.connect(tlsOptions, () => {
            this._connected = true;
            resolve();
          });
        } else {
          this._socket = net.createConnection(
            { host: this._host, port: this._port },
            () => {
              this._connected = true;
              resolve();
            }
          );
        }
        this._socket.on("error", (err) => {
          this._connected = false;
          reject(err);
        });
        this._socket.on("close", () => {
          this._connected = false;
        });
        this._socket.setTimeout(10000);
      } else {
        // UDP -- Node's dgram module; for simplicity use TCP-like socket
        // that sends individual datagrams
        this._socket = net.createConnection(
          { host: this._host, port: this._port },
          () => {
            this._connected = true;
            resolve();
          }
        );
        this._socket.on("error", reject);
      }
    });
  }

  private async _send(message: string): Promise<void> {
    if (!this._connected || !this._socket) {
      await this._connect();
    }

    return new Promise((resolve, reject) => {
      const data = Buffer.from(message, "utf-8");

      if (this._protocol === "tcp") {
        // RFC 5425 octet-counting framing
        const framed = Buffer.concat([
          Buffer.from(`${data.length} `, "utf-8"),
          data,
        ]);
        this._socket!.write(framed, (err) => {
          if (err) reject(err);
          else resolve();
        });
      } else {
        this._socket!.write(data, (err) => {
          if (err) reject(err);
          else resolve();
        });
      }
    });
  }

  export(
    spans: ReadableSpan[],
    resultCallback: (result: ExportResult) => void
  ): void {
    const messages: string[] = [];

    for (const span of spans) {
      const ocsfEvent = this._mapper.mapSpan(span);
      if (!ocsfEvent) continue;

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
      const cefMsg = ocsfEventToCEF(
        eventDict,
        this._vendor,
        this._product,
        this._version
      );
      messages.push(cefMsg);
    }

    if (messages.length === 0) {
      resultCallback({ code: ExportResultCode.SUCCESS });
      return;
    }

    (async () => {
      for (const msg of messages) {
        await this._send(msg);
        this._totalExported++;
      }
      resultCallback({ code: ExportResultCode.SUCCESS });
    })().catch(() => {
      resultCallback({ code: ExportResultCode.FAILED });
    });
  }

  get totalExported(): number {
    return this._totalExported;
  }

  async shutdown(): Promise<void> {
    if (this._socket) {
      this._socket.destroy();
      this._socket = null;
      this._connected = false;
    }
  }

  async forceFlush(): Promise<void> {
    // No-op
  }
}
