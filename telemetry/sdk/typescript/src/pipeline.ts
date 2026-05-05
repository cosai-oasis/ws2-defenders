/**
 * AITF Dual Pipeline Provider.
 *
 * Configures an OpenTelemetry TracerProvider with both OTLP and OCSF
 * export pipelines, enabling the same security-enriched spans to be sent
 * to OTLP-compatible backends (Jaeger, Grafana Tempo, Datadog, Elastic
 * Security) for observability and security analytics AND SIEM/XDR
 * endpoints simultaneously.
 *
 * Usage:
 *
 * ```typescript
 * import { createDualPipelineProvider, AITFInstrumentor } from "@aitf/sdk";
 *
 * const provider = createDualPipelineProvider({
 *   otlpEndpoint: "http://localhost:4317",
 *   ocsfOutputFile: "/var/log/aitf/events.jsonl",
 *   serviceName: "my-ai-service",
 * });
 *
 * const instrumentor = new AITFInstrumentor(provider.tracerProvider);
 * instrumentor.instrumentAll();
 * ```
 */

import {
  BasicTracerProvider,
  BatchSpanProcessor,
  SimpleSpanProcessor,
  ConsoleSpanExporter,
  SpanExporter,
} from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { Resource } from "@opentelemetry/resources";
import { SEMRESATTRS_SERVICE_NAME } from "@opentelemetry/semantic-conventions";
import { OCSFExporter, OCSFExporterOptions } from "./exporters/ocsf-exporter";

/** Options for configuring the DualPipelineProvider. */
export interface DualPipelineOptions {
  /** OTLP gRPC endpoint (e.g., "http://localhost:4317"). */
  otlpEndpoint?: string;

  /** OTLP HTTP endpoint (e.g., "http://localhost:4318/v1/traces"). */
  otlpHttpEndpoint?: string;

  /** Headers for OTLP export (e.g., auth tokens). */
  otlpHeaders?: Record<string, string>;

  /** File path for OCSF JSONL output. */
  ocsfOutputFile?: string;

  /** HTTP endpoint for OCSF event delivery. */
  ocsfEndpoint?: string;

  /** API key for OCSF HTTP endpoint. */
  ocsfApiKey?: string;

  /** Compliance frameworks for OCSF enrichment. */
  complianceFrameworks?: string[];

  /** Enable console span output (development). */
  console?: boolean;

  /** Additional span exporters (CEF syslog, immutable log, etc.). */
  additionalExporters?: SpanExporter[];

  /** OTel service name. */
  serviceName?: string;

  /** Additional OTel resource attributes. */
  resourceAttributes?: Record<string, string>;
}

/**
 * Dual pipeline provider managing a TracerProvider with both OTLP and
 * OCSF export.
 */
export class DualPipelineProvider {
  private readonly provider: BasicTracerProvider;
  private readonly _exporters: SpanExporter[] = [];

  constructor(options: DualPipelineOptions = {}) {
    const {
      otlpEndpoint,
      otlpHttpEndpoint,
      otlpHeaders,
      ocsfOutputFile,
      ocsfEndpoint,
      ocsfApiKey,
      complianceFrameworks,
      console: enableConsole,
      additionalExporters,
      serviceName = "aitf-service",
      resourceAttributes,
    } = options;

    // Build resource
    const attrs: Record<string, string> = {
      [SEMRESATTRS_SERVICE_NAME]: serviceName,
      ...resourceAttributes,
    };
    const resource = new Resource(attrs);

    this.provider = new NodeTracerProvider({ resource });

    // OTLP pipeline (observability & security analytics)
    if (otlpEndpoint) {
      try {
        // Dynamic import — user must install @opentelemetry/exporter-trace-otlp-grpc
        const { OTLPTraceExporter } = require(
          "@opentelemetry/exporter-trace-otlp-grpc"
        );
        const otlpExporter = new OTLPTraceExporter({
          url: otlpEndpoint,
          headers: otlpHeaders,
        });
        this.provider.addSpanProcessor(new BatchSpanProcessor(otlpExporter));
        this._exporters.push(otlpExporter);
      } catch {
        console.warn(
          "OTLP gRPC exporter not available. " +
            "Install: npm install @opentelemetry/exporter-trace-otlp-grpc"
        );
      }
    }

    if (otlpHttpEndpoint) {
      try {
        const { OTLPTraceExporter } = require(
          "@opentelemetry/exporter-trace-otlp-http"
        );
        const otlpExporter = new OTLPTraceExporter({
          url: otlpHttpEndpoint,
          headers: otlpHeaders,
        });
        this.provider.addSpanProcessor(new BatchSpanProcessor(otlpExporter));
        this._exporters.push(otlpExporter);
      } catch {
        console.warn(
          "OTLP HTTP exporter not available. " +
            "Install: npm install @opentelemetry/exporter-trace-otlp-http"
        );
      }
    }

    // OCSF pipeline (OCSF-native SIEM / compliance)
    if (ocsfOutputFile || ocsfEndpoint) {
      const ocsfExporter = new OCSFExporter({
        outputFile: ocsfOutputFile,
        endpoint: ocsfEndpoint,
        apiKey: ocsfApiKey,
        complianceFrameworks,
      });
      this.provider.addSpanProcessor(new BatchSpanProcessor(ocsfExporter));
      this._exporters.push(ocsfExporter);
    }

    // Console (development)
    if (enableConsole) {
      this.provider.addSpanProcessor(
        new SimpleSpanProcessor(new ConsoleSpanExporter())
      );
    }

    // Additional exporters
    if (additionalExporters) {
      for (const exporter of additionalExporters) {
        this.provider.addSpanProcessor(new BatchSpanProcessor(exporter));
        this._exporters.push(exporter);
      }
    }

    if (this._exporters.length === 0 && !enableConsole) {
      console.warn(
        "DualPipelineProvider created with no exporters. " +
          "Set otlpEndpoint and/or ocsfOutputFile."
      );
    }
  }

  /** The configured TracerProvider for use with AITF instrumentors. */
  get tracerProvider(): BasicTracerProvider {
    return this.provider;
  }

  /** Register as the global OTel TracerProvider. */
  setAsGlobal(): void {
    this.provider.register();
  }

  /** Flush and shut down all exporters. */
  async shutdown(): Promise<void> {
    await this.provider.shutdown();
  }

  /** List of active exporters (read-only). */
  get exporters(): ReadonlyArray<SpanExporter> {
    return [...this._exporters];
  }
}

/**
 * Create a provider with both OTel and OCSF export pipelines.
 * This is the recommended setup for production.
 */
export function createDualPipelineProvider(
  options: DualPipelineOptions & {
    otlpEndpoint: string;
    ocsfOutputFile: string;
  }
): DualPipelineProvider {
  return new DualPipelineProvider(options);
}

/**
 * Create a provider that exports only to an OTel backend (OTLP).
 */
export function createOTelOnlyProvider(
  endpoint: string,
  options: Omit<
    DualPipelineOptions,
    "otlpEndpoint" | "ocsfOutputFile" | "ocsfEndpoint"
  > = {}
): DualPipelineProvider {
  return new DualPipelineProvider({ ...options, otlpEndpoint: endpoint });
}

/**
 * Create a provider that exports only OCSF events (SIEM/XDR).
 */
export function createOCSFOnlyProvider(
  outputFile: string,
  options: Omit<
    DualPipelineOptions,
    "otlpEndpoint" | "otlpHttpEndpoint" | "ocsfOutputFile"
  > = {}
): DualPipelineProvider {
  return new DualPipelineProvider({ ...options, ocsfOutputFile: outputFile });
}
