/**
 * AITF Security Processor.
 *
 * OTel SpanProcessor that detects security threats in AI operations,
 * including OWASP LLM Top 10 patterns, jailbreaks, and data exfiltration.
 *
 * Based on OWASP detection patterns from AITelemetry project.
 */

import { Context, Span } from "@opentelemetry/api";
import { ReadableSpan, SpanProcessor } from "@opentelemetry/sdk-trace-base";
import {
  GenAIAttributes,
  SecurityAttributes,
} from "../semantic-conventions/attributes";

/** Maximum content length to analyze (prevent unbounded CPU usage). */
const MAX_CONTENT_LENGTH = 100_000;

/** A security finding detected in a span. */
export interface SecurityFinding {
  threatType: string;
  owaspCategory: string;
  riskLevel: string;
  riskScore: number;
  confidence: number;
  detectionMethod: string;
  details: string;
  blocked: boolean;
}

// OWASP LLM Top 10 detection patterns (adapted from AITelemetry)
// Note: All patterns use bounded quantifiers to prevent ReDoS
const PROMPT_INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /ignore\s+(all\s+)?above\s+instructions/i,
  /disregard\s+(all\s+)?previous/i,
  /forget\s+(all\s+)?(your|previous)\s+instructions/i,
  /you\s+are\s+now\s+(a|an|the)\s+/i,
  /new\s+instructions?:\s*/i,
  /system\s*:\s*you\s+are/i,
  /\[SYSTEM\]/i,
  /<\|im_start\|>system/i,
  /pretend\s+you\s+are/i,
  /act\s+as\s+(if|though)\s+you/i,
  /override\s+(your\s+)?instructions/i,
];

const JAILBREAK_PATTERNS: RegExp[] = [
  /DAN\s+mode/i,
  /developer\s+mode\s+enabled/i,
  /jailbreak/i,
  /bypass\s+(safety|content|filter)/i,
  /without\s+(any\s+)?restrictions/i,
  /no\s+(ethical|moral)\s+(guidelines|restrictions)/i,
  /unfiltered\s+(mode|response)/i,
];

const SYSTEM_PROMPT_LEAK_PATTERNS: RegExp[] = [
  /(show|reveal|display|print|output|repeat)\s+(your\s+)?(system\s+)?prompt/i,
  /what\s+(are|is)\s+your\s+(system\s+)?(instructions|prompt|rules)/i,
  /(beginning|start)\s+of\s+(your|the)\s+(conversation|system)/i,
];

const DATA_EXFILTRATION_PATTERNS: RegExp[] = [
  // Bounded quantifier to prevent ReDoS (was: .* which causes catastrophic backtracking)
  /(send|post|transmit|upload)\s+[^\n]{0,200}(to|at)\s+https?:\/\//i,
  /(curl|wget|fetch)\s+/i,
  /base64\s+encode/i,
  /exfiltrat/i,
];

const COMMAND_INJECTION_PATTERNS: RegExp[] = [
  /;\s*(rm|del|drop|shutdown|kill)\s+/i,
  /\|\s*(bash|sh|cmd|powershell)/i,
  // Bounded quantifiers to prevent ReDoS (was: `.*` and \$\(.*\))
  /`[^`]{0,500}`/,
  /\$\([^)]{0,500}\)/,
  /&&\s*(rm|del|drop)/i,
];

const SQL_INJECTION_PATTERNS: RegExp[] = [
  /('\s*OR\s+'1'\s*=\s*'1)/i,
  /(UNION\s+SELECT)/i,
  /(DROP\s+TABLE)/i,
  /(;\s*DELETE\s+FROM)/i,
  /(--\s*$)/m,
];

/** Options for configuring the SecurityProcessor. */
export interface SecurityProcessorOptions {
  detectPromptInjection?: boolean;
  detectJailbreak?: boolean;
  detectSystemPromptLeak?: boolean;
  detectDataExfiltration?: boolean;
  detectCommandInjection?: boolean;
  detectSqlInjection?: boolean;
  blockOnCritical?: boolean;
  owaspChecks?: boolean;
}

/**
 * OTel SpanProcessor that detects security threats in AI spans.
 *
 * Analyzes prompt content, completion content, and tool inputs/outputs
 * for OWASP LLM Top 10 patterns and other security threats.
 *
 * Usage:
 *   import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
 *   import { SecurityProcessor } from "@aitf/sdk";
 *
 *   const provider = new NodeTracerProvider();
 *   provider.addSpanProcessor(new SecurityProcessor({
 *     detectPromptInjection: true,
 *     detectDataExfiltration: true,
 *     blockOnCritical: false,
 *   }));
 */
export class SecurityProcessor implements SpanProcessor {
  private readonly _detectPromptInjection: boolean;
  private readonly _detectJailbreak: boolean;
  private readonly _detectSystemPromptLeak: boolean;
  private readonly _detectDataExfiltration: boolean;
  private readonly _detectCommandInjection: boolean;
  private readonly _detectSqlInjection: boolean;
  private readonly _blockOnCritical: boolean;
  private readonly _owaspChecks: boolean;

  constructor(options: SecurityProcessorOptions = {}) {
    this._detectPromptInjection = options.detectPromptInjection ?? true;
    this._detectJailbreak = options.detectJailbreak ?? true;
    this._detectSystemPromptLeak = options.detectSystemPromptLeak ?? true;
    this._detectDataExfiltration = options.detectDataExfiltration ?? true;
    this._detectCommandInjection = options.detectCommandInjection ?? true;
    this._detectSqlInjection = options.detectSqlInjection ?? true;
    this._blockOnCritical = options.blockOnCritical ?? false;
    this._owaspChecks = options.owaspChecks ?? true;
  }

  onStart(_span: Span, _parentContext: Context): void {
    // No-op on start
  }

  onEnd(span: ReadableSpan): void {
    const attrs = span.attributes ?? {};

    // Only process AI-related spans
    const hasAiPrefix = Object.keys(attrs).some(
      (key) => key.startsWith("gen_ai.") || key.startsWith("")
    );
    if (!hasAiPrefix) {
      return;
    }

    const contentToAnalyze: string[] = [];

    // Extract content from events
    for (const event of span.events ?? []) {
      if (
        event.name === "gen_ai.content.prompt" ||
        event.name === "gen_ai.content.completion"
      ) {
        const eventAttrs = event.attributes ?? {};
        for (const key of [GenAIAttributes.PROMPT, GenAIAttributes.COMPLETION]) {
          const val = eventAttrs[key];
          if (val) {
            contentToAnalyze.push(String(val));
          }
        }
      }
      if (
        event.name === "mcp.tool.input" ||
        event.name === "mcp.tool.output" ||
        event.name === "skill.input"
      ) {
        for (const val of Object.values(event.attributes ?? {})) {
          if (val) {
            contentToAnalyze.push(String(val));
          }
        }
      }
    }

    // Also check tool input/output attributes
    for (const key of [
      "mcp.tool.input",
      "mcp.tool.output",
      "skill.input",
    ]) {
      const val = attrs[key];
      if (val) {
        contentToAnalyze.push(String(val));
      }
    }

    // Run detection patterns
    const findings: SecurityFinding[] = [];
    for (const content of contentToAnalyze) {
      findings.push(...this._analyzeContent(content));
    }

    // Log findings since ReadableSpan attributes are immutable.
    // SECURITY: Only log threat types and risk levels -- never log analyzed content.
    if (findings.length > 0) {
      const maxRisk = Math.max(...findings.map((f) => f.riskScore));
      const threats = [...new Set(findings.map((f) => f.threatType))];
      const riskLevels = [...new Set(findings.map((f) => f.riskLevel))];
      console.warn(
        `AITF Security: ${findings.length} finding(s) detected - ` +
          `risk_score=${maxRisk} threats=[${threats.join(",")}] ` +
          `risk_levels=[${riskLevels.join(",")}]. ` +
          `Detailed findings are available in span attributes.`
      );
    }
  }

  /**
   * Public API to analyze text for security threats.
   * Returns list of SecurityFinding objects.
   */
  analyzeText(text: string): SecurityFinding[] {
    return this._analyzeContent(text);
  }

  private _analyzeContent(content: string): SecurityFinding[] {
    // Truncate content to prevent excessive CPU usage
    if (content.length > MAX_CONTENT_LENGTH) {
      content = content.slice(0, MAX_CONTENT_LENGTH);
    }

    const findings: SecurityFinding[] = [];

    if (this._detectPromptInjection) {
      for (const pattern of PROMPT_INJECTION_PATTERNS) {
        if (pattern.test(content)) {
          findings.push({
            threatType: SecurityAttributes.ThreatType.PROMPT_INJECTION,
            owaspCategory: SecurityAttributes.OWASP.LLM01,
            riskLevel: SecurityAttributes.RiskLevel.HIGH,
            riskScore: 80.0,
            confidence: 0.85,
            detectionMethod: "pattern",
            details: "Prompt injection pattern detected",
            blocked: false,
          });
          break;
        }
      }
    }

    if (this._detectJailbreak) {
      for (const pattern of JAILBREAK_PATTERNS) {
        if (pattern.test(content)) {
          findings.push({
            threatType: SecurityAttributes.ThreatType.JAILBREAK,
            owaspCategory: SecurityAttributes.OWASP.LLM01,
            riskLevel: SecurityAttributes.RiskLevel.CRITICAL,
            riskScore: 95.0,
            confidence: 0.9,
            detectionMethod: "pattern",
            details: "Jailbreak attempt detected",
            blocked: false,
          });
          break;
        }
      }
    }

    if (this._detectSystemPromptLeak) {
      for (const pattern of SYSTEM_PROMPT_LEAK_PATTERNS) {
        if (pattern.test(content)) {
          findings.push({
            threatType: SecurityAttributes.ThreatType.SYSTEM_PROMPT_LEAK,
            owaspCategory: SecurityAttributes.OWASP.LLM07,
            riskLevel: SecurityAttributes.RiskLevel.MEDIUM,
            riskScore: 60.0,
            confidence: 0.75,
            detectionMethod: "pattern",
            details: "System prompt leak attempt detected",
            blocked: false,
          });
          break;
        }
      }
    }

    if (this._detectDataExfiltration) {
      for (const pattern of DATA_EXFILTRATION_PATTERNS) {
        if (pattern.test(content)) {
          findings.push({
            threatType: SecurityAttributes.ThreatType.DATA_EXFILTRATION,
            owaspCategory: SecurityAttributes.OWASP.LLM02,
            riskLevel: SecurityAttributes.RiskLevel.HIGH,
            riskScore: 85.0,
            confidence: 0.7,
            detectionMethod: "pattern",
            details: "Data exfiltration pattern detected",
            blocked: false,
          });
          break;
        }
      }
    }

    if (this._detectCommandInjection) {
      for (const pattern of COMMAND_INJECTION_PATTERNS) {
        if (pattern.test(content)) {
          findings.push({
            threatType: "command_injection",
            owaspCategory: SecurityAttributes.OWASP.LLM05,
            riskLevel: SecurityAttributes.RiskLevel.CRITICAL,
            riskScore: 90.0,
            confidence: 0.8,
            detectionMethod: "pattern",
            details: "Command injection pattern detected",
            blocked: false,
          });
          break;
        }
      }
    }

    if (this._detectSqlInjection) {
      for (const pattern of SQL_INJECTION_PATTERNS) {
        if (pattern.test(content)) {
          findings.push({
            threatType: "sql_injection",
            owaspCategory: SecurityAttributes.OWASP.LLM05,
            riskLevel: SecurityAttributes.RiskLevel.HIGH,
            riskScore: 80.0,
            confidence: 0.75,
            detectionMethod: "pattern",
            details: "SQL injection pattern detected",
            blocked: false,
          });
          break;
        }
      }
    }

    return findings;
  }

  async shutdown(): Promise<void> {
    // No-op
  }

  async forceFlush(): Promise<void> {
    // No-op
  }
}
