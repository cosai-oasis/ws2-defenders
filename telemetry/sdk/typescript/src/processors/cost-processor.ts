/**
 * AITF Cost Processor.
 *
 * OTel SpanProcessor that calculates and attributes costs for AI operations
 * based on model pricing tables and token usage.
 */

import { Context, Span } from "@opentelemetry/api";
import { ReadableSpan, SpanProcessor } from "@opentelemetry/sdk-trace-base";
import {
  CostAttributes,
  GenAIAttributes,
} from "../semantic-conventions/attributes";

/** Maximum reasonable token count per request. */
const MAX_TOKENS = 10_000_000;

/** Model pricing per 1M tokens (USD). */
export const MODEL_PRICING: Record<string, { input: number; output: number }> =
  {
    // OpenAI
    "gpt-4o": { input: 2.5, output: 10.0 },
    "gpt-4o-mini": { input: 0.15, output: 0.6 },
    "gpt-4-turbo": { input: 10.0, output: 30.0 },
    "gpt-4": { input: 30.0, output: 60.0 },
    "gpt-3.5-turbo": { input: 0.5, output: 1.5 },
    o1: { input: 15.0, output: 60.0 },
    "o1-mini": { input: 3.0, output: 12.0 },
    "o3-mini": { input: 1.1, output: 4.4 },
    "text-embedding-3-small": { input: 0.02, output: 0.0 },
    "text-embedding-3-large": { input: 0.13, output: 0.0 },
    // Anthropic
    "claude-opus-4-6": { input: 15.0, output: 75.0 },
    "claude-sonnet-4-5-20250929": { input: 3.0, output: 15.0 },
    "claude-haiku-4-5-20251001": { input: 0.8, output: 4.0 },
    "claude-3-5-sonnet-20241022": { input: 3.0, output: 15.0 },
    "claude-3-5-haiku-20241022": { input: 0.8, output: 4.0 },
    "claude-3-opus-20240229": { input: 15.0, output: 75.0 },
    // Google
    "gemini-2.0-flash": { input: 0.1, output: 0.4 },
    "gemini-1.5-pro": { input: 1.25, output: 5.0 },
    "gemini-1.5-flash": { input: 0.075, output: 0.3 },
    // Mistral
    "mistral-large-latest": { input: 2.0, output: 6.0 },
    "mistral-small-latest": { input: 0.2, output: 0.6 },
    // Meta (via API providers)
    "llama-3.1-405b": { input: 3.0, output: 3.0 },
    "llama-3.1-70b": { input: 0.8, output: 0.8 },
    "llama-3.1-8b": { input: 0.1, output: 0.1 },
    // Cohere
    "command-r-plus": { input: 2.5, output: 10.0 },
    "command-r": { input: 0.15, output: 0.6 },
  };

/** Cost calculation result. */
export interface CostResult {
  inputCost: number;
  outputCost: number;
  totalCost: number;
  currency: string;
}

/** Options for configuring the CostProcessor. */
export interface CostProcessorOptions {
  customPricing?: Record<string, { input: number; output: number }>;
  defaultUser?: string;
  defaultTeam?: string;
  defaultProject?: string;
  budgetLimit?: number;
  currency?: string;
}

/**
 * OTel SpanProcessor that calculates costs for AI operations.
 *
 * Automatically computes cost based on model and token usage,
 * and adds cost attribution attributes.
 *
 * Usage:
 *   provider.addSpanProcessor(new CostProcessor({
 *     customPricing: { "my-model": { input: 1.0, output: 3.0 } },
 *     defaultUser: "system",
 *     budgetLimit: 100.0,
 *   }));
 */
export class CostProcessor implements SpanProcessor {
  private readonly _pricing: Record<
    string,
    { input: number; output: number }
  >;
  private readonly _defaultUser: string | null;
  private readonly _defaultTeam: string | null;
  private readonly _defaultProject: string | null;
  private readonly _budgetLimit: number | null;
  private readonly _currency: string;
  private _totalCost = 0;

  constructor(options: CostProcessorOptions = {}) {
    // Use spread from known-safe constant, then merge custom pricing safely
    this._pricing = { ...MODEL_PRICING };
    if (options.customPricing) {
      for (const [key, value] of Object.entries(options.customPricing)) {
        if (!Object.prototype.hasOwnProperty.call(options.customPricing, key)) {
          continue;
        }
        // Reject dangerous property names (prototype pollution prevention)
        if (key === "__proto__" || key === "constructor" || key === "prototype") {
          continue;
        }
        this._pricing[key] = value;
      }
    }
    this._defaultUser = options.defaultUser ?? null;
    this._defaultTeam = options.defaultTeam ?? null;
    this._defaultProject = options.defaultProject ?? null;
    this._budgetLimit = options.budgetLimit ?? null;
    this._currency = options.currency ?? "USD";
  }

  onStart(span: Span, _parentContext: Context): void {
    if (this._defaultUser) {
      span.setAttribute(CostAttributes.ATTRIBUTION_USER, this._defaultUser);
    }
    if (this._defaultTeam) {
      span.setAttribute(CostAttributes.ATTRIBUTION_TEAM, this._defaultTeam);
    }
    if (this._defaultProject) {
      span.setAttribute(
        CostAttributes.ATTRIBUTION_PROJECT,
        this._defaultProject
      );
    }
  }

  onEnd(span: ReadableSpan): void {
    const attrs = span.attributes ?? {};
    const model =
      attrs[GenAIAttributes.REQUEST_MODEL] ??
      attrs[GenAIAttributes.RESPONSE_MODEL];
    if (!model) {
      return;
    }

    const inputTokens = Number(
      attrs[GenAIAttributes.USAGE_INPUT_TOKENS] ?? 0
    );
    const outputTokens = Number(
      attrs[GenAIAttributes.USAGE_OUTPUT_TOKENS] ?? 0
    );
    if (!inputTokens && !outputTokens) {
      return;
    }

    const cost = this.calculateCost(
      String(model),
      inputTokens,
      outputTokens
    );
    if (cost) {
      this._totalCost += cost.totalCost;
    }
  }

  /**
   * Calculate cost for a given model and token count.
   * Returns CostResult or null if model unknown.
   */
  calculateCost(
    model: string,
    inputTokens: number,
    outputTokens: number
  ): CostResult | null {
    // Validate token counts
    inputTokens = Math.max(0, Math.min(inputTokens, MAX_TOKENS));
    outputTokens = Math.max(0, Math.min(outputTokens, MAX_TOKENS));

    const pricing = this._getPricing(model);
    if (!pricing) {
      return null;
    }

    const inputCost = (inputTokens / 1_000_000) * pricing.input;
    const outputCost = (outputTokens / 1_000_000) * pricing.output;
    const totalCost = inputCost + outputCost;

    return {
      inputCost: Number(inputCost.toFixed(8)),
      outputCost: Number(outputCost.toFixed(8)),
      totalCost: Number(totalCost.toFixed(8)),
      currency: this._currency,
    };
  }

  /**
   * Get cost attributes suitable for span attributes.
   */
  getCostAttributes(
    model: string,
    inputTokens: number,
    outputTokens: number
  ): Record<string, number | string> {
    const cost = this.calculateCost(model, inputTokens, outputTokens);
    if (!cost) {
      return {};
    }

    const attributes: Record<string, number | string> = {
      [CostAttributes.INPUT_COST]: cost.inputCost,
      [CostAttributes.OUTPUT_COST]: cost.outputCost,
      [CostAttributes.TOTAL_COST]: cost.totalCost,
      [CostAttributes.CURRENCY]: cost.currency,
    };

    // Add pricing info
    const pricing = this._getPricing(model);
    if (pricing) {
      attributes[CostAttributes.PRICING_INPUT_PER_1M] = pricing.input;
      attributes[CostAttributes.PRICING_OUTPUT_PER_1M] = pricing.output;
    }

    // Add budget info
    if (this._budgetLimit !== null) {
      attributes[CostAttributes.BUDGET_LIMIT] = this._budgetLimit;
      attributes[CostAttributes.BUDGET_USED] = this._totalCost;
      attributes[CostAttributes.BUDGET_REMAINING] = Math.max(
        0,
        this._budgetLimit - this._totalCost
      );
    }

    return attributes;
  }

  get totalCost(): number {
    return this._totalCost;
  }

  get budgetRemaining(): number | null {
    if (this._budgetLimit === null) {
      return null;
    }
    return Math.max(0, this._budgetLimit - this._totalCost);
  }

  get budgetExceeded(): boolean {
    if (this._budgetLimit === null) {
      return false;
    }
    return this._totalCost > this._budgetLimit;
  }

  private _getPricing(
    model: string
  ): { input: number; output: number } | null {
    if (Object.prototype.hasOwnProperty.call(this._pricing, model)) {
      return this._pricing[model];
    }
    // Try prefix match (e.g., "gpt-4o-2024-08-06" -> "gpt-4o")
    const sortedKeys = Object.keys(this._pricing).sort(
      (a, b) => b.length - a.length
    );
    for (const key of sortedKeys) {
      if (model.startsWith(key)) {
        return this._pricing[key];
      }
    }
    return null;
  }

  async shutdown(): Promise<void> {
    // No-op
  }

  async forceFlush(): Promise<void> {
    // No-op
  }
}
