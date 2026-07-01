/**
 * LLM Guard configuration helper.
 *
 * The Rust agent reads its LLM Guard settings from the host-side `config.toml`
 * (`[llm_guard]` section — see adr_system/rust_agent/src/config.rs). The
 * dashboard cannot push config to the agent over the wire today, so this module
 * persists the *desired* configuration as JSON on disk. Operators can review /
 * edit it here and copy it into the agent's `config.toml`.
 *
 * The shape intentionally mirrors `LlmGuardConfig` (and its nested structs) in
 * the Rust backend so the two stay in lock-step.
 */
import fs from 'fs';
import path from 'path';

export interface BackendConfig {
  name: string;
  /** ollama | lmstudio | llamacpp */
  kind: string;
  /** Upstream base URL, e.g. http://127.0.0.1:11434 */
  url: string;
  /** Path prefix that routes to this backend (longest match wins; "" = default). */
  route_prefix: string;
  /** Relative path pinged by the health checker, e.g. /api/tags */
  health_path: string;
}

export interface JwtConfig {
  enabled: boolean;
  secret: string;
  issuer: string;
  audience: string;
}

export interface RateLimitConfig {
  enabled: boolean;
  requests_per_minute: number;
  burst: number;
}

export interface MonitoringConfig {
  enabled: boolean;
  detect_prompt_injection: boolean;
  detect_pii: boolean;
  track_tokens: boolean;
  block_on_injection: boolean;
  block_on_pii: boolean;
  max_prompt_chars: number;
}

export interface ProcessAclConfig {
  /** Enforce process-based access control on callers. */
  enabled: boolean;
  /** Decision when no rule matches: "deny" (allowlist) | "allow" (denylist). */
  default: string;
  /** Reject callers whose process (PID) could not be resolved. */
  block_unresolved: boolean;
  /** Allow patterns — caller passes if its exe/cmdline/agent matches ANY. */
  allow: string[];
  /** Deny patterns — caller rejected if it matches ANY (deny wins). */
  deny: string[];
}

export interface LlmGuardConfig {
  enabled: boolean;
  listen_address: string;
  backends: BackendConfig[];
  /** API keys are masked on read; see maskConfig(). */
  auth_tokens: string[];
  jwt: JwtConfig;
  rate_limits: RateLimitConfig;
  monitoring: MonitoringConfig;
  process_acl: ProcessAclConfig;
  health_check_interval_seconds: number;
  max_body_bytes: number;
  upstream_timeout_seconds: number;
}

/** Defaults mirror the Rust `default_llm_guard_*` helpers. */
export function defaultConfig(): LlmGuardConfig {
  return {
    enabled: false,
    listen_address: '127.0.0.1:8011',
    backends: [
      {
        name: 'ollama',
        kind: 'ollama',
        url: 'http://127.0.0.1:11434',
        route_prefix: '',
        health_path: '/api/tags',
      },
      {
        name: 'lmstudio',
        kind: 'lmstudio',
        url: 'http://127.0.0.1:1234',
        route_prefix: '/lmstudio',
        health_path: '/v1/models',
      },
      {
        name: 'llamacpp',
        kind: 'llamacpp',
        url: 'http://127.0.0.1:8080',
        route_prefix: '/llamacpp',
        health_path: '/health',
      },
    ],
    auth_tokens: [],
    jwt: { enabled: false, secret: '', issuer: '', audience: '' },
    rate_limits: { enabled: true, requests_per_minute: 120, burst: 0 },
    monitoring: {
      enabled: true,
      detect_prompt_injection: true,
      detect_pii: true,
      track_tokens: true,
      block_on_injection: false,
      block_on_pii: false,
      max_prompt_chars: 2000,
    },
    process_acl: {
      enabled: false,
      default: 'deny',
      block_unresolved: false,
      allow: [],
      deny: [],
    },
    health_check_interval_seconds: 30,
    max_body_bytes: 8 * 1024 * 1024,
    upstream_timeout_seconds: 60,
  };
}

const DATA_DIR = path.join(process.cwd(), 'data');
const CONFIG_PATH = path.join(DATA_DIR, 'llm-guard-config.json');

/** Read the persisted config, falling back to defaults. */
export function loadConfig(): LlmGuardConfig {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
      const parsed = JSON.parse(raw);
      // Merge over defaults so newly-added fields are always present.
      return mergeConfig(defaultConfig(), parsed);
    }
  } catch (e) {
    // fall through to defaults on any parse/IO error
    console.error('llm-guard: failed to load config, using defaults:', e);
  }
  return defaultConfig();
}

/** Persist the config to disk. */
export function saveConfig(cfg: LlmGuardConfig): LlmGuardConfig {
  const merged = mergeConfig(defaultConfig(), cfg);
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(merged, null, 2), 'utf-8');
  return merged;
}

/** Shallow-but-typed merge of an incoming (possibly partial) config. */
export function mergeConfig(base: LlmGuardConfig, incoming: Partial<LlmGuardConfig>): LlmGuardConfig {
  return {
    enabled: incoming.enabled ?? base.enabled,
    listen_address: incoming.listen_address ?? base.listen_address,
    backends: Array.isArray(incoming.backends)
      ? incoming.backends.map((b) => ({
          name: b?.name ?? '',
          kind: b?.kind ?? 'ollama',
          url: b?.url ?? '',
          route_prefix: b?.route_prefix ?? '',
          health_path: b?.health_path ?? '/health',
        }))
      : base.backends,
    auth_tokens: Array.isArray(incoming.auth_tokens) ? incoming.auth_tokens : base.auth_tokens,
    jwt: { ...base.jwt, ...(incoming.jwt ?? {}) },
    rate_limits: { ...base.rate_limits, ...(incoming.rate_limits ?? {}) },
    monitoring: { ...base.monitoring, ...(incoming.monitoring ?? {}) },
    process_acl: {
      ...base.process_acl,
      ...(incoming.process_acl ?? {}),
      allow: Array.isArray(incoming.process_acl?.allow)
        ? incoming.process_acl!.allow.filter((s) => typeof s === 'string')
        : base.process_acl.allow,
      deny: Array.isArray(incoming.process_acl?.deny)
        ? incoming.process_acl!.deny.filter((s) => typeof s === 'string')
        : base.process_acl.deny,
    },
    health_check_interval_seconds:
      incoming.health_check_interval_seconds ?? base.health_check_interval_seconds,
    max_body_bytes: incoming.max_body_bytes ?? base.max_body_bytes,
    upstream_timeout_seconds: incoming.upstream_timeout_seconds ?? base.upstream_timeout_seconds,
  };
}

/**
 * Mask secrets before sending to the client. API keys / JWT secret are replaced
 * with a fixed-length placeholder that preserves "is it set?" without leaking
 * the value. The client sends back the placeholder unchanged when unedited;
 * applyMaskedSecrets() restores the real value on save.
 */
export const MASK = '••••••••';

export function maskConfig(cfg: LlmGuardConfig): LlmGuardConfig {
  return {
    ...cfg,
    auth_tokens: cfg.auth_tokens.map(() => MASK),
    jwt: { ...cfg.jwt, secret: cfg.jwt.secret ? MASK : '' },
  };
}

/**
 * When the client posts back a masked secret unchanged, restore the stored
 * value so we never overwrite a real secret with the placeholder.
 */
export function applyMaskedSecrets(incoming: LlmGuardConfig, stored: LlmGuardConfig): LlmGuardConfig {
  const auth_tokens = incoming.auth_tokens.map((t, i) =>
    t === MASK ? stored.auth_tokens[i] ?? '' : t,
  );
  const secret = incoming.jwt.secret === MASK ? stored.jwt.secret : incoming.jwt.secret;
  return { ...incoming, auth_tokens, jwt: { ...incoming.jwt, secret } };
}
