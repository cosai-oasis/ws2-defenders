/**
 * Ready-made LLM Guard process-ACL rule profiles.
 *
 * The reverse proxy resolves the *local process* behind every request (PID /
 * exe / cmdline) and attributes it to a known AI agent, then gates access with
 * an allow/deny list of case-insensitive substrings matched against a haystack
 * of `name + exe + cmdline + agent_name` (see ProcessAclConfig). These presets
 * are curated starting points operators can apply from the settings UI and then
 * tweak — they intentionally mirror the Rust `ProcessAclConfig` shape so they
 * can be copied straight into the host's `config.toml`.
 *
 * `default = "deny"` is allowlist semantics (only listed callers pass);
 * `default = "allow"` is denylist semantics (everything except blocked callers
 * passes). `deny` always wins over `allow`.
 */
import type { ProcessAclConfig } from './llm-guard-config';

export interface AclPreset {
  id: string;
  name: string;
  /** One-line summary shown in the picker. */
  description: string;
  /** Longer rationale / what it protects against. */
  detail: string;
  /** "allowlist" | "denylist" | "off" — drives the badge in the UI. */
  kind: 'allowlist' | 'denylist' | 'off';
  recommended?: boolean;
  acl: ProcessAclConfig;
}

// Common building blocks reused across presets.
const KNOWN_CODING_AGENTS = [
  'claude-code',
  'claude',
  'cursor',
  'codex',
  'aider',
  'opencode',
  'continue',
  'cline',
  'windsurf',
  'zed',
  'tabby',
  'copilot',
];

const FIRST_PARTY_LLM_CLIENTS = [
  'ollama',
  'lm studio',
  'lmstudio',
  'llama.cpp',
  'llama-server',
  'llama-cli',
  'open-webui',
  'openwebui',
  'jan',
  'msty',
  'anythingllm',
  'gpt4all',
];

const SCRIPTING_INTERPRETERS = [
  'python',
  'python3',
  'node',
  'deno',
  'bun',
  'ruby',
  'perl',
  'php',
  'bash',
  'zsh',
  'sh ',
  'powershell',
  'pwsh',
];

const EXFIL_TOOLING = ['curl', 'wget', 'nc ', 'ncat', 'netcat', 'socat', 'scp', 'rsync', 'telnet'];

const BROWSERS = ['chrome', 'chromium', 'firefox', 'msedge', 'edge', 'safari', 'brave', 'opera'];

export const LLM_GUARD_ACL_PRESETS: AclPreset[] = [
  {
    id: 'observe-only',
    name: 'Observe only (no enforcement)',
    description: 'Record caller provenance on every event but never block.',
    detail:
      'Baseline posture. The guard still resolves which process is calling and attributes it to a known agent, so you can study traffic in the dashboard before turning on enforcement.',
    kind: 'off',
    acl: { enabled: false, default: 'deny', block_unresolved: false, allow: [], deny: [] },
  },
  {
    id: 'coding-agents-only',
    name: 'Allow known AI coding agents only',
    description: 'Allowlist: Claude Code, Cursor, Codex, Aider, Continue, Cline, …',
    detail:
      'Default-deny. Only recognised AI coding assistants may reach local models; everything else (ad-hoc scripts, browsers, unknown binaries) is rejected with a 403 and an OCSF finding.',
    kind: 'allowlist',
    recommended: true,
    acl: {
      enabled: true,
      default: 'deny',
      block_unresolved: false,
      allow: [...KNOWN_CODING_AGENTS],
      deny: [],
    },
  },
  {
    id: 'first-party-clients',
    name: 'Allow first-party LLM apps',
    description: 'Allowlist: Ollama, LM Studio, llama.cpp, Open WebUI, Jan, Msty, …',
    detail:
      'Default-deny for desktop / first-party local-LLM front-ends. Good for a shared workstation where humans drive the models through GUI apps rather than scripts.',
    kind: 'allowlist',
    acl: {
      enabled: true,
      default: 'deny',
      block_unresolved: false,
      allow: [...FIRST_PARTY_LLM_CLIENTS],
      deny: [],
    },
  },
  {
    id: 'workstation-recommended',
    name: 'Developer workstation (coding agents + LLM apps)',
    description: 'Allowlist: both AI coding agents and first-party LLM clients.',
    detail:
      'Default-deny union of the two allowlists above — a practical lockdown for a developer machine that runs both IDE assistants and a local model GUI.',
    kind: 'allowlist',
    acl: {
      enabled: true,
      default: 'deny',
      block_unresolved: false,
      allow: [...new Set([...KNOWN_CODING_AGENTS, ...FIRST_PARTY_LLM_CLIENTS])],
      deny: [],
    },
  },
  {
    id: 'block-scripts',
    name: 'Block scripting interpreters',
    description: 'Denylist: python, node, ruby, bash, powershell, …',
    detail:
      'Default-allow but reject calls coming directly from a language interpreter — a common shape for ad-hoc exfiltration or unsanctioned automation hitting the model API.',
    kind: 'denylist',
    acl: {
      enabled: true,
      default: 'allow',
      block_unresolved: false,
      allow: [],
      deny: [...SCRIPTING_INTERPRETERS],
    },
  },
  {
    id: 'block-exfil-tooling',
    name: 'Block data-transfer tooling',
    description: 'Denylist: curl, wget, netcat, socat, scp, rsync, …',
    detail:
      'Default-allow but reject network/file-transfer utilities, which have no legitimate reason to be the direct caller of a local inference endpoint.',
    kind: 'denylist',
    acl: {
      enabled: true,
      default: 'allow',
      block_unresolved: false,
      allow: [],
      deny: [...EXFIL_TOOLING],
    },
  },
  {
    id: 'block-browsers',
    name: 'Block browsers',
    description: 'Denylist: Chrome, Firefox, Edge, Safari, Brave, …',
    detail:
      'Default-allow but reject browser processes — stops browser-extension agents and page scripts from reaching local models through the proxy.',
    kind: 'denylist',
    acl: {
      enabled: true,
      default: 'allow',
      block_unresolved: false,
      allow: [],
      deny: [...BROWSERS],
    },
  },
  {
    id: 'strict-lockdown',
    name: 'Strict lockdown (deny all — edit the allowlist)',
    description: 'Allowlist starter: nothing passes until you add entries.',
    detail:
      'Maximum-control template: default-deny AND reject callers whose process cannot be resolved to a PID. Start here and add only the exact binaries you trust. Note: process resolution is Linux-only today, so block_unresolved will reject everything on macOS/Windows.',
    kind: 'allowlist',
    acl: { enabled: true, default: 'deny', block_unresolved: true, allow: [], deny: [] },
  },
];

/** Look up a preset by id. */
export function presetById(id: string): AclPreset | undefined {
  return LLM_GUARD_ACL_PRESETS.find((p) => p.id === id);
}
