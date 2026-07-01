'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useSession } from 'next-auth/react';
import { useFetch } from '@/hooks/use-fetch';
import { motion } from 'framer-motion';
import {
  ShieldHalf, Server, KeyRound, Gauge, Eye, Plus, Trash2, Save,
  Check, X, AlertTriangle, Loader2, ArrowLeft, Lock, Activity,
  Fingerprint, Wand2,
} from 'lucide-react';
import type { LlmGuardConfig, BackendConfig } from '@/lib/llm-guard-config';
import { LLM_GUARD_ACL_PRESETS, presetById } from '@/lib/llm-guard-presets';

const MASK = '••••••••';
const BACKEND_KINDS = ['ollama', 'lmstudio', 'llamacpp'];

// ── small presentational helpers ──────────────────────────────────────
function Toggle({ checked, onChange, disabled }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors disabled:opacity-50 ${
        checked ? 'bg-primary' : 'bg-muted'
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
          checked ? 'translate-x-6' : 'translate-x-1'
        }`}
      />
    </button>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-sm font-medium text-foreground">{label}</span>
      {hint && <span className="block text-xs text-muted-foreground mb-1">{hint}</span>}
      <div className={hint ? '' : 'mt-1'}>{children}</div>
    </label>
  );
}

const inputCls =
  'w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring';

function ToggleRow({ label, hint, checked, onChange, disabled }: { label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2">
      <div>
        <div className="text-sm font-medium text-foreground">{label}</div>
        {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
      </div>
      <Toggle checked={checked} onChange={onChange} disabled={disabled} />
    </div>
  );
}

function Card({ icon: Icon, title, desc, children }: { icon: any; title: string; desc?: string; children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-border bg-card p-5 space-y-4"
    >
      <div className="flex items-start gap-3">
        <div className="rounded-lg bg-primary/10 p-2 text-primary">
          <Icon className="w-5 h-5" />
        </div>
        <div>
          <h2 className="text-base font-semibold text-foreground">{title}</h2>
          {desc && <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>}
        </div>
      </div>
      {children}
    </motion.div>
  );
}

export default function LlmGuardSettingsContent() {
  const { data: session } = useSession() || {};
  const currentUser = session?.user as any;
  const isAdminUser = currentUser?.role === 'owner' || currentUser?.role === 'admin';

  const { data, mutate, isLoading } = useFetch<{ config: LlmGuardConfig }>('/api/llm-guard/config');
  const [cfg, setCfg] = useState<LlmGuardConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [newToken, setNewToken] = useState('');

  useEffect(() => {
    if (data?.config && !cfg) setCfg(data.config);
  }, [data, cfg]);

  const flash = (msg: string, isError = false) => {
    if (isError) { setError(msg); setSuccess(''); }
    else { setSuccess(msg); setError(''); }
    setTimeout(() => { setError(''); setSuccess(''); }, 3500);
  };

  // typed updater helpers
  const patch = (p: Partial<LlmGuardConfig>) => setCfg((c) => (c ? { ...c, ...p } : c));
  const patchMonitoring = (p: Partial<LlmGuardConfig['monitoring']>) =>
    setCfg((c) => (c ? { ...c, monitoring: { ...c.monitoring, ...p } } : c));
  const patchRate = (p: Partial<LlmGuardConfig['rate_limits']>) =>
    setCfg((c) => (c ? { ...c, rate_limits: { ...c.rate_limits, ...p } } : c));
  const patchJwt = (p: Partial<LlmGuardConfig['jwt']>) =>
    setCfg((c) => (c ? { ...c, jwt: { ...c.jwt, ...p } } : c));
  const patchAcl = (p: Partial<LlmGuardConfig['process_acl']>) =>
    setCfg((c) => (c ? { ...c, process_acl: { ...c.process_acl, ...p } } : c));

  // Apply a curated rule preset, replacing the ACL block wholesale.
  const applyPreset = (id: string) => {
    const preset = presetById(id);
    if (!preset) return;
    setCfg((c) => (c ? { ...c, process_acl: { ...preset.acl } } : c));
    flash(`Applied preset: ${preset.name}`);
  };
  // Edit a newline-separated pattern list (allow / deny).
  const patchAclList = (key: 'allow' | 'deny', text: string) =>
    patchAcl({ [key]: text.split('\n').map((s) => s.trim()).filter(Boolean) } as Partial<LlmGuardConfig['process_acl']>);

  const updateBackend = (i: number, p: Partial<BackendConfig>) =>
    setCfg((c) => {
      if (!c) return c;
      const backends = c.backends.slice();
      backends[i] = { ...backends[i], ...p };
      return { ...c, backends };
    });
  const addBackend = () =>
    setCfg((c) =>
      c
        ? {
            ...c,
            backends: [...c.backends, { name: '', kind: 'ollama', url: 'http://127.0.0.1:11434', route_prefix: '', health_path: '/api/tags' }],
          }
        : c,
    );
  const removeBackend = (i: number) =>
    setCfg((c) => (c ? { ...c, backends: c.backends.filter((_, idx) => idx !== i) } : c));

  const addToken = () => {
    const t = newToken.trim();
    if (!t) return;
    setCfg((c) => (c ? { ...c, auth_tokens: [...c.auth_tokens, t] } : c));
    setNewToken('');
  };
  const removeToken = (i: number) =>
    setCfg((c) => (c ? { ...c, auth_tokens: c.auth_tokens.filter((_, idx) => idx !== i) } : c));

  const save = async () => {
    if (!cfg) return;
    if (!isAdminUser) return flash('Admin access required to save', true);
    // basic validation
    for (const b of cfg.backends) {
      if (!b.name.trim() || !b.url.trim()) return flash('Every backend needs a name and URL', true);
    }
    setSaving(true);
    try {
      const res = await fetch('/api/llm-guard/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: cfg }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || 'Save failed');
      setCfg(json.config);
      await mutate();
      flash('LLM Guard configuration saved');
    } catch (e: any) {
      flash(e.message, true);
    } finally {
      setSaving(false);
    }
  };

  if (isLoading || !cfg) {
    return (
      <div className="p-6 flex items-center gap-2 text-muted-foreground">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading LLM Guard configuration…
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-end justify-between flex-wrap gap-3">
        <div>
          <Link href="/llm-guard" className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 mb-2">
            <ArrowLeft className="w-3 h-3" /> Back to LLM Guard dashboard
          </Link>
          <h1 className="text-2xl md:text-3xl font-display font-bold tracking-tight flex items-center gap-2">
            <ShieldHalf className="w-6 h-6 text-primary" />
            LLM Guard Settings
          </h1>
          <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
            Configure the reverse proxy that sits in front of your local LLM backends
            (Ollama, LM Studio, llama.cpp). These settings mirror the agent&apos;s
            <code className="mx-1 px-1 rounded bg-muted text-xs">[llm_guard]</code>
            config — copy them into the host&apos;s <code className="px-1 rounded bg-muted text-xs">config.toml</code> to apply.
          </p>
        </div>
        <button
          onClick={save}
          disabled={saving || !isAdminUser}
          className="px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium flex items-center gap-2 disabled:opacity-50"
        >
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          Save changes
        </button>
      </div>

      {/* flash + permission banners */}
      {!isAdminUser && (
        <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
          <Lock className="w-4 h-4" /> You have read-only access. Only owners and admins can change LLM Guard settings.
        </div>
      )}
      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <X className="w-4 h-4" /> {error}
        </div>
      )}
      {success && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-400">
          <Check className="w-4 h-4" /> {success}
        </div>
      )}

      <fieldset disabled={!isAdminUser} className="space-y-6">
        {/* ── General ── */}
        <Card icon={Activity} title="General" desc="Master switch and listener for the LLM Guard reverse proxy.">
          <ToggleRow
            label="Enable LLM Guard"
            hint="When off, the reverse proxy never binds a port and no traffic is inspected."
            checked={cfg.enabled}
            onChange={(v) => patch({ enabled: v })}
          />
          <div className="grid sm:grid-cols-2 gap-4 pt-2">
            <Field label="Listen address" hint="Point your LLM clients here, e.g. 127.0.0.1:8011">
              <input className={inputCls} value={cfg.listen_address} onChange={(e) => patch({ listen_address: e.target.value })} />
            </Field>
            <Field label="Health-check interval (s)" hint="0 disables periodic checks.">
              <input type="number" min={0} className={inputCls} value={cfg.health_check_interval_seconds}
                onChange={(e) => patch({ health_check_interval_seconds: parseInt(e.target.value || '0', 10) })} />
            </Field>
            <Field label="Upstream timeout (s)">
              <input type="number" min={1} className={inputCls} value={cfg.upstream_timeout_seconds}
                onChange={(e) => patch({ upstream_timeout_seconds: parseInt(e.target.value || '0', 10) })} />
            </Field>
            <Field label="Max request body (bytes)">
              <input type="number" min={1024} className={inputCls} value={cfg.max_body_bytes}
                onChange={(e) => patch({ max_body_bytes: parseInt(e.target.value || '0', 10) })} />
            </Field>
          </div>
        </Card>

        {/* ── Backends ── */}
        <Card icon={Server} title="Backends" desc="Upstream model servers. Requests route by prefix (longest match wins; empty = default).">
          <div className="space-y-3">
            {cfg.backends.map((b, i) => (
              <div key={i} className="rounded-lg border border-border bg-background/50 p-3 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Backend {i + 1}</span>
                  <button onClick={() => removeBackend(i)} className="text-destructive hover:text-destructive/80 p-1" title="Remove backend">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
                <div className="grid sm:grid-cols-2 gap-3">
                  <Field label="Name"><input className={inputCls} value={b.name} placeholder="ollama" onChange={(e) => updateBackend(i, { name: e.target.value })} /></Field>
                  <Field label="Kind">
                    <select className={inputCls} value={b.kind} onChange={(e) => updateBackend(i, { kind: e.target.value })}>
                      {BACKEND_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
                    </select>
                  </Field>
                  <Field label="Upstream URL"><input className={inputCls} value={b.url} placeholder="http://127.0.0.1:11434" onChange={(e) => updateBackend(i, { url: e.target.value })} /></Field>
                  <Field label="Route prefix" hint='Empty = default route'><input className={inputCls} value={b.route_prefix} placeholder="/lmstudio" onChange={(e) => updateBackend(i, { route_prefix: e.target.value })} /></Field>
                  <Field label="Health path"><input className={inputCls} value={b.health_path} placeholder="/api/tags" onChange={(e) => updateBackend(i, { health_path: e.target.value })} /></Field>
                </div>
              </div>
            ))}
            {cfg.backends.length === 0 && (
              <div className="text-sm text-muted-foreground flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> No backends configured.</div>
            )}
            <button onClick={addBackend} className="text-sm text-primary hover:underline flex items-center gap-1">
              <Plus className="w-4 h-4" /> Add backend
            </button>
          </div>
        </Card>

        {/* ── Authentication ── */}
        <Card icon={KeyRound} title="Authentication" desc="API keys and optional HS256 JWT verification. Leave empty for observe-only mode.">
          <Field label="Static API keys" hint="Accepted as Authorization: Bearer <key> or X-API-Key. Existing keys are masked.">
            <div className="space-y-2">
              {cfg.auth_tokens.map((t, i) => (
                <div key={i} className="flex items-center gap-2">
                  <input className={`${inputCls} font-mono`} value={t} readOnly={t === MASK}
                    onChange={(e) => setCfg((c) => { if (!c) return c; const a = c.auth_tokens.slice(); a[i] = e.target.value; return { ...c, auth_tokens: a }; })} />
                  <button onClick={() => removeToken(i)} className="text-destructive hover:text-destructive/80 p-2" title="Remove key">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
              <div className="flex items-center gap-2">
                <input className={`${inputCls} font-mono`} placeholder="Add a new API key…" value={newToken}
                  onChange={(e) => setNewToken(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addToken(); } }} />
                <button onClick={addToken} className="px-3 py-2 rounded-lg border border-border text-sm flex items-center gap-1 hover:bg-accent">
                  <Plus className="w-4 h-4" /> Add
                </button>
              </div>
            </div>
          </Field>

          <div className="pt-2 border-t border-border">
            <ToggleRow label="Enable JWT (HS256)" hint="Accept signed JWTs in addition to static keys." checked={cfg.jwt.enabled} onChange={(v) => patchJwt({ enabled: v })} />
            {cfg.jwt.enabled && (
              <div className="grid sm:grid-cols-2 gap-3 pt-2">
                <Field label="Shared secret" hint="Stored masked once saved.">
                  <input className={`${inputCls} font-mono`} type="text" value={cfg.jwt.secret} readOnly={cfg.jwt.secret === MASK}
                    onChange={(e) => patchJwt({ secret: e.target.value })} placeholder="hmac secret" />
                </Field>
                <Field label="Issuer (iss)" hint="Empty = not checked"><input className={inputCls} value={cfg.jwt.issuer} onChange={(e) => patchJwt({ issuer: e.target.value })} /></Field>
                <Field label="Audience (aud)" hint="Empty = not checked"><input className={inputCls} value={cfg.jwt.audience} onChange={(e) => patchJwt({ audience: e.target.value })} /></Field>
              </div>
            )}
          </div>
        </Card>

        {/* ── Rate limits ── */}
        <Card icon={Gauge} title="Rate limiting" desc="Per-key sliding-window limits (keyed by authenticated subject, PID, or peer).">
          <ToggleRow label="Enable rate limiting" checked={cfg.rate_limits.enabled} onChange={(v) => patchRate({ enabled: v })} />
          <div className="grid sm:grid-cols-2 gap-4 pt-2">
            <Field label="Requests per minute">
              <input type="number" min={1} className={inputCls} value={cfg.rate_limits.requests_per_minute}
                onChange={(e) => patchRate({ requests_per_minute: parseInt(e.target.value || '0', 10) })} disabled={!cfg.rate_limits.enabled} />
            </Field>
            <Field label="Burst" hint="0 = same as requests/min">
              <input type="number" min={0} className={inputCls} value={cfg.rate_limits.burst}
                onChange={(e) => patchRate({ burst: parseInt(e.target.value || '0', 10) })} disabled={!cfg.rate_limits.enabled} />
            </Field>
          </div>
        </Card>

        {/* ── Monitoring ── */}
        <Card icon={Eye} title="Monitoring" desc="Content inspection and token tracking. Blocking is off by default (alert-only).">
          <ToggleRow label="Enable content inspection" hint="When off, the guard only authenticates / rate-limits / proxies." checked={cfg.monitoring.enabled} onChange={(v) => patchMonitoring({ enabled: v })} />
          <div className="pl-1 border-l-2 border-border ml-1 space-y-1 pt-1">
            <ToggleRow label="Detect prompt injection" checked={cfg.monitoring.detect_prompt_injection} onChange={(v) => patchMonitoring({ detect_prompt_injection: v })} disabled={!cfg.monitoring.enabled} />
            <ToggleRow label="Detect PII" hint="Emails, credit cards, SSNs, API keys…" checked={cfg.monitoring.detect_pii} onChange={(v) => patchMonitoring({ detect_pii: v })} disabled={!cfg.monitoring.enabled} />
            <ToggleRow label="Track token usage" checked={cfg.monitoring.track_tokens} onChange={(v) => patchMonitoring({ track_tokens: v })} disabled={!cfg.monitoring.enabled} />
            <ToggleRow label="Block on injection" hint="Reject (403) when a prompt-injection pattern matches." checked={cfg.monitoring.block_on_injection} onChange={(v) => patchMonitoring({ block_on_injection: v })} disabled={!cfg.monitoring.enabled} />
            <ToggleRow label="Block on PII" hint="Reject (403) requests containing PII." checked={cfg.monitoring.block_on_pii} onChange={(v) => patchMonitoring({ block_on_pii: v })} disabled={!cfg.monitoring.enabled} />
          </div>
          <div className="grid sm:grid-cols-2 gap-4 pt-2">
            <Field label="Max prompt characters retained" hint="Truncated in events for privacy.">
              <input type="number" min={0} className={inputCls} value={cfg.monitoring.max_prompt_chars}
                onChange={(e) => patchMonitoring({ max_prompt_chars: parseInt(e.target.value || '0', 10) })} disabled={!cfg.monitoring.enabled} />
            </Field>
          </div>
        </Card>

        {/* ── Process access control ── */}
        <Card
          icon={Fingerprint}
          title="Process access control"
          desc="Gate requests on which local process (or attributed AI agent) is calling. Patterns are case-insensitive substrings matched against the caller's name / exe / cmdline / agent."
        >
          <ToggleRow
            label="Enforce process access control"
            hint="When off, the guard records caller provenance on events but never blocks on it."
            checked={cfg.process_acl.enabled}
            onChange={(v) => patchAcl({ enabled: v })}
          />

          {/* Preset picker */}
          <div className="rounded-lg border border-border bg-background/50 p-3 space-y-2">
            <div className="flex items-center gap-2 text-sm font-medium text-foreground">
              <Wand2 className="w-4 h-4 text-primary" /> Start from a rule preset
            </div>
            <p className="text-xs text-muted-foreground">
              Apply a curated profile, then fine-tune the lists below. Applying a preset replaces the current rules.
            </p>
            <div className="grid sm:grid-cols-2 gap-2 pt-1">
              {LLM_GUARD_ACL_PRESETS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => applyPreset(p.id)}
                  title={p.detail}
                  className="text-left rounded-lg border border-border bg-card p-3 hover:border-primary/50 transition-colors"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-foreground">{p.name}</span>
                    <span
                      className={`text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded ${
                        p.kind === 'allowlist'
                          ? 'bg-emerald-500/15 text-emerald-400'
                          : p.kind === 'denylist'
                          ? 'bg-amber-500/15 text-amber-400'
                          : 'bg-muted text-muted-foreground'
                      }`}
                    >
                      {p.kind}
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">{p.description}</div>
                  {p.recommended && (
                    <div className="text-[10px] text-primary mt-1 font-medium">Recommended</div>
                  )}
                </button>
              ))}
            </div>
          </div>

          <div className="grid sm:grid-cols-2 gap-4 pt-2">
            <Field label="Default decision" hint="When no rule matches.">
              <select
                className={inputCls}
                value={cfg.process_acl.default}
                onChange={(e) => patchAcl({ default: e.target.value })}
                disabled={!cfg.process_acl.enabled}
              >
                <option value="deny">deny — allowlist (only listed callers pass)</option>
                <option value="allow">allow — denylist (block only listed callers)</option>
              </select>
            </Field>
            <div className="flex items-end">
              <ToggleRow
                label="Block unresolved callers"
                hint="Reject callers with no resolvable PID. Linux-only resolution today — leave off on macOS/Windows."
                checked={cfg.process_acl.block_unresolved}
                onChange={(v) => patchAcl({ block_unresolved: v })}
                disabled={!cfg.process_acl.enabled}
              />
            </div>
          </div>

          <div className="grid sm:grid-cols-2 gap-4 pt-1">
            <Field label="Allow patterns" hint="One per line. Caller passes if it matches ANY.">
              <textarea
                className={`${inputCls} font-mono min-h-[120px]`}
                value={cfg.process_acl.allow.join('\n')}
                onChange={(e) => patchAclList('allow', e.target.value)}
                placeholder={'claude-code\ncursor\n/usr/local/bin/ollama'}
                disabled={!cfg.process_acl.enabled}
              />
            </Field>
            <Field label="Deny patterns" hint="One per line. Rejected if it matches ANY (deny wins).">
              <textarea
                className={`${inputCls} font-mono min-h-[120px]`}
                value={cfg.process_acl.deny.join('\n')}
                onChange={(e) => patchAclList('deny', e.target.value)}
                placeholder={'curl\nwget\npython'}
                disabled={!cfg.process_acl.enabled}
              />
            </Field>
          </div>
        </Card>
      </fieldset>
    </div>
  );
}
