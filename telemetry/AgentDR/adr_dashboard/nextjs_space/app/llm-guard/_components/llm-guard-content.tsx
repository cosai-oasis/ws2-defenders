'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useFetch } from '@/hooks/use-fetch';
import { motion } from 'framer-motion';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid,
} from 'recharts';
import {
  ShieldHalf, Server, Settings, RefreshCw, Loader2, CheckCircle2, XCircle,
  AlertTriangle, Ban, Gauge, Coins, Activity, ShieldAlert, Eye, Users, Clock,
} from 'lucide-react';

const HOUR_OPTIONS = [
  { label: '1h', value: 1 },
  { label: '24h', value: 24 },
  { label: '7d', value: 168 },
];

// event-type → label/icon/color
const FINDING_META: Record<string, { label: string; icon: any; color: string }> = {
  llm_guard_finding:        { label: 'Content finding',  icon: ShieldAlert, color: 'text-red-400' },
  llm_guard_auth_denied:    { label: 'Auth denied',      icon: Ban,         color: 'text-orange-400' },
  llm_guard_rate_limited:   { label: 'Rate limited',     icon: Gauge,       color: 'text-yellow-400' },
  llm_guard_no_route:       { label: 'No route',         icon: AlertTriangle, color: 'text-amber-400' },
  llm_guard_upstream_error: { label: 'Upstream error',   icon: XCircle,     color: 'text-rose-400' },
};

function fmtNum(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

function timeAgo(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function StatCard({ icon: Icon, label, value, sub, tone = 'default' }: { icon: any; label: string; value: string | number; sub?: string; tone?: 'default' | 'danger' | 'warn' | 'good' }) {
  const toneCls = {
    default: 'text-primary bg-primary/10',
    danger: 'text-red-400 bg-red-500/10',
    warn: 'text-yellow-400 bg-yellow-500/10',
    good: 'text-emerald-400 bg-emerald-500/10',
  }[tone];
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl border border-border bg-card p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">{label}</span>
        <div className={`rounded-lg p-1.5 ${toneCls}`}><Icon className="w-4 h-4" /></div>
      </div>
      <div className="mt-2 text-2xl font-bold tracking-tight">{value}</div>
      {sub && <div className="text-xs text-muted-foreground mt-0.5">{sub}</div>}
    </motion.div>
  );
}

export function LlmGuardContent() {
  const [hours, setHours] = useState(24);
  const { data: health, mutate: mutateHealth, isLoading: healthLoading } = useFetch<any>('/api/llm-guard/health', 15_000);
  const { data: findings, mutate: mutateFindings, isLoading: findingsLoading } = useFetch<any>(`/api/llm-guard/findings?hours=${hours}`, 15_000);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = async () => {
    setRefreshing(true);
    try { await Promise.all([mutateHealth(), mutateFindings()]); }
    finally { setRefreshing(false); }
  };

  const summary = health?.summary ?? { total: 0, healthy: 0, unhealthy: 0 };
  const backends = health?.backends ?? [];
  const counts = findings?.counts ?? {};
  const tokens = findings?.tokens ?? { prompt: 0, completion: 0, total: 0, byProvider: {} };
  const trend = findings?.trend ?? [];
  const sessions = findings?.sessions ?? [];
  const findingList = findings?.findings ?? [];

  return (
    <div className="p-4 md:p-6 space-y-6">
      {/* Header */}
      <div className="flex items-end justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold tracking-tight flex items-center gap-2">
            <ShieldHalf className="w-6 h-6 text-primary" />
            LLM Guard
          </h1>
          <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
            Reverse-proxy protection for your local LLM backends — health, security findings,
            token usage and rate-limit activity from the agent&apos;s{' '}
            <code className="px-1 rounded bg-muted text-xs">llm-guard</code> telemetry.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-border overflow-hidden">
            {HOUR_OPTIONS.map((o) => (
              <button key={o.value} onClick={() => setHours(o.value)}
                className={`px-3 py-1.5 text-xs font-medium ${hours === o.value ? 'bg-primary text-primary-foreground' : 'hover:bg-accent'}`}>
                {o.label}
              </button>
            ))}
          </div>
          <button onClick={refresh} disabled={refreshing} className="px-3 py-1.5 rounded-lg border border-border text-xs font-medium flex items-center gap-1 hover:bg-accent disabled:opacity-50">
            {refreshing ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />} Refresh
          </button>
          <Link href="/settings/llm-guard" className="px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs font-medium flex items-center gap-1">
            <Settings className="w-3 h-3" /> Configure
          </Link>
        </div>
      </div>

      {/* degraded / disabled banners */}
      {health && !health.enabled && (
        <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
          <AlertTriangle className="w-4 h-4" /> LLM Guard is currently <strong>disabled</strong> in the configuration.{' '}
          <Link href="/settings/llm-guard" className="underline">Enable it in settings.</Link>
        </div>
      )}
      {findings?.degraded && (
        <div className="flex items-center gap-2 rounded-lg border border-border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
          <AlertTriangle className="w-4 h-4" /> Telemetry store unavailable — showing empty statistics.
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard icon={Server} label="Backends healthy" value={`${summary.healthy}/${summary.total}`} tone={summary.unhealthy > 0 ? 'warn' : 'good'} />
        <StatCard icon={Activity} label="Requests" value={fmtNum(counts.requests ?? 0)} sub={`last ${hours}h`} />
        <StatCard icon={Ban} label="Blocked" value={fmtNum(counts.blocked ?? 0)} tone={(counts.blocked ?? 0) > 0 ? 'danger' : 'default'} />
        <StatCard icon={Gauge} label="Rate limited" value={fmtNum(counts.rateLimited ?? 0)} tone={(counts.rateLimited ?? 0) > 0 ? 'warn' : 'default'} />
        <StatCard icon={ShieldAlert} label="Injection / PII" value={`${counts.injection ?? 0} / ${counts.pii ?? 0}`} tone={(counts.injection ?? 0) + (counts.pii ?? 0) > 0 ? 'danger' : 'default'} />
        <StatCard icon={Coins} label="Tokens" value={fmtNum(tokens.total ?? 0)} sub={`${fmtNum(tokens.prompt)} in / ${fmtNum(tokens.completion)} out`} />
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Backend health */}
        <section className="rounded-xl border border-border bg-card p-5 lg:col-span-1">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-base font-semibold flex items-center gap-2"><Server className="w-4 h-4 text-primary" /> Backend health</h2>
            {healthLoading && <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />}
          </div>
          <div className="space-y-2">
            {backends.length === 0 && <div className="text-sm text-muted-foreground">No backends configured.</div>}
            {backends.map((b: any) => {
              const healthy = b.status === 'healthy';
              return (
                <div key={b.name} className="flex items-center justify-between rounded-lg border border-border bg-background/50 px-3 py-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      {healthy ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                      <span className="text-sm font-medium truncate">{b.name}</span>
                      <span className="text-[10px] uppercase tracking-wide rounded bg-muted px-1.5 py-0.5 text-muted-foreground">{b.kind}</span>
                    </div>
                    <div className="text-xs text-muted-foreground truncate mt-0.5">{b.url}{b.route_prefix ? ` · ${b.route_prefix}` : ''}</div>
                  </div>
                  <div className="text-right shrink-0 ml-2">
                    <div className={`text-xs font-medium ${healthy ? 'text-emerald-400' : 'text-red-400'}`}>{healthy ? 'Healthy' : 'Down'}</div>
                    <div className="text-[11px] text-muted-foreground">{b.latencyMs != null ? `${b.latencyMs}ms` : (b.detail ?? '—')}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Token usage trend */}
        <section className="rounded-xl border border-border bg-card p-5 lg:col-span-2">
          <h2 className="text-base font-semibold flex items-center gap-2 mb-3"><Coins className="w-4 h-4 text-primary" /> Token usage trend</h2>
          <div className="h-64">
            {trend.length === 0 ? (
              <div className="h-full flex items-center justify-center text-sm text-muted-foreground">No token activity in this window.</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trend} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                  <defs>
                    <linearGradient id="tokGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#A19AD3" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#A19AD3" stopOpacity={0.05} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
                  <XAxis dataKey="hour" tickFormatter={(h) => new Date(h).toLocaleTimeString([], { hour: '2-digit' })} tick={{ fontSize: 10 }} tickLine={false} />
                  <YAxis tick={{ fontSize: 10 }} tickLine={false} tickFormatter={(v) => fmtNum(v)} width={40} />
                  <Tooltip
                    contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 8, fontSize: 12 }}
                    labelFormatter={(h) => new Date(h as string).toLocaleString()}
                    formatter={(v: any, name: any) => [fmtNum(Number(v)), name === 'tokens' ? 'Tokens' : 'Requests']}
                  />
                  <Area type="monotone" dataKey="tokens" stroke="#A19AD3" fill="url(#tokGrad)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </section>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Recent findings */}
        <section className="rounded-xl border border-border bg-card p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-base font-semibold flex items-center gap-2"><Eye className="w-4 h-4 text-primary" /> Recent security findings</h2>
            {findingsLoading && <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />}
          </div>
          <div className="space-y-2 max-h-[28rem] overflow-y-auto">
            {findingList.length === 0 && <div className="text-sm text-muted-foreground py-6 text-center">No findings in the last {hours}h. 🎉</div>}
            {findingList.map((f: any) => {
              const meta = FINDING_META[f.eventType] ?? { label: f.eventType, icon: AlertTriangle, color: 'text-muted-foreground' };
              const Icon = meta.icon;
              const labels = [
                ...(f.securityFinding?.injections ?? []),
                ...(f.securityFinding?.pii ?? []),
              ];
              return (
                <div key={f.id} className="flex items-start gap-3 rounded-lg border border-border bg-background/50 px-3 py-2">
                  <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${meta.color}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium">{meta.label}</span>
                      {f.provider && <span className="text-[10px] uppercase rounded bg-muted px-1.5 py-0.5 text-muted-foreground">{f.provider}</span>}
                      {f.securityFinding?.blocked && <span className="text-[10px] uppercase rounded bg-red-500/15 text-red-400 px-1.5 py-0.5">blocked</span>}
                    </div>
                    <div className="text-xs text-muted-foreground truncate mt-0.5">{f.message ?? '—'}</div>
                    {labels.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {labels.map((l: string, i: number) => (
                          <span key={i} className="text-[10px] rounded bg-red-500/10 text-red-400 px-1.5 py-0.5">{l}</span>
                        ))}
                      </div>
                    )}
                    <div className="text-[11px] text-muted-foreground mt-1 flex items-center gap-2">
                      <Clock className="w-3 h-3" /> {timeAgo(f.timestamp)}
                      {f.agentName && <span>· {f.agentName}</span>}
                      {f.host && <span>· {f.host}</span>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Active sessions / rate-limit status */}
        <section className="rounded-xl border border-border bg-card p-5 lg:col-span-1">
          <h2 className="text-base font-semibold flex items-center gap-2 mb-3"><Users className="w-4 h-4 text-primary" /> Active sessions</h2>
          <div className="space-y-2 max-h-[28rem] overflow-y-auto">
            {sessions.length === 0 && <div className="text-sm text-muted-foreground">No active callers in this window.</div>}
            {sessions.map((s: any, i: number) => (
              <div key={i} className="flex items-center justify-between rounded-lg border border-border bg-background/50 px-3 py-2">
                <div className="min-w-0">
                  <div className="text-sm font-medium truncate">{s.subject}</div>
                  {s.agentName && <div className="text-[11px] text-muted-foreground truncate">{s.agentName}</div>}
                </div>
                <div className="text-right shrink-0 ml-2">
                  <div className="text-sm font-semibold">{fmtNum(s.requests)}</div>
                  <div className="text-[11px] text-muted-foreground">{timeAgo(s.lastSeen)}</div>
                </div>
              </div>
            ))}
          </div>
          {health?.enabled && (
            <div className="mt-3 pt-3 border-t border-border text-xs text-muted-foreground">
              Listening on <code className="px-1 rounded bg-muted">{health.listenAddress}</code>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
