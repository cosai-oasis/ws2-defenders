'use client';
import { useState } from 'react';
import { useFetch } from '@/hooks/use-fetch';
import { Activity, Brain, Loader2, RefreshCw, Server, Users, Cpu } from 'lucide-react';

const METRIC_LABELS: Record<string, string> = {
  tokens_per_hour:        'Tokens / hour',
  files_touched_per_hour: 'Files touched / hour',
  mcp_tool_diversity:     'MCP tool diversity',
  offhours_share:         'Off-hours share',
  api_call_rate:          'API call rate (inference / hr)',
};

interface Baseline {
  id: string;
  hostId: string | null;
  host: { hostname: string } | null;
  userName: string | null;
  agentName: string | null;
  metric: string;
  windowDays: number;
  sampleCount: number;
  mean: number;
  stdev: number;
  p50: number;
  p95: number;
  p99: number;
  lastValue: number;
  computedAt: string;
}

export function UebaContent() {
  const [metric, setMetric] = useState('tokens_per_hour');
  const [busy, setBusy] = useState(false);
  const { data, mutate, isLoading } = useFetch(`/api/baselines?metric=${metric}`, 30_000);
  const baselines: Baseline[] = data?.baselines ?? [];

  async function recompute() {
    setBusy(true);
    try {
      await fetch('/api/baselines/recompute', { method: 'POST', body: JSON.stringify({ windowDays: 14 }) });
      await mutate();
    } finally {
      setBusy(false);
    }
  }

  // Stable color spectrum for z-score severity.
  const zColor = (z: number) => {
    if (z < 1.5)  return 'text-emerald-400';
    if (z < 2.5)  return 'text-yellow-400';
    if (z < 3.5)  return 'text-orange-400';
    return 'text-red-400';
  };

  return (
    <div className="p-4 md:p-6 space-y-6">
      <div className="flex items-end justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold tracking-tight flex items-center gap-2">
            <Brain className="w-6 h-6 text-primary" />
            Per-agent UEBA baselines
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Rolling per-(host, user, agent) baselines. Each event is scored
            against the matching baseline; events with high z-scores surface
            in the Sessions view.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={metric}
            onChange={(e) => setMetric(e.target.value)}
            className="bg-card border border-border rounded px-2 py-1 text-xs"
          >
            {Object.entries(METRIC_LABELS).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </select>
          <button
            onClick={recompute}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-xs font-medium flex items-center gap-1 disabled:opacity-50"
          >
            {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            Recompute (last 14 days)
          </button>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="text-left p-3"><Server className="w-3 h-3 inline" /> Host</th>
              <th className="text-left p-3"><Users className="w-3 h-3 inline" /> User</th>
              <th className="text-left p-3"><Cpu className="w-3 h-3 inline" /> Agent</th>
              <th className="text-right p-3">n</th>
              <th className="text-right p-3">μ</th>
              <th className="text-right p-3">σ</th>
              <th className="text-right p-3">p50</th>
              <th className="text-right p-3">p95</th>
              <th className="text-right p-3">p99</th>
              <th className="text-right p-3">Computed</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={10} className="p-6 text-center text-muted-foreground">Loading baselines…</td></tr>
            )}
            {!isLoading && baselines.length === 0 && (
              <tr><td colSpan={10} className="p-6 text-center text-muted-foreground">
                No baselines for this metric yet — click <b>Recompute</b> after ingesting some events.
              </td></tr>
            )}
            {baselines.map((b) => (
              <tr key={b.id} className="border-t border-border hover:bg-muted/30">
                <td className="p-3 font-mono text-xs">{b.host?.hostname ?? <span className="text-muted-foreground">—</span>}</td>
                <td className="p-3 font-mono text-xs">{b.userName ?? <span className="text-muted-foreground">—</span>}</td>
                <td className="p-3 font-mono text-xs">{b.agentName ?? <span className="text-muted-foreground">—</span>}</td>
                <td className="p-3 text-right font-mono text-xs">{b.sampleCount}</td>
                <td className="p-3 text-right font-mono text-xs">{b.mean.toFixed(1)}</td>
                <td className="p-3 text-right font-mono text-xs">{b.stdev.toFixed(1)}</td>
                <td className="p-3 text-right font-mono text-xs">{b.p50.toFixed(1)}</td>
                <td className="p-3 text-right font-mono text-xs">{b.p95.toFixed(1)}</td>
                <td className="p-3 text-right font-mono text-xs">{b.p99.toFixed(1)}</td>
                <td className="p-3 text-right text-xs text-muted-foreground">
                  {new Date(b.computedAt).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="rounded-lg border border-dashed border-border p-4 text-xs text-muted-foreground">
        <Activity className="w-3 h-3 inline mr-1" />
        Metric definitions are in <code className="font-mono">lib/baselines.ts</code>.
        Baselines are computed from indexed Event columns
        (<code>hostName</code> / <code>userName</code> / <code>agentName</code>, populated
        by <code>/api/sync</code>) over a configurable rolling window.
      </div>
    </div>
  );
}
