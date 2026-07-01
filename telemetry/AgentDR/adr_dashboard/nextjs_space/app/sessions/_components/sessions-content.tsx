'use client';
import { useState } from 'react';
import Link from 'next/link';
import { useFetch } from '@/hooks/use-fetch';
import {
  Activity, Cpu, Globe, Layers, Server, ShieldAlert, Clock, AlertTriangle, Users,
} from 'lucide-react';
import { getOpIcon } from '@/lib/aitf';

interface SessionRow {
  traceId: string;
  first: string;
  last: string;
  eventCount: number;
  maxSeverity: number;
  hosts: string[];
  users: string[];
  agents: string[];
  providers: string[];
  classes: number[];
  operations: string[];
  multiHost: boolean;
  sampleMessage: string | null;
}

const sevLabel = (n: number) => ['', 'low', 'low', 'medium', 'high', 'critical'][n] ?? 'unknown';
const sevColor = (n: number) => ({
  low: 'bg-emerald-500/15 text-emerald-400',
  medium: 'bg-yellow-500/15 text-yellow-400',
  high: 'bg-orange-500/15 text-orange-400',
  critical: 'bg-red-500/15 text-red-400',
}[sevLabel(n)] ?? 'bg-muted text-muted-foreground');

function shortTrace(t: string) { return t.length > 12 ? `${t.slice(0, 6)}…${t.slice(-4)}` : t; }
function ago(iso: string) {
  const d = Date.now() - new Date(iso).getTime();
  if (d < 60_000)       return `${Math.floor(d / 1000)}s ago`;
  if (d < 3600_000)     return `${Math.floor(d / 60_000)}m ago`;
  if (d < 86_400_000)   return `${Math.floor(d / 3_600_000)}h ago`;
  return `${Math.floor(d / 86_400_000)}d ago`;
}

export function SessionsContent() {
  const [minSeverity, setMinSeverity] = useState('low');
  const [onlyMultiHost, setOnlyMultiHost] = useState(false);
  const { data, isLoading } = useFetch(`/api/sessions?limit=100&minSeverity=${minSeverity}`, 10_000);
  const sessions: SessionRow[] = data?.sessions ?? [];
  const filtered = onlyMultiHost ? sessions.filter(s => s.multiHost) : sessions;

  return (
    <div className="p-4 md:p-6 space-y-6">
      <div className="flex items-end justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold tracking-tight">Sessions</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Trace-grouped agent runs with multi-host correlation and kill-chain replay.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="text-xs text-muted-foreground flex items-center gap-2">
            Min severity
            <select
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value)}
              className="bg-card border border-border rounded px-2 py-1 text-xs"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
          <label className="text-xs flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={onlyMultiHost}
              onChange={(e) => setOnlyMultiHost(e.target.checked)}
              className="accent-primary"
            />
            Multi-host only
          </label>
        </div>
      </div>

      <div className="grid gap-3">
        {isLoading && <div className="text-sm text-muted-foreground">Loading sessions…</div>}
        {!isLoading && filtered.length === 0 && (
          <div className="rounded-lg border border-dashed border-border p-8 text-center text-muted-foreground">
            No sessions matched. Try lowering the severity filter.
          </div>
        )}
        {filtered.map((s) => (
          <Link
            key={s.traceId}
            href={`/sessions/${s.traceId}`}
            className="rounded-lg border border-border bg-card hover:bg-muted/40 transition-colors p-4 flex flex-col gap-2"
          >
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-3">
                <code className="text-xs font-mono text-primary">{shortTrace(s.traceId)}</code>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${sevColor(s.maxSeverity)}`}>
                  {sevLabel(s.maxSeverity).toUpperCase()}
                </span>
                {s.multiHost && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-purple-500/15 text-purple-400 flex items-center gap-1">
                    <Globe className="w-3 h-3" /> multi-host
                  </span>
                )}
              </div>
              <div className="text-xs text-muted-foreground flex items-center gap-1">
                <Clock className="w-3 h-3" /> {ago(s.last)}
              </div>
            </div>
            <div className="text-sm">
              {s.sampleMessage ?? <span className="text-muted-foreground italic">no message</span>}
            </div>
            <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
              <span className="flex items-center gap-1"><Activity className="w-3 h-3" />{s.eventCount} events</span>
              <span className="flex items-center gap-1"><Server className="w-3 h-3" />{s.hosts.length} host{s.hosts.length === 1 ? '' : 's'}</span>
              <span className="flex items-center gap-1"><Users className="w-3 h-3" />{s.users.length || '—'} user</span>
              <span className="flex items-center gap-1"><Cpu className="w-3 h-3" />{s.agents.join(', ') || '—'}</span>
              <span className="flex items-center gap-1"><Layers className="w-3 h-3" />
                {(s.operations ?? []).map(op => getOpIcon(op)).join(' ')}
              </span>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
