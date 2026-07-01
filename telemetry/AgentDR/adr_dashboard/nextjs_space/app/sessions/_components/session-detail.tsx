'use client';
import Link from 'next/link';
import { useFetch } from '@/hooks/use-fetch';
import { ArrowLeft, Server, Users, Cpu, Globe, ShieldAlert, Activity, FileSearch } from 'lucide-react';
import { getOpLabel, getOpIcon } from '@/lib/aitf';

interface KillChainEvent {
  id: string;
  timestamp: string;
  eventType: string;
  classUid: number | null;
  aiOperation: string | null;
  riskLevel: string;
  hostName: string | null;
  userName: string | null;
  agentName: string | null;
  provider: string | null;
  model: string | null;
  toolName: string | null;
  mcpServer: string | null;
  message: string | null;
  details: string;
  traceId: string | null;
  spanId: string | null;
}

const riskBg: Record<string, string> = {
  low: 'border-emerald-500/40',
  medium: 'border-yellow-500/40',
  high: 'border-orange-500/40',
  critical: 'border-red-500/40',
};

const PHASE_ORDER = [
  'agent_launch', 'inference', 'tool_execution', 'mcp_call',
  'prompt_injection', 'data_access', 'privilege_change', 'compliance_drift', 'other'
];

const PHASE_LABEL: Record<string, string> = {
  agent_launch: 'Agent Launch',
  inference: 'Inference',
  tool_execution: 'Tool Execution',
  mcp_call: 'MCP Call',
  prompt_injection: 'Prompt Injection',
  data_access: 'Data Access',
  privilege_change: 'Privilege Change',
  compliance_drift: 'Compliance Drift',
  other: 'Other',
};

export function SessionDetail({ traceId }: { traceId: string }) {
  const { data, isLoading } = useFetch(`/api/sessions/${traceId}`, 0);

  if (isLoading) return <div className="p-6 text-sm text-muted-foreground">Loading…</div>;
  if (!data) return <div className="p-6 text-sm text-muted-foreground">No session found.</div>;

  const events: KillChainEvent[] = data.events ?? [];
  const alerts = data.alerts ?? [];
  const ueba = data.ueba ?? [];
  const phases: Record<string, number> = data.phases ?? {};
  const hosts: string[] = data.hosts ?? [];
  const users: string[] = data.users ?? [];
  const agents: string[] = data.agents ?? [];

  return (
    <div className="p-4 md:p-6 space-y-6">
      <div>
        <Link href="/sessions" className="text-xs text-muted-foreground hover:text-foreground inline-flex items-center gap-1 mb-2">
          <ArrowLeft className="w-3 h-3" /> Back to sessions
        </Link>
        <h1 className="text-2xl font-display font-bold tracking-tight">Session <code className="text-primary font-mono text-base">{traceId.slice(0, 12)}…</code></h1>
        <p className="text-sm text-muted-foreground mt-1">
          {events.length} event{events.length === 1 ? '' : 's'} · {alerts.length} alert{alerts.length === 1 ? '' : 's'} ·
          {hosts.length > 1 ? <span className="text-purple-400 font-medium"> {hosts.length} hosts</span> : <> 1 host</>}
        </p>
      </div>

      {/* Kill-chain phase strip */}
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="text-xs uppercase tracking-wider text-muted-foreground mb-3">Kill-chain phases</div>
        <div className="flex flex-wrap items-stretch gap-2">
          {PHASE_ORDER.filter(p => phases[p]).map((p) => (
            <div key={p} className="flex items-center gap-2 px-3 py-2 rounded bg-muted/40 border border-border">
              <ShieldAlert className="w-3 h-3 text-primary" />
              <span className="text-xs font-medium">{PHASE_LABEL[p]}</span>
              <span className="text-xs text-muted-foreground">×{phases[p]}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Cross-host summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground mb-2">
            <Server className="w-3 h-3" /> Hosts
          </div>
          <div className="text-sm font-mono space-y-1">
            {hosts.length === 0 && <span className="text-muted-foreground">—</span>}
            {hosts.map(h => <div key={h}>{h}</div>)}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground mb-2">
            <Users className="w-3 h-3" /> Users
          </div>
          <div className="text-sm font-mono space-y-1">
            {users.length === 0 && <span className="text-muted-foreground">—</span>}
            {users.map(u => <div key={u}>{u}</div>)}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground mb-2">
            <Cpu className="w-3 h-3" /> Agents
          </div>
          <div className="text-sm font-mono space-y-1">
            {agents.length === 0 && <span className="text-muted-foreground">—</span>}
            {agents.map(a => <div key={a}>{a}</div>)}
          </div>
        </div>
      </div>

      {/* UEBA outliers */}
      {ueba.length > 0 && (
        <div className="rounded-lg border border-orange-500/40 bg-orange-500/5 p-4">
          <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-orange-400 mb-3">
            <Activity className="w-3 h-3" /> UEBA outliers
          </div>
          <div className="space-y-1 text-sm">
            {ueba.slice(0, 6).map((u: any) => (
              <div key={u.id} className="flex items-center justify-between font-mono text-xs">
                <span>{u.agentName ?? '—'} / {u.userName ?? '—'} · {u.metric}</span>
                <span>observed <b>{u.observed.toFixed(1)}</b> · baseline μ={u.baselineMean.toFixed(1)} σ={u.baselineStdev.toFixed(1)} · <b className="text-orange-400">z={u.zScore.toFixed(2)}</b></span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Event timeline */}
      <div>
        <div className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Timeline</div>
        <ol className="space-y-2">
          {events.map((ev) => (
            <li key={ev.id} className={`rounded-lg border ${riskBg[ev.riskLevel] ?? 'border-border'} bg-card p-3`}>
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2 text-xs">
                  <span className="font-mono text-muted-foreground">{new Date(ev.timestamp).toLocaleString()}</span>
                  {ev.aiOperation && (
                    <span className="px-1.5 py-0.5 rounded bg-primary/10 text-primary font-mono text-[10px]">
                      {getOpIcon(ev.aiOperation)} {getOpLabel(ev.aiOperation)}
                      {ev.classUid ? <span className="ml-1 opacity-70">({ev.classUid})</span> : null}
                    </span>
                  )}
                  <span className="font-medium">{ev.eventType}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted">{ev.riskLevel}</span>
                </div>
                <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                  {ev.hostName && <span><Server className="w-3 h-3 inline" /> {ev.hostName}</span>}
                  {ev.userName && <span><Users className="w-3 h-3 inline" /> {ev.userName}</span>}
                  {ev.agentName && <span><Cpu className="w-3 h-3 inline" /> {ev.agentName}</span>}
                  {ev.provider && <span><Globe className="w-3 h-3 inline" /> {ev.provider}/{ev.model}</span>}
                  {ev.toolName && <span><FileSearch className="w-3 h-3 inline" /> {ev.toolName}</span>}
                </div>
              </div>
              {ev.message && <div className="mt-1 text-sm">{ev.message}</div>}
              <details className="mt-1">
                <summary className="text-[10px] text-muted-foreground cursor-pointer">details</summary>
                <pre className="text-[10px] mt-1 bg-muted/30 p-2 rounded overflow-x-auto whitespace-pre-wrap break-all">
                  {(() => { try { return JSON.stringify(JSON.parse(ev.details), null, 2); } catch { return ev.details; } })()}
                </pre>
              </details>
            </li>
          ))}
        </ol>
      </div>

      {alerts.length > 0 && (
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Alerts in this session</div>
          <ul className="space-y-2">
            {alerts.map((a: any) => (
              <li key={a.id} className="rounded-lg border border-red-500/40 bg-red-500/5 p-3 text-sm">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  <span className="font-medium">{a.alertType}</span>
                  <span className="px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 text-[10px]">{a.severity}</span>
                  {a.ruleId && <code className="font-mono text-[10px] text-muted-foreground">{a.ruleId}</code>}
                </div>
                <div className="text-xs text-muted-foreground mt-1">{a.description}</div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
