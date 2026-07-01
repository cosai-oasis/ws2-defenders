'use client';
import { useFetch } from '@/hooks/use-fetch';
import {
  Shield, AlertTriangle, Activity, Users, Brain, TrendingUp, RefreshCw, Zap, Cpu, Layers, Eye, Terminal, MessageSquare, Plug
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { getOpLabel, getOpIcon, getOpColor, AGENT_CATEGORIES, KNOWN_AGENTS } from '@/lib/aitf';

function CountUp({ target, duration = 1500 }: { target: number; duration?: number }) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (target <= 0) return;
    const start = Date.now();
    const timer = setInterval(() => {
      const elapsed = Date.now() - start;
      const progress = Math.min(elapsed / duration, 1);
      setCount(Math.floor(progress * target));
      if (progress >= 1) clearInterval(timer);
    }, 16);
    return () => clearInterval(timer);
  }, [target, duration]);
  return <span>{count}</span>;
}

function RiskBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    low: 'bg-emerald-500/15 text-emerald-400',
    medium: 'bg-yellow-500/15 text-yellow-400',
    high: 'bg-orange-500/15 text-orange-400',
    critical: 'bg-red-500/15 text-red-400',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${colors[level] ?? 'bg-muted text-muted-foreground'}`}>
      {level?.toUpperCase?.() ?? 'UNKNOWN'}
    </span>
  );
}

function AiOperationBadge({ aiOperation }: { aiOperation: string | null }) {
  if (!aiOperation) return null;
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-primary/10 ${getOpColor(aiOperation)}`}>
      {getOpIcon(aiOperation)} {getOpLabel(aiOperation)}
    </span>
  );
}

export function DashboardContent() {
  const { data: stats, isLoading: statsLoading } = useFetch('/api/stats', 5000);
  const { data: recentData } = useFetch('/api/events/recent?limit=10', 5000);
  const { data: alertData } = useFetch('/api/alerts?resolved=false', 5000);

  const statCards = [
    { label: 'Total Events', value: stats?.totalEvents ?? 0, icon: Activity, color: 'text-blue-400', bg: 'bg-blue-500/10' },
    { label: 'Security Findings', value: (stats?.eventsByClass ?? []).find((c: any) => c.classUid === 2004)?.count ?? 0, icon: Shield, color: 'text-red-400', bg: 'bg-red-500/10' },
    { label: 'Model Inferences', value: (stats?.eventsByOperation ?? []).find((o: any) => o.aiOperation === 'inference')?.count ?? 0, icon: Brain, color: 'text-blue-400', bg: 'bg-blue-500/10' },
    { label: 'Agent Sessions', value: (stats?.eventsByOperation ?? []).find((o: any) => o.aiOperation === 'agent_action')?.count ?? 0, icon: Cpu, color: 'text-purple-400', bg: 'bg-purple-500/10' },
    { label: 'Active Alerts', value: stats?.unresolvedAlerts ?? 0, icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
    { label: 'AI Providers', value: stats?.eventsByProvider?.length ?? 0, icon: Layers, color: 'text-cyan-400', bg: 'bg-cyan-500/10' },
  ];

  const recentEvents = recentData?.events ?? [];
  const unresolvedAlerts = alertData?.alerts ?? [];

  return (
    <div className="p-4 md:p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold tracking-tight">CoSAI Security Overview</h1>
          <p className="text-sm text-muted-foreground mt-1">CoSAI Telemetry Framework — AITF AI-Operation Monitoring</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-2 py-1 rounded bg-primary/10 text-primary text-[10px] font-mono">OCSF v1.1.0</span>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-500/10 text-emerald-400 text-xs font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Live
          </div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {statCards.map((card, i) => (
          <motion.div
            key={card.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="bg-card rounded-xl p-4 border border-border hover:border-primary/30 transition-all"
          >
            <div className={`w-9 h-9 rounded-lg ${card.bg} flex items-center justify-center mb-3`}>
              <card.icon className={`w-5 h-5 ${card.color}`} />
            </div>
            <p className="text-2xl font-bold font-mono">
              <CountUp target={card.value} />
            </p>
            <p className="text-xs text-muted-foreground mt-1">{card.label}</p>
          </motion.div>
        ))}
      </div>

      {/* OCSF Event Class Distribution */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="bg-card rounded-xl border border-border p-4"
      >
        <h2 className="font-semibold flex items-center gap-2 mb-4">
          <Eye className="w-4 h-4 text-primary" />
          AITF — AI Operations
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
          {(stats?.eventsByOperation ?? []).map((op: any) => {
            const maxCount = stats?.eventsByOperation?.[0]?.count ?? 1;
            return (
              <div key={op.aiOperation} className="bg-background/50 rounded-lg p-3 border border-border/50">
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="text-sm">{getOpIcon(op.aiOperation)}</span>
                  <span className={`text-xs font-mono font-bold ${getOpColor(op.aiOperation)}`}>{op.classUid}</span>
                </div>
                <p className="text-lg font-bold font-mono">{op.count}</p>
                <p className="text-[10px] text-muted-foreground leading-tight">{op.label ?? getOpLabel(op.aiOperation)}</p>
                <div className="h-1 bg-muted rounded-full overflow-hidden mt-2">
                  <div
                    className="h-full bg-primary/60 rounded-full"
                    style={{ width: `${(op.count / maxCount) * 100}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </motion.div>

      {/* Agent Coverage & Threat Landscape */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.25 }}
        className="bg-card rounded-xl border border-border p-4"
      >
        <h2 className="font-semibold flex items-center gap-2 mb-4">
          <Plug className="w-4 h-4 text-primary" />
          Agent Coverage — Monitored Agent Types
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {Object.entries(AGENT_CATEGORIES).map(([key, cat]) => {
            const agents = Object.values(KNOWN_AGENTS).filter(a => a.category === key);
            return (
              <div key={key} className="bg-background/50 rounded-lg p-3 border border-border/50">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-lg">{cat.icon}</span>
                  <span className={`text-sm font-semibold ${cat.color}`}>{cat.label}</span>
                  <span className="ml-auto text-xs font-mono text-muted-foreground">{agents.length}</span>
                </div>
                <p className="text-[10px] text-muted-foreground mb-2">{cat.description}</p>
                <div className="flex flex-wrap gap-1">
                  {agents.map(a => {
                    const riskColor = a.risk === 'high' ? 'bg-red-500/15 text-red-400' : a.risk === 'medium' ? 'bg-yellow-500/15 text-yellow-400' : 'bg-emerald-500/15 text-emerald-400';
                    return (
                      <span key={a.name} className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${riskColor}`}>
                        {a.name}
                      </span>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
        <div className="mt-3 flex items-center gap-4 text-[10px] text-muted-foreground">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-400" /> Low Risk</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-400" /> Medium Risk</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-400" /> High Risk</span>
          <span className="ml-auto font-mono">{Object.keys(KNOWN_AGENTS).length} agents monitored</span>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Events */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-card rounded-xl border border-border overflow-hidden"
        >
          <div className="flex items-center justify-between p-4 border-b border-border">
            <h2 className="font-semibold flex items-center gap-2">
              <Activity className="w-4 h-4 text-primary" />
              Recent Telemetry Events
            </h2>
            <RefreshCw className="w-3.5 h-3.5 text-muted-foreground animate-spin" style={{ animationDuration: '3s' }} />
          </div>
          <div className="divide-y divide-border max-h-[400px] overflow-y-auto">
            {(recentEvents ?? []).slice(0, 10).map((event: any, i: number) => (
              <div key={event?.id ?? i} className="px-4 py-3 hover:bg-accent/30 transition-colors">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <AiOperationBadge aiOperation={event?.aiOperation} />
                    <span className="font-mono text-xs font-medium text-foreground">{event?.message ? event.message.slice(0, 60) : event?.eventType ?? 'unknown'}</span>
                  </div>
                  <RiskBadge level={event?.riskLevel ?? 'low'} />
                </div>
                <div className="flex items-center gap-3 mt-1">
                  {event?.provider && <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 font-mono">{event.provider}</span>}
                  {event?.model && <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 font-mono">{event.model}</span>}
                  {event?.agentDetected && <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 font-mono">{event.agentDetected}</span>}
                  <span className="text-[10px] text-muted-foreground font-mono ml-auto">
                    {event?.timestamp ? new Date(event.timestamp).toLocaleString() : ''}
                  </span>
                </div>
              </div>
            ))}
            {(recentEvents?.length ?? 0) === 0 && (
              <div className="p-8 text-center text-muted-foreground text-sm">No recent events</div>
            )}
          </div>
        </motion.div>

        {/* Active Alerts */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-card rounded-xl border border-border overflow-hidden"
        >
          <div className="flex items-center justify-between p-4 border-b border-border">
            <h2 className="font-semibold flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              CoSAI Detection Alerts
            </h2>
            <span className="text-xs text-muted-foreground">{unresolvedAlerts?.length ?? 0} unresolved</span>
          </div>
          <div className="divide-y divide-border max-h-[400px] overflow-y-auto">
            {(unresolvedAlerts ?? []).slice(0, 8).map((alert: any, i: number) => {
              const severityColor: Record<string, string> = {
                low: 'border-l-emerald-400',
                medium: 'border-l-yellow-400',
                high: 'border-l-orange-400',
                critical: 'border-l-red-400',
              };
              return (
                <div key={alert?.id ?? i} className={`px-4 py-3 border-l-2 ${severityColor[alert?.severity] ?? 'border-l-muted'} hover:bg-accent/30 transition-colors`}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      {alert?.ruleId && <span className="text-[10px] font-mono font-bold text-orange-400">{alert.ruleId}</span>}
                      <span className="text-xs font-medium">{alert?.alertType ?? ''}</span>
                    </div>
                    <RiskBadge level={alert?.severity ?? 'low'} />
                  </div>
                  <p className="text-xs text-muted-foreground line-clamp-2">{alert?.description ?? ''}</p>
                  <div className="flex items-center gap-2 mt-1">
                    {alert?.owaspCategory && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 font-mono">{alert.owaspCategory}</span>}
                    <span className="text-[10px] text-muted-foreground font-mono ml-auto">
                      {alert?.timestamp ? new Date(alert.timestamp).toLocaleString() : ''}
                    </span>
                  </div>
                </div>
              );
            })}
            {(unresolvedAlerts?.length ?? 0) === 0 && (
              <div className="p-8 text-center text-muted-foreground text-sm">No active alerts</div>
            )}
          </div>
        </motion.div>
      </div>

      {/* Bottom section: Providers, Models, Agents */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* AI Providers */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-card rounded-xl border border-border p-4"
        >
          <h2 className="font-semibold flex items-center gap-2 mb-4">
            <Layers className="w-4 h-4 text-cyan-400" />
            AI Providers
          </h2>
          <div className="space-y-3">
            {(stats?.eventsByProvider ?? []).map((p: any, i: number) => {
              const maxCount = stats?.eventsByProvider?.[0]?.count ?? 1;
              const colors = ['from-blue-500 to-cyan-500', 'from-purple-500 to-pink-500', 'from-emerald-500 to-teal-500', 'from-orange-500 to-amber-500', 'from-indigo-500 to-violet-500'];
              return (
                <div key={p?.provider ?? i}>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="font-mono text-xs capitalize">{p?.provider ?? 'Unknown'}</span>
                    <span className="text-muted-foreground text-xs">{p?.count ?? 0}</span>
                  </div>
                  <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                    <div
                      className={`h-full bg-gradient-to-r ${colors[i % colors.length]} rounded-full transition-all duration-500`}
                      style={{ width: `${((p?.count ?? 0) / maxCount) * 100}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </motion.div>

        {/* Top Models */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.55 }}
          className="bg-card rounded-xl border border-border p-4"
        >
          <h2 className="font-semibold flex items-center gap-2 mb-4">
            <Brain className="w-4 h-4 text-blue-400" />
            Top AI Models
          </h2>
          <div className="space-y-3">
            {(stats?.eventsByModel ?? []).slice(0, 6).map((m: any, i: number) => {
              const maxCount = stats?.eventsByModel?.[0]?.count ?? 1;
              return (
                <div key={m?.model ?? i}>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="font-mono text-xs">{m?.model ?? 'Unknown'}</span>
                    <span className="text-muted-foreground text-xs">{m?.count ?? 0}</span>
                  </div>
                  <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-blue-500 to-purple-500 rounded-full transition-all duration-500"
                      style={{ width: `${((m?.count ?? 0) / maxCount) * 100}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </motion.div>

        {/* Top Agents */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="bg-card rounded-xl border border-border p-4"
        >
          <h2 className="font-semibold flex items-center gap-2 mb-4">
            <Users className="w-4 h-4 text-purple-400" />
            Top AI Agents
          </h2>
          <div className="space-y-3">
            {(stats?.topAgents ?? []).slice(0, 6).map((a: any, i: number) => {
              const maxCount = stats?.topAgents?.[0]?.count ?? 1;
              return (
                <div key={a?.agent ?? i}>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="font-mono text-xs">{a?.agent ?? 'Unknown'}</span>
                    <span className="text-muted-foreground text-xs">{a?.count ?? 0}</span>
                  </div>
                  <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-purple-500 to-pink-500 rounded-full transition-all duration-500"
                      style={{ width: `${((a?.count ?? 0) / maxCount) * 100}%` }}
                    />
                  </div>
                </div>
              );
            })}
            {(stats?.topAgents?.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground text-center py-4">No agents detected</p>
            )}
          </div>
        </motion.div>
      </div>
    </div>
  );
}
