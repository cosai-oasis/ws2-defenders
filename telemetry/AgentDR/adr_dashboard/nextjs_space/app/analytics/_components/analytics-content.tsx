'use client';
import { useFetch } from '@/hooks/use-fetch';
import { BarChart3 } from 'lucide-react';
import dynamic from 'next/dynamic';
import { motion } from 'framer-motion';
import { getOpLabel, getOpIcon, getOpHex } from '@/lib/aitf';

const TimelineChart = dynamic(() => import('./timeline-chart'), { ssr: false, loading: () => <ChartSkeleton /> });
const TypeDistributionChart = dynamic(() => import('./type-distribution-chart'), { ssr: false, loading: () => <ChartSkeleton /> });
const RiskBreakdownChart = dynamic(() => import('./risk-breakdown-chart'), { ssr: false, loading: () => <ChartSkeleton /> });
const AgentChart = dynamic(() => import('./agent-chart'), { ssr: false, loading: () => <ChartSkeleton /> });
const HeatmapChart = dynamic(() => import('./heatmap-chart'), { ssr: false, loading: () => <ChartSkeleton height="300px" /> });

function ChartSkeleton({ height = '280px' }: { height?: string }) {
  return (
    <div className="bg-card rounded-xl border border-border p-4 animate-pulse" style={{ height }}>
      <div className="h-4 w-32 bg-muted rounded mb-4" />
      <div className="h-full bg-muted/50 rounded" />
    </div>
  );
}

export function AnalyticsContent() {
  const { data: stats, isLoading } = useFetch('/api/stats', 10000);

  return (
    <div className="p-4 md:p-6 space-y-6">
      <div>
        <h1 className="text-2xl md:text-3xl font-display font-bold tracking-tight flex items-center gap-2">
          <BarChart3 className="w-7 h-7 text-primary" />
          CoSAI Analytics
        </h1>
        <p className="text-sm text-muted-foreground mt-1">CoSAI Telemetry Framework — AITF AI-operation insights</p>
      </div>

      {/* AITF AI-Operation Distribution */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="bg-card rounded-xl border border-border p-4">
        <h2 className="font-semibold mb-4 text-sm">AITF AI-Operation Distribution</h2>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {(stats?.eventsByOperation ?? []).map((op: any) => {
            const color = op.hex ?? getOpHex(op.aiOperation);
            return (
              <div key={op.aiOperation} className="relative overflow-hidden rounded-lg border border-border p-3 bg-background/50">
                <div className="absolute bottom-0 left-0 right-0 h-1" style={{ backgroundColor: color, opacity: 0.6 }} />
                <div className="flex items-center gap-1.5 mb-2">
                  <span className="text-base">{getOpIcon(op.aiOperation)}</span>
                  <span className="font-mono text-[10px] font-bold" style={{ color }}>{op.classUid}</span>
                </div>
                <p className="text-xl font-bold font-mono">{op.count}</p>
                <p className="text-[10px] text-muted-foreground leading-tight mt-0.5">{op.label ?? getOpLabel(op.aiOperation)}</p>
              </div>
            );
          })}
        </div>
      </motion.div>

      {/* AI Provider & Model Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="bg-card rounded-xl border border-border p-4">
          <h2 className="font-semibold mb-4 text-sm">AI Provider Distribution</h2>
          <div className="space-y-3">
            {(stats?.eventsByProvider ?? []).map((p: any, i: number) => {
              const maxCount = stats?.eventsByProvider?.[0]?.count ?? 1;
              const colors = ['#60a5fa', '#c084fc', '#4ade80', '#fb923c', '#f87171', '#22d3ee'];
              return (
                <div key={p.provider}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-medium capitalize">{p.provider}</span>
                    <span className="text-xs text-muted-foreground">{p.count}</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${(p.count / maxCount) * 100}%`, backgroundColor: colors[i % colors.length] }} />
                  </div>
                </div>
              );
            })}
          </div>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-card rounded-xl border border-border p-4">
          <h2 className="font-semibold mb-4 text-sm">Top AI Models</h2>
          <div className="space-y-3">
            {(stats?.eventsByModel ?? []).map((m: any, i: number) => {
              const maxCount = stats?.eventsByModel?.[0]?.count ?? 1;
              return (
                <div key={m.model}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs">{m.model}</span>
                    <span className="text-xs text-muted-foreground">{m.count}</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-blue-500 to-purple-500 rounded-full" style={{ width: `${(m.count / maxCount) * 100}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </motion.div>
      </div>

      {/* Timeline */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }} className="bg-card rounded-xl border border-border p-4">
        <h2 className="font-semibold mb-4 text-sm">Activity Timeline (by Risk Level)</h2>
        <div style={{ height: '300px' }}>
          <TimelineChart data={stats?.timeline ?? []} />
        </div>
      </motion.div>

      {/* Distribution + Risk */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-card rounded-xl border border-border p-4">
          <h2 className="font-semibold mb-4 text-sm">Event Type Distribution</h2>
          <div style={{ height: '300px' }}>
            <TypeDistributionChart data={stats?.eventsByType ?? []} />
          </div>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="bg-card rounded-xl border border-border p-4">
          <h2 className="font-semibold mb-4 text-sm">Risk Level Breakdown</h2>
          <div style={{ height: '300px' }}>
            <RiskBreakdownChart data={stats?.eventsByRisk ?? []} />
          </div>
        </motion.div>
      </div>

      {/* Agent + Detection Rules */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="bg-card rounded-xl border border-border p-4">
          <h2 className="font-semibold mb-4 text-sm">Top Detected AI Agents</h2>
          <div style={{ height: '300px' }}>
            <AgentChart data={stats?.topAgents ?? []} />
          </div>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }} className="bg-card rounded-xl border border-border p-4">
          <h2 className="font-semibold mb-4 text-sm">CoSAI Detection Rules Triggered</h2>
          <div className="space-y-3">
            {(stats?.alertsByRule ?? []).map((r: any, i: number) => {
              const maxCount = stats?.alertsByRule?.[0]?.count ?? 1;
              return (
                <div key={r.ruleId}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-orange-400">{r.ruleId}</span>
                    <span className="text-xs text-muted-foreground">{r.count} alerts</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-orange-500 to-red-500 rounded-full" style={{ width: `${(r.count / maxCount) * 100}%` }} />
                  </div>
                </div>
              );
            })}
            {(stats?.alertsByRule?.length ?? 0) === 0 && (
              <p className="text-sm text-muted-foreground text-center py-8">No detection rules triggered</p>
            )}
          </div>
        </motion.div>
      </div>

      {/* Heatmap */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="bg-card rounded-xl border border-border p-4">
        <h2 className="font-semibold mb-4 text-sm">Activity Heatmap (Hour of Day)</h2>
        <div style={{ height: '300px' }}>
          <HeatmapChart data={stats?.heatmapData ?? {}} />
        </div>
      </motion.div>
    </div>
  );
}
