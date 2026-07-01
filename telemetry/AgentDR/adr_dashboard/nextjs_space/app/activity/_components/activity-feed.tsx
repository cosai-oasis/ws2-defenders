'use client';
import { useFetch } from '@/hooks/use-fetch';
import { Activity, Pause, Play } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { getOpLabel, getOpIcon, getOpColor } from '@/lib/aitf';

const riskColors: Record<string, { dot: string; bg: string; text: string; border: string }> = {
  low: { dot: 'bg-emerald-400', bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-l-emerald-400' },
  medium: { dot: 'bg-yellow-400', bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-l-yellow-400' },
  high: { dot: 'bg-orange-400', bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-l-orange-400' },
  critical: { dot: 'bg-red-400', bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-l-red-400' },
};

export function ActivityFeed() {
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState('all');
  const [opFilter, setOpFilter] = useState<string | null>(null);
  const { data } = useFetch('/api/events/recent?limit=100', paused ? 0 : 5000);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  const allEvents = data?.events ?? [];
  let events = filter === 'all' ? allEvents : allEvents.filter((e: any) => e?.riskLevel === filter);
  if (opFilter !== null) events = events.filter((e: any) => e?.aiOperation === opFilter);

  useEffect(() => {
    if (autoScroll && scrollRef.current) scrollRef.current.scrollTop = 0;
  }, [events?.length, autoScroll]);

  // Unique AI operations in current events
  const operations = [...new Set(allEvents.map((e: any) => e?.aiOperation).filter(Boolean))] as string[];

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold tracking-tight flex items-center gap-2">
            <Activity className="w-7 h-7 text-primary" />
            Live Telemetry Feed
          </h1>
          <p className="text-sm text-muted-foreground mt-1">AITF AI-operation event stream • Auto-refresh 5s</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPaused(!paused)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              paused ? 'bg-yellow-500/15 text-yellow-400' : 'bg-emerald-500/15 text-emerald-400'
            }`}
          >
            {paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            {paused ? 'Paused' : 'Live'}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <div className="flex items-center gap-1 bg-card rounded-lg border border-border p-0.5">
          {['all', 'critical', 'high', 'medium', 'low'].map((level) => (
            <button
              key={level}
              onClick={() => setFilter(level)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                filter === level ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {level === 'all' ? 'All Risk' : level.charAt(0).toUpperCase() + level.slice(1)}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1 bg-card rounded-lg border border-border p-0.5 overflow-x-auto">
          <button
            onClick={() => setOpFilter(null)}
            className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
              opFilter === null ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            All Operations
          </button>
          {operations.sort().map((op) => (
            <button
              key={op}
              onClick={() => setOpFilter(opFilter === op ? null : op)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                opFilter === op ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {getOpIcon(op)} {getOpLabel(op)}
            </button>
          ))}
        </div>
      </div>

      <div ref={scrollRef} className="space-y-2 max-h-[calc(100vh-220px)] overflow-y-auto pr-1">
        <AnimatePresence mode="popLayout">
          {(events ?? []).map((event: any, i: number) => {
            const colors = riskColors[event?.riskLevel ?? 'low'] ?? riskColors.low;
            return (
              <motion.div
                key={event?.id ?? i}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.2 }}
                className={`bg-card rounded-lg border border-border border-l-2 ${colors.border} p-3 hover:bg-accent/30 transition-colors`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0 flex-1 flex-wrap">
                    <span className={`w-2 h-2 rounded-full ${colors.dot} flex-shrink-0`} />
                    {event?.aiOperation && (
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-primary/10 ${getOpColor(event.aiOperation)}`}>
                        {getOpIcon(event.aiOperation)} {getOpLabel(event.aiOperation)}
                      </span>
                    )}
                    <span className="font-mono text-xs font-semibold">
                      {event?.message ? event.message.slice(0, 70) : event?.eventType ?? 'unknown'}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${colors.bg} ${colors.text}`}>
                      {event?.riskLevel?.toUpperCase?.() ?? 'LOW'}
                    </span>
                  </div>
                  <span className="text-[10px] text-muted-foreground font-mono whitespace-nowrap">
                    {event?.timestamp ? new Date(event.timestamp).toLocaleTimeString() : ''}
                  </span>
                </div>
                <div className="flex items-center gap-2 mt-1.5 ml-4 flex-wrap">
                  {event?.provider && <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 font-mono">{event.provider}</span>}
                  {event?.model && <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 font-mono">{event.model}</span>}
                  {event?.agentDetected && <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 font-mono">🤖 {event.agentDetected}</span>}
                  {event?.toolName && <span className="text-[10px] px-1.5 py-0.5 rounded bg-teal-500/10 text-teal-400 font-mono">🔧 {event.toolName}</span>}
                  {event?.mcpServer && <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 font-mono">MCP: {event.mcpServer}</span>}
                  <span className="text-[10px] text-muted-foreground ml-auto">{event?.source ?? ''}</span>
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
        {(events?.length ?? 0) === 0 && (
          <div className="text-center text-muted-foreground py-16 text-sm">No events match the selected filters</div>
        )}
      </div>
    </div>
  );
}
