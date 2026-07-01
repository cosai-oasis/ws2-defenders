'use client';
import { useFetch } from '@/hooks/use-fetch';
import { useState, useCallback } from 'react';
import { ScrollText, Search, ChevronLeft, ChevronRight, ChevronDown, X } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';
import { getOpLabel, getOpIcon, getOpColor, AI_OPERATIONS } from '@/lib/aitf';

const riskColors: Record<string, string> = {
  low: 'bg-emerald-500/15 text-emerald-400',
  medium: 'bg-yellow-500/15 text-yellow-400',
  high: 'bg-orange-500/15 text-orange-400',
  critical: 'bg-red-500/15 text-red-400',
};

export function LogViewer() {
  const [search, setSearch] = useState('');
  const [eventType, setEventType] = useState('');
  const [riskLevel, setRiskLevel] = useState('');
  const [source, setSource] = useState('');
  const [agent, setAgent] = useState('');
  const [aiOperation, setAiOperation] = useState('');
  const [provider, setProvider] = useState('');
  const [page, setPage] = useState(1);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const limit = 25;

  const buildUrl = useCallback(() => {
    const params = new URLSearchParams();
    params.set('page', String(page));
    params.set('limit', String(limit));
    if (search) params.set('search', search);
    if (eventType) params.set('eventType', eventType);
    if (riskLevel) params.set('riskLevel', riskLevel);
    if (source) params.set('source', source);
    if (agent) params.set('agent', agent);
    if (aiOperation) params.set('aiOperation', aiOperation);
    if (provider) params.set('provider', provider);
    return `/api/events?${params.toString()}`;
  }, [search, eventType, riskLevel, source, agent, aiOperation, provider, page]);

  const { data, isLoading } = useFetch(buildUrl());
  const { data: statsData } = useFetch('/api/stats');

  const events = data?.events ?? [];
  const totalPages = data?.totalPages ?? 1;
  const total = data?.total ?? 0;

  const eventTypes = (statsData?.eventsByType ?? []).map((e: any) => e?.type).filter(Boolean);
  const sources = (statsData?.eventsBySource ?? []).map((e: any) => e?.source).filter(Boolean);
  const agents = statsData?.uniqueAgents ?? [];
  const providers = (statsData?.eventsByProvider ?? []).map((e: any) => e?.provider).filter(Boolean);

  const clearFilters = () => {
    setSearch(''); setEventType(''); setRiskLevel(''); setSource(''); setAgent(''); setAiOperation(''); setProvider(''); setPage(1);
  };

  const hasFilters = search || eventType || riskLevel || source || agent || aiOperation || provider;

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl md:text-3xl font-display font-bold tracking-tight flex items-center gap-2">
            <ScrollText className="w-7 h-7 text-primary" />
            Event Log Explorer
          </h1>
          <p className="text-sm text-muted-foreground mt-1">AITF AI-operation telemetry events • {total} total</p>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-card rounded-xl border border-border p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Search className="w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search events, models, providers..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="h-8 text-sm"
          />
          {hasFilters && (
            <Button variant="ghost" size="sm" onClick={clearFilters} className="h-8 text-xs">
              <X className="w-3.5 h-3.5 mr-1" /> Clear
            </Button>
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <select value={aiOperation} onChange={(e) => { setAiOperation(e.target.value); setPage(1); }} className="h-8 px-2 rounded-md border border-border bg-background text-xs">
            <option value="">All AI Operations</option>
            {Object.entries(AI_OPERATIONS).map(([op, info]) => (
              <option key={op} value={op}>{info.icon} {info.label}</option>
            ))}
          </select>
          <select value={provider} onChange={(e) => { setProvider(e.target.value); setPage(1); }} className="h-8 px-2 rounded-md border border-border bg-background text-xs">
            <option value="">All Providers</option>
            {providers.map((p: string) => <option key={p} value={p}>{p}</option>)}
          </select>
          <select value={riskLevel} onChange={(e) => { setRiskLevel(e.target.value); setPage(1); }} className="h-8 px-2 rounded-md border border-border bg-background text-xs">
            <option value="">All Risk Levels</option>
            {['low', 'medium', 'high', 'critical'].map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
          <select value={eventType} onChange={(e) => { setEventType(e.target.value); setPage(1); }} className="h-8 px-2 rounded-md border border-border bg-background text-xs">
            <option value="">All Event Types</option>
            {eventTypes.map((t: string) => <option key={t} value={t}>{t}</option>)}
          </select>
          <select value={agent} onChange={(e) => { setAgent(e.target.value); setPage(1); }} className="h-8 px-2 rounded-md border border-border bg-background text-xs">
            <option value="">All Agents</option>
            {agents.map((a: string) => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-card rounded-xl border border-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground">Time</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground">AI Operation</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground">Event</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground">Risk</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground">Provider / Model</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground">Agent</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {events.map((event: any) => (
                <>
                  <tr
                    key={event.id}
                    className="hover:bg-accent/30 cursor-pointer transition-colors"
                    onClick={() => setExpandedId(expandedId === event.id ? null : event.id)}
                  >
                    <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(event.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5">
                      {event.aiOperation ? (
                        <span className={`text-xs font-mono font-bold ${getOpColor(event.aiOperation)}`}>
                          {getOpIcon(event.aiOperation)} {getOpLabel(event.aiOperation)}
                          {event.classUid ? <span className="ml-1 text-[10px] text-muted-foreground">({event.classUid})</span> : null}
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <p className="text-xs font-medium truncate max-w-[280px]">{event.message || event.eventType}</p>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${riskColors[event.riskLevel] ?? ''}`}>
                        {event.riskLevel?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1">
                        {event.provider && <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 font-mono">{event.provider}</span>}
                        {event.model && <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 font-mono">{event.model}</span>}
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      {event.agentDetected && <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 font-mono">{event.agentDetected}</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform ${expandedId === event.id ? 'rotate-180' : ''}`} />
                    </td>
                  </tr>
                  {expandedId === event.id && (
                    <tr key={`${event.id}-detail`}>
                      <td colSpan={7} className="px-4 py-3 bg-muted/20">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                          <div>
                            <p className="font-semibold text-muted-foreground mb-1">Event Details</p>
                            <pre className="bg-background rounded p-2 overflow-auto max-h-[200px] text-[11px] font-mono">
                              {JSON.stringify(JSON.parse(event.details || '{}'), null, 2)}
                            </pre>
                          </div>
                          <div className="space-y-2">
                            {event.tokenUsage && (
                              <div>
                                <p className="font-semibold text-muted-foreground mb-1">Token Usage</p>
                                <pre className="bg-background rounded p-2 text-[11px] font-mono">
                                  {JSON.stringify(JSON.parse(event.tokenUsage), null, 2)}
                                </pre>
                              </div>
                            )}
                            {event.costInfo && (
                              <div>
                                <p className="font-semibold text-muted-foreground mb-1">Cost</p>
                                <pre className="bg-background rounded p-2 text-[11px] font-mono">
                                  {JSON.stringify(JSON.parse(event.costInfo), null, 2)}
                                </pre>
                              </div>
                            )}
                            {event.securityFinding && (
                              <div>
                                <p className="font-semibold text-red-400 mb-1">🛡️ Security Finding</p>
                                <pre className="bg-red-500/5 border border-red-500/20 rounded p-2 text-[11px] font-mono">
                                  {JSON.stringify(JSON.parse(event.securityFinding), null, 2)}
                                </pre>
                              </div>
                            )}
                            {event.compliance && (
                              <div>
                                <p className="font-semibold text-muted-foreground mb-1">Compliance</p>
                                <pre className="bg-background rounded p-2 text-[11px] font-mono">
                                  {JSON.stringify(JSON.parse(event.compliance), null, 2)}
                                </pre>
                              </div>
                            )}
                            {event.traceId && (
                              <div className="flex items-center gap-2">
                                <span className="text-muted-foreground">Trace:</span>
                                <span className="font-mono text-[10px] bg-background px-2 py-0.5 rounded">{event.traceId}</span>
                              </div>
                            )}
                            {event.spanId && (
                              <div className="flex items-center gap-2">
                                <span className="text-muted-foreground">Span:</span>
                                <span className="font-mono text-[10px] bg-background px-2 py-0.5 rounded">{event.spanId}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>

        {events.length === 0 && !isLoading && (
          <div className="p-12 text-center text-muted-foreground text-sm">No events match your filters</div>
        )}
        {isLoading && (
          <div className="p-12 text-center text-muted-foreground text-sm">Loading events...</div>
        )}

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-border">
          <span className="text-xs text-muted-foreground">Page {page} of {totalPages} • {total} events</span>
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)} className="h-7">
              <ChevronLeft className="w-4 h-4" />
            </Button>
            <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)} className="h-7">
              <ChevronRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
