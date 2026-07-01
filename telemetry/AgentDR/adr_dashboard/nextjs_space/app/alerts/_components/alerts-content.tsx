'use client';
import { useFetch } from '@/hooks/use-fetch';
import { useState } from 'react';
import { AlertTriangle, CheckCircle, XCircle, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { motion, AnimatePresence } from 'framer-motion';
import { DETECTION_RULES } from '@/lib/aitf';

const severityColors: Record<string, { bg: string; text: string; border: string }> = {
  low: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-l-emerald-400' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-l-yellow-400' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-l-orange-400' },
  critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-l-red-400' },
};

export function AlertsContent() {
  const [sevFilter, setSevFilter] = useState('');
  const [resolvedFilter, setResolvedFilter] = useState('');
  const { data, mutate } = useFetch(
    `/api/alerts?${sevFilter ? `severity=${sevFilter}&` : ''}${resolvedFilter !== '' ? `resolved=${resolvedFilter}` : ''}`
  );
  const alerts = data?.alerts ?? [];

  const toggleResolved = async (id: string, resolved: boolean) => {
    await fetch('/api/alerts', { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, resolved }) });
    mutate();
  };

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-2xl md:text-3xl font-display font-bold tracking-tight flex items-center gap-2">
          <Shield className="w-7 h-7 text-red-400" />
          CoSAI Detection Alerts
        </h1>
        <p className="text-sm text-muted-foreground mt-1">CoSAI detection rules (DET-001–020) • OWASP LLM Top 10 mapping</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <div className="flex items-center gap-1 bg-card rounded-lg border border-border p-0.5">
          {['', 'critical', 'high', 'medium', 'low'].map((level) => (
            <button key={level} onClick={() => setSevFilter(level)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${sevFilter === level ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:text-foreground'}`}>
              {level || 'All'}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1 bg-card rounded-lg border border-border p-0.5">
          {[{ label: 'All', value: '' }, { label: 'Active', value: 'false' }, { label: 'Resolved', value: 'true' }].map((opt) => (
            <button key={opt.value} onClick={() => setResolvedFilter(opt.value)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${resolvedFilter === opt.value ? 'bg-primary/15 text-primary' : 'text-muted-foreground hover:text-foreground'}`}>
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Alerts */}
      <div className="space-y-2">
        <AnimatePresence mode="popLayout">
          {alerts.map((alert: any) => {
            const colors = severityColors[alert.severity] ?? severityColors.medium;
            let details: any = {};
            try { details = JSON.parse(alert.details ?? '{}'); } catch {}
            const ruleInfo = alert.ruleId ? DETECTION_RULES[alert.ruleId] : null;

            return (
              <motion.div
                key={alert.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className={`bg-card rounded-xl border border-border border-l-4 ${colors.border} p-4`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      {alert.ruleId && (
                        <span className="font-mono text-xs font-bold text-orange-400 bg-orange-500/10 px-2 py-0.5 rounded">{alert.ruleId}</span>
                      )}
                      <span className="text-sm font-semibold">{alert.alertType}</span>
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${colors.bg} ${colors.text}`}>
                        {alert.severity?.toUpperCase()}
                      </span>
                      {alert.owaspCategory && (
                        <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 text-[10px] font-mono font-bold">
                          OWASP {alert.owaspCategory}
                        </span>
                      )}
                      {alert.resolved ? (
                        <span className="flex items-center gap-1 text-emerald-400 text-[10px]"><CheckCircle className="w-3 h-3" /> Resolved</span>
                      ) : (
                        <span className="flex items-center gap-1 text-red-400 text-[10px]"><XCircle className="w-3 h-3" /> Active</span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground mb-2">{alert.description}</p>
                    <div className="flex items-center gap-3 flex-wrap">
                      {ruleInfo?.category && <span className="text-[10px] bg-primary/10 text-primary px-1.5 py-0.5 rounded">{ruleInfo.category}</span>}
                      {details?.affected_agent && <span className="text-[10px] bg-cyan-500/10 text-cyan-400 px-1.5 py-0.5 rounded font-mono">🤖 {details.affected_agent}</span>}
                      {details?.detection_method && <span className="text-[10px] bg-muted text-muted-foreground px-1.5 py-0.5 rounded">{details.detection_method}</span>}
                      <span className="text-[10px] text-muted-foreground font-mono ml-auto">
                        {new Date(alert.timestamp).toLocaleString()}
                      </span>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => toggleResolved(alert.id, !alert.resolved)}
                    className="text-xs h-7 shrink-0"
                  >
                    {alert.resolved ? 'Reopen' : 'Resolve'}
                  </Button>
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
        {alerts.length === 0 && (
          <div className="text-center text-muted-foreground py-16 text-sm">No alerts match your filters</div>
        )}
      </div>
    </div>
  );
}
