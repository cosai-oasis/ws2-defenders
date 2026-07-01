'use client';

import { useState } from 'react';
import { useSession } from 'next-auth/react';
import { useFetch } from '@/hooks/use-fetch';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck, ChevronDown, ChevronUp, Save, Power, PowerOff,
  AlertTriangle, Shield, Zap, Eye, Ban, Bell,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { DETECTION_RULES } from '@/lib/aitf';

const SEVERITY_COLORS: Record<string, string> = {
  low: 'bg-green-500/20 text-green-400 border-green-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
};

const ACTION_ICONS: Record<string, any> = {
  alert: Bell,
  block: Ban,
  log: Eye,
};

const ACTION_COLORS: Record<string, string> = {
  alert: 'text-yellow-400',
  block: 'text-red-400',
  log: 'text-blue-400',
};

export default function PoliciesContent() {
  const { data: session } = useSession() || {};
  const currentUser = session?.user as any;
  const isAdminUser = currentUser?.role === 'owner' || currentUser?.role === 'admin';

  const { data, mutate } = useFetch('/api/policies');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [saving, setSaving] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);

  // Local edits tracked per-policy
  const [edits, setEdits] = useState<Record<string, any>>({});

  const policies = data?.policies ?? [];

  const getEdit = (id: string, field: string, fallback: any) => {
    return edits[id]?.[field] ?? fallback;
  };

  const setEdit = (id: string, field: string, value: any) => {
    setEdits(prev => ({
      ...prev,
      [id]: { ...prev[id], [field]: value },
    }));
  };

  const flash = (msg: string, type: 'success' | 'error' = 'success') => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 3000);
  };

  const toggleEnabled = async (policy: any) => {
    try {
      const res = await fetch('/api/policies', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: policy.id, enabled: !policy.enabled }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      flash(`${policy.name} ${policy.enabled ? 'disabled' : 'enabled'}`);
      mutate();
    } catch (e: any) {
      flash(e.message, 'error');
    }
  };

  const savePolicy = async (policy: any) => {
    const changes = edits[policy.id];
    if (!changes || Object.keys(changes).length === 0) return;

    setSaving(policy.id);
    try {
      const payload: any = { id: policy.id };
      if (changes.severity) payload.severity = changes.severity;
      if (changes.action) payload.action = changes.action;
      if (changes.threshold) {
        // Merge threshold changes
        const currentThreshold = typeof policy.threshold === 'object' ? policy.threshold : {};
        payload.threshold = { ...currentThreshold, ...changes.threshold };
      }
      const res = await fetch('/api/policies', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      flash(`${policy.name} updated`);
      setEdits(prev => { const next = { ...prev }; delete next[policy.id]; return next; });
      mutate();
    } catch (e: any) {
      flash(e.message, 'error');
    } finally {
      setSaving(null);
    }
  };

  const enabledCount = policies.filter((p: any) => p.enabled).length;
  const criticalCount = policies.filter((p: any) => p.severity === 'critical').length;

  return (
    <div className="p-4 md:p-6 space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-3 mb-1">
          <ShieldCheck className="w-6 h-6 text-primary" />
          <h1 className="text-2xl font-display font-bold">Detection Policies</h1>
        </div>
        <p className="text-sm text-muted-foreground">
          Configure CoSAI detection rules, thresholds, and response actions for AI agent monitoring.
        </p>
      </motion.div>

      {/* Feedback */}
      {feedback && (
        <div className={`flex items-center gap-2 p-3 rounded-lg text-sm border ${
          feedback.type === 'error'
            ? 'bg-red-500/10 border-red-500/30 text-red-400'
            : 'bg-green-500/10 border-green-500/30 text-green-400'
        }`}>
          {feedback.type === 'error' ? <AlertTriangle className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
          {feedback.msg}
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-card rounded-xl border border-border p-4">
          <p className="text-xs text-muted-foreground">Total Rules</p>
          <p className="text-2xl font-bold font-mono">{policies.length}</p>
        </div>
        <div className="bg-card rounded-xl border border-border p-4">
          <p className="text-xs text-muted-foreground">Active</p>
          <p className="text-2xl font-bold font-mono text-green-400">{enabledCount}</p>
        </div>
        <div className="bg-card rounded-xl border border-border p-4">
          <p className="text-xs text-muted-foreground">Disabled</p>
          <p className="text-2xl font-bold font-mono text-gray-400">{policies.length - enabledCount}</p>
        </div>
        <div className="bg-card rounded-xl border border-border p-4">
          <p className="text-xs text-muted-foreground">Critical Rules</p>
          <p className="text-2xl font-bold font-mono text-red-400">{criticalCount}</p>
        </div>
      </div>

      {/* Policy list */}
      <div className="space-y-3">
        {policies.map((policy: any) => {
          const isExpanded = expandedId === policy.id;
          const ruleInfo = DETECTION_RULES[policy.ruleId];
          const threshold = typeof policy.threshold === 'object' ? policy.threshold : {};
          const ActionIcon = ACTION_ICONS[getEdit(policy.id, 'action', policy.action)] ?? Bell;
          const hasEdits = edits[policy.id] && Object.keys(edits[policy.id]).length > 0;

          return (
            <motion.div
              key={policy.id}
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              className={`bg-card rounded-xl border transition-colors ${
                policy.enabled ? 'border-border' : 'border-border/50 opacity-70'
              }`}
            >
              {/* Row header */}
              <div
                className="flex items-center justify-between p-4 cursor-pointer hover:bg-accent/20 transition-colors rounded-xl"
                onClick={() => setExpandedId(isExpanded ? null : policy.id)}
              >
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <div className={`w-2 h-8 rounded-full flex-shrink-0 ${
                    !policy.enabled ? 'bg-gray-600' :
                    policy.severity === 'critical' ? 'bg-red-500' :
                    policy.severity === 'high' ? 'bg-orange-500' :
                    policy.severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                  }`} />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-primary">{policy.ruleId}</span>
                      <span className="font-medium text-sm truncate">{policy.name}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-medium border ${SEVERITY_COLORS[policy.severity]}`}>
                        {policy.severity}
                      </span>
                      <span className={`inline-flex items-center gap-1 text-[10px] ${ACTION_COLORS[policy.action]}`}>
                        <ActionIcon className="w-3 h-3" /> {policy.action}
                      </span>
                      {ruleInfo?.category && (
                        <span className="text-[10px] text-muted-foreground">{ruleInfo.category}</span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {isAdminUser && (
                    <button
                      onClick={(e) => { e.stopPropagation(); toggleEnabled(policy); }}
                      className={`p-1.5 rounded-md transition-colors ${
                        policy.enabled
                          ? 'text-green-400 hover:bg-green-500/20'
                          : 'text-gray-500 hover:bg-gray-500/20'
                      }`}
                      title={policy.enabled ? 'Disable rule' : 'Enable rule'}
                    >
                      {policy.enabled ? <Power className="w-4 h-4" /> : <PowerOff className="w-4 h-4" />}
                    </button>
                  )}
                  {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                </div>
              </div>

              {/* Expanded detail */}
              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="overflow-hidden"
                  >
                    <div className="px-4 pb-4 pt-1 border-t border-border space-y-4">
                      {/* Config row */}
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                          <label className="text-xs font-medium text-muted-foreground mb-1 block">Severity</label>
                          <select
                            value={getEdit(policy.id, 'severity', policy.severity)}
                            onChange={e => setEdit(policy.id, 'severity', e.target.value)}
                            className="w-full h-9 px-3 rounded-md border border-border bg-background text-sm"
                            disabled={!isAdminUser}
                          >
                            <option value="low">Low</option>
                            <option value="medium">Medium</option>
                            <option value="high">High</option>
                            <option value="critical">Critical</option>
                          </select>
                        </div>
                        <div>
                          <label className="text-xs font-medium text-muted-foreground mb-1 block">Action</label>
                          <select
                            value={getEdit(policy.id, 'action', policy.action)}
                            onChange={e => setEdit(policy.id, 'action', e.target.value)}
                            className="w-full h-9 px-3 rounded-md border border-border bg-background text-sm"
                            disabled={!isAdminUser}
                          >
                            <option value="alert">Alert</option>
                            <option value="block">Block</option>
                            <option value="log">Log Only</option>
                          </select>
                        </div>
                        <div>
                          <label className="text-xs font-medium text-muted-foreground mb-1 block">Status</label>
                          <div className={`h-9 px-3 flex items-center rounded-md border text-sm ${
                            policy.enabled ? 'border-green-500/30 text-green-400' : 'border-gray-500/30 text-gray-400'
                          }`}>
                            {policy.enabled ? 'Active' : 'Disabled'}
                          </div>
                        </div>
                      </div>

                      {/* Threshold parameters */}
                      {Object.keys(threshold).length > 0 && (
                        <div>
                          <label className="text-xs font-medium text-muted-foreground mb-2 block">Threshold Parameters</label>
                          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                            {Object.entries(threshold).map(([key, value]) => (
                              <div key={key} className="flex flex-col">
                                <label className="text-[10px] text-muted-foreground mb-1 font-mono">{key}</label>
                                {typeof value === 'boolean' ? (
                                  <div className="flex items-center gap-2">
                                    <input
                                      type="checkbox"
                                      checked={getEdit(policy.id, 'threshold', {})[key] ?? value}
                                      onChange={e => setEdit(policy.id, 'threshold', {
                                        ...(edits[policy.id]?.threshold ?? {}),
                                        [key]: e.target.checked,
                                      })}
                                      disabled={!isAdminUser}
                                      className="w-4 h-4 rounded"
                                    />
                                    <span className="text-xs">{(getEdit(policy.id, 'threshold', {})[key] ?? value) ? 'true' : 'false'}</span>
                                  </div>
                                ) : Array.isArray(value) ? (
                                  <Input
                                    defaultValue={(value as string[]).join(', ')}
                                    className="h-8 text-xs font-mono"
                                    disabled={!isAdminUser}
                                    onBlur={e => setEdit(policy.id, 'threshold', {
                                      ...(edits[policy.id]?.threshold ?? {}),
                                      [key]: e.target.value.split(',').map((s: string) => s.trim()),
                                    })}
                                  />
                                ) : (
                                  <Input
                                    type="number"
                                    defaultValue={value as number}
                                    className="h-8 text-xs font-mono"
                                    disabled={!isAdminUser}
                                    onBlur={e => setEdit(policy.id, 'threshold', {
                                      ...(edits[policy.id]?.threshold ?? {}),
                                      [key]: Number(e.target.value),
                                    })}
                                  />
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Save button */}
                      {isAdminUser && hasEdits && (
                        <Button size="sm" onClick={() => savePolicy(policy)} disabled={saving === policy.id}>
                          <Save className="w-3 h-3 mr-1" /> {saving === policy.id ? 'Saving...' : 'Save Changes'}
                        </Button>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          );
        })}

        {policies.length === 0 && (
          <div className="text-center py-12 text-muted-foreground">
            <ShieldCheck className="w-10 h-10 mx-auto mb-3 opacity-40" />
            <p>No policies configured</p>
          </div>
        )}
      </div>
    </div>
  );
}
