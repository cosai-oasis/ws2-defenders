'use client';

import { useState, useCallback } from 'react';
import Link from 'next/link';
import { useSession } from 'next-auth/react';
import { useFetch } from '@/hooks/use-fetch';
import { motion } from 'framer-motion';
import {
  Settings, Building2, Users, HardDrive, Shield, Plus, Trash2,
  Save, User, Crown, ChevronDown, ChevronUp, Database, Archive,
  AlertTriangle, Check, X, Edit2, RefreshCw, FileCheck, Download,
  ShieldCheck, Clock, Globe, ShieldHalf, ChevronRight,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const ROLE_OPTIONS = ['owner', 'admin', 'analyst', 'viewer'];
const ROLE_COLORS: Record<string, string> = {
  owner: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  admin: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  analyst: 'bg-green-500/20 text-green-400 border-green-500/30',
  viewer: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};
const ROLE_ICONS: Record<string, any> = {
  owner: Crown,
  admin: Shield,
  analyst: User,
  viewer: User,
};

export default function SettingsContent() {
  const { data: session } = useSession() || {};
  const currentUser = session?.user as any;
  const isAdminUser = currentUser?.role === 'owner' || currentUser?.role === 'admin';

  const { data: orgData, mutate: mutateOrg } = useFetch('/api/organization');
  const { data: usersData, mutate: mutateUsers } = useFetch('/api/users');
  const { data: storageData, mutate: mutateStorage } = useFetch('/api/settings/storage');
  const { data: rulesData, mutate: mutateRules } = useFetch('/api/settings/rules');

  const [activeTab, setActiveTab] = useState<'general' | 'users' | 'storage' | 'rules'>('general');
  const [orgName, setOrgName] = useState('');
  const [orgPlan, setOrgPlan] = useState('team');
  const [creating, setCreating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // User invite state
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteName, setInviteName] = useState('');
  const [inviteRole, setInviteRole] = useState('analyst');
  const [invitePassword, setInvitePassword] = useState('');

  // Storage state
  const [retentionDays, setRetentionDays] = useState<number>(90);
  const [maxStorageMb, setMaxStorageMb] = useState<number>(5000);
  const [archiveEnabled, setArchiveEnabled] = useState(false);
  const [archiveAfterDays, setArchiveAfterDays] = useState<number>(30);
  const [exportFormat, setExportFormat] = useState('jsonl');
  const [autoCleanup, setAutoCleanup] = useState(true);
  const [storageLoaded, setStorageLoaded] = useState(false);

  // Load storage values when data arrives
  if (storageData?.config && !storageLoaded) {
    const c = storageData.config;
    setRetentionDays(c.retentionDays ?? 90);
    setMaxStorageMb(c.maxStorageMb ?? 5000);
    setArchiveEnabled(c.archiveEnabled ?? false);
    setArchiveAfterDays(c.archiveAfterDays ?? 30);
    setExportFormat(c.exportFormat ?? 'jsonl');
    setAutoCleanup(c.autoCleanup ?? true);
    setStorageLoaded(true);
  }

  const mode = orgData?.mode ?? 'individual';
  const org = orgData?.org;
  const members = usersData?.users ?? [];
  const storageUsage = storageData?.usage;

  const flash = (msg: string, isError = false) => {
    if (isError) { setError(msg); setSuccess(''); }
    else { setSuccess(msg); setError(''); }
    setTimeout(() => { setError(''); setSuccess(''); }, 3000);
  };

  const createOrg = async () => {
    if (!orgName.trim()) return flash('Organization name required', true);
    setCreating(true);
    try {
      const res = await fetch('/api/organization', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: orgName, plan: orgPlan }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      flash('Organization created! Refresh to see changes.');
      mutateOrg();
      mutateUsers();
    } catch (e: any) {
      flash(e.message, true);
    } finally {
      setCreating(false);
    }
  };

  const updateOrg = async () => {
    setSaving(true);
    try {
      const res = await fetch('/api/organization', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: orgName || org?.name }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      flash('Organization updated');
      mutateOrg();
    } catch (e: any) {
      flash(e.message, true);
    } finally {
      setSaving(false);
    }
  };

  const inviteUser = async () => {
    if (!inviteEmail.trim()) return flash('Email required', true);
    try {
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: inviteEmail, name: inviteName, role: inviteRole, password: invitePassword || undefined }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      flash(data.tempPassword ? `User added. Temp password: ${data.tempPassword}` : 'User added');
      setInviteEmail(''); setInviteName(''); setInvitePassword('');
      setShowInvite(false);
      mutateUsers();
    } catch (e: any) {
      flash(e.message, true);
    }
  };

  const updateUserRole = async (userId: string, role: string) => {
    try {
      const res = await fetch('/api/users', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, role }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      mutateUsers();
    } catch (e: any) {
      flash(e.message, true);
    }
  };

  const removeUser = async (userId: string) => {
    if (!confirm('Remove this user from the organization?')) return;
    try {
      const res = await fetch(`/api/users?userId=${userId}`, { method: 'DELETE' });
      if (!res.ok) throw new Error((await res.json()).error);
      flash('User removed');
      mutateUsers();
    } catch (e: any) {
      flash(e.message, true);
    }
  };

  const saveStorage = async () => {
    setSaving(true);
    try {
      const res = await fetch('/api/settings/storage', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ retentionDays, maxStorageMb, archiveEnabled, archiveAfterDays, exportFormat, autoCleanup }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      flash('Storage settings saved');
      mutateStorage();
    } catch (e: any) {
      flash(e.message, true);
    } finally {
      setSaving(false);
    }
  };

  // Rules update state
  const [updatingRules, setUpdatingRules] = useState(false);
  const [rulesUpdateResult, setRulesUpdateResult] = useState<any>(null);

  const triggerRulesUpdate = useCallback(async () => {
    setUpdatingRules(true);
    setRulesUpdateResult(null);
    try {
      const res = await fetch('/api/settings/rules', { method: 'POST' });
      const data = await res.json();
      setRulesUpdateResult(data);
      mutateRules();
    } catch (err: any) {
      setRulesUpdateResult({ status: 'error', error: err?.message });
    } finally {
      setUpdatingRules(false);
    }
  }, [mutateRules]);

  const tabs = [
    { id: 'general' as const, label: 'General', icon: Building2 },
    { id: 'users' as const, label: 'Users', icon: Users },
    { id: 'storage' as const, label: 'Log Storage', icon: HardDrive },
    { id: 'rules' as const, label: 'Detection Rules', icon: ShieldCheck },
  ];

  return (
    <div className="p-4 md:p-6 space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-3 mb-1">
          <Settings className="w-6 h-6 text-primary" />
          <h1 className="text-2xl font-display font-bold">Settings</h1>
        </div>
        <p className="text-sm text-muted-foreground">
          {mode === 'organization'
            ? `Managing ${org?.name ?? 'organization'} • ${org?.plan ?? 'team'} plan`
            : 'Individual mode • Create an organization to collaborate with your team'}
        </p>
      </motion.div>

      {/* Feedback */}
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}
      {success && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 text-sm">
          <Check className="w-4 h-4 flex-shrink-0" /> {success}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 bg-card/50 rounded-lg p-1 border border-border">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
              activeTab === tab.id
                ? 'bg-primary/10 text-primary'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/50'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* LLM Guard — lives on its own page; surface it from the settings hub */}
      <Link
        href="/settings/llm-guard"
        className="flex items-center justify-between gap-4 rounded-xl border border-border bg-card p-4 hover:border-primary/50 transition-colors group"
      >
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-primary/10 p-2 text-primary">
            <ShieldHalf className="w-5 h-5" />
          </div>
          <div>
            <div className="text-sm font-semibold text-foreground">LLM Guard</div>
            <div className="text-xs text-muted-foreground">
              Configure the reverse proxy fronting local models — backends, auth, rate limits, and prompt-injection / PII inspection
            </div>
          </div>
        </div>
        <ChevronRight className="w-5 h-5 text-muted-foreground group-hover:text-primary transition-colors" />
      </Link>

      {/* General Tab */}
      {activeTab === 'general' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
          {mode === 'individual' ? (
            <div className="bg-card rounded-xl border border-border p-6 space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <Building2 className="w-5 h-5 text-primary" /> Create Organization
              </h2>
              <p className="text-sm text-muted-foreground">
                Upgrade to organization mode to add team members, set shared policies, and manage log storage centrally.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Organization Name</label>
                  <Input value={orgName} onChange={e => setOrgName(e.target.value)} placeholder="Acme Corp" />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Plan</label>
                  <select
                    value={orgPlan} onChange={e => setOrgPlan(e.target.value)}
                    className="w-full h-10 px-3 rounded-md border border-border bg-background text-sm"
                  >
                    <option value="team">Team</option>
                    <option value="enterprise">Enterprise</option>
                  </select>
                </div>
              </div>
              <Button onClick={createOrg} disabled={creating}>
                <Plus className="w-4 h-4 mr-2" /> {creating ? 'Creating...' : 'Create Organization'}
              </Button>
            </div>
          ) : (
            <div className="bg-card rounded-xl border border-border p-6 space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <Building2 className="w-5 h-5 text-primary" /> Organization Details
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Name</label>
                  <Input defaultValue={org?.name ?? ''} onChange={e => setOrgName(e.target.value)} disabled={!isAdminUser} />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Slug</label>
                  <Input value={org?.slug ?? ''} disabled className="opacity-60" />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Plan</label>
                  <div className="h-10 px-3 flex items-center rounded-md border border-border bg-background text-sm capitalize">
                    {org?.plan ?? 'team'}
                  </div>
                </div>
              </div>
              {isAdminUser && (
                <Button onClick={updateOrg} disabled={saving} variant="outline" size="sm">
                  <Save className="w-4 h-4 mr-2" /> Save Changes
                </Button>
              )}
            </div>
          )}

          {/* Current User Info */}
          <div className="bg-card rounded-xl border border-border p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <User className="w-5 h-5 text-primary" /> Your Profile
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Name</label>
                <div className="h-10 px-3 flex items-center rounded-md border border-border bg-background text-sm">
                  {currentUser?.name ?? 'User'}
                </div>
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Email</label>
                <div className="h-10 px-3 flex items-center rounded-md border border-border bg-background text-sm">
                  {currentUser?.email ?? ''}
                </div>
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Role</label>
                <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border ${ROLE_COLORS[currentUser?.role ?? 'analyst']}`}>
                  {currentUser?.role ?? 'analyst'}
                </span>
              </div>
            </div>
          </div>

          {/* Mode indicator */}
          <div className="bg-card rounded-xl border border-border p-6">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" /> Deployment Mode
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className={`p-4 rounded-lg border-2 ${
                mode === 'individual' ? 'border-primary bg-primary/5' : 'border-border opacity-60'
              }`}>
                <h3 className="font-medium flex items-center gap-2">
                  <User className="w-4 h-4" /> Individual
                </h3>
                <p className="text-xs text-muted-foreground mt-1">
                  Single user, personal policies, local log storage. Ideal for individual developers.
                </p>
              </div>
              <div className={`p-4 rounded-lg border-2 ${
                mode === 'organization' ? 'border-primary bg-primary/5' : 'border-border opacity-60'
              }`}>
                <h3 className="font-medium flex items-center gap-2">
                  <Building2 className="w-4 h-4" /> Organization
                </h3>
                <p className="text-xs text-muted-foreground mt-1">
                  Multi-user with roles, shared policies, centralized log storage. For teams &amp; enterprises.
                </p>
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* Users Tab */}
      {activeTab === 'users' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
          <div className="bg-card rounded-xl border border-border p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <Users className="w-5 h-5 text-primary" />
                {mode === 'organization' ? 'Team Members' : 'User Account'}
              </h2>
              {mode === 'organization' && isAdminUser && (
                <Button size="sm" onClick={() => setShowInvite(!showInvite)}>
                  <Plus className="w-4 h-4 mr-1" /> Add User
                </Button>
              )}
            </div>

            {/* Invite form */}
            {showInvite && (
              <div className="mb-4 p-4 rounded-lg border border-border bg-background space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Email *</label>
                    <Input value={inviteEmail} onChange={e => setInviteEmail(e.target.value)} placeholder="user@company.com" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Name</label>
                    <Input value={inviteName} onChange={e => setInviteName(e.target.value)} placeholder="Jane Smith" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Role</label>
                    <select
                      value={inviteRole} onChange={e => setInviteRole(e.target.value)}
                      className="w-full h-10 px-3 rounded-md border border-border bg-background text-sm"
                    >
                      <option value="analyst">Analyst</option>
                      <option value="admin">Admin</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Password (optional)</label>
                    <Input value={invitePassword} onChange={e => setInvitePassword(e.target.value)} placeholder="Auto-generated" type="password" />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" onClick={inviteUser}><Plus className="w-3 h-3 mr-1" /> Add</Button>
                  <Button size="sm" variant="outline" onClick={() => setShowInvite(false)}><X className="w-3 h-3 mr-1" /> Cancel</Button>
                </div>
              </div>
            )}

            {/* Member list */}
            <div className="space-y-2">
              {members.map((m: any) => {
                const RoleIcon = ROLE_ICONS[m.role] ?? User;
                return (
                  <div key={m.id} className="flex items-center justify-between p-3 rounded-lg border border-border hover:bg-accent/20 transition-colors">
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-full bg-primary/10 flex items-center justify-center">
                        <RoleIcon className="w-4 h-4 text-primary" />
                      </div>
                      <div>
                        <p className="text-sm font-medium">{m.name || m.email.split('@')[0]}</p>
                        <p className="text-xs text-muted-foreground">{m.email}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {mode === 'organization' && isAdminUser && m.id !== currentUser?.id ? (
                        <select
                          value={m.role}
                          onChange={e => updateUserRole(m.id, e.target.value)}
                          className="h-8 px-2 rounded-md border border-border bg-background text-xs"
                        >
                          {ROLE_OPTIONS.filter(r => r !== 'owner' || currentUser?.role === 'owner').map(r => (
                            <option key={r} value={r}>{r}</option>
                          ))}
                        </select>
                      ) : (
                        <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium border ${ROLE_COLORS[m.role]}`}>
                          {m.role}
                        </span>
                      )}
                      {mode === 'organization' && isAdminUser && m.id !== currentUser?.id && m.role !== 'owner' && (
                        <button onClick={() => removeUser(m.id)} className="text-red-400 hover:text-red-300 p-1">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
              {members.length === 0 && (
                <p className="text-sm text-muted-foreground text-center py-8">No users found</p>
              )}
            </div>
          </div>

          {/* Role descriptions */}
          <div className="bg-card rounded-xl border border-border p-6">
            <h3 className="text-sm font-semibold mb-3">Role Permissions</h3>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              {[
                { role: 'Owner', desc: 'Full access. Manage org, users, policies, and storage.' },
                { role: 'Admin', desc: 'Manage users, configure policies and storage settings.' },
                { role: 'Analyst', desc: 'View dashboard, events, alerts. Resolve alerts.' },
                { role: 'Viewer', desc: 'Read-only access to dashboard and reports.' },
              ].map(r => (
                <div key={r.role} className="p-3 rounded-lg border border-border">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border mb-2 ${ROLE_COLORS[r.role.toLowerCase()]}`}>
                    {r.role}
                  </span>
                  <p className="text-xs text-muted-foreground">{r.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      )}

      {/* Storage Tab */}
      {activeTab === 'storage' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
          {/* Usage overview */}
          <div className="bg-card rounded-xl border border-border p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Database className="w-5 h-5 text-primary" /> Storage Usage
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="p-4 rounded-lg bg-background border border-border">
                <p className="text-xs text-muted-foreground">Events</p>
                <p className="text-2xl font-bold font-mono">{storageUsage?.eventCount?.toLocaleString() ?? '—'}</p>
              </div>
              <div className="p-4 rounded-lg bg-background border border-border">
                <p className="text-xs text-muted-foreground">Alerts</p>
                <p className="text-2xl font-bold font-mono">{storageUsage?.alertCount?.toLocaleString() ?? '—'}</p>
              </div>
              <div className="p-4 rounded-lg bg-background border border-border">
                <p className="text-xs text-muted-foreground">Est. Usage</p>
                <p className="text-2xl font-bold font-mono">{storageUsage?.estimatedUsageMb ?? '—'} <span className="text-sm text-muted-foreground">MB</span></p>
              </div>
              <div className="p-4 rounded-lg bg-background border border-border">
                <p className="text-xs text-muted-foreground">Quota</p>
                <p className="text-2xl font-bold font-mono">{maxStorageMb?.toLocaleString() ?? '5000'} <span className="text-sm text-muted-foreground">MB</span></p>
              </div>
            </div>
            {storageUsage?.estimatedUsageMb && maxStorageMb > 0 && (
              <div className="mt-4">
                <div className="flex justify-between text-xs text-muted-foreground mb-1">
                  <span>Storage utilization</span>
                  <span>{Math.round((storageUsage.estimatedUsageMb / maxStorageMb) * 100)}%</span>
                </div>
                <div className="h-2 bg-background rounded-full overflow-hidden border border-border">
                  <div
                    className="h-full bg-primary rounded-full transition-all"
                    style={{ width: `${Math.min(100, (storageUsage.estimatedUsageMb / maxStorageMb) * 100)}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Retention settings */}
          <div className="bg-card rounded-xl border border-border p-6 space-y-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <HardDrive className="w-5 h-5 text-primary" /> Retention &amp; Storage Policy
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Retention Period (days)</label>
                <Input type="number" value={retentionDays} onChange={e => setRetentionDays(Number(e.target.value))} disabled={!isAdminUser} min={1} max={3650} />
                <p className="text-[10px] text-muted-foreground mt-1">Events older than this are purged</p>
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Max Storage (MB)</label>
                <Input type="number" value={maxStorageMb} onChange={e => setMaxStorageMb(Number(e.target.value))} disabled={!isAdminUser} min={100} />
                <p className="text-[10px] text-muted-foreground mt-1">Maximum storage allocation</p>
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground mb-1 block">Export Format</label>
                <select
                  value={exportFormat} onChange={e => setExportFormat(e.target.value)}
                  className="w-full h-10 px-3 rounded-md border border-border bg-background text-sm"
                  disabled={!isAdminUser}
                >
                  <option value="jsonl">JSONL</option>
                  <option value="csv">CSV</option>
                  <option value="parquet">Parquet</option>
                </select>
                <p className="text-[10px] text-muted-foreground mt-1">Default export format</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="flex items-center gap-3 p-3 rounded-lg border border-border">
                <input type="checkbox" checked={autoCleanup} onChange={e => setAutoCleanup(e.target.checked)} disabled={!isAdminUser}
                  className="w-4 h-4 rounded border-border" />
                <div>
                  <p className="text-sm font-medium">Auto Cleanup</p>
                  <p className="text-[10px] text-muted-foreground">Automatically purge expired events</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-3 rounded-lg border border-border">
                <input type="checkbox" checked={archiveEnabled} onChange={e => setArchiveEnabled(e.target.checked)} disabled={!isAdminUser}
                  className="w-4 h-4 rounded border-border" />
                <div>
                  <p className="text-sm font-medium">Archive Mode</p>
                  <p className="text-[10px] text-muted-foreground">Move old events to cold storage</p>
                </div>
              </div>
              {archiveEnabled && (
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Archive After (days)</label>
                  <Input type="number" value={archiveAfterDays} onChange={e => setArchiveAfterDays(Number(e.target.value))} disabled={!isAdminUser} min={1} />
                </div>
              )}
            </div>

            {isAdminUser && (
              <Button onClick={saveStorage} disabled={saving}>
                <Save className="w-4 h-4 mr-2" /> {saving ? 'Saving...' : 'Save Storage Settings'}
              </Button>
            )}
          </div>
        </motion.div>
      )}

      {/* Detection Rules Tab */}
      {activeTab === 'rules' && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
          {/* Status Overview */}
          <div className="bg-card rounded-xl border border-border p-6 space-y-5">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-primary" />
                CoSAI Community Detection Rules
              </h2>
              {rulesData?.integrity && (
                <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border ${
                  rulesData.integrity === 'ok'
                    ? 'bg-green-500/10 text-green-400 border-green-500/30'
                    : 'bg-red-500/10 text-red-400 border-red-500/30'
                }`}>
                  {rulesData.integrity === 'ok' ? <Check className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                  {rulesData.integrity === 'ok' ? 'Verified' : 'Integrity Failed'}
                </span>
              )}
            </div>

            {/* Summary Stats */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-background/50 rounded-lg border border-border p-4">
                <p className="text-xs text-muted-foreground mb-1">Rule Version</p>
                <p className="text-lg font-mono font-semibold">{rulesData?.version ?? '—'}</p>
              </div>
              <div className="bg-background/50 rounded-lg border border-border p-4">
                <p className="text-xs text-muted-foreground mb-1">Agent Signatures</p>
                <p className="text-lg font-mono font-semibold">{rulesData?.agentCount ?? '—'}</p>
              </div>
              <div className="bg-background/50 rounded-lg border border-border p-4">
                <p className="text-xs text-muted-foreground mb-1">Rule Files</p>
                <p className="text-lg font-mono font-semibold">{rulesData?.files ? rulesData.files.length : '—'}</p>
              </div>
            </div>

            {/* File-by-File Integrity */}
            {rulesData?.files && Array.isArray(rulesData.files) && (
              <div>
                <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                  <FileCheck className="w-4 h-4 text-muted-foreground" />
                  File Integrity
                </h3>
                <div className="rounded-lg border border-border overflow-hidden">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-muted/30">
                        <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">File</th>
                        <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">SHA-256</th>
                        <th className="text-center px-4 py-2 text-xs font-medium text-muted-foreground">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {rulesData.files.map((f: any) => (
                        <tr key={f.file} className="hover:bg-muted/10 transition-colors">
                          <td className="px-4 py-2.5 font-mono text-xs">{f.file}</td>
                          <td className="px-4 py-2.5 font-mono text-[10px] text-muted-foreground truncate max-w-[200px]" title={f.hash}>
                            {f.hash || '—'}
                          </td>
                          <td className="px-4 py-2.5 text-center">
                            {f.status === 'ok' ? (
                              <span className="inline-flex items-center gap-1 text-green-400 text-xs"><Check className="w-3 h-3" /> OK</span>
                            ) : f.status === 'missing' ? (
                              <span className="inline-flex items-center gap-1 text-yellow-400 text-xs"><AlertTriangle className="w-3 h-3" /> Missing</span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-red-400 text-xs"><X className="w-3 h-3" /> Mismatch</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Schedule & Remote Info */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="flex items-start gap-3 p-3 rounded-lg border border-border">
                <Clock className="w-4 h-4 text-muted-foreground mt-0.5" />
                <div>
                  <p className="text-sm font-medium">Auto-Update Schedule</p>
                  <p className="text-xs text-muted-foreground">
                    {rulesData?.schedule
                      ? `Every ${rulesData.schedule.interval} at ${rulesData.schedule.time}`
                      : 'Every 24 hours at 01:00 UTC'}
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3 p-3 rounded-lg border border-border">
                <Globe className="w-4 h-4 text-muted-foreground mt-0.5" />
                <div>
                  <p className="text-sm font-medium">Remote Source</p>
                  <p className="text-xs text-muted-foreground font-mono truncate max-w-xs" title={rulesData?.remoteUrl}>
                    {rulesData?.remoteUrl ?? 'github.com/girdav01/aitf'}
                  </p>
                </div>
              </div>
            </div>

            {/* Update Action */}
            {isAdminUser && (
              <div className="flex items-center gap-4 pt-2 border-t border-border">
                <Button onClick={triggerRulesUpdate} disabled={updatingRules}>
                  {updatingRules ? (
                    <><RefreshCw className="w-4 h-4 mr-2 animate-spin" /> Updating…</>
                  ) : (
                    <><Download className="w-4 h-4 mr-2" /> Check for Updates</>
                  )}
                </Button>
                {rulesUpdateResult && (
                  <span className={`text-xs font-medium ${
                    rulesUpdateResult.status === 'updated' || rulesUpdateResult.status === 'up_to_date'
                      ? 'text-green-400' : 'text-red-400'
                  }`}>
                    {rulesUpdateResult.status === 'updated'
                      ? `✓ Updated — ${rulesUpdateResult.updated?.length ?? 0} files replaced`
                      : rulesUpdateResult.status === 'up_to_date'
                        ? '✓ Already up to date'
                        : `⚠ ${rulesUpdateResult.error ?? rulesUpdateResult.errors?.join(', ') ?? 'Update failed'}`}
                  </span>
                )}
              </div>
            )}
          </div>

          {/* CLI Reference */}
          <div className="bg-card rounded-xl border border-border p-6 space-y-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Settings className="w-5 h-5 text-primary" />
              Agent CLI Commands
            </h2>
            <p className="text-sm text-muted-foreground">
              Use these commands on deployed agents to manage rule integrity directly.
            </p>
            <div className="space-y-3">
              <div className="bg-background/50 rounded-lg border border-border p-4">
                <p className="text-xs font-semibold text-muted-foreground mb-2">Python Agent</p>
                <code className="block text-xs font-mono text-foreground bg-muted/30 rounded px-3 py-2">
                  python main.py verify&nbsp;&nbsp;&nbsp;&nbsp;# Check integrity of local rules
                </code>
                <code className="block text-xs font-mono text-foreground bg-muted/30 rounded px-3 py-2 mt-1">
                  python main.py update&nbsp;&nbsp;&nbsp;&nbsp;# Download &amp; verify latest rules
                </code>
                <code className="block text-xs font-mono text-foreground bg-muted/30 rounded px-3 py-2 mt-1">
                  python main.py update --force&nbsp;# Force re-download even if current
                </code>
              </div>
              <div className="bg-background/50 rounded-lg border border-border p-4">
                <p className="text-xs font-semibold text-muted-foreground mb-2">Rust Agent</p>
                <code className="block text-xs font-mono text-foreground bg-muted/30 rounded px-3 py-2">
                  ./adr_agent --verify&nbsp;&nbsp;&nbsp;&nbsp;# Check integrity of local rules
                </code>
                <code className="block text-xs font-mono text-foreground bg-muted/30 rounded px-3 py-2 mt-1">
                  ./adr_agent --update&nbsp;&nbsp;&nbsp;&nbsp;# Download &amp; verify latest rules
                </code>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}