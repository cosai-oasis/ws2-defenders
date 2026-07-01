'use client';

import { useState } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import {
  Shield, Zap, Eye, Brain, Lock, AlertTriangle, Activity,
  ChevronRight, ArrowRight, Terminal, Layers, GitBranch,
  Network, FileSearch, Cpu, BarChart3, Globe, CheckCircle2,
  Copy, Check, BookOpen, Rocket, Users, Server,
  ChevronDown, ExternalLink
} from 'lucide-react';
import { AI_OPERATIONS, DETECTION_RULES, KNOWN_AGENTS, AGENT_CATEGORIES } from '@/lib/aitf';

/* ── Reusable components ── */

function SectionHeading({ badge, title, subtitle }: { badge: string; title: string; subtitle: string }) {
  return (
    <div className="text-center max-w-3xl mx-auto mb-12 md:mb-16">
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-primary/10 text-primary text-xs font-semibold mb-4 tracking-wide uppercase">
        {badge}
      </span>
      <h2 className="text-3xl md:text-4xl font-display font-bold tracking-tight mb-4">{title}</h2>
      <p className="text-muted-foreground text-base md:text-lg leading-relaxed">{subtitle}</p>
    </div>
  );
}

function CodeBlock({ code, lang = 'bash' }: { code: string; lang?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <div className="relative group rounded-xl bg-[hsl(222,47%,5%)] border border-border overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-border/50">
        <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">{lang}</span>
        <button onClick={handleCopy} className="text-muted-foreground hover:text-foreground transition-colors p-1">
          {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
      </div>
      <pre className="p-4 overflow-x-auto text-sm font-mono leading-relaxed text-[hsl(210,40%,86%)]">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function FeatureCard({ icon: Icon, title, description, color }: {
  icon: any; title: string; description: string; color: string;
}) {
  return (
    <div className="group relative bg-card rounded-xl border border-border p-6 hover:border-primary/30 transition-all duration-300 hover:shadow-lg hover:shadow-primary/5">
      <div className={`inline-flex items-center justify-center w-11 h-11 rounded-lg bg-gradient-to-br ${color} mb-4`}>
        <Icon className="w-5 h-5 text-white" />
      </div>
      <h3 className="font-semibold text-base mb-2">{title}</h3>
      <p className="text-sm text-muted-foreground leading-relaxed">{description}</p>
    </div>
  );
}

function StatCard({ value, label, icon: Icon }: { value: string; label: string; icon: any }) {
  return (
    <div className="text-center p-6">
      <Icon className="w-6 h-6 text-primary mx-auto mb-3" />
      <div className="text-3xl md:text-4xl font-display font-bold text-primary mb-1">{value}</div>
      <div className="text-sm text-muted-foreground">{label}</div>
    </div>
  );
}

/* ── Severity badge ── */
const SEV_STYLES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/20',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/20',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/20',
  low: 'bg-green-500/15 text-green-400 border-green-500/20',
};

/* ── FAQ item ── */
function FaqItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-border rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-5 text-left hover:bg-card/50 transition-colors"
      >
        <span className="font-medium text-sm pr-4">{q}</span>
        <ChevronDown className={`w-4 h-4 text-muted-foreground shrink-0 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="px-5 pb-5 pt-0 text-sm text-muted-foreground leading-relaxed">{a}</div>
      )}
    </div>
  );
}

/* ── Architecture layer ── */
function ArchLayer({ title, items, color, icon: Icon }: {
  title: string; items: string[]; color: string; icon: any;
}) {
  return (
    <div className={`relative rounded-xl border ${color} p-5`}>
      <div className="flex items-center gap-2 mb-3">
        <Icon className="w-4 h-4" />
        <h4 className="font-semibold text-sm">{title}</h4>
      </div>
      <div className="flex flex-wrap gap-2">
        {items.map(item => (
          <span key={item} className="px-2.5 py-1 rounded-md bg-background/50 text-xs font-mono">{item}</span>
        ))}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════════ */
/*  MAIN SHOWCASE COMPONENT                                             */
/* ══════════════════════════════════════════════════════════════════════ */

export default function ShowcaseContent() {
  const detectionRuleEntries = Object.entries(DETECTION_RULES);
  const aiOperationEntries = Object.entries(AI_OPERATIONS);
  const agentEntries = Object.entries(KNOWN_AGENTS);

  // Group agents by category
  const agentsByCategory: Record<string, Array<{ key: string; name: string; risk: string }>> = {};
  agentEntries.forEach(([key, val]) => {
    if (!agentsByCategory[val.category]) agentsByCategory[val.category] = [];
    agentsByCategory[val.category].push({ key, name: val.name, risk: val.risk });
  });

  return (
    <div className="min-h-screen bg-background text-foreground">

      {/* ═══ NAVIGATION ═══ */}
      <nav className="sticky top-0 z-50 backdrop-blur-xl bg-background/80 border-b border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-14">
            <div className="flex items-center gap-2">
              <Image src="/cosai-logo.png" alt="CoSAI" width={90} height={37} className="h-6 w-auto dark:brightness-0 dark:invert" />
              <span className="font-display font-bold text-sm">ADR</span>
              <span className="hidden sm:inline text-[10px] px-2 py-0.5 rounded-full bg-primary/10 text-primary font-mono">v1.0</span>
            </div>
            <div className="hidden md:flex items-center gap-6 text-sm text-muted-foreground">
              <a href="#features" className="hover:text-foreground transition-colors">Features</a>
              <a href="#architecture" className="hover:text-foreground transition-colors">Architecture</a>
              <a href="#ocsf" className="hover:text-foreground transition-colors">OCSF Classes</a>
              <a href="#rules" className="hover:text-foreground transition-colors">Detection Rules</a>
              <a href="#agents" className="hover:text-foreground transition-colors">Agents</a>
              <a href="#quickstart" className="hover:text-foreground transition-colors">Quick Start</a>
            </div>
            <Link
              href="/login"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition-colors"
            >
              Open Dashboard <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </nav>

      {/* ═══ HERO ═══ */}
      <section className="relative overflow-hidden">
        {/* Grid background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,hsl(var(--border)/0.3)_1px,transparent_1px),linear-gradient(to_bottom,hsl(var(--border)/0.3)_1px,transparent_1px)] bg-[size:60px_60px]" />
        <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent" />
        {/* Glow */}
        <div className="absolute top-20 left-1/2 -translate-x-1/2 w-[600px] h-[400px] bg-primary/10 rounded-full blur-[120px] pointer-events-none" />

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-24 md:pt-28 md:pb-32">
          <div className="text-center max-w-4xl mx-auto">
            <div className="flex justify-center mb-8">
              <Image src="/cosai-logo.png" alt="CoSAI — Coalition for Secure AI" width={240} height={99} className="h-16 sm:h-20 w-auto dark:brightness-0 dark:invert" priority />
            </div>

            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-card border border-border mb-8 text-xs">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-muted-foreground">Built on</span>
              <span className="font-semibold text-foreground">AITF OCSF Class-Reuse</span>
              <span className="text-muted-foreground">• Coalition for Secure AI</span>
            </div>

            <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-display font-bold tracking-tight mb-6 leading-[1.1]">
              Agent Detection{' '}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-primary via-blue-400 to-cyan-400">
                & Response
              </span>
            </h1>

            <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-10 leading-relaxed">
              Monitor, detect, and respond to AI agent threats in real time.
              CoSAI ADR extends OCSF with purpose-built telemetry for LLM inference,
              agent autonomy, tool execution, and MCP security.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                href="/login"
                className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-primary text-primary-foreground font-semibold hover:bg-primary/90 transition-all shadow-lg shadow-primary/20"
              >
                <Rocket className="w-4 h-4" /> Launch Dashboard
              </Link>
              <a
                href="#quickstart"
                className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-card border border-border text-foreground font-semibold hover:bg-card/80 transition-all"
              >
                <BookOpen className="w-4 h-4" /> Quick Start Guide
              </a>
            </div>
          </div>

          {/* Stats bar */}
          <div className="mt-20 grid grid-cols-2 md:grid-cols-4 gap-px bg-border rounded-2xl overflow-hidden border border-border">
            <div className="bg-card"><StatCard value="20" label="Detection Rules" icon={Shield} /></div>
            <div className="bg-card"><StatCard value="10" label="OCSF Event Classes" icon={Layers} /></div>
            <div className="bg-card"><StatCard value="39" label="Monitored Agents" icon={Users} /></div>
            <div className="bg-card"><StatCard value="2" label="Agent Runtimes" icon={Cpu} /></div>
          </div>
        </div>
      </section>

      {/* ═══ WHAT IS CoSAI ADR ═══ */}
      <section className="py-20 md:py-28 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SectionHeading
            badge="Overview"
            title="What is CoSAI ADR?"
            subtitle="A security monitoring framework designed from the ground up for the age of autonomous AI agents."
          />

          <div className="grid md:grid-cols-2 gap-8 items-start">
            <div className="space-y-6">
              <div className="bg-card rounded-xl border border-border p-6">
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Brain className="w-4 h-4 text-primary" /> The Problem
                </h3>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  AI agents like Cursor, Claude Code, AutoGPT, and OpenClaw operate with increasing autonomy —
                  executing code, accessing files, calling APIs, and delegating to other agents. Traditional
                  security tooling (EDR/SIEM) was never designed to track LLM inference chains, prompt injections,
                  tool permission boundaries, or multi-agent delegation patterns.
                </p>
              </div>
              <div className="bg-card rounded-xl border border-border p-6">
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Zap className="w-4 h-4 text-primary" /> The Solution
                </h3>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  CoSAI ADR adopts the <strong className="text-foreground">AITF OCSF Class-Reuse Model</strong> — AI
                  events reuse existing OCSF classes and carry an ai_operation profile. 16 AI operations capture
                  everything from model inference and agent actions to MCP operations, supply chain anomalies, and
                  cost spikes. 20 detection rules map directly to the OWASP LLM Top 10.
                </p>
              </div>
            </div>

            <div className="bg-card rounded-xl border border-border p-6">
              <h3 className="font-semibold mb-4 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" /> Key Capabilities
              </h3>
              <div className="space-y-3">
                {[
                  'Real-time process, file & network monitoring for AI agents',
                  'AITF OCSF class-reuse structured telemetry output (JSONL)',
                  '20 behavioral detection rules with configurable thresholds',
                  'OWASP LLM Top 10, NIST AI RMF, MITRE ATLAS mappings',
                  'Multi-agent tracking: coding, general-purpose, workflow',
                  'MCP server & tool permission boundary monitoring',
                  'Prompt injection & jailbreak escalation detection',
                  'Supply chain compromise & credential access alerts',
                  'Organization multi-tenancy with role-based access',
                  'Dual runtime: Python agent + Rust agent (4.8 MB binary)',
                ].map((item, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <ChevronRight className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                    <span className="text-sm text-muted-foreground">{item}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══ FEATURES ═══ */}
      <section id="features" className="py-20 md:py-28 bg-card/30 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SectionHeading
            badge="Features"
            title="Purpose-Built for AI Security"
            subtitle="Every feature is designed around the unique threat model of autonomous AI agents."
          />

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
            <FeatureCard icon={Eye} title="Live Telemetry Feed" description="Real-time streaming of AITF AI-operation events. Auto-refresh every 5 seconds with risk-level color coding and ai_operation filtering." color="from-blue-500/20 to-blue-600/20" />
            <FeatureCard icon={AlertTriangle} title="Detection Alerts" description="20 behavioral rules triggered by pattern matching, statistical analysis, and behavioral profiling. Each alert maps to OWASP LLM Top 10." color="from-red-500/20 to-red-600/20" />
            <FeatureCard icon={BarChart3} title="Analytics Dashboard" description="OCSF class distribution, provider/model breakdowns, top agent charts, timeline heatmaps, and detection rule frequency analysis." color="from-purple-500/20 to-purple-600/20" />
            <FeatureCard icon={Lock} title="Policy Engine" description="Enable/disable rules, set severity and action (alert/block/log), configure per-rule thresholds. Organization-scoped or global." color="from-orange-500/20 to-orange-600/20" />
            <FeatureCard icon={FileSearch} title="Log Explorer" description="Paginated, searchable event log with OCSF class, provider, model, and risk filters. Expandable rows show full telemetry detail." color="from-cyan-500/20 to-cyan-600/20" />
            <FeatureCard icon={Users} title="Multi-Tenancy" description="Individual or organization mode. Role-based access (owner, admin, analyst, viewer). Scoped events, alerts, policies, and storage." color="from-green-500/20 to-green-600/20" />
            <FeatureCard icon={Network} title="Agent Monitoring" description="Track 22 known AI agents across coding, general-purpose, and workflow categories. Signature-based detection with risk scoring." color="from-indigo-500/20 to-indigo-600/20" />
            <FeatureCard icon={Terminal} title="Dual Runtime" description="Python agent for rapid prototyping and full-feature monitoring. Rust agent (4.8 MB) for production deployment with minimal overhead." color="from-yellow-500/20 to-yellow-600/20" />
            <FeatureCard icon={Globe} title="Compliance Mapping" description="OWASP LLM Top 10, NIST AI RMF, EU AI Act, ISO 42001, SOC 2 Type II, MITRE ATLAS, CSA AI Safety, PCI DSS 4.0 coverage." color="from-pink-500/20 to-pink-600/20" />
          </div>
        </div>
      </section>

      {/* ═══ ARCHITECTURE ═══ */}
      <section id="architecture" className="py-20 md:py-28 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SectionHeading
            badge="Architecture"
            title="How It Works"
            subtitle="Three layers — endpoint agents generate telemetry, the dashboard surfaces insights, and the policy engine drives response."
          />

          <div className="space-y-4 max-w-4xl mx-auto">
            <ArchLayer
              title="Layer 1 — Endpoint Agents"
              items={['Process Monitor', 'File Watcher', 'Network Sniffer', 'Agent Identifier', 'OCSF Serializer']}
              color="border-blue-500/30 bg-blue-500/5"
              icon={Cpu}
            />
            <div className="flex justify-center">
              <div className="h-8 w-px bg-border relative">
                <ChevronDown className="w-4 h-4 text-muted-foreground absolute -bottom-2 -left-[7px]" />
              </div>
            </div>
            <ArchLayer
              title="Layer 2 — Telemetry Pipeline"
              items={['JSONL Output', 'events.jsonl', '/api/sync', 'PostgreSQL', 'Prisma ORM']}
              color="border-purple-500/30 bg-purple-500/5"
              icon={GitBranch}
            />
            <div className="flex justify-center">
              <div className="h-8 w-px bg-border relative">
                <ChevronDown className="w-4 h-4 text-muted-foreground absolute -bottom-2 -left-[7px]" />
              </div>
            </div>
            <ArchLayer
              title="Layer 3 — Dashboard & Response"
              items={['Live Feed', 'Alert Manager', 'Policy Engine', 'Analytics', 'Log Explorer', 'Multi-Tenancy']}
              color="border-emerald-500/30 bg-emerald-500/5"
              icon={BarChart3}
            />
          </div>

          {/* Data flow */}
          <div className="mt-16 bg-card rounded-xl border border-border p-6 max-w-4xl mx-auto">
            <h3 className="font-semibold text-sm mb-4 text-center">End-to-End Data Flow</h3>
            <div className="flex flex-wrap items-center justify-center gap-2 text-xs font-mono">
              {['AI Agent Process', '→', 'Endpoint Monitor', '→', 'Pattern Detector', '→', 'OCSF Serializer', '→', 'JSONL File', '→', '/api/sync', '→', 'PostgreSQL', '→', 'Dashboard UI'].map((step, i) => (
                step === '→'
                  ? <ArrowRight key={i} className="w-3 h-3 text-muted-foreground shrink-0" />
                  : <span key={i} className="px-2.5 py-1.5 rounded-lg bg-background border border-border whitespace-nowrap">{step}</span>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ═══ OCSF CLASSES ═══ */}
      <section id="ocsf" className="py-20 md:py-28 bg-card/30 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SectionHeading
            badge="AITF OCSF Class-Reuse"
            title="16 AI Operations over Reused OCSF Classes"
            subtitle="AITF drops a bespoke category and instead reuses existing OCSF classes, carrying the AI-specific semantic in an ai_operation profile string."
          />

          <div className="grid sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {aiOperationEntries.map(([op, meta]) => (
              <div key={op} className="bg-card rounded-xl border border-border p-4 hover:border-primary/20 transition-colors">
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-xl">{meta.icon}</span>
                  <span className="font-mono text-xs text-muted-foreground">{op}</span>
                </div>
                <h4 className={`font-semibold text-sm ${meta.color}`}>{meta.label}</h4>
                <p className="text-xs text-muted-foreground mt-1">
                  Reuses OCSF class <span className="font-mono">{meta.classUid}</span>
                </p>
              </div>
            ))}
          </div>

          {/* AITF Event sample */}
          <div className="mt-12 max-w-4xl mx-auto">
            <h3 className="text-sm font-semibold mb-3 text-center">Sample AITF Class-Reuse Event</h3>
            <CodeBlock lang="json" code={`{
  "class_uid": 6003,
  "class_name": "API Activity",
  "profile": "ai_operation",
  "ai_operation": "inference",
  "activity_id": 1,
  "type_uid": 600301,
  "severity_id": 2,
  "time": "2026-05-01T12:34:56.789Z",
  "metadata": {
    "version": "1.1.0",
    "product": { "name": "CoSAI ADR", "vendor_name": "CoSAI" }
  },
  "agent": { "name": "cursor", "type": "coding" },
  "model": { "name": "claude-4-sonnet", "provider": "anthropic" },
  "token_usage": { "prompt": 1240, "completion": 890, "total": 2130 },
  "cost_info": { "estimated_usd": 0.0043 },
  "trace_id": "abc123",
  "span_id": "def456"
}`} />
          </div>
        </div>
      </section>

      {/* ═══ DETECTION RULES ═══ */}
      <section id="rules" className="py-20 md:py-28 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SectionHeading
            badge="Detection Engine"
            title="20 Behavioral Detection Rules"
            subtitle="Each rule detects a specific AI agent threat pattern and maps to OWASP LLM Top 10 categories for compliance."
          />

          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {detectionRuleEntries.map(([ruleId, rule]) => (
              <div key={ruleId} className="bg-card rounded-xl border border-border p-4 hover:border-primary/20 transition-colors">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-[11px] text-primary">{ruleId}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${SEV_STYLES[rule.severity]}`}>
                    {rule.severity}
                  </span>
                </div>
                <h4 className="font-semibold text-sm mb-1">{rule.name}</h4>
                <span className="text-[10px] text-muted-foreground font-mono">{rule.category}</span>
              </div>
            ))}
          </div>

          {/* Rule categories breakdown */}
          <div className="mt-12 grid sm:grid-cols-4 gap-4 max-w-4xl mx-auto">
            {[
              { label: 'Critical', count: detectionRuleEntries.filter(([, r]) => r.severity === 'critical').length, color: 'text-red-400 bg-red-500/10' },
              { label: 'High', count: detectionRuleEntries.filter(([, r]) => r.severity === 'high').length, color: 'text-orange-400 bg-orange-500/10' },
              { label: 'Medium', count: detectionRuleEntries.filter(([, r]) => r.severity === 'medium').length, color: 'text-yellow-400 bg-yellow-500/10' },
              { label: 'Categories', count: [...new Set(detectionRuleEntries.map(([, r]) => r.category))].length, color: 'text-primary bg-primary/10' },
            ].map(s => (
              <div key={s.label} className={`rounded-xl p-4 text-center ${s.color}`}>
                <div className="text-2xl font-bold">{s.count}</div>
                <div className="text-xs mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ AGENT COVERAGE ═══ */}
      <section id="agents" className="py-20 md:py-28 bg-card/30 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SectionHeading
            badge="Agent Coverage"
            title="39 Monitored AI Agents"
            subtitle="Signature-based identification across coding assistants, general-purpose agents, workflow orchestrators, enterprise Copilots, and browser automation agents."
          />

          <div className="grid md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-6">
            {Object.entries(AGENT_CATEGORIES).map(([catKey, cat]) => (
              <div key={catKey} className="bg-card rounded-xl border border-border overflow-hidden">
                <div className="p-4 border-b border-border">
                  <div className="flex items-center gap-2">
                    <span className="text-xl">{cat.icon}</span>
                    <div>
                      <h4 className={`font-semibold text-sm ${cat.color}`}>{cat.label}</h4>
                      <p className="text-[11px] text-muted-foreground">{cat.description}</p>
                    </div>
                  </div>
                </div>
                <div className="p-4 space-y-2">
                  {(agentsByCategory[catKey] ?? []).map(agent => {
                    const riskColor = agent.risk === 'high' ? 'text-red-400' : agent.risk === 'medium' ? 'text-yellow-400' : 'text-green-400';
                    return (
                      <div key={agent.key} className="flex items-center justify-between py-1.5">
                        <span className="text-sm">{agent.name}</span>
                        <span className={`text-[10px] font-mono ${riskColor}`}>{agent.risk}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ DASHBOARD WALKTHROUGH ═══ */}
      <section className="py-20 md:py-28 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SectionHeading
            badge="Dashboard Tour"
            title="Navigate the Interface"
            subtitle="A quick walkthrough of every page in the CoSAI ADR dashboard."
          />

          <div className="grid md:grid-cols-2 gap-6">
            {[
              { icon: Activity, title: 'Security Overview', path: '/dashboard', description: 'At-a-glance stats: total events, active alerts, unique agents, OCSF class distribution grid, provider & model summaries, and live detection alert feed.', color: 'text-blue-400' },
              { icon: Zap, title: 'Live Telemetry Feed', path: '/activity', description: 'Streaming event feed with 5-second auto-refresh. Filter by OCSF class. Each event shows risk badge, agent, provider, model, and timestamp.', color: 'text-purple-400' },
              { icon: FileSearch, title: 'Event Log Explorer', path: '/logs', description: 'Full paginated log with search, OCSF class dropdown, provider/model/risk/source filters. Expandable rows reveal token usage, cost, compliance, and trace IDs.', color: 'text-cyan-400' },
              { icon: BarChart3, title: 'Analytics & Charts', path: '/analytics', description: 'OCSF class distribution, timeline area chart, risk breakdown bar chart, top agents, provider/model rankings, detection rule frequency, and activity heatmap.', color: 'text-emerald-400' },
              { icon: AlertTriangle, title: 'Detection Alerts', path: '/alerts', description: 'All triggered alerts with rule ID, OWASP mapping, severity badge, detection method, affected agent. Filter by severity & resolution status. One-click resolve.', color: 'text-red-400' },
              { icon: Shield, title: 'Detection Policies', path: '/policies', description: 'Toggle rules on/off, set severity level, choose action (alert/block/log), configure per-rule thresholds. Organization-scoped or global.', color: 'text-orange-400' },
              { icon: Server, title: 'Settings', path: '/settings', description: 'Organization management (create, edit, switch mode). User management (invite, roles). Log storage configuration (retention, quotas, archive, export format).', color: 'text-yellow-400' },
            ].map((page) => (
              <div key={page.path} className="bg-card rounded-xl border border-border p-5 flex gap-4 hover:border-primary/20 transition-colors">
                <div className="shrink-0">
                  <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                    <page.icon className={`w-5 h-5 ${page.color}`} />
                  </div>
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <h4 className="font-semibold text-sm">{page.title}</h4>
                    <span className="font-mono text-[10px] text-muted-foreground">{page.path}</span>
                  </div>
                  <p className="text-sm text-muted-foreground leading-relaxed">{page.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ QUICK START ═══ */}
      <section id="quickstart" className="py-20 md:py-28 bg-card/30 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SectionHeading
            badge="Quick Start"
            title="Get Running in Minutes"
            subtitle="Deploy the agent on any workstation where AI agents operate, then point the dashboard at your telemetry."
          />

          <div className="max-w-3xl mx-auto space-y-8">
            {/* Step 1 */}
            <div className="flex gap-4">
              <div className="shrink-0 w-8 h-8 rounded-full bg-primary flex items-center justify-center text-primary-foreground text-sm font-bold">1</div>
              <div className="flex-1">
                <h3 className="font-semibold mb-3">Start the Python Agent</h3>
                <CodeBlock lang="bash" code={`# Clone the repository
git clone https://github.com/girdav01/aitf.git
cd aitf/agent

# Install dependencies
pip install -r requirements.txt

# Run with default settings
python -m engine --root /home/user --watch /home/user/projects`} />
              </div>
            </div>

            {/* Step 2 */}
            <div className="flex gap-4">
              <div className="shrink-0 w-8 h-8 rounded-full bg-primary flex items-center justify-center text-primary-foreground text-sm font-bold">2</div>
              <div className="flex-1">
                <h3 className="font-semibold mb-3">Or Use the Rust Agent (Production)</h3>
                <CodeBlock lang="bash" code={`# Build from source
cd aitf/rust_agent
cargo build --release

# Run the agent (4.8 MB binary)
./target/release/adr_agent --root /home/user --watch /home/user/projects`} />
              </div>
            </div>

            {/* Step 3 */}
            <div className="flex gap-4">
              <div className="shrink-0 w-8 h-8 rounded-full bg-primary flex items-center justify-center text-primary-foreground text-sm font-bold">3</div>
              <div className="flex-1">
                <h3 className="font-semibold mb-3">Sync Telemetry to Dashboard</h3>
                <CodeBlock lang="bash" code={`# The agent outputs JSONL to data/events.jsonl
# Sync to the dashboard API:
curl -X POST https://your-dashboard.example.com/api/sync \\
  -H "Authorization: Bearer <session-token>" \\
  -H "Content-Type: application/json"`} />
              </div>
            </div>

            {/* Step 4 */}
            <div className="flex gap-4">
              <div className="shrink-0 w-8 h-8 rounded-full bg-primary flex items-center justify-center text-primary-foreground text-sm font-bold">4</div>
              <div className="flex-1">
                <h3 className="font-semibold mb-3">Configure Detection Policies</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  Open the <strong className="text-foreground">Detection Policies</strong> page to enable/disable rules,
                  set severity levels, configure thresholds, and choose response actions (alert, block, or log).
                  Policies can be scoped globally or per-organization.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══ COMPLIANCE ═══ */}
      <section className="py-20 md:py-28 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <SectionHeading
            badge="Compliance"
            title="Framework Coverage"
            subtitle="CoSAI ADR detection rules map to the industry's most important AI security and governance frameworks."
          />

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 max-w-4xl mx-auto">
            {[
              { name: 'OWASP LLM Top 10', desc: 'LLM01–LLM10 mapping' },
              { name: 'NIST AI RMF', desc: 'MAP, MEASURE, MANAGE' },
              { name: 'MITRE ATLAS', desc: 'Adversarial ML tactics' },
              { name: 'EU AI Act', desc: 'High-risk AI systems' },
              { name: 'ISO 42001', desc: 'AI management system' },
              { name: 'SOC 2 Type II', desc: 'Trust service criteria' },
              { name: 'CSA AI Safety', desc: 'Cloud AI governance' },
              { name: 'PCI DSS 4.0', desc: 'Payment data security' },
            ].map(fw => (
              <div key={fw.name} className="bg-card rounded-xl border border-border p-4 text-center hover:border-primary/20 transition-colors">
                <h4 className="font-semibold text-sm mb-1">{fw.name}</h4>
                <p className="text-[11px] text-muted-foreground">{fw.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══ FAQ ═══ */}
      <section className="py-20 md:py-28 bg-card/30 border-t border-border">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
          <SectionHeading
            badge="FAQ"
            title="Common Questions"
            subtitle="Everything you need to know about deploying and using CoSAI ADR."
          />

          <div className="space-y-3">
            <FaqItem q="What AI agents does CoSAI ADR monitor?" a="CoSAI ADR monitors 22 agents across three categories: coding assistants (Cursor, Claude Code, GitHub Copilot, Windsurf, Aider, Cline, Augment Code, Continue.dev), general-purpose agents (OpenClaw, AutoGPT, BabyAGI, SuperAGI, SmolAgents, and OpenClaw variants), and workflow orchestrators (LangChain, CrewAI, AutoGen, LlamaIndex). New agent signatures can be added by updating the agent models." />
            <FaqItem q="How does AITF map AI events to OCSF?" a="AITF follows the OCSF Class-Reuse Model: instead of a bespoke category, each AI event reuses an existing OCSF class (e.g. 6003 API Activity, 6005 Datastore Activity, 2004 Detection Finding, 9001 Agent Activity) and carries the AI-specific semantic in an ai_operation profile string (inference, tool_execution, mcp_operation, data_retrieval, prompt_injection, supply_chain, and more). Each event follows the OCSF schema structure with standard metadata, severity, and observables." />
            <FaqItem q="How does detection work?" a="The endpoint agent monitors three channels: processes (psutil/sysinfo), files (watchdog/notify), and network (packet inspection). Events are tagged with a reused OCSF class and an ai_operation profile, then run through 20 detection rules. Each rule uses pattern matching, statistical thresholds, or behavioral baselines. When a rule fires, an alert is created with the rule ID, severity, OWASP mapping, and affected agent." />
            <FaqItem q="Python agent vs Rust agent?" a="Both agents produce identical AITF OCSF class-reuse JSONL output and implement all 20 detection rules. The Python agent is easier to extend and debug (watchdog, psutil, mitmproxy). The Rust agent compiles to a 4.8 MB static binary using tokio, sysinfo, notify — ideal for production deployments where minimal resource footprint matters." />
            <FaqItem q="Can I run this in production?" a="Yes. The Rust agent is designed for production use. The dashboard is a standard Next.js 14 application deployable to any hosting platform. The PostgreSQL database handles multi-tenancy with organization-scoped data. Detection policies and storage configuration are manageable per-organization or globally." />
            <FaqItem q="What about AITF-DET rule IDs?" a="The AITF-DET-001 through DET-020 rule identifiers are technical prefixes retained for backward compatibility. They reference the original AI Telemetry Framework specification. All user-facing branding uses 'CoSAI' to reflect alignment with the Coalition for Secure AI initiative." />
          </div>
        </div>
      </section>

      {/* ═══ CTA ═══ */}
      <section className="py-20 md:py-28 border-t border-border">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <div className="flex justify-center mb-6">
            <Image src="/cosai-logo.png" alt="CoSAI" width={160} height={66} className="h-12 w-auto dark:brightness-0 dark:invert" />
          </div>
          <h2 className="text-3xl md:text-4xl font-display font-bold tracking-tight mb-4">
            Ready to Secure Your AI Agents?
          </h2>
          <p className="text-muted-foreground text-lg mb-8 max-w-xl mx-auto">
            Start monitoring in minutes. Deploy the agent, sync telemetry, and gain full visibility into AI agent behavior.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              href="/login"
              className="inline-flex items-center gap-2 px-8 py-3.5 rounded-xl bg-primary text-primary-foreground font-semibold hover:bg-primary/90 transition-all shadow-lg shadow-primary/20 text-base"
            >
              <Rocket className="w-5 h-5" /> Open Dashboard
            </Link>
            <a
              href="https://github.com/girdav01/aitf"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-8 py-3.5 rounded-xl bg-card border border-border text-foreground font-semibold hover:bg-card/80 transition-all text-base"
            >
              <ExternalLink className="w-5 h-5" /> View on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* ═══ FOOTER ═══ */}
      <footer className="border-t border-border py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Image src="/cosai-logo.png" alt="CoSAI" width={72} height={30} className="h-5 w-auto dark:brightness-0 dark:invert" />
              <span className="text-sm font-semibold">ADR</span>
            </div>
            <div className="flex items-center gap-6 text-xs text-muted-foreground">
              <span>AITF OCSF Class-Reuse</span>
              <span>•</span>
              <span>OWASP LLM Top 10</span>
              <span>•</span>
              <a href="https://github.com/girdav01/aitf" target="_blank" rel="noopener noreferrer" className="hover:text-foreground transition-colors">GitHub</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
