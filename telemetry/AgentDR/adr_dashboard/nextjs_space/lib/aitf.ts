// AITF OCSF Class-Reuse constants and helpers
// ─────────────────────────────────────────────
// AITF dropped its bespoke "Category 7" classes and now follows the OCSF
// Class-Reuse Model: each AI event reuses an existing OCSF class and carries
// an `ai_operation` profile string holding the AI-specific semantic. The
// primary semantic dimension is `aiOperation`; `classUid` is retained for
// OCSF-level compliance display.
//
// Detection signatures, endpoints, and policies are loaded from the
// CoSAI Community JSON rule files (data/cosai-community/) so they can
// be updated without modifying source code.

import agentSignaturesData from '@/data/cosai-community/rules/agent-signatures.json';
import detectionRulesData from '@/data/cosai-community/policies/detection-rules.json';

// ── AITF ai_operation profile metadata ──
// Keyed by the `ai_operation` string emitted by the agent. Each entry carries
// the display label/icon/color plus the reused OCSF `classUid` it maps onto.

export interface AiOperationMeta {
  label: string;
  icon: string;
  color: string;   // tailwind text color class
  hex: string;     // raw hex for charts/inline styles
  classUid: number;
}

export const AI_OPERATIONS: Record<string, AiOperationMeta> = {
  inference:             { label: 'Model Inference',       icon: '🧠', color: 'text-blue-400',    hex: '#60a5fa', classUid: 6003 },
  tool_execution:        { label: 'Tool Execution',        icon: '🔧', color: 'text-cyan-400',    hex: '#22d3ee', classUid: 6003 },
  mcp_operation:         { label: 'MCP Operation',         icon: '🔌', color: 'text-teal-400',    hex: '#2dd4bf', classUid: 6003 },
  data_retrieval:        { label: 'Data Retrieval',        icon: '📊', color: 'text-sky-400',     hex: '#38bdf8', classUid: 6005 },
  model_ops:             { label: 'Model Operations',      icon: '⚙️', color: 'text-indigo-400',  hex: '#818cf8', classUid: 6002 },
  agent_action:          { label: 'Agent Activity',        icon: '🤖', color: 'text-purple-400',  hex: '#c084fc', classUid: 9001 },
  delegation:            { label: 'Delegation',            icon: '🤝', color: 'text-violet-400',  hex: '#a78bfa', classUid: 9002 },
  prompt_injection:      { label: 'Prompt Injection',      icon: '🛡️', color: 'text-red-400',     hex: '#f87171', classUid: 2004 },
  data_exfiltration:     { label: 'Data Exfiltration',     icon: '📤', color: 'text-rose-400',    hex: '#fb7185', classUid: 2004 },
  permission_escalation: { label: 'Permission Escalation', icon: '🔐', color: 'text-amber-400',   hex: '#fbbf24', classUid: 2004 },
  guardrail:             { label: 'Guardrail Event',       icon: '🚧', color: 'text-orange-400',  hex: '#fb923c', classUid: 2004 },
  cost_anomaly:          { label: 'Cost Anomaly',          icon: '💸', color: 'text-amber-500',   hex: '#f59e0b', classUid: 2004 },
  compliance_violation:  { label: 'Compliance Finding',    icon: '📋', color: 'text-yellow-400',  hex: '#facc15', classUid: 2003 },
  supply_chain:          { label: 'Supply Chain',          icon: '🔗', color: 'text-orange-500',  hex: '#f97316', classUid: 2002 },
  identity:              { label: 'Identity',              icon: '🔑', color: 'text-green-400',   hex: '#4ade80', classUid: 3002 },
  asset_inventory:       { label: 'Asset Inventory',       icon: '📦', color: 'text-pink-400',    hex: '#f472b6', classUid: 5001 },
};

// ── OCSF class metadata (class-level display only) ──
// Keyed by the reused OCSF class_uid → human label.

export const OCSF_CLASSES: Record<number, string> = {
  6003: 'API Activity',
  6005: 'Datastore Activity',
  6002: 'Application Lifecycle',
  5001: 'Inventory Info',
  3002: 'Authentication',
  2004: 'Detection Finding',
  2003: 'Compliance Finding',
  2002: 'Vulnerability Finding',
  9001: 'Agent Activity (proposed)',
  9002: 'Delegation Activity (proposed)',
};

// ── Detection rules — loaded from cosai-community/policies/detection-rules.json ──

export const DETECTION_RULES: Record<string, { name: string; category: string; severity: string }> =
  Object.fromEntries(
    detectionRulesData.rules.map((r) => [r.id, { name: r.name, category: r.category, severity: r.severity }])
  );

// ── ai_operation helpers (primary AI semantic dimension) ──

export function getOpLabel(op: string | null | undefined): string {
  if (!op) return 'Unknown';
  return AI_OPERATIONS[op]?.label ?? op;
}

export function getOpIcon(op: string | null | undefined): string {
  if (!op) return '❓';
  return AI_OPERATIONS[op]?.icon ?? '❓';
}

export function getOpColor(op: string | null | undefined): string {
  if (!op) return 'text-muted-foreground';
  return AI_OPERATIONS[op]?.color ?? 'text-muted-foreground';
}

export function getOpHex(op: string | null | undefined): string {
  if (!op) return '#888';
  return AI_OPERATIONS[op]?.hex ?? '#888';
}

// ── OCSF class-level helper (compliance display) ──

export function getClassLabel(classUid: number | null | undefined): string {
  if (!classUid) return 'Unknown';
  return OCSF_CLASSES[classUid] ?? `Class ${classUid}`;
}

// ── Agent categories — loaded from cosai-community/rules/agent-signatures.json ──

export const AGENT_CATEGORIES: Record<string, { label: string; icon: string; color: string; description: string }> =
  Object.fromEntries(
    Object.entries(agentSignaturesData.categories).map(([key, cat]) => [
      key,
      { label: cat.label, icon: cat.icon, color: cat.color, description: cat.description },
    ])
  );

// ── Known agent signatures — loaded from cosai-community/rules/agent-signatures.json ──

export const KNOWN_AGENTS: Record<string, { name: string; category: string; risk: string }> =
  Object.fromEntries(
    agentSignaturesData.signatures.map((s) => [s.id, { name: s.name, category: s.category, risk: s.risk }])
  );

export function getAgentCategory(agentName: string | null | undefined): string {
  if (!agentName) return 'unknown';
  const key = agentName.toLowerCase().replace(/[^a-z0-9-]/g, '');
  return KNOWN_AGENTS[key]?.category ?? 'unknown';
}
