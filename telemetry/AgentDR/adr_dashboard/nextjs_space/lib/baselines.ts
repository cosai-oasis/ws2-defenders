/**
 * Tier 4 — UEBA baselining for AI agents.
 *
 * Computes rolling per-(host, user, agent) baselines for five behavioural
 * metrics and exposes a z-score so analysts can rank recent events by how
 * anomalous they look against that user/agent's own history. Most UEBA
 * systems baseline humans; here we baseline the agent acting on behalf
 * of the human, so anomalies attributable to a specific runtime surface
 * even when the human owner's overall activity looks normal.
 *
 * Metrics (per 1-hour window):
 *   - tokens_per_hour          : sum of token_usage.total seen for that bucket
 *   - files_touched_per_hour   : distinct file paths under Event.details.path
 *   - mcp_tool_diversity       : distinct MCP method names (tool_name w/ ai_operation=mcp_operation)
 *   - offhours_share           : fraction of events outside 08:00–20:00 local
 *   - api_call_rate            : count of ai_operation=inference events
 *
 * Baselines store mean / stdev / p50 / p95 / p99 so the z-score returned by
 * scoreEvent() is stable and doesn't require re-scanning the whole history
 * on every event.
 */

import { prisma } from '@/lib/prisma';

export type Metric =
  | 'tokens_per_hour'
  | 'files_touched_per_hour'
  | 'mcp_tool_diversity'
  | 'offhours_share'
  | 'api_call_rate';

export const METRICS: Metric[] = [
  'tokens_per_hour',
  'files_touched_per_hour',
  'mcp_tool_diversity',
  'offhours_share',
  'api_call_rate',
];

/** Bucket size for behavioural metrics: 1 hour. */
const BUCKET_MS = 60 * 60 * 1000;

interface EventLike {
  timestamp: Date;
  classUid: number | null;
  aiOperation: string | null;
  toolName: string | null;
  mcpServer: string | null;
  tokenUsage: string | null;       // JSON
  details: string;                  // JSON
  actor: string | null;             // JSON (legacy fallback)
  hostName: string | null;
  userName: string | null;
  agentName: string | null;
}

interface Bucket {
  hourStart: number;
  tokens: number;
  files: Set<string>;
  mcpTools: Set<string>;
  total: number;
  offhours: number;
  api: number;
}

function key(host: string | null, user: string | null, agent: string | null) {
  return `${host ?? '-'}|${user ?? '-'}|${agent ?? '-'}`;
}

function bucketize(events: EventLike[]): Map<string, Map<number, Bucket>> {
  const out = new Map<string, Map<number, Bucket>>();
  for (const ev of events) {
    const host = ev.hostName;
    const user = ev.userName;
    const agent = ev.agentName;
    const k = key(host, user, agent);
    const ts = ev.timestamp.getTime();
    const hour = Math.floor(ts / BUCKET_MS) * BUCKET_MS;

    let buckets = out.get(k);
    if (!buckets) { buckets = new Map(); out.set(k, buckets); }
    let b = buckets.get(hour);
    if (!b) {
      b = { hourStart: hour, tokens: 0, files: new Set(), mcpTools: new Set(), total: 0, offhours: 0, api: 0 };
      buckets.set(hour, b);
    }

    b.total += 1;
    const localHour = new Date(ts).getHours();
    if (localHour < 8 || localHour >= 20) b.offhours += 1;

    if (ev.aiOperation === 'inference') b.api += 1;

    if (ev.tokenUsage) {
      try {
        const tu = JSON.parse(ev.tokenUsage);
        const t = Number(tu?.total ?? tu?.output ?? 0);
        if (!Number.isNaN(t)) b.tokens += t;
      } catch { /* ignore */ }
    }
    try {
      const d = JSON.parse(ev.details);
      const p = d?.path ?? d?.source_path;
      if (typeof p === 'string') b.files.add(p);
    } catch { /* ignore */ }
    if (ev.aiOperation === 'mcp_operation' && ev.toolName) b.mcpTools.add(ev.toolName);
  }
  return out;
}

interface Stats { count: number; mean: number; stdev: number; p50: number; p95: number; p99: number; }

function summarise(values: number[]): Stats {
  if (values.length === 0) return { count: 0, mean: 0, stdev: 0, p50: 0, p95: 0, p99: 0 };
  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((a, v) => a + v, 0);
  const mean = sum / sorted.length;
  const variance = sorted.reduce((a, v) => a + (v - mean) ** 2, 0) / sorted.length;
  const stdev = Math.sqrt(variance);
  const pick = (q: number) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
  return { count: sorted.length, mean, stdev, p50: pick(0.5), p95: pick(0.95), p99: pick(0.99) };
}

/**
 * Recompute baselines for the last `windowDays` of events. Idempotent —
 * uses `upsert` keyed by (hostId|null, userName|null, agentName|null, metric).
 */
export async function recomputeBaselines(opts: { windowDays?: number; orgId?: string | null } = {}) {
  const windowDays = opts.windowDays ?? 14;
  const since = new Date(Date.now() - windowDays * 24 * 60 * 60 * 1000);

  const events = await prisma.event.findMany({
    where: {
      timestamp: { gte: since },
      ...(opts.orgId ? { orgId: opts.orgId } : {}),
    },
    select: {
      timestamp: true, classUid: true, aiOperation: true, toolName: true, mcpServer: true,
      tokenUsage: true, details: true, actor: true,
      hostName: true, userName: true, agentName: true,
    },
  });

  const buckets = bucketize(events as EventLike[]);
  const summary: Record<string, Record<Metric, Stats>> = {};

  for (const [k, perHour] of buckets) {
    const tokens: number[] = [];
    const files: number[] = [];
    const tools: number[] = [];
    const off: number[] = [];
    const api: number[] = [];
    for (const b of perHour.values()) {
      tokens.push(b.tokens);
      files.push(b.files.size);
      tools.push(b.mcpTools.size);
      off.push(b.total === 0 ? 0 : b.offhours / b.total);
      api.push(b.api);
    }
    summary[k] = {
      tokens_per_hour:        summarise(tokens),
      files_touched_per_hour: summarise(files),
      mcp_tool_diversity:     summarise(tools),
      offhours_share:         summarise(off),
      api_call_rate:          summarise(api),
    };
  }

  // Persist
  let upserted = 0;
  for (const [k, perMetric] of Object.entries(summary)) {
    const [host, user, agent] = k.split('|').map(p => p === '-' ? null : p);
    const hostRow = host ? await prisma.host.upsert({
      where: { hostname: host },
      update: { lastSeen: new Date(), orgId: opts.orgId ?? null },
      create: { hostname: host, lastSeen: new Date(), orgId: opts.orgId ?? null },
    }) : null;

    for (const [metric, stats] of Object.entries(perMetric) as [Metric, Stats][]) {
      await prisma.baseline.upsert({
        where: {
          hostId_userName_agentName_metric: {
            hostId: hostRow?.id ?? '',
            userName: user ?? '',
            agentName: agent ?? '',
            metric,
          },
        },
        update: {
          windowDays, sampleCount: stats.count,
          mean: stats.mean, stdev: stats.stdev,
          p50: stats.p50, p95: stats.p95, p99: stats.p99,
          computedAt: new Date(),
        },
        create: {
          hostId: hostRow?.id ?? null,
          userName: user, agentName: agent, metric,
          windowDays, sampleCount: stats.count,
          mean: stats.mean, stdev: stats.stdev,
          p50: stats.p50, p95: stats.p95, p99: stats.p99,
          orgId: opts.orgId ?? null,
        },
      }).catch(() => {});
      upserted += 1;
    }
  }
  return { groups: buckets.size, baselines: upserted, since };
}

/** z-score with stdev=0 guard. */
export function zscore(observed: number, mean: number, stdev: number): number {
  if (stdev === 0) return observed > mean ? Infinity : 0;
  return (observed - mean) / stdev;
}

/**
 * Score one recent event against the matching baseline and write a
 * UebaScore row. Returns the z-score (Infinity → flat baseline).
 */
export async function scoreEvent(eventId: string): Promise<number | null> {
  const ev = await prisma.event.findUnique({ where: { id: eventId } });
  if (!ev || !ev.tokenUsage) return null;
  let tu: any = {};
  try { tu = JSON.parse(ev.tokenUsage); } catch { return null; }
  const total = Number(tu?.total ?? tu?.output ?? 0);
  if (!Number.isFinite(total) || total === 0) return null;

  const host = ev.hostName ? await prisma.host.findUnique({ where: { hostname: ev.hostName } }) : null;
  const baseline = await prisma.baseline.findFirst({
    where: {
      hostId: host?.id ?? null,
      userName: ev.userName ?? null,
      agentName: ev.agentName ?? null,
      metric: 'tokens_per_hour',
    },
  });
  if (!baseline) return null;
  const z = zscore(total, baseline.mean, baseline.stdev);
  await prisma.uebaScore.create({
    data: {
      eventId: ev.id,
      traceId: ev.traceId,
      userName: ev.userName,
      agentName: ev.agentName,
      metric: 'tokens_per_hour',
      observed: total,
      baselineMean: baseline.mean,
      baselineStdev: baseline.stdev,
      zScore: Number.isFinite(z) ? z : 9999,
      orgId: ev.orgId,
    },
  });
  return z;
}
