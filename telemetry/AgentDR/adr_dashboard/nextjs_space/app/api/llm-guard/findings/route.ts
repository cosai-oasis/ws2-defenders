export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getSessionUser } from '@/lib/session-helpers';
import { prisma } from '@/lib/prisma';

/**
 * LLM Guard telemetry endpoint. Reads the events the Rust reverse proxy emits
 * with `source = "llm-guard"` (see adr_system/rust_agent/src/proxy/reverse.rs):
 *
 *   llm_guard_request        — per-request inference observation (has tokenUsage)
 *   llm_guard_finding        — prompt-injection / PII detection finding
 *   llm_guard_auth_denied    — rejected: bad/missing credentials (407/401)
 *   llm_guard_rate_limited   — rejected: rate limit exceeded (429)
 *   llm_guard_no_route       — rejected: no backend matched (502)
 *   llm_guard_upstream_error — upstream backend failure
 *
 * All DB access is wrapped so the page degrades gracefully when Postgres is
 * unavailable (returns zeroed stats instead of a 500).
 */

const BLOCK_TYPES = [
  'llm_guard_finding',
  'llm_guard_auth_denied',
  'llm_guard_rate_limited',
  'llm_guard_no_route',
  'llm_guard_upstream_error',
];

function safeParse(json: string | null): any {
  if (!json) return null;
  try {
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/** Sum token counts from a heterogeneous upstream token_usage blob. */
function extractTokens(tu: any): { prompt: number; completion: number; total: number } {
  const out = { prompt: 0, completion: 0, total: 0 };
  if (!tu || typeof tu !== 'object') return out;
  const num = (v: any) => (typeof v === 'number' && isFinite(v) ? v : 0);
  // OpenAI-style
  out.prompt = num(tu.prompt_tokens) || num(tu.input_tokens) || num(tu.prompt_eval_count);
  out.completion = num(tu.completion_tokens) || num(tu.output_tokens) || num(tu.eval_count);
  out.total = num(tu.total_tokens) || out.prompt + out.completion;
  if (out.total === 0) out.total = out.prompt + out.completion;
  return out;
}

export async function GET(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const hours = Math.min(Math.max(parseInt(url.searchParams.get('hours') ?? '24', 10) || 24, 1), 720);
  const since = new Date(Date.now() - hours * 3600 * 1000);

  const orgScope = user.orgId ? { orgId: user.orgId } : {};
  const baseWhere = { source: 'llm-guard', timestamp: { gte: since }, ...orgScope };

  try {
    const [recentEvents, byType, requestEvents, findingEvents] = await Promise.all([
      // Recent findings/blocks for the table.
      prisma.event.findMany({
        where: { ...baseWhere, eventType: { in: BLOCK_TYPES } },
        orderBy: { timestamp: 'desc' },
        take: 50,
        select: {
          id: true, timestamp: true, eventType: true, riskLevel: true, severityId: true,
          message: true, provider: true, agentName: true, agentFramework: true,
          securityFinding: true, details: true, hostName: true, userName: true,
        },
      }),
      // Counts per event type.
      prisma.event.groupBy({ by: ['eventType'], where: baseWhere, _count: true }),
      // Inference requests carry token usage.
      prisma.event.findMany({
        where: { ...baseWhere, eventType: 'llm_guard_request' },
        orderBy: { timestamp: 'asc' },
        select: { timestamp: true, provider: true, tokenUsage: true, details: true, userName: true, agentName: true },
      }),
      // Findings for injection/pii breakdown.
      prisma.event.findMany({
        where: { ...baseWhere, eventType: 'llm_guard_finding' },
        select: { securityFinding: true },
      }),
    ]);

    // ── Token usage stats + hourly trend ──
    let promptTokens = 0, completionTokens = 0, totalTokens = 0;
    const trendMap: Record<string, { hour: string; tokens: number; requests: number }> = {};
    const providerTokens: Record<string, number> = {};
    for (const ev of requestEvents) {
      const t = extractTokens(safeParse(ev.tokenUsage));
      promptTokens += t.prompt;
      completionTokens += t.completion;
      totalTokens += t.total;
      const hour = new Date(ev.timestamp).toISOString().slice(0, 13) + ':00:00Z';
      if (!trendMap[hour]) trendMap[hour] = { hour, tokens: 0, requests: 0 };
      trendMap[hour].tokens += t.total;
      trendMap[hour].requests += 1;
      const prov = ev.provider ?? 'unknown';
      providerTokens[prov] = (providerTokens[prov] ?? 0) + t.total;
    }
    const trend = Object.values(trendMap).sort((a, b) => a.hour.localeCompare(b.hour));

    // ── Injection / PII breakdown ──
    let injectionCount = 0, piiCount = 0;
    for (const f of findingEvents) {
      const sf = safeParse(f.securityFinding);
      if (sf?.injections?.length) injectionCount += 1;
      if (sf?.pii?.length) piiCount += 1;
    }

    // ── Counts ──
    const counts: Record<string, number> = {};
    for (const row of byType) counts[row.eventType] = (row as any)._count ?? 0;

    // ── Active "sessions" — distinct callers in the window with recent activity ──
    const sessionMap: Record<string, { subject: string; requests: number; lastSeen: string; agentName: string | null }> = {};
    for (const ev of requestEvents) {
      const d = safeParse(ev.details);
      const subject = d?.subject || ev.userName || ev.agentName || 'anonymous';
      if (!sessionMap[subject]) {
        sessionMap[subject] = { subject, requests: 0, lastSeen: ev.timestamp.toISOString(), agentName: ev.agentName ?? null };
      }
      sessionMap[subject].requests += 1;
      sessionMap[subject].lastSeen = ev.timestamp.toISOString();
    }
    const sessions = Object.values(sessionMap).sort((a, b) => b.lastSeen.localeCompare(a.lastSeen)).slice(0, 20);

    const findings = recentEvents.map((e) => ({
      id: e.id,
      timestamp: e.timestamp.toISOString(),
      eventType: e.eventType,
      riskLevel: e.riskLevel,
      severityId: e.severityId,
      message: e.message,
      provider: e.provider,
      agentName: e.agentName,
      agentFramework: e.agentFramework,
      host: e.hostName,
      user: e.userName,
      securityFinding: safeParse(e.securityFinding),
      details: safeParse(e.details),
    }));

    return NextResponse.json({
      ok: true,
      windowHours: hours,
      counts: {
        total: byType.reduce((s, r) => s + ((r as any)._count ?? 0), 0),
        requests: counts['llm_guard_request'] ?? 0,
        findings: counts['llm_guard_finding'] ?? 0,
        blocked: (counts['llm_guard_auth_denied'] ?? 0) + (counts['llm_guard_rate_limited'] ?? 0)
          + (counts['llm_guard_no_route'] ?? 0) + (counts['llm_guard_upstream_error'] ?? 0),
        authDenied: counts['llm_guard_auth_denied'] ?? 0,
        rateLimited: counts['llm_guard_rate_limited'] ?? 0,
        noRoute: counts['llm_guard_no_route'] ?? 0,
        upstreamError: counts['llm_guard_upstream_error'] ?? 0,
        injection: injectionCount,
        pii: piiCount,
      },
      tokens: { prompt: promptTokens, completion: completionTokens, total: totalTokens, byProvider: providerTokens },
      trend,
      sessions,
      findings,
    });
  } catch (e: any) {
    // DB unreachable — return an empty-but-valid payload so the UI still renders.
    return NextResponse.json({
      ok: false,
      degraded: true,
      error: 'Telemetry store unavailable',
      windowHours: hours,
      counts: { total: 0, requests: 0, findings: 0, blocked: 0, authDenied: 0, rateLimited: 0, noRoute: 0, upstreamError: 0, injection: 0, pii: 0 },
      tokens: { prompt: 0, completion: 0, total: 0, byProvider: {} },
      trend: [],
      sessions: [],
      findings: [],
    });
  }
}
