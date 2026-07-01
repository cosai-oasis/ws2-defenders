export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { prisma } from '@/lib/prisma';

/**
 * Tier 4 — list sessions (trace_id–grouped event groups) with multi-host
 * correlation metadata: distinct hosts/users/agents touched, max severity,
 * first and last seen.
 *
 *   GET /api/sessions?since=2026-05-10&limit=50&minSeverity=high
 */
export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const since = url.searchParams.get('since');
  const limit = Math.min(Number(url.searchParams.get('limit') ?? 50), 500);
  const minSeverity = url.searchParams.get('minSeverity'); // low|medium|high|critical

  const where: any = { traceId: { not: null } };
  if (since) where.timestamp = { gte: new Date(since) };
  const severityRank: Record<string, number> = { low: 1, medium: 3, high: 4, critical: 5 };
  if (minSeverity && severityRank[minSeverity]) {
    where.severityId = { gte: severityRank[minSeverity] };
  }

  // Pull recent events for grouping; aggregate in JS (Prisma has no
  // first-class group-by-many here). Cap at 50k pre-grouping for safety.
  const rows = await prisma.event.findMany({
    where,
    orderBy: { timestamp: 'desc' },
    take: 50_000,
    select: {
      id: true, traceId: true, timestamp: true, eventType: true,
      classUid: true, aiOperation: true, riskLevel: true, severityId: true,
      hostName: true, userName: true, agentName: true, provider: true, model: true,
      message: true,
    },
  });

  const map = new Map<string, any>();
  for (const ev of rows) {
    if (!ev.traceId) continue;
    let s = map.get(ev.traceId);
    if (!s) {
      s = {
        traceId: ev.traceId,
        first: ev.timestamp, last: ev.timestamp,
        eventCount: 0, maxSeverity: 0,
        hosts: new Set<string>(), users: new Set<string>(),
        agents: new Set<string>(), providers: new Set<string>(),
        classes: new Set<number>(),
        operations: new Set<string>(),
        sampleMessage: ev.message,
      };
      map.set(ev.traceId, s);
    }
    s.eventCount += 1;
    if (ev.timestamp < s.first) s.first = ev.timestamp;
    if (ev.timestamp > s.last)  s.last  = ev.timestamp;
    s.maxSeverity = Math.max(s.maxSeverity, ev.severityId ?? 0);
    if (ev.hostName)  s.hosts.add(ev.hostName);
    if (ev.userName)  s.users.add(ev.userName);
    if (ev.agentName) s.agents.add(ev.agentName);
    if (ev.provider)  s.providers.add(ev.provider);
    if (ev.classUid)  s.classes.add(ev.classUid);
    if (ev.aiOperation) s.operations.add(ev.aiOperation);
  }

  const sessions = [...map.values()].map(s => ({
    traceId: s.traceId,
    first: s.first, last: s.last,
    eventCount: s.eventCount,
    maxSeverity: s.maxSeverity,
    hosts: [...s.hosts], users: [...s.users],
    agents: [...s.agents], providers: [...s.providers],
    classes: [...s.classes],
    operations: [...s.operations],
    multiHost: s.hosts.size > 1,
    sampleMessage: s.sampleMessage,
  })).sort((a, b) => (b.last as any) - (a.last as any)).slice(0, limit);

  return NextResponse.json({ sessions, totalScanned: rows.length });
}
