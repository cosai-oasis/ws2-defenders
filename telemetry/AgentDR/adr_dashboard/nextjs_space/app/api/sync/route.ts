export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { prisma } from '@/lib/prisma';
import fs from 'fs';
import path from 'path';

/**
 * Ingest endpoint. Two modes:
 *
 *   POST /api/sync                         — re-import data/events.jsonl
 *                                            (legacy local-replay path)
 *   POST /api/sync  with JSON body         — accept a batch from the Rust
 *                                            agent: { events: [<EventRecord>,
 *                                            ...] }
 *
 * Both modes denormalise `actor.host` and `actor.user` into the indexed
 * Event.hostName / Event.userName columns and upsert the Host registry for
 * Tier 4 multi-host correlation.
 */
export async function POST(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const orgId = (session as any).user?.orgId ?? null;

  // Path A: JSON body with events array (Rust agent push)
  const ctype = req.headers.get('content-type') ?? '';
  if (ctype.includes('application/json')) {
    let body: any = {};
    try { body = await req.json(); } catch { /* fall through */ }
    if (Array.isArray(body?.events)) {
      const synced = await ingestEvents(body.events, orgId);
      return NextResponse.json({ synced, total: body.events.length });
    }
  }

  // Path B: legacy file replay
  try {
    const jsonlPath = path.join(process.cwd(), 'data', 'events.jsonl');
    if (!fs.existsSync(jsonlPath)) {
      return NextResponse.json({ error: 'JSONL file not found', synced: 0 });
    }
    const lines = fs.readFileSync(jsonlPath, 'utf-8').split('\n').filter((l: string) => l.trim());
    const parsed = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    const synced = await ingestEvents(parsed as any[], orgId);
    return NextResponse.json({ synced, total: parsed.length });
  } catch (error: any) {
    return NextResponse.json({ error: error?.message ?? 'Server error' }, { status: 500 });
  }
}

async function ingestEvents(events: any[], orgId: string | null): Promise<number> {
  let synced = 0;
  const seenHosts = new Map<string, Date>();
  for (const data of events) {
    if (!data) continue;
    try {
      const ts = new Date(data.timestamp);
      const actor = data.actor ?? null;
      const hostName = actor?.host ?? null;
      const userName = actor?.user ?? null;

      const existing = await prisma.event.findFirst({
        where: { timestamp: ts, eventType: data.event_type ?? 'unknown' },
      });
      if (existing) continue;

      await prisma.event.create({
        data: {
          timestamp: ts,
          eventType: data.event_type ?? 'unknown',
          details: JSON.stringify(data.details ?? {}),
          riskLevel: data.risk_level ?? 'low',
          agentDetected: data.agent_detected ?? null,
          source: data.source ?? null,
          tags: data.tags ? JSON.stringify(data.tags) : null,
          orgId,
          classUid:      data.class_uid ?? null,
          aiOperation:   data.ai_operation ?? null,
          typeUid:       data.type_uid ?? null,
          activityId:    data.activity_id ?? null,
          severityId:    data.severity_id ?? null,
          statusId:      data.status_id ?? null,
          message:       data.message ?? null,
          provider:      data.provider ?? null,
          model:         data.model ?? null,
          agentName:     data.agent_name ?? null,
          agentFramework: data.agent_framework ?? null,
          toolName:      data.tool_name ?? null,
          mcpServer:     data.mcp_server ?? null,
          actor:         actor ? JSON.stringify(actor) : null,
          compliance:    data.compliance ? JSON.stringify(data.compliance) : null,
          securityFinding: data.security_finding ? JSON.stringify(data.security_finding) : null,
          tokenUsage:    data.token_usage ? JSON.stringify(data.token_usage) : null,
          costInfo:      data.cost_info ? JSON.stringify(data.cost_info) : null,
          traceId:       data.trace_id ?? null,
          spanId:        data.span_id ?? null,
          hostName, userName,
        },
      });
      synced++;
      if (hostName) {
        const prev = seenHosts.get(hostName);
        if (!prev || prev < ts) seenHosts.set(hostName, ts);
      }
    } catch { /* skip invalid */ }
  }

  // Upsert Host registry in bulk.
  for (const [hostname, lastSeen] of seenHosts) {
    await prisma.host.upsert({
      where: { hostname },
      update: { lastSeen, orgId },
      create: { hostname, lastSeen, orgId },
    }).catch(() => {});
  }
  return synced;
}
