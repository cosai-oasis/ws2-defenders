export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { prisma } from '@/lib/prisma';

/**
 * Tier 4 — kill-chain detail for one trace_id.
 *
 * Returns:
 *   - ordered event timeline (ASC by timestamp)
 *   - all alerts that quote the trace_id (joined via securityFinding JSON)
 *   - per-event UEBA z-scores from UebaScore
 *
 *   GET /api/sessions/<traceId>
 */
export async function GET(req: NextRequest, ctx: { params: { traceId: string } }) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const traceId = ctx.params.traceId;
  if (!traceId) return NextResponse.json({ error: 'missing traceId' }, { status: 400 });

  const [events, alerts, scores] = await Promise.all([
    prisma.event.findMany({
      where: { traceId },
      orderBy: { timestamp: 'asc' },
      take: 5000,
    }),
    prisma.alert.findMany({
      where: { details: { contains: traceId } },
      orderBy: { timestamp: 'asc' },
    }),
    prisma.uebaScore.findMany({
      where: { traceId },
      orderBy: { zScore: 'desc' },
    }),
  ]);

  // Cheap "kill chain" derivation: cluster events by ai_operation and present
  // them as MITRE-style phases (initial access ~ agent_action, execution ~
  // tool_execution, collection ~ data_exfiltration, etc.).
  const phaseFor = (op: string | null) => {
    switch (op) {
      case 'agent_action':          return 'agent_launch';
      case 'delegation':            return 'agent_launch';
      case 'inference':             return 'inference';
      case 'tool_execution':        return 'tool_execution';
      case 'mcp_operation':         return 'mcp_call';
      case 'prompt_injection':      return 'prompt_injection';
      case 'data_retrieval':        return 'data_access';
      case 'data_exfiltration':     return 'data_access';
      case 'permission_escalation': return 'privilege_change';
      case 'compliance_violation':  return 'compliance_drift';
      default:                      return 'other';
    }
  };
  const phases: Record<string, number> = {};
  for (const ev of events) {
    const p = phaseFor(ev.aiOperation);
    phases[p] = (phases[p] ?? 0) + 1;
  }

  return NextResponse.json({
    traceId,
    events,
    alerts,
    ueba: scores,
    phases,
    hosts:  Array.from(new Set(events.map((e: any) => e.hostName).filter(Boolean))),
    users:  Array.from(new Set(events.map((e: any) => e.userName).filter(Boolean))),
    agents: Array.from(new Set(events.map((e: any) => e.agentName).filter(Boolean))),
  });
}
