export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { recomputeBaselines } from '@/lib/baselines';

/**
 * POST /api/baselines/recompute
 *
 * Body: { windowDays?: number }
 *
 * Recompute behavioural baselines for the requesting session's org (or
 * across all events if the caller is an owner). Safe to call repeatedly;
 * upserts every (host, user, agent, metric) row.
 */
export async function POST(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  let windowDays = 14;
  try {
    const body = await req.json();
    if (Number.isFinite(body?.windowDays)) windowDays = Math.min(Math.max(1, body.windowDays), 90);
  } catch { /* ignore body */ }

  const orgId = (session as any).user?.orgId ?? null;
  const result = await recomputeBaselines({ windowDays, orgId });
  return NextResponse.json(result);
}
