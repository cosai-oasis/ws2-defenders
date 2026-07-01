export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { prisma } from '@/lib/prisma';

/** GET /api/baselines — list current UEBA baselines (optionally per metric). */
export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const metric = url.searchParams.get('metric');
  const where: any = {};
  if (metric) where.metric = metric;

  const baselines = await prisma.baseline.findMany({
    where,
    orderBy: [{ metric: 'asc' }, { mean: 'desc' }],
    take: 1000,
    include: { host: { select: { hostname: true } } },
  });
  return NextResponse.json({ baselines });
}
