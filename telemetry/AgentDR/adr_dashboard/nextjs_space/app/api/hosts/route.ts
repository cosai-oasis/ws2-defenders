export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { prisma } from '@/lib/prisma';

/** GET /api/hosts — registry of every endpoint that has reported events. */
export async function GET(_req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const hosts = await prisma.host.findMany({
    orderBy: { lastSeen: 'desc' },
    take: 500,
  });
  return NextResponse.json({ hosts });
}
