export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { prisma } from '@/lib/prisma';

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const limit = parseInt(url.searchParams.get('limit') ?? '20');

  try {
    const events = await prisma.event.findMany({
      orderBy: { timestamp: 'desc' },
      take: limit,
    });
    return NextResponse.json({ events });
  } catch (error: any) {
    return NextResponse.json({ error: error?.message ?? 'Server error' }, { status: 500 });
  }
}
