export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { prisma } from '@/lib/prisma';

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const severity = url.searchParams.get('severity');
  const resolved = url.searchParams.get('resolved');

  const where: any = {};
  if (severity) where.severity = severity;
  if (resolved !== null && resolved !== undefined && resolved !== '') where.resolved = resolved === 'true';

  try {
    const alerts = await prisma.alert.findMany({
      where,
      orderBy: { timestamp: 'desc' },
    });
    return NextResponse.json({ alerts });
  } catch (error: any) {
    return NextResponse.json({ error: error?.message ?? 'Server error' }, { status: 500 });
  }
}

export async function PATCH(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  try {
    const { id, resolved } = await req.json();
    const alert = await prisma.alert.update({
      where: { id },
      data: { resolved },
    });
    return NextResponse.json({ alert });
  } catch (error: any) {
    return NextResponse.json({ error: error?.message ?? 'Server error' }, { status: 500 });
  }
}
