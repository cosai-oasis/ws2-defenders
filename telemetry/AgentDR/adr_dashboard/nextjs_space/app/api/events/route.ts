export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { prisma } from '@/lib/prisma';

export async function GET(req: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const eventType = url.searchParams.get('eventType');
  const riskLevel = url.searchParams.get('riskLevel');
  const agent = url.searchParams.get('agent');
  const source = url.searchParams.get('source');
  const search = url.searchParams.get('search');
  const startDate = url.searchParams.get('startDate');
  const endDate = url.searchParams.get('endDate');
  const classUid = url.searchParams.get('classUid');
  const aiOperation = url.searchParams.get('aiOperation');
  const provider = url.searchParams.get('provider');
  const model = url.searchParams.get('model');
  const page = parseInt(url.searchParams.get('page') ?? '1');
  const limit = parseInt(url.searchParams.get('limit') ?? '50');
  const sortBy = url.searchParams.get('sortBy') ?? 'timestamp';
  const sortOrder = url.searchParams.get('sortOrder') ?? 'desc';

  const where: any = {};
  if (eventType) where.eventType = eventType;
  if (riskLevel) where.riskLevel = riskLevel;
  if (agent) where.agentDetected = agent;
  if (source) where.source = source;
  if (classUid) where.classUid = parseInt(classUid);
  if (aiOperation) where.aiOperation = aiOperation;
  if (provider) where.provider = provider;
  if (model) where.model = model;
  if (startDate || endDate) {
    where.timestamp = {};
    if (startDate) where.timestamp.gte = new Date(startDate);
    if (endDate) where.timestamp.lte = new Date(endDate);
  }
  if (search) {
    where.OR = [
      { details: { contains: search } },
      { eventType: { contains: search } },
      { agentDetected: { contains: search } },
      { message: { contains: search } },
      { model: { contains: search } },
      { provider: { contains: search } },
    ];
  }

  try {
    const [events, total] = await Promise.all([
      prisma.event.findMany({
        where,
        orderBy: { [sortBy]: sortOrder },
        skip: (page - 1) * limit,
        take: limit,
      }),
      prisma.event.count({ where }),
    ]);
    return NextResponse.json({ events, total, page, limit, totalPages: Math.ceil(total / limit) });
  } catch (error: any) {
    return NextResponse.json({ error: error?.message ?? 'Server error' }, { status: 500 });
  }
}
