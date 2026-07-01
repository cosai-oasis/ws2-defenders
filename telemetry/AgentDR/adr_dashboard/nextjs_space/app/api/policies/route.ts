export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getSessionUser, isAdmin } from '@/lib/session-helpers';

// GET: Fetch policies (org-level if in org, global otherwise)
export async function GET() {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  // Fetch org-specific policies if in org, otherwise global (orgId=null)
  const orgId = user.orgId;
  let policies = await prisma.policy.findMany({
    where: { orgId: orgId ?? undefined },
    orderBy: { ruleId: 'asc' },
  });

  // If in org but no org-level policies yet, fall back to global
  if (orgId && policies.length === 0) {
    policies = await prisma.policy.findMany({
      where: { orgId: null },
      orderBy: { ruleId: 'asc' },
    });
  }

  return NextResponse.json({
    policies: policies.map((p: any) => ({
      ...p,
      threshold: p.threshold ? JSON.parse(p.threshold) : {},
    })),
  });
}

// PATCH: Update a policy's settings
export async function PATCH(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (!isAdmin(user)) return NextResponse.json({ error: 'Admin access required' }, { status: 403 });

  const body = await req.json();
  const { id, enabled, severity, threshold, action } = body;
  if (!id) return NextResponse.json({ error: 'Policy ID required' }, { status: 400 });

  const policy = await prisma.policy.findUnique({ where: { id } });
  if (!policy) return NextResponse.json({ error: 'Policy not found' }, { status: 404 });

  // If updating a global policy while in an org, create an org-specific copy
  if (policy.orgId === null && user.orgId) {
    const orgPolicy = await prisma.policy.create({
      data: {
        name: policy.name,
        ruleId: policy.ruleId,
        enabled: enabled !== undefined ? enabled : policy.enabled,
        severity: severity || policy.severity,
        threshold: threshold !== undefined ? JSON.stringify(threshold) : policy.threshold,
        action: action || policy.action,
        orgId: user.orgId,
      },
    }).catch(() => null);
    if (orgPolicy) {
      return NextResponse.json({ policy: { ...orgPolicy, threshold: orgPolicy.threshold ? JSON.parse(orgPolicy.threshold) : {} } });
    }
  }

  const updateData: any = {};
  if (enabled !== undefined) updateData.enabled = enabled;
  if (severity) updateData.severity = severity;
  if (threshold !== undefined) updateData.threshold = JSON.stringify(threshold);
  if (action) updateData.action = action;

  const updated = await prisma.policy.update({ where: { id }, data: updateData });
  return NextResponse.json({ policy: { ...updated, threshold: updated.threshold ? JSON.parse(updated.threshold) : {} } });
}
