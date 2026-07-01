export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getSessionUser, isAdmin, isOwner } from '@/lib/session-helpers';

// GET: Fetch current user's organization info
export async function GET() {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  if (!user.orgId) {
    // Individual mode — return stub
    return NextResponse.json({
      mode: 'individual',
      org: null,
      members: [],
    });
  }

  const org = await prisma.organization.findUnique({
    where: { id: user.orgId },
    include: {
      users: { select: { id: true, name: true, email: true, role: true, createdAt: true } },
    },
  });

  return NextResponse.json({
    mode: 'organization',
    org: org ? {
      id: org.id,
      name: org.name,
      slug: org.slug,
      plan: org.plan,
      settings: org.settings ? JSON.parse(org.settings) : {},
      createdAt: org.createdAt,
    } : null,
    members: org?.users ?? [],
  });
}

// POST: Create an organization (individual → org upgrade)
export async function POST(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  if (user.orgId) {
    return NextResponse.json({ error: 'Already in an organization' }, { status: 400 });
  }

  const body = await req.json();
  const { name, plan } = body;
  if (!name) return NextResponse.json({ error: 'Organization name required' }, { status: 400 });

  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

  // Check slug uniqueness
  const existing = await prisma.organization.findUnique({ where: { slug } });
  if (existing) return NextResponse.json({ error: 'Organization slug already taken' }, { status: 400 });

  const org = await prisma.organization.create({
    data: {
      name,
      slug,
      plan: plan || 'team',
      settings: JSON.stringify({ notifications: true, twoFactor: false }),
    },
  });

  // Create default storage config for org
  await prisma.storageConfig.create({
    data: {
      retentionDays: 90,
      maxStorageMb: 10000,
      archiveEnabled: false,
      archiveAfterDays: 30,
      exportFormat: 'jsonl',
      autoCleanup: true,
      orgId: org.id,
    },
  }).catch(() => {});

  // Create org-level default policies by copying global policies
  const globalPolicies = await prisma.policy.findMany({ where: { orgId: null } });
  for (const gp of globalPolicies) {
    await prisma.policy.create({
      data: {
        name: gp.name,
        ruleId: gp.ruleId,
        enabled: gp.enabled,
        severity: gp.severity,
        threshold: gp.threshold,
        action: gp.action,
        orgId: org.id,
      },
    }).catch(() => {});
  }

  // Update user → owner of org
  await prisma.user.update({
    where: { id: user.id },
    data: { orgId: org.id, role: 'owner' },
  });

  return NextResponse.json({ org: { id: org.id, name: org.name, slug: org.slug, plan: org.plan } });
}

// PATCH: Update organization settings
export async function PATCH(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (!user.orgId) return NextResponse.json({ error: 'Not in an organization' }, { status: 400 });
  if (!isAdmin(user)) return NextResponse.json({ error: 'Admin access required' }, { status: 403 });

  const body = await req.json();
  const { name, plan, settings } = body;

  const updateData: any = {};
  if (name) updateData.name = name;
  if (plan) updateData.plan = plan;
  if (settings) updateData.settings = JSON.stringify(settings);

  const org = await prisma.organization.update({
    where: { id: user.orgId },
    data: updateData,
  });

  return NextResponse.json({ org: { id: org.id, name: org.name, slug: org.slug, plan: org.plan } });
}
