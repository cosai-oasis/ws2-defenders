export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { getSessionUser, isAdmin } from '@/lib/session-helpers';

// GET: Fetch storage config
export async function GET() {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  // Look for org-specific config first, then global
  let config = user.orgId
    ? await prisma.storageConfig.findFirst({ where: { orgId: user.orgId } })
    : await prisma.storageConfig.findFirst({ where: { orgId: null } });

  if (!config) {
    config = await prisma.storageConfig.findFirst({ where: { orgId: null } });
  }

  // Compute current storage usage estimate
  const eventCount = await prisma.event.count({
    where: user.orgId ? { orgId: user.orgId } : {},
  });
  const alertCount = await prisma.alert.count({
    where: user.orgId ? { orgId: user.orgId } : {},
  });
  // Rough estimate: ~2KB per event, ~1KB per alert
  const estimatedUsageMb = Math.round((eventCount * 2 + alertCount * 1) / 1024 * 100) / 100;

  return NextResponse.json({
    config: config ?? {
      retentionDays: 90,
      maxStorageMb: 5000,
      archiveEnabled: false,
      archiveAfterDays: 30,
      exportFormat: 'jsonl',
      autoCleanup: true,
    },
    usage: {
      eventCount,
      alertCount,
      estimatedUsageMb,
    },
  });
}

// PATCH: Update storage config
export async function PATCH(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (!isAdmin(user)) return NextResponse.json({ error: 'Admin access required' }, { status: 403 });

  const body = await req.json();
  const {
    retentionDays,
    maxStorageMb,
    archiveEnabled,
    archiveAfterDays,
    exportFormat,
    autoCleanup,
  } = body;

  const orgId = user.orgId;

  // Find or create storage config for scope
  let config = await prisma.storageConfig.findFirst({ where: { orgId: orgId ?? undefined } });

  // For individual users without org, use global (orgId=null)
  if (!config && !orgId) {
    config = await prisma.storageConfig.findFirst({ where: { orgId: null } });
  }

  const updateData: any = {};
  if (retentionDays !== undefined) updateData.retentionDays = retentionDays;
  if (maxStorageMb !== undefined) updateData.maxStorageMb = maxStorageMb;
  if (archiveEnabled !== undefined) updateData.archiveEnabled = archiveEnabled;
  if (archiveAfterDays !== undefined) updateData.archiveAfterDays = archiveAfterDays;
  if (exportFormat !== undefined) updateData.exportFormat = exportFormat;
  if (autoCleanup !== undefined) updateData.autoCleanup = autoCleanup;

  if (config) {
    const updated = await prisma.storageConfig.update({ where: { id: config.id }, data: updateData });
    return NextResponse.json({ config: updated });
  }

  // Create new config for this scope
  const created = await prisma.storageConfig.create({
    data: {
      retentionDays: retentionDays ?? 90,
      maxStorageMb: maxStorageMb ?? 5000,
      archiveEnabled: archiveEnabled ?? false,
      archiveAfterDays: archiveAfterDays ?? 30,
      exportFormat: exportFormat ?? 'jsonl',
      autoCleanup: autoCleanup ?? true,
      orgId: orgId ?? null,
    },
  });
  return NextResponse.json({ config: created });
}
