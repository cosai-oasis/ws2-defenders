export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { prisma } from '@/lib/prisma';
import { getSessionUser, isAdmin, isOwner } from '@/lib/session-helpers';

// GET: List users (org members or self for individual)
export async function GET() {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  if (user.orgId) {
    // Org mode: admins see all members, others see just themselves
    if (isAdmin(user)) {
      const members = await prisma.user.findMany({
        where: { orgId: user.orgId },
        select: { id: true, name: true, email: true, role: true, createdAt: true },
        orderBy: { createdAt: 'asc' },
      });
      return NextResponse.json({ users: members });
    }
  }

  // Individual or non-admin: return self
  const self = await prisma.user.findUnique({
    where: { id: user.id },
    select: { id: true, name: true, email: true, role: true, createdAt: true },
  });
  return NextResponse.json({ users: self ? [self] : [] });
}

// POST: Invite / add a user to the organization
export async function POST(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (!user.orgId) return NextResponse.json({ error: 'Organization required to add users' }, { status: 400 });
  if (!isAdmin(user)) return NextResponse.json({ error: 'Admin access required' }, { status: 403 });

  const body = await req.json();
  const { email, name, role, password } = body;
  if (!email) return NextResponse.json({ error: 'Email required' }, { status: 400 });

  // Check if user already exists
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    if (existing.orgId === user.orgId) {
      return NextResponse.json({ error: 'User already in organization' }, { status: 400 });
    }
    // Add existing user to org
    await prisma.user.update({
      where: { id: existing.id },
      data: { orgId: user.orgId, role: role || 'analyst' },
    });
    return NextResponse.json({ message: 'User added to organization', userId: existing.id });
  }

  // Create new user in org
  const tempPassword = password || Math.random().toString(36).slice(-10);
  const hashed = await bcrypt.hash(tempPassword, 10);
  const newUser = await prisma.user.create({
    data: {
      email,
      password: hashed,
      name: name || email.split('@')[0],
      role: role || 'analyst',
      orgId: user.orgId,
    },
  });

  return NextResponse.json({
    message: 'User created and added to organization',
    userId: newUser.id,
    tempPassword: password ? undefined : tempPassword,
  });
}

// PATCH: Update a user's role
export async function PATCH(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const body = await req.json();
  const { userId, role, name } = body;

  // Users can update their own name
  if (!userId || userId === user.id) {
    const updateData: any = {};
    if (name !== undefined) updateData.name = name;
    if (Object.keys(updateData).length > 0) {
      await prisma.user.update({ where: { id: user.id }, data: updateData });
    }
    return NextResponse.json({ message: 'Profile updated' });
  }

  // Role changes require admin
  if (!isAdmin(user)) return NextResponse.json({ error: 'Admin access required' }, { status: 403 });

  // Cannot change owner role unless you are the owner
  const target = await prisma.user.findUnique({ where: { id: userId } });
  if (!target) return NextResponse.json({ error: 'User not found' }, { status: 404 });
  if (target.role === 'owner' && !isOwner(user)) {
    return NextResponse.json({ error: 'Only owners can modify owner role' }, { status: 403 });
  }

  const updateData: any = {};
  if (role) updateData.role = role;
  if (name !== undefined) updateData.name = name;
  await prisma.user.update({ where: { id: userId }, data: updateData });

  return NextResponse.json({ message: 'User updated' });
}

// DELETE: Remove a user from the organization
export async function DELETE(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (!isAdmin(user)) return NextResponse.json({ error: 'Admin access required' }, { status: 403 });

  const { searchParams } = new URL(req.url);
  const userId = searchParams.get('userId');
  if (!userId) return NextResponse.json({ error: 'userId required' }, { status: 400 });
  if (userId === user.id) return NextResponse.json({ error: 'Cannot remove yourself' }, { status: 400 });

  const target = await prisma.user.findUnique({ where: { id: userId } });
  if (!target) return NextResponse.json({ error: 'User not found' }, { status: 404 });
  if (target.role === 'owner') return NextResponse.json({ error: 'Cannot remove the owner' }, { status: 403 });

  // Remove from org (don't delete the user — just unlink)
  await prisma.user.update({ where: { id: userId }, data: { orgId: null, role: 'analyst' } });
  return NextResponse.json({ message: 'User removed from organization' });
}
