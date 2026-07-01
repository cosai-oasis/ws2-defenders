import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';

export interface SessionUser {
  id: string;
  email: string;
  name?: string;
  role: string;     // owner | admin | analyst | viewer
  orgId: string | null;
}

export async function getSessionUser(): Promise<SessionUser | null> {
  const session = await getServerSession(authOptions);
  if (!session?.user) return null;
  const u = session.user as any;
  return {
    id: u.id,
    email: u.email ?? '',
    name: u.name ?? undefined,
    role: u.role ?? 'analyst',
    orgId: u.orgId ?? null,
  };
}

export function isAdmin(user: SessionUser): boolean {
  return user.role === 'owner' || user.role === 'admin';
}

export function isOwner(user: SessionUser): boolean {
  return user.role === 'owner';
}
