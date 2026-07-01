export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getSessionUser, isAdmin } from '@/lib/session-helpers';
import {
  loadConfig,
  saveConfig,
  maskConfig,
  applyMaskedSecrets,
  mergeConfig,
  defaultConfig,
  type LlmGuardConfig,
} from '@/lib/llm-guard-config';

// GET: return the persisted LLM Guard config (secrets masked).
export async function GET() {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const cfg = loadConfig();
  return NextResponse.json({ config: maskConfig(cfg), defaults: maskConfig(defaultConfig()) });
}

// POST: persist a new LLM Guard config. Admin/owner only.
export async function POST(req: NextRequest) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (!isAdmin(user)) {
    return NextResponse.json({ error: 'Admin access required' }, { status: 403 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const incoming = body?.config ?? body;
  if (!incoming || typeof incoming !== 'object') {
    return NextResponse.json({ error: 'Missing config object' }, { status: 400 });
  }

  // Validate backends minimally.
  if (Array.isArray(incoming.backends)) {
    for (const b of incoming.backends) {
      if (!b?.name || !b?.url) {
        return NextResponse.json(
          { error: 'Each backend requires a name and url' },
          { status: 400 },
        );
      }
    }
  }

  const stored = loadConfig();
  const merged: LlmGuardConfig = mergeConfig(defaultConfig(), incoming);
  const withSecrets = applyMaskedSecrets(merged, stored);
  const saved = saveConfig(withSecrets);

  return NextResponse.json({ config: maskConfig(saved), saved: true });
}
