export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import path from 'path';

/**
 * CoSAI Community Rules — integrity status & on-demand update API.
 *
 * GET  → returns integrity status (hashes, versions, file list)
 * POST → triggers rule update (download + verify from remote)
 */

const RULE_FILES = [
  'rules/agent-signatures.json',
  'rules/ai-endpoints.json',
  'rules/messaging-endpoints.json',
  'policies/detection-rules.json',
];

const MANIFEST_FILE = 'checksums.sha256';

function communityDir(): string {
  // Try relative to project (works in both dev and production)
  const candidates = [
    path.join(process.cwd(), 'data', 'cosai-community'),
    path.join(__dirname, '..', '..', '..', '..', 'data', 'cosai-community'),
  ];
  for (const dir of candidates) {
    if (existsSync(path.join(dir, MANIFEST_FILE))) return dir;
  }
  return candidates[0]; // fallback
}

function sha256File(filepath: string): string {
  try {
    const data = readFileSync(filepath);
    return createHash('sha256').update(data).digest('hex');
  } catch {
    return '';
  }
}

function loadManifest(dir: string): Record<string, string> {
  const manifestPath = path.join(dir, MANIFEST_FILE);
  if (!existsSync(manifestPath)) return {};
  const text = readFileSync(manifestPath, 'utf-8');
  const result: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      result[parts.slice(1).join(' ').trim()] = parts[0].trim();
    }
  }
  return result;
}

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const dir = communityDir();
  const manifest = loadManifest(dir);
  let allOk = true;

  const files = RULE_FILES.map((relpath) => {
    const filepath = path.join(dir, relpath);
    const expected = manifest[relpath] || '';
    if (!existsSync(filepath)) {
      allOk = false;
      return { file: relpath, status: 'missing', hash: '' };
    }
    const actual = sha256File(filepath);
    const ok = actual === expected;
    if (!ok) allOk = false;
    return {
      file: relpath,
      status: ok ? 'ok' : 'mismatch',
      hash: actual.slice(0, 16),
    };
  });

  // Read version from agent-signatures
  let version = 'unknown';
  try {
    const sigPath = path.join(dir, 'rules/agent-signatures.json');
    const data = JSON.parse(readFileSync(sigPath, 'utf-8'));
    version = data.version || 'unknown';
  } catch {}

  // Count agents
  let agentCount = 0;
  try {
    const sigPath = path.join(dir, 'rules/agent-signatures.json');
    const data = JSON.parse(readFileSync(sigPath, 'utf-8'));
    agentCount = data.signatures?.length || 0;
  } catch {}

  const remoteUrl = process.env.COSAI_RULES_URL ||
    'https://raw.githubusercontent.com/girdav01/aitf/main/cosai-community';

  return NextResponse.json({
    integrity: allOk ? 'ok' : 'failed',
    version,
    agentCount,
    files,
    remoteUrl,
    communityDir: dir,
    schedule: {
      enabled: true,
      interval: '24h',
      time: '01:00 UTC',
    },
  });
}

export async function POST(request: NextRequest) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const user = session.user as any;
  if (user?.role !== 'owner' && user?.role !== 'admin') {
    return NextResponse.json({ error: 'Admin access required' }, { status: 403 });
  }

  const remoteUrl = (
    process.env.COSAI_RULES_URL ||
    'https://raw.githubusercontent.com/girdav01/aitf/main/cosai-community'
  ).replace(/\/$/, '');

  const dir = communityDir();

  try {
    // 1. Download manifest
    const manifestResp = await fetch(`${remoteUrl}/${MANIFEST_FILE}`, {
      headers: { 'User-Agent': 'CoSAI-ADR-Dashboard/1.0' },
      signal: AbortSignal.timeout(30000),
    });
    if (!manifestResp.ok) {
      return NextResponse.json({
        status: 'error',
        error: `Failed to download manifest: HTTP ${manifestResp.status}`,
      });
    }
    const manifestText = await manifestResp.text();
    const newManifest: Record<string, string> = {};
    for (const line of manifestText.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        newManifest[parts.slice(1).join(' ').trim()] = parts[0].trim();
      }
    }

    // Check if anything changed
    const oldManifest = loadManifest(dir);
    const changed = RULE_FILES.some((f) => newManifest[f] !== oldManifest[f]);
    if (!changed) {
      return NextResponse.json({ status: 'up_to_date', updated: [] });
    }

    // 2. Download + verify each file
    const updated: string[] = [];
    const failures: string[] = [];

    for (const relpath of RULE_FILES) {
      const url = `${remoteUrl}/${relpath}`;
      const resp = await fetch(url, {
        headers: { 'User-Agent': 'CoSAI-ADR-Dashboard/1.0' },
        signal: AbortSignal.timeout(30000),
      });
      if (!resp.ok) {
        failures.push(`${relpath}: HTTP ${resp.status}`);
        continue;
      }
      const buffer = Buffer.from(await resp.arrayBuffer());
      const actual = createHash('sha256').update(buffer).digest('hex');
      const expected = newManifest[relpath];
      if (expected && actual !== expected) {
        failures.push(
          `${relpath}: hash mismatch (expected ${expected.slice(0, 16)}… got ${actual.slice(0, 16)}…)`
        );
        continue;
      }

      // Write verified file
      const { writeFileSync, mkdirSync } = await import('fs');
      const destPath = path.join(dir, relpath);
      mkdirSync(path.dirname(destPath), { recursive: true });
      writeFileSync(destPath, buffer);
      updated.push(relpath);
    }

    if (failures.length > 0) {
      return NextResponse.json({
        status: 'integrity_failed',
        errors: failures,
      });
    }

    // Write new manifest
    const { writeFileSync: ws } = await import('fs');
    ws(path.join(dir, MANIFEST_FILE), manifestText);

    return NextResponse.json({ status: 'updated', updated });
  } catch (err: any) {
    return NextResponse.json({
      status: 'error',
      error: err?.message || 'Unknown error',
    });
  }
}
