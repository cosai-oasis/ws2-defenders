export const dynamic = 'force-dynamic';
import { NextResponse } from 'next/server';
import { getSessionUser } from '@/lib/session-helpers';
import { loadConfig, type BackendConfig } from '@/lib/llm-guard-config';

interface BackendHealth {
  name: string;
  kind: string;
  url: string;
  route_prefix: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  httpStatus: number | null;
  latencyMs: number | null;
  checkedAt: string;
  detail: string | null;
}

async function probe(backend: BackendConfig, timeoutMs: number): Promise<BackendHealth> {
  const base = (backend.url || '').replace(/\/+$/, '');
  const healthPath = backend.health_path || '/health';
  const target = `${base}${healthPath.startsWith('/') ? '' : '/'}${healthPath}`;
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const result: BackendHealth = {
    name: backend.name,
    kind: backend.kind,
    url: backend.url,
    route_prefix: backend.route_prefix,
    status: 'unknown',
    httpStatus: null,
    latencyMs: null,
    checkedAt: new Date().toISOString(),
    detail: null,
  };

  try {
    const res = await fetch(target, { method: 'GET', signal: controller.signal, cache: 'no-store' });
    result.latencyMs = Date.now() - started;
    result.httpStatus = res.status;
    result.status = res.ok ? 'healthy' : 'unhealthy';
    if (!res.ok) result.detail = `HTTP ${res.status}`;
  } catch (e: any) {
    result.latencyMs = Date.now() - started;
    result.status = 'unhealthy';
    result.detail = e?.name === 'AbortError' ? 'timeout' : (e?.message ?? 'connection failed');
  } finally {
    clearTimeout(timer);
  }
  return result;
}

// GET: probe every configured backend and report health.
export async function GET() {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const cfg = loadConfig();
  const timeoutMs = Math.min(Math.max((cfg.upstream_timeout_seconds || 5) * 1000, 1000), 10000);

  const backends = await Promise.all(cfg.backends.map((b) => probe(b, timeoutMs)));
  const healthy = backends.filter((b) => b.status === 'healthy').length;

  return NextResponse.json({
    enabled: cfg.enabled,
    listenAddress: cfg.listen_address,
    healthCheckIntervalSeconds: cfg.health_check_interval_seconds,
    summary: {
      total: backends.length,
      healthy,
      unhealthy: backends.length - healthy,
    },
    backends,
    checkedAt: new Date().toISOString(),
  });
}
