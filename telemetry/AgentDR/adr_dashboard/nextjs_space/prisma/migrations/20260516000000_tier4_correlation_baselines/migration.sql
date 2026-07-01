-- Tier 4 — multi-host correlation + UEBA baselines.
--
-- Apply with `prisma migrate deploy` (production) or `prisma migrate dev`
-- (development). Idempotent: every table / column / index uses IF NOT EXISTS.

-- ── Denormalised correlation columns on Event ─────────────────────────────
ALTER TABLE "Event" ADD COLUMN IF NOT EXISTS "hostName" TEXT;
ALTER TABLE "Event" ADD COLUMN IF NOT EXISTS "userName" TEXT;

CREATE INDEX IF NOT EXISTS "Event_traceId_idx"  ON "Event"("traceId");
CREATE INDEX IF NOT EXISTS "Event_hostName_idx" ON "Event"("hostName");
CREATE INDEX IF NOT EXISTS "Event_userName_idx" ON "Event"("userName");

-- ── Host registry ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS "Host" (
    "id"        TEXT NOT NULL,
    "hostname"  TEXT NOT NULL,
    "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen"  TIMESTAMP(3) NOT NULL,
    "os"        TEXT,
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "metadata"  TEXT,
    "orgId"     TEXT,
    CONSTRAINT "Host_pkey"          PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX IF NOT EXISTS "Host_hostname_key" ON "Host"("hostname");
CREATE INDEX IF NOT EXISTS "Host_orgId_idx"    ON "Host"("orgId");
CREATE INDEX IF NOT EXISTS "Host_lastSeen_idx" ON "Host"("lastSeen");

-- ── Per-(host, user, agent, metric) baseline ──────────────────────────────
CREATE TABLE IF NOT EXISTS "Baseline" (
    "id"          TEXT NOT NULL,
    "hostId"      TEXT,
    "userName"    TEXT,
    "agentName"   TEXT,
    "metric"      TEXT NOT NULL,
    "windowDays"  INTEGER NOT NULL DEFAULT 14,
    "sampleCount" INTEGER NOT NULL DEFAULT 0,
    "mean"        DOUBLE PRECISION NOT NULL DEFAULT 0,
    "stdev"       DOUBLE PRECISION NOT NULL DEFAULT 0,
    "p50"         DOUBLE PRECISION NOT NULL DEFAULT 0,
    "p95"         DOUBLE PRECISION NOT NULL DEFAULT 0,
    "p99"         DOUBLE PRECISION NOT NULL DEFAULT 0,
    "lastValue"   DOUBLE PRECISION NOT NULL DEFAULT 0,
    "computedAt"  TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "orgId"       TEXT,
    CONSTRAINT "Baseline_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "Baseline_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "Host"("id") ON DELETE SET NULL ON UPDATE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS "Baseline_host_user_agent_metric_key"
    ON "Baseline"("hostId", "userName", "agentName", "metric");
CREATE INDEX IF NOT EXISTS "Baseline_orgId_idx"  ON "Baseline"("orgId");
CREATE INDEX IF NOT EXISTS "Baseline_metric_idx" ON "Baseline"("metric");

-- ── UEBA per-event score ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS "UebaScore" (
    "id"            TEXT NOT NULL,
    "eventId"       TEXT,
    "traceId"       TEXT,
    "userName"      TEXT,
    "agentName"     TEXT,
    "metric"        TEXT NOT NULL,
    "observed"      DOUBLE PRECISION NOT NULL,
    "baselineMean"  DOUBLE PRECISION NOT NULL,
    "baselineStdev" DOUBLE PRECISION NOT NULL,
    "zScore"        DOUBLE PRECISION NOT NULL,
    "computedAt"    TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "orgId"         TEXT,
    CONSTRAINT "UebaScore_pkey" PRIMARY KEY ("id")
);
CREATE INDEX IF NOT EXISTS "UebaScore_traceId_idx" ON "UebaScore"("traceId");
CREATE INDEX IF NOT EXISTS "UebaScore_zScore_idx"  ON "UebaScore"("zScore");
CREATE INDEX IF NOT EXISTS "UebaScore_orgId_idx"   ON "UebaScore"("orgId");
