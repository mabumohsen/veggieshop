-- -----------------------------------------------------------------------------
-- VeggieShop :: Platform Infrastructure
-- Migration: V2__event_dedupe.sql
--
-- Purpose
--   Dedupe store for Kafka/event consumers to enforce idempotent side effects.
--   Keyed by (tenant_id, event_id, version) with a TTL. The consumer writes a
--   row before executing side effects; replays will find the existing row and
--   skip/short-circuit safely.
--
-- PRD v2.0 alignment
--   - Exactly-once (consumer level): dedupe store with replay fences & TTL (§11)
--   - Multi-tenancy: strict tenant scoping (§4)
--   - Operations/Housekeeping: TTL index and cleanup SLOs (§16)
--
-- Notes
--   - Keep this table lean: only technical fields, no PII.
--   - TTL: default policy ≥ 7d (configure via application). Cleanup job deletes
--     rows where expires_at < now().
--   - We intentionally avoid table partitioning here (volumes are moderate and
--     TTL is short). If needed, introduce RANGE partitioning by created_at in a
--     future migration without breaking the PK contract.
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS event_dedupe (
  tenant_id     TEXT        NOT NULL,                         -- tenant scope
  event_id      TEXT        NOT NULL,                         -- provider/event id (free-form; UUID or string)
  version       BIGINT      NOT NULL DEFAULT 0,               -- event version/fingerprint
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),           -- insert time (DB clock)
  expires_at    TIMESTAMPTZ NOT NULL,                         -- TTL cutoff for housekeeping

  -- Constraints
  CONSTRAINT pk_event_dedupe PRIMARY KEY (tenant_id, event_id, version),
  CONSTRAINT chk_event_dedupe_tenant_len CHECK (char_length(tenant_id) BETWEEN 1 AND 64),
  CONSTRAINT chk_event_dedupe_expires_after_created CHECK (expires_at > created_at)
);

-- -----------------------------------------------------------------------------
-- Indexes (support fast TTL cleanup and observability queries)
-- -----------------------------------------------------------------------------

-- TTL cleanup accelerator
CREATE INDEX IF NOT EXISTS idx_event_dedupe_expires_at
  ON event_dedupe (expires_at);

-- Operational visibility (how many entries per tenant / recent arrivals)
CREATE INDEX IF NOT EXISTS idx_event_dedupe_tenant_created
  ON event_dedupe (tenant_id, created_at DESC);

-- Optional helper: quick lookup by (tenant_id, event_id) regardless of version.
-- Useful when version is embedded in the event_id or not used.
CREATE INDEX IF NOT EXISTS idx_event_dedupe_tenant_event
  ON event_dedupe (tenant_id, event_id);

-- -----------------------------------------------------------------------------
-- Comments (documentation in catalog)
-- -----------------------------------------------------------------------------
COMMENT ON TABLE  event_dedupe IS 'Idempotent consumer dedupe store (tenant_id, event_id, version) with TTL. No PII.';
COMMENT ON COLUMN event_dedupe.tenant_id  IS 'Tenant scope. Enforced by application-level authZ and queries.';
COMMENT ON COLUMN event_dedupe.event_id   IS 'Provider event identifier (string/UUID).';
COMMENT ON COLUMN event_dedupe.version    IS 'Event version/fingerprint to fence replays.';
COMMENT ON COLUMN event_dedupe.created_at IS 'Insertion timestamp (DB clock).';
COMMENT ON COLUMN event_dedupe.expires_at IS 'Records older than this are eligible for deletion (TTL).';

-- -----------------------------------------------------------------------------
-- Housekeeping guidance (for reference; executed by application scheduler)
-- -----------------------------------------------------------------------------
-- DELETE FROM event_dedupe WHERE expires_at < now() LIMIT 10000;
-- Consider a scheduled job running at least hourly during peak ingestion,
-- with metrics on deleted row counts and table bloat.
