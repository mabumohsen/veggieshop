-- -----------------------------------------------------------------------------
-- VeggieShop :: Platform Infrastructure
-- Migration: V3__outbox.sql
--
-- Purpose
--   Transactional Outbox table for reliable event publication to Kafka.
--   Records are written in the same DB transaction as domain changes and
--   drained with: SELECT ... FOR UPDATE SKIP LOCKED ORDER BY created_at ASC.
--
-- PRD v2.0 alignment
--   - Exactly-once (producer side): transactional outbox + reliable drain (§11)
--   - Performance & SLOs: FIFO ordering by created_at; SKIP LOCKED friendly (§16)
--   - Multi-tenancy: strict tenant scoping; topic & headers without PII (§4, §15)
--
-- Notes
--   - Keep payloads PII-free (store references like piiRef instead).
--   - Consider a scheduled purge for published rows (see housekeeping section).
--   - Optional: enable gen_random_uuid() via pgcrypto if you want DB-side UUIDs.
--     CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS outbox (
  -- Identity
  id              UUID        NOT NULL PRIMARY KEY,
  tenant_id       TEXT        NOT NULL,                         -- tenant scope (authZ enforced in app)
  topic           TEXT        NOT NULL,                         -- logical destination (Kafka topic)

  -- Optional routing/diagnostics (no PII)
  event_key       TEXT,                                         -- partitioning key
  aggregate_type  TEXT,                                         -- e.g., Order, InventoryBatch
  aggregate_id    TEXT,                                         -- e.g., orderId
  event_type      TEXT,                                         -- domain event name
  entity_version  BIGINT,                                       -- x-entity-version at write time

  -- Message content
  payload         JSONB       NOT NULL,                         -- contracted payload (PII-free)
  headers         JSONB,                                        -- optional producer headers/extensions

  -- Timing & state
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),           -- insert time (DB clock)
  available_at    TIMESTAMPTZ NOT NULL DEFAULT now(),           -- eligible for drain when <= now()
  published_at    TIMESTAMPTZ,                                  -- set on success

  status          VARCHAR(24) NOT NULL,                         -- PENDING | PUBLISHED | QUARANTINED
  attempts        INT         NOT NULL DEFAULT 0,               -- publish attempts
  last_error      VARCHAR(2048),                                 -- truncated last error (diagnostics)

  -- Optimistic locking (JPA @Version)
  row_version     BIGINT      NOT NULL DEFAULT 0,

  -- Constraints (keep portable, avoid custom enum types)
  CONSTRAINT chk_outbox_status CHECK (status IN ('PENDING','PUBLISHED','QUARANTINED')),
  CONSTRAINT chk_outbox_tenant_len CHECK (char_length(tenant_id) BETWEEN 1 AND 64),
  CONSTRAINT chk_outbox_topic_len  CHECK (char_length(topic) BETWEEN 1 AND 200),
  CONSTRAINT chk_outbox_attempts   CHECK (attempts >= 0),
  CONSTRAINT chk_outbox_avail_after_created CHECK (available_at >= created_at)
);

-- -----------------------------------------------------------------------------
-- Indexes
-- -----------------------------------------------------------------------------

-- Fast queue scan for drainers: eligible PENDING rows by availability then FIFO by created_at.
CREATE INDEX IF NOT EXISTS idx_outbox_pending_available
  ON outbox (available_at, created_at)
  WHERE status = 'PENDING';

-- Tenant/topic locality (useful for sharded/tenant-specific publishers and observability).
CREATE INDEX IF NOT EXISTS idx_outbox_tenant_topic
  ON outbox (tenant_id, topic);

-- Operational analytics / cleanup for published rows.
CREATE INDEX IF NOT EXISTS idx_outbox_published_at
  ON outbox (published_at);

-- Optional: speed up FIFO ordering in rare cases where the partial index above
-- is insufficient due to planner choices.
CREATE INDEX IF NOT EXISTS idx_outbox_created_at
  ON outbox (created_at);

-- -----------------------------------------------------------------------------
-- Catalog comments (self-documenting schema)
-- -----------------------------------------------------------------------------
COMMENT ON TABLE  outbox IS 'Transactional outbox (tenant-scoped) for reliable event publishing. PII-free payloads.';
COMMENT ON COLUMN outbox.id             IS 'Record identifier (UUID).';
COMMENT ON COLUMN outbox.tenant_id      IS 'Tenant scope; app enforces isolation.';
COMMENT ON COLUMN outbox.topic          IS 'Logical destination (Kafka topic).';
COMMENT ON COLUMN outbox.event_key      IS 'Partitioning key for Kafka (optional).';
COMMENT ON COLUMN outbox.aggregate_type IS 'Aggregate type for diagnostics (e.g., Order).';
COMMENT ON COLUMN outbox.aggregate_id   IS 'Aggregate id for diagnostics/ordering.';
COMMENT ON COLUMN outbox.event_type     IS 'Domain event type (contract family/name).';
COMMENT ON COLUMN outbox.entity_version IS 'Entity version at write time (for X-Entity-Version headers).';
COMMENT ON COLUMN outbox.payload        IS 'Contracted JSON payload (jsonb). No PII.';
COMMENT ON COLUMN outbox.headers        IS 'Optional producer headers/extensions (jsonb).';
COMMENT ON COLUMN outbox.created_at     IS 'Insert timestamp (DB clock).';
COMMENT ON COLUMN outbox.available_at   IS 'Eligible for drain when <= now(); supports scheduled/delayed publishing.';
COMMENT ON COLUMN outbox.published_at   IS 'Set on successful publish.';
COMMENT ON COLUMN outbox.status         IS 'PENDING | PUBLISHED | QUARANTINED.';
COMMENT ON COLUMN outbox.attempts       IS 'Publish attempt counter.';
COMMENT ON COLUMN outbox.last_error     IS 'Last error message (truncated to 2048 chars) for diagnostics.';
COMMENT ON COLUMN outbox.row_version    IS 'Optimistic lock counter (@Version).';

-- -----------------------------------------------------------------------------
-- Housekeeping guidance (executed by application scheduler / ops jobs)
-- -----------------------------------------------------------------------------
-- -- Example purge of old published rows (tune retention per environment):
-- DELETE FROM outbox
--  WHERE status = 'PUBLISHED'
--    AND published_at < now() - interval '7 days'
--  LIMIT 10000;
--
-- -- Drainer selection (reference for app logic):
-- -- SELECT * FROM outbox
-- --  WHERE status = 'PENDING' AND available_at <= now()
-- --  ORDER BY created_at ASC
-- --  FOR UPDATE SKIP LOCKED
-- --  LIMIT :batch;
