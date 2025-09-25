-- -----------------------------------------------------------------------------
-- VeggieShop :: Platform Infrastructure
-- Migration: V1__idempotency.sql
--
-- Purpose
--   Idempotency store for HTTP mutating endpoints. Stores a canonical request
--   fingerprint and a response snapshot to guarantee "same request → same effect".
--
-- PRD v2.0 alignment
--   - Required for all mutating HTTP APIs (PRD §10)
--   - Monthly partitioning and TTL housekeeping (PRD §10, §16)
--   - No PII leakage in logs; response JSON kept in DB only (PRD §15, §17)
--
-- Notes
--   - Logical table name is "idempotency"; monthly partitions are created under
--     the pattern idempotency_YYYY_MM and are RANGE partitions by created_at.
--   - Uniqueness is enforced per-partition on (tenant_id, key). This works with
--     INSERT ... ON CONFLICT DO NOTHING used by the application layer.
--   - Keep the payload compact; avoid storing large blobs (use object storage instead).
-- -----------------------------------------------------------------------------

-- Parent partitioned table (no global PK because Postgres requires partition key
-- columns in UNIQUE/PK at the parent level; we enforce uniqueness per-partition).
CREATE TABLE IF NOT EXISTS idempotency
(
  tenant_id     TEXT        NOT NULL,                               -- tenant scope
  key           UUID        NOT NULL,                               -- idempotency key (UUID from client)
  request_hash  TEXT        NOT NULL,                               -- hex SHA-256 (method+path+canonical body)
  http_method   VARCHAR(10) NOT NULL,                               -- e.g., POST, PATCH
  http_path     VARCHAR(512) NOT NULL,                              -- normalized path template (no volatile query)
  response_json JSONB       NOT NULL,                               -- response snapshot (Problem+JSON or 2xx body)
  status_code   INT         NOT NULL,                               -- HTTP status of the original response
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),                 -- insert time (DB clock)
  expires_at    TIMESTAMPTZ NOT NULL,                               -- TTL cutoff (housekeeping deletes after)
  row_version   BIGINT      NOT NULL DEFAULT 0,                     -- optimistic lock (@Version)

  -- Basic sanity checks (portable)
  CONSTRAINT chk_idem_tenant_len   CHECK (char_length(tenant_id) BETWEEN 1 AND 64),
  CONSTRAINT chk_idem_status_code  CHECK (status_code BETWEEN 100 AND 599),
  CONSTRAINT chk_idem_expiry       CHECK (expires_at > created_at)
)
PARTITION BY RANGE (created_at);

-- Helpful partitioned indexes (metadata only; child indexes will be created in the DO block)
-- (Create declarative "partitioned indexes" for logical visibility; concrete indexes are attached per partition.)
CREATE INDEX IF NOT EXISTS idx_idem_expires_at     ON idempotency (expires_at);
CREATE INDEX IF NOT EXISTS idx_idem_tenant_created ON idempotency (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_idem_tenant_reqhash ON idempotency (tenant_id, request_hash);
CREATE INDEX IF NOT EXISTS idx_idem_http           ON idempotency (http_method, http_path);

COMMENT ON TABLE  idempotency IS 'Idempotency store (tenant-scoped), monthly partitioned by created_at.';
COMMENT ON COLUMN idempotency.tenant_id     IS 'Tenant scope; app enforces isolation.';
COMMENT ON COLUMN idempotency.key           IS 'Idempotency key (UUID).';
COMMENT ON COLUMN idempotency.request_hash  IS 'Stable hash of canonical request (method+path+body+headers where applicable).';
COMMENT ON COLUMN idempotency.http_method   IS 'HTTP method of the original request.';
COMMENT ON COLUMN idempotency.http_path     IS 'Normalized path template (without volatile query strings).';
COMMENT ON COLUMN idempotency.response_json IS 'JSONB response snapshot; never logged.';
COMMENT ON COLUMN idempotency.status_code   IS 'Original HTTP status code.';
COMMENT ON COLUMN idempotency.created_at    IS 'Insertion timestamp (DB clock).';
COMMENT ON COLUMN idempotency.expires_at    IS 'Records older than this are eligible for TTL cleanup.';
COMMENT ON COLUMN idempotency.row_version   IS 'Optimistic lock counter (@Version).';

-- -----------------------------------------------------------------------------
-- Bootstrap partitions for the current and next month
--   - Each partition adds a UNIQUE index on (tenant_id, key) to support
--     ON CONFLICT DO NOTHING semantics in the repository.
--   - Matching utility indexes are created per-partition to keep scans fast.
-- -----------------------------------------------------------------------------
DO $$
DECLARE
  i               int;
  start_month     date;
  next_month      date;
  part_name       text;
BEGIN
  -- Create partitions for current month (i=0) and next month (i=1).
  FOR i IN 0..1 LOOP
    start_month := date_trunc('month', now())::date + (i || ' month')::interval;
    next_month  := date_trunc('month', now())::date + ((i+1) || ' month')::interval;
    part_name   := format('idempotency_%s', to_char(start_month, 'YYYY_MM'));

    -- Create partition if missing
    EXECUTE format($sql$
      CREATE TABLE IF NOT EXISTS %I
      PARTITION OF idempotency
      FOR VALUES FROM (%L) TO (%L)
    $sql$, part_name, start_month::timestamptz, next_month::timestamptz);

    -- Enforce uniqueness per-partition (tenant_id, key)
    EXECUTE format($sql$
      CREATE UNIQUE INDEX IF NOT EXISTS ux_%I_tenant_key
      ON %I (tenant_id, key)
    $sql$, part_name, part_name);

    -- TTL / housekeeping accelerator
    EXECUTE format($sql$
      CREATE INDEX IF NOT EXISTS idx_%I_expires_at
      ON %I (expires_at)
    $sql$, part_name, part_name);

    -- Tenant+created_at locality (observability / range scans)
    EXECUTE format($sql$
      CREATE INDEX IF NOT EXISTS idx_%I_tenant_created
      ON %I (tenant_id, created_at)
    $sql$, part_name, part_name);

    -- Optional diagnostics: request_hash and method+path
    EXECUTE format($sql$
      CREATE INDEX IF NOT EXISTS idx_%I_tenant_reqhash
      ON %I (tenant_id, request_hash)
    $sql$, part_name, part_name);

    EXECUTE format($sql$
      CREATE INDEX IF NOT EXISTS idx_%I_http
      ON %I (http_method, http_path)
    $sql$, part_name, part_name);
  END LOOP;
END$$;

-- -----------------------------------------------------------------------------
-- Housekeeping guidance (executed by application scheduler / ops jobs)
-- -----------------------------------------------------------------------------
-- -- TTL cleanup (run hourly/daily based on volume; consider LIMIT + loops)
-- DELETE FROM idempotency
--  WHERE expires_at < now()
--  LIMIT 10000;
--
-- -- Monthly roll procedure (example):
-- --   1) Run a scheduled job on the 25th to create the next partition:
-- --        CALL admin.create_idempotency_partition('YYYY-MM-01');  -- (see below helper)
-- --   2) Monitor size and vacuum/analyze stats regularly.
--
-- Optional helper: function to create an arbitrary monthly partition (for ops)
-- CREATE OR REPLACE FUNCTION admin.create_idempotency_partition(p_start DATE) RETURNS void AS $$
-- DECLARE
--   p_end    DATE := (date_trunc('month', p_start)::date + INTERVAL '1 month')::date;
--   p_name   TEXT := format('idempotency_%s', to_char(p_start, 'YYYY_MM'));
-- BEGIN
--   EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF idempotency FOR VALUES FROM (%L) TO (%L)',
--                  p_name, p_start::timestamptz, p_end::timestamptz);
--   EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS ux_%I_tenant_key ON %I (tenant_id, key)', p_name, p_name);
--   EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_expires_at ON %I (expires_at)', p_name, p_name);
--   EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_tenant_created ON %I (tenant_id, created_at)', p_name, p_name);
--   EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_tenant_reqhash ON %I (tenant_id, request_hash)', p_name, p_name);
--   EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_http ON %I (http_method, http_path)', p_name, p_name);
-- END; $$ LANGUAGE plpgsql SECURITY DEFINER;
