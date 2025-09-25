-- -----------------------------------------------------------------------------
-- VeggieShop :: Platform Infrastructure
-- Repeatable Migration: R__pg_tuning.sql
--
-- Purpose
--   Cluster-agnostic, safe PostgreSQL utilities and best-practice helpers used
--   by the VeggieShop platform. This script is REPEATABLE and idempotent:
--   it creates extensions (if available) and lightweight helper functions,
--   views for observability, and session-level tuning helpers.
--
-- Target
--   PostgreSQL 15+ (as per PRD v2.0)
--
-- Principles
--   - No global GUCs changed here; apps set per-session settings via helpers.
--   - No hard role assumptions; SECURITY DEFINER avoided unless unavoidable.
--   - Everything is idempotent (IF NOT EXISTS / CREATE OR REPLACE).
--
-- Highlights
--   - Extensions: pgcrypto, pg_stat_statements, btree_gin/gist (if present)
--   - Schema "util" for helpers
--   - Exponential backoff + jitter helpers (for outbox retry scheduling, etc.)
--   - Session timeout setup helper (statement/lock/idle timeouts)
--   - Advisory lock with timeout helper (transaction-scoped)
--   - Lightweight monitoring views for outbox/idempotency health
-- -----------------------------------------------------------------------------

-- == Extensions (optional, safe if missing) ===================================
DO $ext$
BEGIN
  -- crypto and UUID helpers
  BEGIN
    EXECUTE 'CREATE EXTENSION IF NOT EXISTS pgcrypto';
  EXCEPTION WHEN OTHERS THEN
    -- extension may be unavailable (managed env); ignore
    NULL;
  END;

  -- query stats (observability)
  BEGIN
    EXECUTE 'CREATE EXTENSION IF NOT EXISTS pg_stat_statements';
  EXCEPTION WHEN OTHERS THEN
    NULL;
  END;

  -- indexing helpers for mixed datatypes
  BEGIN
    EXECUTE 'CREATE EXTENSION IF NOT EXISTS btree_gin';
  EXCEPTION WHEN OTHERS THEN
    NULL;
  END;

  BEGIN
    EXECUTE 'CREATE EXTENSION IF NOT EXISTS btree_gist';
  EXCEPTION WHEN OTHERS THEN
    NULL;
  END;
END
$ext$;

-- == Utility schema ===========================================================
CREATE SCHEMA IF NOT EXISTS util;
COMMENT ON SCHEMA util IS 'VeggieShop utility schema: tuning helpers, retry math, observability views.';

-- == Backoff & jitter helpers =================================================

-- Returns an integer backoff (milliseconds) using exponential backoff with jitter.
-- backoff = min(cap_ms, base_ms * 2^attempts) ± (jitter_ratio * backoff)
CREATE OR REPLACE FUNCTION util.exponential_backoff_ms(
  attempts      integer,
  base_ms       integer DEFAULT 100,
  cap_ms        integer DEFAULT 60000,
  jitter_ratio  numeric DEFAULT 0.20
) RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  raw_ms     numeric;
  capped_ms  numeric;
  jitter     numeric;
  sign       integer;
  out_ms     integer;
BEGIN
  IF attempts < 0 THEN attempts := 0; END IF;
  IF base_ms < 1 THEN base_ms := 1; END IF;
  IF cap_ms < base_ms THEN cap_ms := base_ms; END IF;
  IF jitter_ratio < 0 THEN jitter_ratio := 0; END IF;

  raw_ms := base_ms * power(2, attempts);
  capped_ms := LEAST(cap_ms, raw_ms);

  -- random jitter in [-jitter_ratio, +jitter_ratio]
  sign := CASE WHEN random() < 0.5 THEN -1 ELSE 1 END;
  jitter := sign * jitter_ratio * capped_ms * random();

  out_ms := GREATEST(1, FLOOR(capped_ms + jitter));
  RETURN out_ms;
END;
$$;

COMMENT ON FUNCTION util.exponential_backoff_ms(integer, integer, integer, numeric)
  IS 'Exponential backoff (ms) with ±jitter. Use for retry scheduling (outbox, webhooks, etc.).';

-- Convenience: compute "next retry at" timestamp from attempts counter.
CREATE OR REPLACE FUNCTION util.next_retry_at(
  attempts      integer,
  base_ms       integer DEFAULT 100,
  cap_ms        integer DEFAULT 60000,
  jitter_ratio  numeric DEFAULT 0.20
) RETURNS timestamptz
LANGUAGE sql
AS $$
  SELECT now() + make_interval(millis => util.exponential_backoff_ms($1,$2,$3,$4));
$$;

COMMENT ON FUNCTION util.next_retry_at(integer, integer, integer, numeric)
  IS 'Returns now()+exponential_backoff_ms(...) as timestamptz.';


-- == Session timeout helper ===================================================
-- Apply sane per-session timeouts (does not change cluster-wide settings).
-- Typical app call at startup:
--   SELECT util.set_app_timeouts( statement_ms => 2000, lock_ms => 1000, idle_in_txn_ms => 5000 );
CREATE OR REPLACE FUNCTION util.set_app_timeouts(
  statement_ms    integer DEFAULT 2000,
  lock_ms         integer DEFAULT 1000,
  idle_in_txn_ms  integer DEFAULT 5000
) RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM set_config('statement_timeout', statement_ms::text, false);
  PERFORM set_config('lock_timeout', lock_ms::text, false);
  PERFORM set_config('idle_in_transaction_session_timeout', idle_in_txn_ms::text, false);
END;
$$;

COMMENT ON FUNCTION util.set_app_timeouts(integer, integer, integer)
  IS 'Sets per-session statement/lock/idle-in-txn timeouts (ms).';

-- == Advisory lock with timeout (transaction-scoped) ==========================
-- Try to acquire pg_try_advisory_xact_lock(key) with a bounded wait.
-- Returns true if acquired, false on timeout.
CREATE OR REPLACE FUNCTION util.try_advisory_xact_lock_timeout(
  lock_key   bigint,
  timeout_ms integer DEFAULT 250
) RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
  deadline timestamptz := clock_timestamp() + make_interval(millis => timeout_ms);
BEGIN
  LOOP
    IF pg_try_advisory_xact_lock(lock_key) THEN
      RETURN true;
    END IF;

    EXIT WHEN clock_timestamp() >= deadline;
    PERFORM pg_sleep( LEAST(0.01, GREATEST(0.001, (deadline - clock_timestamp()) / interval '1 second')) );
  END LOOP;
  RETURN false;
END;
$$;

COMMENT ON FUNCTION util.try_advisory_xact_lock_timeout(bigint, integer)
  IS 'Attempts pg_try_advisory_xact_lock(lock_key) until timeout_ms elapses. True if acquired.';

-- == Observability views (read-only, no PII) =================================

-- Outbox queue health: counts by status and oldest created_at per status.
CREATE OR REPLACE VIEW util.v_outbox_queue AS
SELECT
  status,
  COUNT(*)                         AS rows_count,
  MIN(created_at)                  AS oldest_created_at,
  MAX(created_at)                  AS newest_created_at,
  COALESCE(AVG(attempts)::numeric,0) AS avg_attempts,
  COALESCE(MAX(attempts),0)        AS max_attempts,
  COUNT(*) FILTER (WHERE available_at <= now()
                   AND status = 'PENDING') AS drainable_now
FROM outbox
GROUP BY status;

COMMENT ON VIEW util.v_outbox_queue IS 'Outbox queue health (counts, attempts, drainable_now). PII-free.';

-- Idempotency TTL outlook: how many rows expire per day (next 14 days window).
CREATE OR REPLACE VIEW util.v_idempotency_ttl AS
SELECT
  date_trunc('day', expires_at) AS day,
  COUNT(*)                      AS rows_expiring
FROM idempotency
WHERE expires_at <= now() + interval '14 days'
GROUP BY 1
ORDER BY 1;

COMMENT ON VIEW util.v_idempotency_ttl IS 'Upcoming idempotency expirations (14-day window).';

-- == Helpful operators / casts (safety) ======================================

-- Safe text length check (NULL-tolerant).
CREATE OR REPLACE FUNCTION util.text_len(t text)
RETURNS integer
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT COALESCE(length($1), 0) $$;

COMMENT ON FUNCTION util.text_len(text) IS 'NULL-tolerant text length.';

-- == Optional guidance ========================================================
-- To leverage these utilities from application code:
--   - Call:      SELECT util.set_app_timeouts(2000, 1000, 5000);
--   - Backoff:   SELECT util.next_retry_at(attempts := 3, base_ms := 100, cap_ms := 30000, jitter_ratio := 0.2);
--   - Advisory:  SELECT util.try_advisory_xact_lock_timeout( hashtextextended('some-key', 0), 250 );
--
-- Monitoring queries:
--   SELECT * FROM util.v_outbox_queue;
--   SELECT * FROM util.v_idempotency_ttl;
--
-- Housekeeping examples (run by app schedulers; see V1/V2/V3 migrations):
--   DELETE FROM event_dedupe  WHERE expires_at < now() LIMIT 10000;
--   DELETE FROM idempotency   WHERE expires_at < now() LIMIT 10000;
--   DELETE FROM outbox        WHERE status='PUBLISHED' AND published_at < now()-interval '7 days' LIMIT 10000;
-- -----------------------------------------------------------------------------
