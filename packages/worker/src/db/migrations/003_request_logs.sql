-- Migration 003: Request Logs (rolling ring buffer)
-- Stores the last ~10,000 requests for dashboard queries.
-- Cloudflare Logpush is the primary high-volume channel; this table is a
-- convenience window for the Phase 8 dashboard only.
-- D1 writes are always via ctx.waitUntil() — never in the hot path.
-- Fail-open: if D1 is unavailable, skip the write and continue (see ADR 001).

CREATE TABLE IF NOT EXISTS request_logs (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  trace_id       TEXT    NOT NULL,
  timestamp      INTEGER NOT NULL,   -- Unix timestamp (milliseconds)
  method         TEXT    NOT NULL,   -- RPC method name
  source_ip      TEXT    NOT NULL,
  api_key_hash   TEXT,               -- NULL for unauthenticated (rejected) requests
  threat_score   INTEGER,            -- NULL if WASM scorer failed (fail-open)
  wasm_result    TEXT    NOT NULL DEFAULT 'ok' CHECK (wasm_result IN ('ok', 'error')),
  decision       TEXT    NOT NULL CHECK (decision IN ('allow', 'block', 'rate_limited')),
  latency_ms     INTEGER NOT NULL,
  status_code    INTEGER NOT NULL
);

-- Enforce ring-buffer row limit (~10,000 rows, 30-day TTL).
-- The application layer deletes oldest rows when inserting beyond the cap,
-- but this index makes range-based TTL deletes efficient.
CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_request_logs_trace    ON request_logs (trace_id);
