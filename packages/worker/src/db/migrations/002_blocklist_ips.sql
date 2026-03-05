-- Migration 002: Blocklisted IPs
-- Persists blocked IP addresses with an optional expiry timestamp.
-- Phase 6 blocklist middleware checks this table (with LRU in-memory cache).
-- Fail-open: KV/D1 unavailability allows the request through (see ADR 001).

CREATE TABLE IF NOT EXISTS blocklist_ips (
  ip         TEXT    PRIMARY KEY,
  reason     TEXT    NOT NULL,
  source     TEXT    NOT NULL DEFAULT 'manual',  -- e.g. "phishfort", "manual", "auto"
  created_at INTEGER NOT NULL,                   -- Unix timestamp (seconds)
  expires_at INTEGER                             -- NULL means no expiry
);

CREATE INDEX IF NOT EXISTS idx_blocklist_ips_expires ON blocklist_ips (expires_at)
  WHERE expires_at IS NOT NULL;
