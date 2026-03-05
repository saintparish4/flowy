-- Migration 001: API Keys
-- Stores hashed API keys for authentication.
-- Raw keys are never stored — only SHA-256 hex digests.
-- Phase 2 auth middleware reads from this table (with KV write-through cache).

CREATE TABLE IF NOT EXISTS api_keys (
  key_hash   TEXT    PRIMARY KEY,  -- SHA-256 hex of the raw API key
  owner      TEXT    NOT NULL,     -- human-readable owner identifier
  enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at INTEGER NOT NULL      -- Unix timestamp (seconds)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_enabled ON api_keys (enabled);
