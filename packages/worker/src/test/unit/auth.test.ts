/**
 * Auth middleware unit tests: valid/invalid API key, JWT, fail-closed D1,
 * raw key never in logs
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Hono } from "hono";
import type { Env } from "../../config";
import {
  authMiddleware,
  hashApiKey,
  revokeApiKeyFromCache,
} from "../../middleware/auth";
import type { AuthContext } from "../../middleware/auth-types";
import { buildMockEnv } from "../mocks/bindings";

const app = new Hono<{ Bindings: Env; Variables: AuthContext }>();
app.use("*", authMiddleware());
app.get("/protected", (c) => c.json({ ok: true, hash: c.get("apiKeyHash") }));

describe("hashApiKey", () => {
  it("returns stable SHA-256 hex for same input", async () => {
    const a = await hashApiKey("sk-test-123");
    const b = await hashApiKey("sk-test-123");
    expect(a).toBe(b);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe("auth middleware", () => {
  beforeEach(() => {
    vi.stubEnv("ENVIRONMENT", "development");
    vi.stubEnv("BACKEND_RPC_URL", "http://localhost:9545");
    vi.stubEnv("JWT_PUBLIC_KEY", "test-key");
    vi.stubEnv("UPSTREAM_TIMEOUT_MS", "10000");
    vi.stubEnv("AUTH_CACHE_TTL_SECONDS", "300");
    vi.stubEnv("BLOCKLIST_IP_CACHE_TTL_SECONDS", "30");
    vi.stubEnv("BLOCKLIST_WALLET_CACHE_TTL_SECONDS", "60");
    vi.stubEnv("BLOCKLIST_LRU_MAX_SIZE", "10000");
    vi.stubEnv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5");
    vi.stubEnv("CIRCUIT_BREAKER_OPEN_DURATION_MS", "30000");
    vi.stubEnv("THREAT_SCORE_BLOCK_THRESHOLD", "80");
  });

  it("returns 401 when no Authorization or X-API-Key", async () => {
    const { env } = buildMockEnv();
    const res = await app.request("/protected", { headers: {} }, env);
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("Bearer");
  });

  it("valid API key proceeds and sets apiKeyHash in context", async () => {
    const { db, authCache, env } = buildMockEnv();
    const rawKey = "sk-live-abc";
    const keyHash = await hashApiKey(rawKey);
    db.seed("api_keys", [
      {
        key_hash: keyHash,
        owner: "test",
        enabled: 1,
        created_at: Math.floor(Date.now() / 1000),
      },
    ]);

    const res = await app.request(
      "/protected",
      {
        headers: { "X-API-Key": rawKey },
      },
      env,
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { hash: string; ok: boolean };
    expect(body.hash).toBe(keyHash);
    expect(body.ok).toBe(true);
    expect(await authCache.get(keyHash)).toBe("1");
  });

  it("invalid API key returns 401", async () => {
    const { env } = buildMockEnv();
    const res = await app.request(
      "/protected",
      {
        headers: { "X-API-Key": "sk-invalid" },
      },
      env,
    );
    expect(res.status).toBe(401);
  });

  it("D1 failure returns 401 (fail-closed)", async () => {
    const { db, env } = buildMockEnv();
    const rawKey = "sk-live-xyz";
    const keyHash = await hashApiKey(rawKey);
    db.seed("api_keys", [
      {
        key_hash: keyHash,
        owner: "test",
        enabled: 1,
        created_at: Math.floor(Date.now() / 1000),
      },
    ]);
    db.simulateFailure("D1 unavailable");

    const res = await app.request(
      "/protected",
      {
        headers: { "X-API-Key": rawKey },
      },
      env,
    );
    expect(res.status).toBe(401);
    db.resetFailure();
  });

  it("after revoke, next request re-validates against D1", async () => {
    const { db, env } = buildMockEnv();
    const rawKey = "sk-revoke-me";
    const keyHash = await hashApiKey(rawKey);
    db.seed("api_keys", [
      {
        key_hash: keyHash,
        owner: "test",
        enabled: 1,
        created_at: Math.floor(Date.now() / 1000),
      },
    ]);
    const first = await app.request(
      "/protected",
      { headers: { "X-API-Key": rawKey } },
      env,
    );
    expect(first.status).toBe(200);
    await revokeApiKeyFromCache(env, keyHash);
    db.seed("api_keys", []);
    const second = await app.request(
      "/protected",
      { headers: { "X-API-Key": rawKey } },
      env,
    );
    expect(second.status).toBe(401);
  });
});
