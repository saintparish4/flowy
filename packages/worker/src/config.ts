/**
 * Single source of truth for all runtime configuration.
 *
 * All modules must import from here — never read `env` directly.
 * Validates eagerly at Worker startup so misconfiguration is caught before
 * any request is served, not silently during request handling.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Env bindings type (mirrors wrangler.toml)
// ---------------------------------------------------------------------------

export interface Env {
  // D1 database
  DB: D1Database;

  // KV namespaces
  AUTH_CACHE: KVNamespace;
  BLOCKLIST_WALLETS: KVNamespace;
  BLOCKLIST_DOMAINS: KVNamespace;

  // Durable Objects
  RATE_LIMITER: DurableObjectNamespace;

  // Vars (always strings from Workers runtime)
  ENVIRONMENT: string;
  BACKEND_RPC_URL: string;
  JWT_PUBLIC_KEY: string;
  UPSTREAM_TIMEOUT_MS: string;
  AUTH_CACHE_TTL_SECONDS: string;
  BLOCKLIST_IP_CACHE_TTL_SECONDS: string;
  BLOCKLIST_WALLET_CACHE_TTL_SECONDS: string;
  BLOCKLIST_LRU_MAX_SIZE: string;
  CIRCUIT_BREAKER_FAILURE_THRESHOLD: string;
  CIRCUIT_BREAKER_OPEN_DURATION_MS: string;
  THREAT_SCORE_BLOCK_THRESHOLD: string;

  // Optional — only required for enterprise tier
  SAML_METADATA_URL?: string;
  SLACK_WEBHOOK_URL?: string;
  PAGERDUTY_ROUTING_KEY?: string;
}

// ---------------------------------------------------------------------------
// Parsed, typed config schema
// ---------------------------------------------------------------------------

const positiveInt = z
  .string()
  .regex(/^\d+$/, "must be a positive integer string")
  .transform(Number)
  .refine((n) => n > 0, "must be > 0");

const ConfigSchema = z.object({
  environment: z.enum(["development", "staging", "production"]),
  backendRpcUrl: z.string().url("BACKEND_RPC_URL must be a valid URL"),
  jwtPublicKey: z.string().min(1, "JWT_PUBLIC_KEY is required"),
  upstreamTimeoutMs: positiveInt,
  authCacheTtlSeconds: positiveInt,
  blocklistIpCacheTtlSeconds: positiveInt,
  blocklistWalletCacheTtlSeconds: positiveInt,
  blocklistLruMaxSize: positiveInt,
  circuitBreakerFailureThreshold: positiveInt,
  circuitBreakerOpenDurationMs: positiveInt,
  threatScoreBlockThreshold: z
    .string()
    .regex(/^\d+$/)
    .transform(Number)
    .refine((n) => n >= 0 && n <= 100, "must be between 0 and 100"),
});

export type Config = z.infer<typeof ConfigSchema>;

// ---------------------------------------------------------------------------
// Per-method rate limits (sourced from config, never hardcoded in middleware)
// Unit: requests per minute per API key
// ---------------------------------------------------------------------------

export const METHOD_RATE_LIMITS: Record<string, number> = {
  eth_getLogs: 20,
  eth_sendRawTransaction: 10,
  eth_call: 100,
  eth_blockNumber: 200,
  eth_getBalance: 100,
  // Catch-all for unlisted methods
  _default: 60,
};

// ---------------------------------------------------------------------------
// Validation and export
// ---------------------------------------------------------------------------

/**
 * Parses and validates all required env vars.
 * Throws a descriptive ConfigError on the first missing or malformed value —
 * this surfaces at startup, not buried in a request handler.
 */
export function parseConfig(env: Env): Config {
  const raw = {
    environment: env.ENVIRONMENT,
    backendRpcUrl: env.BACKEND_RPC_URL,
    jwtPublicKey: env.JWT_PUBLIC_KEY,
    upstreamTimeoutMs: env.UPSTREAM_TIMEOUT_MS,
    authCacheTtlSeconds: env.AUTH_CACHE_TTL_SECONDS,
    blocklistIpCacheTtlSeconds: env.BLOCKLIST_IP_CACHE_TTL_SECONDS,
    blocklistWalletCacheTtlSeconds: env.BLOCKLIST_WALLET_CACHE_TTL_SECONDS,
    blocklistLruMaxSize: env.BLOCKLIST_LRU_MAX_SIZE,
    circuitBreakerFailureThreshold: env.CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    circuitBreakerOpenDurationMs: env.CIRCUIT_BREAKER_OPEN_DURATION_MS,
    threatScoreBlockThreshold: env.THREAT_SCORE_BLOCK_THRESHOLD,
  };

  const result = ConfigSchema.safeParse(raw);

  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  • ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new ConfigError(
      `Hexa Worker failed to start — invalid configuration:\n${issues}`
    );
  }

  return result.data;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}
