/**
 * Global Configuration Types for Cloudflare Workers
 *
 * Centralized type definitions for environment configuration
 */

import { RateLimiterType } from "../rateLimiter/types";

/**
 * Environment variables for Workers
 */
export interface Env {
  // KV namespace for rate limiting
  RATE_LIMIT_KV: KVNamespace;

  // Optional: Seperate KV namespace for idempotency (defaults to RATE_LIMIT_KV)
  IDEMPOTENCY_KV?: KVNamespace;

  // Idempotency TTL in seconds (default: 86400 = 24 hours)
  IDEMPOTENCY_TTL?: number;

  // Rate Limiter type selection (default: 'token-bucket')
  RATE_LIMITER_TYPE?: RateLimiterType;

  // Token bucket capacity (default: 100)
  TOKEN_BUCKET_CAPACITY?: string;

  // Token bucket refull rate per second (default: 10)
  TOKEN_BUCKET_REFILL_RATE?: string;
}

/**
 * Configuration for the entire security stack
 */
export interface SecurityConfig {
  // Rate limiter configuration
  rateLimit: {
    type: RateLimiterType;
    tokenBucket?: {
      capacity: number;
      refillRate: number;
    };
    slidingWindow?: {
      maxRequests: number;
      windowSizeSeconds: number;
    };
  };

  // Idempotency configuration
  idempotency: {
    enabled: boolean;
    ttlSeconds: number;
  };

  // KV namespaces
  kv: {
    rateLimit: KVNamespace;
    idempotency: KVNamespace;
  };
}

/**
 *
 * @param env Parse environment variables into SecurityConfig
 */
export function parseSecurityConfig(env: Env): SecurityConfig {
  const rateLimiterType = (env.RATE_LIMITER_TYPE ||
    "token-bucket") as RateLimiterType;
  const idempotencyTtl = parseInt(
    env.IDEMPOTENCY_TTL?.toString() || "86400",
    10
  );

  // Token bucket defaults
  const tokenBucketCapacity = parseInt(env.TOKEN_BUCKET_CAPACITY || "100", 10);
  const tokenBucketRefillRate = parseInt(
    env.TOKEN_BUCKET_REFILL_RATE || "10",
    10
  );

  return {
    rateLimit: {
      type: rateLimiterType,
      tokenBucket: {
        capacity: tokenBucketCapacity,
        refillRate: tokenBucketRefillRate,
      },
    },
    idempotency: {
      enabled: true,
      ttlSeconds: idempotencyTtl,
    },
    kv: {
      rateLimit: env.RATE_LIMIT_KV,
      idempotency: env.IDEMPOTENCY_KV || env.RATE_LIMIT_KV,
    },
  };
}

/**
 * Default security configuration
 */
export const DEFAULT_CONFIG: Omit<SecurityConfig, "kv"> = {
  rateLimit: {
    type: "token-bucket",
    tokenBucket: {
      capacity: 100,
      refillRate: 10, // 10 tokens/second = 600 requests/minute
    },
  },
  idempotency: {
    enabled: true,
    ttlSeconds: 86400, // 24 hours
  },
};
