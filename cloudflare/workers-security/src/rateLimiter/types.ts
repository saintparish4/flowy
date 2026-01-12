/**
 * Token Bucket Rate Limiter Types for Cloudflare Workers
 *
 * Token Bucket is more efficient for KV storage than Sliding Window:
 * - 0(1) complexity (vs 0(n) for Sliding Window)
 * - Small storage footprint (~20 bytes vs hundreds)
 * - Faster KV operations
 * - Burst tolerance built-in
 */

/**
 * Result of a rate limit check
 */
export type RateLimitDecision =
  | { type: "Allowed"; tokensRemaining: number }
  | { type: "Rejected"; retryAfterSeconds: number };

/**
 * Helper constructors for RateLimitDecision
 */
export const RateLimitDecision = {
  Allowed: (tokensRemaining: number): RateLimitDecision => ({
    type: "Allowed",
    tokensRemaining,
  }),

  Rejected: (retryAfterSeconds: number): RateLimitDecision => ({
    type: "Rejected",
    retryAfterSeconds,
  }),
};

/**
 * Rate limiter interface
 */
export interface RateLimiter {
  /**
   * Check if a request is allowed for the given key
   *
   * @param key The rate limit key (e.g., API key, user ID, IP address)
   * @param nowMs Current timestamp in milliseconds since epoch
   * @returns Promise<RateLimitDecision> - Allowed or Rejected with retry-after
   */
  allow(key: string, nowMs: number): Promise<RateLimitDecision>;

  /**
   * Get the current token count for a key (for monitoring/debugging)
   *
   * @param key The rate limit key
   * @returns Promise<number> - Current available tokens
   */
  getTokens(key: string): Promise<number>;
}

/**
 * Internal storage format in KV for token bucket
 *
 * Stored as: `ratelimit:tb:{key}` -> TokenBucketState
 *
 * Only need 2 numbers - extremely efficient
 */
export interface TokenBucketState {
  // Current number of tokens in the bucket
  tokens: number;

  // Last refill timestamp in milliseconds since epoch
  lastRefillMs: number;
}

/**
 * Configuration for TokenBucketRateLimiter
 */
export interface TokenBucketConfig {
  // Maximum bucket capacity (burst allowance)
  capacity: number;

  // Refill rate: tokens added per second
  refillRate: number;

  // KV namespace to use for storage
  kv: KVNamespace;

  // Optional key prefix (default: 'ratelimit:tb:')
  keyPrefix?: string;

  // Cost per request in tokens (default: 1)
  costPerRequest?: number;
}

/**
 * Alternative: Fixed Window Rate Limiter (simpler, less efficient)
 *
 * Useful for very simple use cases where precision does not matter
 * Stores only a counter that resets at window boundaries
 */
export interface FixedWindowState {
  // Request count in current window
  count: number;

  // Window start timestamp in milliseconds
  windowStartMs: number;
}

/**
 * Rate limiter type selection 
 */
export type RateLimiterType = 'token-bucket' | 'sliding-window' | 'fixed-window' | 'legacy'; 