/**
 * Token Bucket Rate Limiter for Cloudflare Workers
 *
 * Token Bucket is optimized for KV storage:
 * - O(1) complexity (vs O(n) for sliding window)
 * - Small storage footprint (~20 bytes vs hundreds)
 * - Built-in burst tolerance
 * - KV-friendly operations
 *
 * Algorithm:
 * 1. Get current bucket state from KV (tokens, lastRefillMs)
 * 2. Calculate elapsed time since last refill
 * 3. Refill tokens: min(capacity, tokens + (elapsed * refillRate / 1000))
 * 4. Update lastRefillMs to current time
 * 5. If tokens >= cost: consume token(s) and allow
 * 6. Else: calculate retry-after and reject
 */

import {
  RateLimiter,
  RateLimitDecision,
  TokenBucketConfig,
  TokenBucketState,
} from "./types";

/**
 * Token Bucket Rate Limiter implementation
 */
export class TokenBucketRateLimiter implements RateLimiter {
  private readonly capacity: number;
  private readonly refillRate: number;
  private readonly kv: KVNamespace;
  private readonly keyPrefix: string;
  private readonly costPerRequest: number;

  /**
   * Create a new token bucket rate limiter
   *
   * @param config Configuration object
   */
  constructor(config: TokenBucketConfig) {
    if (config.capacity <= 0) {
      throw new Error("capacity must be positive");
    }
    if (config.refillRate <= 0) {
      throw new Error("refillRate must be positive");
    }
    if (!config.kv) {
      throw new Error("kv namespace is required");
    }

    this.capacity = config.capacity;
    this.refillRate = config.refillRate;
    this.kv = config.kv;
    this.keyPrefix = config.keyPrefix || "ratelimit:tb:";
    this.costPerRequest = config.costPerRequest || 1;
  }

  /**
   * Get full the KV key for rate limit key
   */
  private getKVKey(key: string): string {
    return `${this.keyPrefix}${key}`;
  }

  /**
   * Initialize a new bucket for a key
   */
  private initializeBucket(nowMs: number): TokenBucketState {
    return {
      tokens: this.capacity,
      lastRefillMs: nowMs,
    };
  }

  /**
   * Calculate tokens to add based on elapsed time
   *
   * Formula: tokensToAdd = (elapsedMS / 1000) * refillRate
   *
   * @param elapsedMs Milliseconds since last refill
   * @returns Number of tokens to add
   */
  private calculateRefill(elapsedMs: number): number {
    return (elapsedMs / 1000) * this.refillRate;
  }

  /**
   * Refill the bucket on elapsed time
   *
   * @param state Current bucket state
   * @param nowMs Current timestamp
   * @returns Updated bucket state
   */
  private refillBucket(
    state: TokenBucketState,
    nowMs: number
  ): TokenBucketState {
    const elapsedMs = nowMs - state.lastRefillMs;

    if (elapsedMs <= 0) {
      // No time has passed or clock went backwards
      return state;
    }

    const tokensToAdd = this.calculateRefill(elapsedMs);
    const newTokens = Math.min(this.capacity, state.tokens + tokensToAdd);

    return {
      tokens: newTokens,
      lastRefillMs: nowMs,
    };
  }

  /**
   * Calculate retry-after duration in seconds.
   *
   * Formula: retryAfter = (tokensNeeded - currentTokens) / refillRate
   *
   * @param currentTokens Current token count
   * @param tokensNeeded Tokens needed for request
   * @returns Retry-after in seconds
   */
  private calculateRetryAfter(
    currentTokens: number,
    tokensNeeded: number
  ): number {
    const deficit = tokensNeeded - currentTokens;
    const retryAfterSeconds = deficit / this.refillRate;
    return Math.ceil(retryAfterSeconds);
  }

  /**
   * Check if a request is allowed for the given key.
   *
   * Main algorithm with KV operations and retry logic for eventual consistency.
   *
   * @param key The rate limit key
   * @param nowMs Current timestamp in milliseconds
   * @returns Promise<RateLimitDecision>
   */
  async allow(key: string, nowMs: number): Promise<RateLimitDecision> {
    if (!key) {
      throw new Error("key cannot be null or empty");
    }

    const kvKey = this.getKVKey(key);
    const maxRetries = 3;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        // Step 1: Get current state from KV
        const stored = await this.kv.get<TokenBucketState>(kvKey, "json");

        // Step 2: Initialize or refill bucket
        const currentState = stored
          ? this.refillBucket(stored, nowMs)
          : this.initializeBucket(nowMs);

        // Step 3: Check if request can be allowed
        if (currentState.tokens >= this.costPerRequest) {
          // Allow request - consume token(s)
          const newState: TokenBucketState = {
            tokens: currentState.tokens - this.costPerRequest,
            lastRefillMs: nowMs,
          };

          // Step 4: Try to store updated state
          await this.kv.put(kvKey, JSON.stringify(newState), {
            // Set TTL to allow cleanup after inactivity
            // Use 2x the time to fully refill as a reasonable expiration
            expirationTtl: Math.ceil((this.capacity / this.refillRate) * 2),
          });

          // Step 5: Verify write (handle race conditions)
          // Brief delay for KV consistency
          if (attempt < maxRetries - 1) {
            await new Promise((resolve) => setTimeout(resolve, 10));

            const verified = await this.kv.get<TokenBucketState>(kvKey, "json");

            if (!verified) {
              // Entry disappeared - retry
              continue;
            }

            // Check if our write succeeded
            // If tokens are significantly different, we may have lost a race
            const tokenDifference = Math.abs(verified.tokens - newState.tokens);

            if (tokenDifference > this.costPerRequest) {
              // Possible race condition - retry
              continue;
            }
          }

          // Success
          return RateLimitDecision.Allowed(newState.tokens);
        } else {
          // Reject request - not enough tokens
          const retryAfterSeconds = this.calculateRetryAfter(
            currentState.tokens,
            this.costPerRequest
          );

          return RateLimitDecision.Rejected(retryAfterSeconds);
        }
      } catch (error) {
        // KV error - retry or fail open
        if (attempt === maxRetries - 1) {
          console.error(
            `Rate limiter error after ${maxRetries} attempts:`,
            error
          );
          // Fail open - allow request to prevent blocking legitimate traffic
          return RateLimitDecision.Allowed(this.capacity);
        }

        // Wait before retry
        await new Promise((resolve) => setTimeout(resolve, 50 * (attempt + 1)));
      }
    }

    // Should not reach here, but fail open if we do
    return RateLimitDecision.Allowed(this.capacity);
  }

  /**
   * Get the current token count for a key.
   *
   * @param key The rate limit key
   * @returns Promise<number> - Current available tokens (after refill)
   */
  async getTokens(key: string): Promise<number> {
    if (!key) {
      return this.capacity;
    }

    const kvKey = this.getKVKey(key);
    const stored = await this.kv.get<TokenBucketState>(kvKey, "json");

    if (!stored) {
      return this.capacity;
    }

    const nowMs = Date.now();
    const refilled = this.refillBucket(stored, nowMs);

    return refilled.tokens;
  }

  /**
   * Clear the rate limit for a key (for testing/admin).
   *
   * @param key The rate limit key
   */
  async clear(key: string): Promise<void> {
    const kvKey = this.getKVKey(key);
    await this.kv.delete(kvKey);
  }

  /**
   * Reset a key to full capacity (for testing/admin).
   *
   * @param key The rate limit key
   */
  async reset(key: string): Promise<void> {
    const kvKey = this.getKVKey(key);
    const newState = this.initializeBucket(Date.now());

    await this.kv.put(kvKey, JSON.stringify(newState), {
      expirationTtl: Math.ceil((this.capacity / this.refillRate) * 2),
    });
  }
}

/**
 * Factory function to create a token bucket rate limiter.
 */
export function createTokenBucketRateLimiter(
  config: TokenBucketConfig
): RateLimiter {
  return new TokenBucketRateLimiter(config);
}
