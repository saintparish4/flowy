import type { Env, RateLimitConfig, RateLimitResult } from "./types";

// Cloudflare Workers KV type
type KVNamespace = {
  get(key: string, type?: string): Promise<any>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
};

// Token bucket rate limiter using Cloudflare KV
// Implements a sliding window counter algorithm

export class RateLimiter {
  private kv: KVNamespace | null;
  private mockStore: Map<string, { count: number; resetAt: number }>;
  private useMock: boolean;

  constructor(kv?: KVNamespace) {
    this.kv = kv || null;
    this.mockStore = new Map();
    this.useMock = !kv;
  }

  /**
   * Check if a request should be rate limited
   * @param config Rate limit configuration
   * @returns Rate limit result with allowed status and metadata
   */

  async check(config: RateLimitConfig): Promise<RateLimitResult> {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - config.window;

    if (this.useMock) {
      return this.checkMock(config, now);
    }

    // Use KV for distributed rate limiting
    const key = `ratelimit:${config.key}`;

    try {
      // Get current counter
      const data = (await this.kv!.get(key, "json")) as {
        count: number;
        resetAt: number;
      } | null;

      let count = 0;
      let resetAt = now + config.window;

      if (data) {
        // Check if window has expired
        if (data.resetAt <= now) {
          // Reset the counter
          count = 0;
          resetAt = now + config.window;
        } else {
          count = data.count;
          resetAt = data.resetAt;
        }
      }

      // Increment the counter
      count++;

      // Check if limit exceeded
      const allowed = count <= config.limit;
      const remaining = Math.max(0, config.limit - count);

      // Store updated counter
      await this.kv!.put(
        key,
        JSON.stringify({ count, resetAt }),
        { expirationTtl: config.window + 60 } // Add buffer to TTL
      );

      return {
        allowed,
        limit: config.limit,
        remaining,
        resetAt,
        retryAfter: allowed ? undefined : resetAt - now,
      };
    } catch (error) {
      console.error("Rate limiter error:", error);
      // Fail open - allow request if KV is unavailable
      return {
        allowed: true,
        limit: config.limit,
        remaining: config.limit,
        resetAt: now + config.window,
      };
    }
  }

  // Mock implementation for local development
  private checkMock(config: RateLimitConfig, now: number): RateLimitResult {
    const key = `ratelimit:${config.key}`;
    const data = this.mockStore.get(key);

    let count = 0;
    let resetAt = now + config.window;

    if (data) {
      if (data.resetAt <= now) {
        count = 0;
        resetAt = now + config.window;
      } else {
        count = data.count;
        resetAt = data.resetAt;
      }
    }

    count++;
    this.mockStore.set(key, { count, resetAt });

    const allowed = count <= config.limit;
    const remaining = Math.max(0, config.limit - count);

    return {
      allowed,
      limit: config.limit,
      remaining,
      resetAt,
      retryAfter: allowed ? undefined : resetAt - now,
    };
  }

  // Reset rate limit for a specific key (useful for testing)
  async reset(key: string): Promise<void> {
    const rlKey = `ratelimit:${key}`;

    if (this.useMock) {
      this.mockStore.delete(rlKey);
    } else {
      await this.kv!.delete(rlKey);
    }
  }
}

// Create a rate limiter instance
export function createRateLimiter(env: Env): RateLimiter {
  return new RateLimiter(env.RATE_LIMIT_KV);
}

// Extract rate limit key from request
//Uses IP address by default, but can be customized based on auth tokens, API keys, etc.

export function getRateLimitKey(
  request: Request,
  prefix: string = "ip"
): string {
  const ip =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    "unknown";

  // You can customize this based on your needs:
  // - For authenticated users: use user ID
  // - For API endpoints: use API key
  // - For specific paths: combine path + IP

  return `${prefix}:${ip}`;
}

// Predefined rate limit profiles
export const RATE_LIMIT_PROFILES = {
  // Very strict for login/auth endpoints (prevents brute force)
  STRICT: { limit: 5, window: 60 }, // 5 requests per minute

  // Normal for general API endpoints
  NORMAL: { limit: 100, window: 60 }, // 100 requests per minute

  // Relaxed for static content or public endpoints
  RELAXED: { limit: 1000, window: 60 }, // 1000 requests per minute

  // Per-hour limits for expensive operations
  HOURLY: { limit: 100, window: 3600 }, // 100 requests per hour

  // Per-day limits for very expensive operations
  DAILY: { limit: 1000, window: 86400 }, // 1000 requests per day
};
