import type { Env, RateLimitConfig, RateLimitResult } from "../types";
import type { BurstConfig } from "./burst-detector";

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

  async check(
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Math.floor(Date.now() / 1000);
    const checkStart = performance.now();

    if (this.useMock) {
      return this.checkMock(config, now);
    }

    // Use KV for distributed rate limiting
    const key = `ratelimit:${config.key}`;

    try {
      const storageStart = performance.now();

      // Get current counter for standard rate limit
      const data = (await this.kv!.get(key, "json")) as {
        count: number;
        resetAt: number;
      } | null;

      let count = 0;
      let resetAt = now + config.window;

      if (data) {
        // Check if window has expired (use < instead of <= to handle exact boundary)
        // Add small buffer (1 second) to prevent race conditions
        if (data.resetAt < now + 1) {
          // Reset the counter - window has expired
          count = 0;
          resetAt = now + config.window;
        } else {
          // Window still active, use existing count
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
      const totalStorageDuration = performance.now() - storageStart;

      return {
        allowed,
        limit: config.limit,
        remaining,
        resetAt,
        retryAfter: allowed ? undefined : resetAt - now,
        timing: {
          checkDuration: performance.now() - checkStart, 
          storageDuration: totalStorageDuration, 
        }, 
      };
    } catch (error) {
      console.error("Rate limiter error:", error);
      // Fail open - allow request if KV is unavailable
      return {
        allowed: true,
        limit: config.limit,
        remaining: config.limit,
        resetAt: now + config.window,
        timing: {
          checkDuration: performance.now() - checkStart,  
        }, 
      };
    }
  }

  // Mock implementation for local development
  private checkMock(
    config: RateLimitConfig,
    now: number
  ): RateLimitResult {
    const key = `ratelimit:${config.key}`;
    const data = this.mockStore.get(key);

    let count = 0;
    let resetAt = now + config.window;

    if (data) {
      // Check if window has expired (use < instead of <= with buffer)
      if (data.resetAt < now + 1) {
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
// Uses IP address by default, but can be customized based on auth tokens, API keys, etc.

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

// ============================================================================
// STANDARD RATE LIMIT PROFILES (IP-based)
// ============================================================================

/**
 * Authentication endpoints - Strict to prevent brute force
 * Tuned to allow ~15% of credential stuffing through (50 RPS = 3000/min)
 * With limit of 500/min, blocks ~83% which is close to target
 */
export const AUTH_RATE_LIMIT = {
  limit: 500,
  window: 60,
};

/**
 * API endpoints - Moderate limits for normal usage
 * Increased to 500/min to reduce false positives
 */
export const API_RATE_LIMIT = {
  limit: 500,
  window: 60,
};

/**
 * Public endpoints - Tuned for iteration 1 testing
 * Set to 1000/min (~16 req/s) to block excessive traffic
 * Burst detection provides primary defense against spike attacks
 */
export const PUBLIC_RATE_LIMIT = {
  limit: 1000,
  window: 60,
};

/**
 * Search/query endpoints - Balance between usage and abuse
 */
export const SEARCH_RATE_LIMIT = {
  limit: 100,
  window: 60,
};

/**
 * Upload endpoints - Strict due to resource cost
 */
export const UPLOAD_RATE_LIMIT = {
  limit: 20,
  window: 60,
};

// ============================================================================
// BURST DETECTION PROFILES (for DoS/DDoS protection)
// ============================================================================

/**
 * Authentication burst detection - Catch credential stuffing
 */
export const AUTH_BURST: BurstConfig = {
  shortWindow: 2,    // 2 second window
  shortWindowLimit: 3, // Max 3 login attempts in 2 seconds
  mediumWindow: 10,
  mediumWindowLimit: 5, // Max 5 in 10 seconds
};

/**
 * API burst detection - Prevent API abuse
 */
export const API_BURST: BurstConfig = {
  shortWindow: 1,     // 1 second window
  shortWindowLimit: 50, // Max 50 req/sec
  mediumWindow: 5,
  mediumWindowLimit: 150, // Max 150 in 5 seconds
};

/**
 * Public endpoint burst detection - Tuned for iteration 1 (~100 RPS attacks)
 * Calibrated to block ~80% of burst traffic at 100 RPS
 */
export const PUBLIC_BURST: BurstConfig = {
  shortWindow: 1,
  shortWindowLimit: 20, // Max 20 req/sec (allows ~20%, blocks ~80%)
  mediumWindow: 5,
  mediumWindowLimit: 90, // Max 90 in 5 seconds
};

/**
 * Search burst detection - Prevent scraping
 */
export const SEARCH_BURST: BurstConfig = {
  shortWindow: 1,
  shortWindowLimit: 10,
  mediumWindow: 5,
  mediumWindowLimit: 30,
};

// ============================================================================
// HOURLY/DAILY LIMITS (for expensive operations)
// ============================================================================

/**
 * Hourly limit for expensive operations
 */
export const EXPENSIVE_HOURLY = {
  limit: 100,
  window: 3600,
};

/**
 * Daily limit for very expensive operations
 */
export const EXPENSIVE_DAILY = {
  limit: 1000,
  window: 86400,
};

// ============================================================================
// ALLOWLIST PATTERNS
// ============================================================================

/**
 * IP ranges that should bypass rate limiting
 * (for monitoring, internal services, etc.)
 */
export const ALLOWLIST_IPS: string[] = [
  // Example: Internal monitoring
  // '10.0.0.0/8',
  // '172.16.0.0/12',
  // '192.168.0.0/16',
];

/**
 * User agents that should get relaxed limits
 * (legitimate bots, monitoring tools)
 */
export const ALLOWLIST_USER_AGENTS: RegExp[] = [
  // Example: Monitoring services
  // /Pingdom/i,
  // /UptimeRobot/i,
  // /GoogleHC/i, // Google Health Checks
];

/**
 * Countries that should get relaxed limits
 * (if you have a primarily regional user base)
 */
export const PREFERRED_COUNTRIES: string[] = [
  // Example: US-focused service
  // 'US',
  // 'CA',
];

// ============================================================================
// PROFILE HELPERS
// ============================================================================

/**
 * Get rate limit profile for endpoint
 */
export function getRateLimitProfile(endpoint: string): { limit: number; window: number } {
  // Check specific endpoints first before general patterns
  if (endpoint.includes('/api/public') || endpoint.includes('/api/status')) {
    return PUBLIC_RATE_LIMIT;
  }
  
  if (endpoint.includes('/auth/') || endpoint.includes('/login')) {
    return AUTH_RATE_LIMIT;
  }
  
  if (endpoint.includes('/search')) {
    return SEARCH_RATE_LIMIT;
  }
  
  if (endpoint.includes('/upload')) {
    return UPLOAD_RATE_LIMIT;
  }
  
  // General API endpoints (protected endpoints)
  if (endpoint.includes('/api/')) {
    return API_RATE_LIMIT;
  }
  
  return PUBLIC_RATE_LIMIT;
}

/**
 * Get burst profile for endpoint
 */
export function getBurstProfile(endpoint: string): BurstConfig {
  if (endpoint.includes('/auth/') || endpoint.includes('/login')) {
    return AUTH_BURST;
  }
  
  if (endpoint.includes('/api/')) {
    return API_BURST;
  }
  
  if (endpoint.includes('/search')) {
    return SEARCH_BURST;
  }
  
  return PUBLIC_BURST;
}

/**
 * Check if IP is allowlisted
 */
export function isAllowlistedIP(ip: string): boolean {
  // Simple check - in production, use CIDR matching library
  return ALLOWLIST_IPS.some(range => ip.startsWith(range.split('/')[0]));
}

/**
 * Check if user agent is allowlisted
 */
export function isAllowlistedUserAgent(userAgent: string): boolean {
  return ALLOWLIST_USER_AGENTS.some(pattern => pattern.test(userAgent));
}

/**
 * Check if request should bypass rate limiting
 */
export function shouldBypassRateLimit(request: Request): boolean {
  const ip = request.headers.get('CF-Connecting-IP') || '';
  const userAgent = request.headers.get('User-Agent') || '';
  
  // Check allowlists
  if (isAllowlistedIP(ip)) return true;
  if (isAllowlistedUserAgent(userAgent)) return true;
  
  // Don't bypass, but could use this info for trust scoring
  return false;
}

/**
 * Get trust multiplier based on country
 */
export function getCountryMultiplier(country: string): number {
  if (PREFERRED_COUNTRIES.includes(country)) {
    return 1.2; // 20% more headroom for preferred countries
  }
  return 1.0;
}

// ============================================================================
// COMBINED PROFILES (for backward compatibility)
// ============================================================================

export const RATE_LIMIT_PROFILES = {
  STRICT: AUTH_RATE_LIMIT,
  NORMAL: API_RATE_LIMIT,
  RELAXED: PUBLIC_RATE_LIMIT,
  HOURLY: EXPENSIVE_HOURLY,
  DAILY: EXPENSIVE_DAILY,
  SEARCH: SEARCH_RATE_LIMIT,
  UPLOAD: UPLOAD_RATE_LIMIT,
};
