import type { Env, RateLimitConfig, RateLimitResult } from "./types";
import type { BurstConfig } from "./burst-detector";

// Cloudflare Workers KV type
type KVNamespace = {
  get(key: string, type?: string): Promise<any>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
};

/**
 * Session information for behavioral analysis
 */
export interface Session {
  id: string;
  firstSeen: number;
  lastSeen: number;
  requestCount: number;
  blockedCount: number;
  endpoints: Set<string>;
  userAgent?: string;
  country?: string;
  reputation: number; // 0-100, higher is better
  trustLevel: 'new' | 'establishing' | 'trusted' | 'suspicious' | 'blocked';
}

/**
 * Behavioral signals for analysis
 */
export interface BehavioralSignals {
  requestPattern: 'human-like' | 'bot-like' | 'unknown';
  endpointDiversity: number; // 0-1, higher means accessing many endpoints
  timeVariance: number; // 0-1, higher means irregular timing
  blockedRatio: number; // 0-1, ratio of blocked requests
  sessionAge: number; // milliseconds
}

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
// SESSION-BASED RATE LIMIT MULTIPLIERS
// ============================================================================

/**
 * Multipliers applied based on session trust level
 * These allow trusted users more headroom
 */
export const TRUST_MULTIPLIERS = {
  trusted: 3.0,      // Established users get 3x the limit
  establishing: 2.0, // Building trust gets 2x
  new: 1.0,          // New sessions get base limit
  suspicious: 0.5,   // Suspicious gets 0.5x
  blocked: 0.1,      // Blocked gets minimal (for appeals)
};

// ============================================================================
// BURST DETECTION PROFILES
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

/**
 * Behavioral analysis thresholds
 */
export const BEHAVIORAL_THRESHOLDS = {
  // Request rate thresholds (req/sec)
  BOT_THRESHOLD: 10,    // >10 req/s likely bot
  HUMAN_THRESHOLD: 2,   // <2 req/s likely human
  
  // Endpoint diversity (number of unique endpoints)
  DIVERSE_THRESHOLD: 5, // Accessing 5+ endpoints suggests legitimate browsing
  FOCUSED_THRESHOLD: 2, // Accessing 1-2 endpoints might be automation
  
  // Session age thresholds (milliseconds)
  NEW_SESSION: 60000,        // <1 minute
  ESTABLISHING_SESSION: 300000, // 1-5 minutes
  TRUSTED_SESSION: 900000,   // >15 minutes
  
  // Blocked ratio thresholds
  SUSPICIOUS_BLOCK_RATIO: 0.3,  // >30% blocked is suspicious
  BLOCKED_BLOCK_RATIO: 0.7,     // >70% blocked should be blocked
};

/**
 * Enhanced rate limiter with session tracking and behavioral analysis
 */
export class SessionAwareRateLimiter {
  private kv: KVNamespace | null;
  private mockStore: Map<string, any>;
  private useMock: boolean;
  private sessions: Map<string, Session>;

  constructor(kv?: KVNamespace) {
    this.kv = kv || null;
    this.mockStore = new Map();
    this.useMock = !kv;
    this.sessions = new Map();
  }

  /**
   * Get or create session for a request
   */
  private async getSession(sessionId: string, request: Request): Promise<Session> {
    // Try to load existing session
    let session = this.sessions.get(sessionId);
    
    if (!session) {
      // Try to load from storage
      const key = `session:${sessionId}`;
      let stored: Session | null = null;
      
      if (this.useMock) {
        stored = this.mockStore.get(key);
      } else {
        try {
          const data = await this.kv!.get(key, 'json');
          if (data) {
            stored = data as Session;
            // Reconstitute Set from array
            if (Array.isArray((stored as any).endpoints)) {
              stored.endpoints = new Set((stored as any).endpoints);
            }
          }
        } catch (error) {
          console.error('Error loading session:', error);
        }
      }
      
      if (stored) {
        session = stored;
      } else {
        // Create new session
        session = {
          id: sessionId,
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          requestCount: 0,
          blockedCount: 0,
          endpoints: new Set(),
          userAgent: request.headers.get('User-Agent') || undefined,
          country: request.headers.get('CF-IPCountry') || undefined,
          reputation: 50, // Start neutral
          trustLevel: 'new',
        };
      }
      
      this.sessions.set(sessionId, session);
    }
    
    // Update session
    session.lastSeen = Date.now();
    session.requestCount++;
    
    const url = new URL(request.url);
    session.endpoints.add(url.pathname);
    
    return session;
  }

  /**
   * Save session to storage
   */
  private async saveSession(session: Session): Promise<void> {
    const key = `session:${session.id}`;
    
    // Convert Set to array for storage
    const sessionData = {
      ...session,
      endpoints: Array.from(session.endpoints),
    };
    
    if (this.useMock) {
      this.mockStore.set(key, sessionData);
    } else {
      try {
        await this.kv!.put(key, JSON.stringify(sessionData), {
          expirationTtl: 3600, // 1 hour
        });
      } catch (error) {
        console.error('Error saving session:', error);
      }
    }
  }

  /**
   * Analyze behavioral signals
   */
  private analyzeBehavior(session: Session): BehavioralSignals {
    const now = Date.now();
    const sessionAge = now - session.firstSeen;
    const requestRate = session.requestCount / (sessionAge / 1000); // req/s
    
    // Analyze request pattern using thresholds
    let requestPattern: BehavioralSignals['requestPattern'] = 'unknown';
    if (requestRate > BEHAVIORAL_THRESHOLDS.BOT_THRESHOLD) {
      requestPattern = 'bot-like';
    } else if (requestRate < BEHAVIORAL_THRESHOLDS.HUMAN_THRESHOLD && sessionAge > 5000) {
      requestPattern = 'human-like';
    }
    
    // Calculate endpoint diversity (0-1) using thresholds
    const endpointDiversity = Math.min(1, session.endpoints.size / BEHAVIORAL_THRESHOLDS.DIVERSE_THRESHOLD);
    
    // Calculate blocked ratio
    const blockedRatio = session.requestCount > 0
      ? session.blockedCount / session.requestCount
      : 0;
    
    // Time variance (simplified - in production, analyze actual request timestamps)
    const timeVariance = requestPattern === 'bot-like' ? 0.1 : 0.7;
    
    return {
      requestPattern,
      endpointDiversity,
      timeVariance,
      blockedRatio,
      sessionAge,
    };
  }

  /**
   * Update session reputation based on behavioral signals
   */
  private updateReputation(session: Session, signals: BehavioralSignals, blocked: boolean): void {
    let reputationDelta = 0;
    
    // Positive signals
    if (signals.requestPattern === 'human-like') reputationDelta += 5;
    if (signals.endpointDiversity > 0.5) reputationDelta += 3;
    if (signals.timeVariance > 0.5) reputationDelta += 3;
    if (signals.sessionAge > BEHAVIORAL_THRESHOLDS.NEW_SESSION) reputationDelta += 5;
    
    // Negative signals
    if (signals.requestPattern === 'bot-like') reputationDelta -= 10;
    if (signals.blockedRatio > BEHAVIORAL_THRESHOLDS.SUSPICIOUS_BLOCK_RATIO) reputationDelta -= 15;
    if (blocked) {
      reputationDelta -= 5;
      session.blockedCount++;
    }
    
    // Apply delta
    session.reputation = Math.max(0, Math.min(100, session.reputation + reputationDelta));
    
    // Update trust level using thresholds
    if (session.reputation >= 80 && signals.sessionAge > BEHAVIORAL_THRESHOLDS.ESTABLISHING_SESSION) {
      session.trustLevel = 'trusted'; // High reputation + established session
    } else if (session.reputation >= 60) {
      session.trustLevel = 'establishing'; // Building trust
    } else if (session.reputation <= 20 || signals.blockedRatio > BEHAVIORAL_THRESHOLDS.BLOCKED_BLOCK_RATIO) {
      session.trustLevel = 'blocked'; // Very low reputation or high block ratio
    } else if (session.reputation <= 40) {
      session.trustLevel = 'suspicious'; // Low reputation
    } else {
      session.trustLevel = 'new'; // New or neutral
    }
  }

  /**
   * Get adjusted rate limit based on session trust
   */
  private getAdjustedLimit(baseConfig: RateLimitConfig, session: Session): RateLimitConfig {
    const multiplier = TRUST_MULTIPLIERS[session.trustLevel];
    
    return {
      ...baseConfig,
      limit: Math.floor(baseConfig.limit * multiplier),
    };
  }

  /**
   * Check rate limit with session awareness and behavioral analysis
   */
  async check(
    config: RateLimitConfig,
    sessionId: string,
    request: Request
  ): Promise<RateLimitResult & { session?: Session; signals?: BehavioralSignals }> {
    const checkStart = performance.now();
    
    // Get or create session
    const session = await this.getSession(sessionId, request);
    
    // Analyze behavior
    const signals = this.analyzeBehavior(session);
    
    // Get adjusted rate limit based on trust
    const adjustedConfig = this.getAdjustedLimit(config, session);
    
    // Perform standard rate limit check with adjusted limit
    const now = Math.floor(Date.now() / 1000);
    const key = `ratelimit:${adjustedConfig.key}`;
    
    let allowed = false;
    let limit = adjustedConfig.limit;
    let remaining = 0;
    let resetAt = now + adjustedConfig.window;
    
    try {
      let data: { count: number; resetAt: number } | null = null;
      
      if (this.useMock) {
        data = this.mockStore.get(key);
      } else {
        const stored = await this.kv!.get(key, 'json');
        data = stored as { count: number; resetAt: number } | null;
      }
      
      let count = 0;
      
      if (data) {
        if (data.resetAt <= now) {
          count = 0;
          resetAt = now + adjustedConfig.window;
        } else {
          count = data.count;
          resetAt = data.resetAt;
        }
      }
      
      count++;
      allowed = count <= adjustedConfig.limit;
      remaining = Math.max(0, adjustedConfig.limit - count);
      
      // Store updated counter
      const newData = { count, resetAt };
      if (this.useMock) {
        this.mockStore.set(key, newData);
      } else {
        await this.kv!.put(key, JSON.stringify(newData), {
          expirationTtl: adjustedConfig.window + 60,
        });
      }
    } catch (error) {
      console.error('Rate limiter error:', error);
      // Fail open
      allowed = true;
      limit = adjustedConfig.limit;
      remaining = adjustedConfig.limit;
    }
    
    // Update reputation based on result
    this.updateReputation(session, signals, !allowed);
    
    // Save session
    await this.saveSession(session);
    
    return {
      allowed,
      limit,
      remaining,
      resetAt,
      retryAfter: allowed ? undefined : resetAt - now,
      timing: {
        checkDuration: performance.now() - checkStart,
      },
      session,
      signals,
    };
  }

  /**
   * Get session information
   */
  async getSessionInfo(sessionId: string): Promise<Session | null> {
    return this.sessions.get(sessionId) || null;
  }

  /**
   * Clear session
   */
  async clearSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
    
    const key = `session:${sessionId}`;
    if (this.useMock) {
      this.mockStore.delete(key);
    } else {
      await this.kv!.delete(key);
    }
  }
}

/**
 * Extract session ID from request
 * Prioritizes session cookie, falls back to IP
 */
export function getSessionId(request: Request): string {
  // Try to get session from cookie
  const cookies = request.headers.get('Cookie');
  if (cookies) {
    const match = cookies.match(/session_id=([^;]+)/);
    if (match) {
      return match[1];
    }
  }
  
  // Fall back to IP-based session
  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Forwarded-For') ||
             'unknown';
  
  return `ip:${ip}`;
}

/**
 * Create a session-aware rate limiter
 */
export function createSessionRateLimiter(env: Env): SessionAwareRateLimiter {
  return new SessionAwareRateLimiter(env.RATE_LIMIT_KV);
}
