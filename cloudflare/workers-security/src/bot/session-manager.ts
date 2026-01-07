/**
 * Bot Session Manager
 * Handles session tracking and behavioral analysis for bot management
 * Extracted from rate-limiter to focus on bot protection concerns
 */

import type { Env, RateLimitConfig, RateLimitResult } from "../types";

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
  trustLevel: TrustLevel;
}

/**
 * Trust levels for session management
 */
export type TrustLevel = 'new' | 'establishing' | 'trusted' | 'suspicious' | 'blocked';

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

/**
 * Multipliers applied based on session trust level
 * These allow trusted users more headroom
 */
export const TRUST_MULTIPLIERS: Record<TrustLevel, number> = {
  trusted: 3.0,      // Established users get 3x the limit
  establishing: 2.0, // Building trust gets 2x
  new: 1.0,          // New sessions get base limit
  suspicious: 0.5,   // Suspicious gets 0.5x
  blocked: 0.1,      // Blocked gets minimal (for appeals)
};

/**
 * Generate a session ID from request information
 * Uses IP + User-Agent hash as a fallback when no session cookie exists
 */
export function getSessionId(request: Request): string {
  // Try to get session from cookie first
  const cookieHeader = request.headers.get('Cookie');
  if (cookieHeader) {
    const sessionMatch = cookieHeader.match(/session_id=([^;]+)/);
    if (sessionMatch) {
      return sessionMatch[1];
    }
  }
  
  // Fallback: create ID from IP + User-Agent
  const ip = request.headers.get('CF-Connecting-IP') || 
             request.headers.get('X-Forwarded-For')?.split(',')[0] || 
             'unknown';
  const userAgent = request.headers.get('User-Agent') || 'unknown';
  
  // Simple hash for session identification
  const data = `${ip}:${userAgent}`;
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  
  return `session_${Math.abs(hash).toString(36)}`;
}

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
 * Bot Session Manager with behavioral analysis
 * Manages session tracking and trust scoring for bot detection
 */
export class BotSessionManager {
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
  async getSession(sessionId: string, request: Request): Promise<Session> {
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
  async saveSession(session: Session): Promise<void> {
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
  analyzeBehavior(session: Session): BehavioralSignals {
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
  updateReputation(session: Session, signals: BehavioralSignals, blocked: boolean): void {
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
  getAdjustedLimit(baseConfig: RateLimitConfig, session: Session): RateLimitConfig {
    const multiplier = TRUST_MULTIPLIERS[session.trustLevel];
    
    return {
      ...baseConfig,
      limit: Math.floor(baseConfig.limit * multiplier),
    };
  }

  /**
   * Check if session appears to be a bot
   */
  isLikelyBot(session: Session): boolean {
    const signals = this.analyzeBehavior(session);
    return signals.requestPattern === 'bot-like' || 
           session.trustLevel === 'blocked' ||
           session.trustLevel === 'suspicious';
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

  /**
   * Get all active sessions
   */
  getAllSessions(): Session[] {
    return Array.from(this.sessions.values());
  }

  /**
   * Cleanup old sessions from memory
   */
  cleanupSessions(maxAge: number = 3600000): void {
    const now = Date.now();
    const cutoff = now - maxAge;
    
    for (const [id, session] of this.sessions.entries()) {
      if (session.lastSeen < cutoff) {
        this.sessions.delete(id);
      }
    }
  }
}

/**
 * Session-aware rate limiter that incorporates behavioral analysis
 */
export class SessionAwareRateLimiter {
  private kv: KVNamespace | null;
  private mockStore: Map<string, any>;
  private useMock: boolean;
  private sessionManager: BotSessionManager;

  constructor(kv?: KVNamespace) {
    this.kv = kv || null;
    this.mockStore = new Map();
    this.useMock = !kv;
    this.sessionManager = new BotSessionManager(kv);
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
    const session = await this.sessionManager.getSession(sessionId, request);
    
    // Analyze behavior
    const signals = this.sessionManager.analyzeBehavior(session);
    
    // Get adjusted rate limit based on trust
    const adjustedConfig = this.sessionManager.getAdjustedLimit(config, session);
    
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
    this.sessionManager.updateReputation(session, signals, !allowed);
    
    // Save session
    await this.sessionManager.saveSession(session);
    
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
   * Get session manager for direct access
   */
  getSessionManager(): BotSessionManager {
    return this.sessionManager;
  }
}

/**
/**
 * Create a bot session manager
 */
export function createBotSessionManager(env: Env): BotSessionManager {
  return new BotSessionManager(env.RATE_LIMIT_KV);
}

/**
 * Create a session-aware rate limiter
 */
export function createSessionRateLimiter(env: Env): SessionAwareRateLimiter {
  return new SessionAwareRateLimiter(env.RATE_LIMIT_KV);
}

