/// <reference types="@cloudflare/workers-types" />

// Environment variables
export interface Env {
  RATE_LIMIT_KV: KVNamespace;
  DB?: D1Database;
  TURNSTILE_SECRET_KEY?: string;
  ENVIRONMENT: string;
  TURNSTILE_ENABLED: string;
  // Debug settings
  DEBUG_MODE?: string;      // "true" to enable debug logging
  DEBUG_LEVEL?: string;     // "error" | "warn" | "info" | "debug" | "trace"
  DEBUG_CONSOLE?: string;   // "false" to disable console output
  // Geolocation settings
  BLOCKED_COUNTRIES?: string; // Comma-separated list of country codes to block
  CHALLENGED_COUNTRIES?: string; // Comma-separated list of country codes to challenge
}

// Request tracing
export interface TraceInfo {
  traceId: string;
  timestamp: number;
  method: string;
  url: string;
  ip: string;
  country?: string;
  rayId?: string;
}

// Performance metrics
export interface PerformanceMetrics {
  startTime: number;
  endTime?: number;
  duration?: number;
  rateLimitCheckTime?: number;
  burstCheckTime?: number;
  turnstileCheckTime?: number;
  wafCheckTime?: number;
  geolocationCheckTime?: number;
  ipTrackingCheckTime?: number;
  botCheckTime?: number;
  handlerTime?: number;
  timings: {
    [key: string]: number;
  };
}

// Experiment context
export interface ExperimentContext {
  experimentId?: string;
  profileName?: string;
  attackType?: string;
  isTestTraffic?: boolean;
}

// Enhanced trace info
export interface EnhancedTraceInfo extends TraceInfo {
  requestTimestamp: number; // Request arrival time (captured at entry point)
  performance: PerformanceMetrics;
  experiment?: ExperimentContext;
}

// ============================================================================
// RATE LIMITING TYPES
// ============================================================================

export interface RateLimitConfig {
  key: string;
  limit: number;
  window: number; // seconds
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
  timing?: {
    checkDuration: number; // Time spent checking rate limit
    storageDuration?: number; // Time spent on KV operations  
  }
}

// ============================================================================
// TURNSTILE TYPES
// ============================================================================

export interface TurnstileVerifyResponse {
  success: boolean;
  challenge_ts?: string;
  hostname?: string;
  "error-codes"?: string[];
  action?: string;
  cdata?: string;
}

// ============================================================================
// WAF TYPES (XSS + Insecure Deserialization)
// ============================================================================

export interface WAFRule {
  id: string;
  description: string;
  action: "block" | "challenge" | "allow";
  conditions: Array<{
    field: string;
    operator: string;
    value: string;
  }>;
}

export interface WAFResult {
  blocked: boolean;
  rule?: WAFRule;
  reason?: string;
  timing?: {
    checkDuration: number; // Time spent evaluating WAF rules
    rulesEvaluated: number; // Number of rules evaluated
  };
}

// ============================================================================
// BOT MANAGEMENT TYPES
// ============================================================================

/**
 * Bot protection check result
 */
export interface BotCheckResult {
  allowed: boolean;
  reason?: string;
  challenges: string[];
  classification?: {
    class: 'legitimate' | 'suspicious' | 'malicious' | 'unknown';
    score: number;
    reasons: string[];
  };
}

/**
 * Session trust levels for bot management
 */
export type TrustLevel = 'new' | 'establishing' | 'trusted' | 'suspicious' | 'blocked';

/**
 * Session information for bot detection
 */
export interface BotSession {
  id: string;
  firstSeen: number;
  lastSeen: number;
  requestCount: number;
  blockedCount: number;
  reputation: number;
  trustLevel: TrustLevel;
  country?: string;
  userAgent?: string;
}

/**
 * Credential stuffing detection result
 */
export interface CredentialStuffingCheckResult {
  isAttack: boolean;
  confidence: number;
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  reason: string;
  recommendation: 'allow' | 'challenge' | 'block' | 'lockout';
}

/**
 * Spam detection result
 */
export interface SpamCheckResult {
  isSpam: boolean;
  confidence: number;
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  reason: string;
  recommendation: 'allow' | 'challenge' | 'throttle' | 'block';
}

// ============================================================================
// GEOLOCATION TYPES
// ============================================================================

/**
 * Geolocation check result
 */
export interface GeolocationCheckResult {
  allowed: boolean;
  country?: string;
  countryName?: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  reason?: string;
  action: 'allow' | 'challenge' | 'block';
}

/**
 * Country information
 */
export interface CountryInfo {
  code: string;
  name?: string;
  riskLevel?: 'low' | 'medium' | 'high' | 'critical';
  reason?: string;
}

// ============================================================================
// IP TRACKING TYPES
// ============================================================================

/**
 * IP tracking record
 */
export interface IPRecord {
  ip: string;
  firstSeen: number;
  lastSeen: number;
  totalRequests: number;
  blockedRequests: number;
  challengedRequests: number;
  country?: string;
  asn?: string;
  reputation: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  isBlocked: boolean;
  blockReason?: string;
  blockUntil?: number;
  isTrusted: boolean;
}

/**
 * IP event types
 */
export type IPEventType = 
  | 'request'
  | 'blocked'
  | 'challenged'
  | 'waf_violation'
  | 'rate_limit'
  | 'burst_detected'
  | 'credential_stuffing'
  | 'spam_detected'
  | 'reputation_change'
  | 'blocked_manually'
  | 'unblocked'
  | 'trusted'
  | 'untrusted';

/**
 * IP event
 */
export interface IPEvent {
  timestamp: number;
  type: IPEventType;
  details?: string;
  metadata?: Record<string, any>;
}

/**
 * IP block check result
 */
export interface IPBlockCheckResult {
  blocked: boolean;
  reason?: string;
  record?: IPRecord;
}

// ============================================================================
// TRAFFIC CLASSIFICATION TYPES
// ============================================================================

/**
 * Traffic classification result
 */
export type TrafficClass = 'legitimate' | 'suspicious' | 'malicious' | 'unknown';

/**
 * Traffic signals used for classification
 */
export interface TrafficSignals {
  hasValidUserAgent: boolean;
  userAgentType: 'browser' | 'bot' | 'tool' | 'unknown';
  hasCommonHeaders: boolean;
  usesHTTPS: boolean;
  requestRate: number;
  burstiness: number;
  endpointDiversity: number;
  sequentialPatterns: boolean;
  hasWAFViolations: boolean;
  hasSQLPatterns: boolean;
  hasXSSPatterns: boolean;
  hasPathTraversal: boolean;
  sessionAge: number;
  sessionRequestCount: number;
  sessionBlockedRatio: number;
  sessionReputation: number;
  country?: string;
  asn?: string;
  knownVPN: boolean;
  knownDatacenter: boolean;
}

/**
 * Classification result with details
 */
export interface ClassificationResult {
  class: TrafficClass;
  score: number;
  confidence: number;
  signals: Partial<TrafficSignals>;
  reasons: string[];
}

// ============================================================================
// API RESPONSE TYPES
// ============================================================================

export interface APIResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  trace?: TraceInfo;
  rateLimit?: {
    limit: number;
    remaining: number;
    resetAt: number;
  };
  security?: {
    waf?: {
      blocked: boolean;
      rule?: string;
    };
    geolocation?: {
      country?: string;
      blocked: boolean;
    };
    ipTracking?: {
      reputation: number;
      riskLevel: string;
    };
    botProtection?: {
      challenges: string[];
    };
  };
}
