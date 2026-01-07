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

// Rate Limiting
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

// Turnstile
export interface TurnstileVerifyResponse {
  success: boolean;
  challenge_ts?: string;
  hostname?: string;
  "error-codes"?: string[];
  action?: string;
  cdata?: string;
}

// WAF simulation
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

// API Response types
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
}
