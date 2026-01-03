// Environment variables
export interface Env {
  RATE_LIMIT_KV: KVNamespace;
  DB?: D1Database;
  TURNSTILE_SECRET_KEY?: string;
  ENVIRONMENT: string;
  TURNSTILE_ENABLED: string;
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
