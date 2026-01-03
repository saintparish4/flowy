import type { Env } from "./types";
import {
  createTraceInfo,
  createErrorResponse,
  createSuccessResponse,
  logTrace,
  addTraceHeaders,
} from "./tracing";
import {
  createRateLimiter,
  getRateLimitKey,
  RATE_LIMIT_PROFILES,
} from "./rate-limiter";
import {
  createTurnstileVerifier,
  TurnstileVerifier,
  requireTurnstile,
} from "./turnstile";
import { checkWAF, createWAFBlockResponse, getWAFRules } from "./waf";

// Cloudflare Workers types
type ExecutionContext = {
  waitUntil(promise: Promise<any>): void;
  passThroughOnException(): void;
};

type CfProperties = {
  colo?: string;
  country?: string;
  [key: string]: any;
};

interface RequestWithCf extends Request {
  cf?: CfProperties;
}

// CORS headers for development
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, CF-Turnstile-Token",
};

/**
 * Handle OPTIONS preflight requests
 */
function handleOptions(): Response {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}

/**
 * Main Worker entry point
 */
export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return handleOptions();
    }

    // Create trace for this request
    const trace = createTraceInfo(request);
    logTrace(trace, { environment: env.ENVIRONMENT });

    try {
      const url = new URL(request.url);

      // WAF check - block malicious requests early
      const wafResult = checkWAF(request);
      if (wafResult.blocked) {
        const response = createWAFBlockResponse(wafResult);
        logTrace(trace, { waf: "blocked", rule: wafResult.rule?.id });
        return addTraceHeaders(response, trace);
      }

      // Route handling
      switch (url.pathname) {
        case "/":
          return handleRoot(request, env, trace);

        case "/api/public":
          return handlePublicAPI(request, env, trace);

        case "/api/protected":
          return handleProtectedAPI(request, env, trace);

        case "/api/login":
          return handleLogin(request, env, trace);

        case "/api/status":
          return handleStatus(request, env, trace);

        case "/api/rules":
          return handleRules(request, env, trace);

        default:
          return createErrorResponse("Not Found", 404, trace);
      }
    } catch (error) {
      console.error("Worker error:", error);
      logTrace(trace, { error: String(error) });

      return createErrorResponse("Internal Server Error", 500, trace, {
        error: String(error),
      });
    }
  },
};

/**
 * Root endpoint - shows API documentation
 */
async function handleRoot(
  request: Request,
  env: Env,
  trace: any
): Promise<Response> {
  const docs = {
    name: "Cloudflare Workers Security Example",
    version: "1.0.0",
    endpoints: {
      "/": "API documentation (this page)",
      "/api/public": "Public endpoint with relaxed rate limiting",
      "/api/protected": "Protected endpoint requiring Turnstile verification",
      "/api/login": "Login endpoint with strict rate limiting",
      "/api/status": "Service status and configuration info",
      "/api/rules": "List active WAF rules",
    },
    features: [
      "Request tracing with unique trace IDs",
      "Rate limiting using Cloudflare KV",
      "Turnstile bot protection",
      "WAF rule simulation",
      "Mock implementations for local development",
    ],
    security: {
      turnstileEnabled: env.TURNSTILE_ENABLED === "true",
      wafEnabled: true,
      rateLimitingEnabled: true,
    },
  };

  return createSuccessResponse(docs, trace, CORS_HEADERS);
}

/**
 * Public API endpoint with relaxed rate limiting
 */
async function handlePublicAPI(
  request: Request,
  env: Env,
  trace: any
): Promise<Response> {
  const rateLimiter = createRateLimiter(env);
  const key = getRateLimitKey(request, "public");

  const rateLimit = await rateLimiter.check({
    key,
    ...RATE_LIMIT_PROFILES.RELAXED,
  });

  if (!rateLimit.allowed) {
    logTrace(trace, { rateLimit: "exceeded", profile: "relaxed" });
    return createErrorResponse("Rate limit exceeded", 429, trace, {
      rateLimit: {
        limit: rateLimit.limit,
        remaining: rateLimit.remaining,
        resetAt: rateLimit.resetAt,
        retryAfter: rateLimit.retryAfter,
      },
    });
  }

  const data = {
    message: "This is a public API endpoint",
    timestamp: Date.now(),
    yourIP: trace.ip,
  };

  const response = createSuccessResponse(data, trace, CORS_HEADERS);

  // Add rate limit headers
  const headers = new Headers(response.headers);
  headers.set("X-RateLimit-Limit", rateLimit.limit.toString());
  headers.set("X-RateLimit-Remaining", rateLimit.remaining.toString());
  headers.set("X-RateLimit-Reset", rateLimit.resetAt.toString());

  return new Response(response.body, {
    status: response.status,
    headers,
  });
}

/**
 * Protected API endpoint requiring Turnstile verification
 */
async function handleProtectedAPI(
  request: Request,
  env: Env,
  trace: any
): Promise<Response> {
  // Check Turnstile first
  const turnstileResult = await requireTurnstile(request, env);

  if (!turnstileResult.success) {
    logTrace(trace, { turnstile: "failed" });
    return createErrorResponse(
      turnstileResult.error || "Verification failed",
      403,
      trace,
      { turnstileError: turnstileResult.response?.["error-codes"] }
    );
  }

  // Apply rate limiting
  const rateLimiter = createRateLimiter(env);
  const key = getRateLimitKey(request, "protected");

  const rateLimit = await rateLimiter.check({
    key,
    ...RATE_LIMIT_PROFILES.NORMAL,
  });

  if (!rateLimit.allowed) {
    logTrace(trace, { rateLimit: "exceeded", profile: "normal" });
    return createErrorResponse("Rate limit exceeded", 429, trace, {
      rateLimit,
    });
  }

  const data = {
    message: "Successfully accessed protected endpoint",
    timestamp: Date.now(),
    turnstileValidated: true,
  };

  return createSuccessResponse(data, trace, CORS_HEADERS);
}

/**
 * Login endpoint with strict rate limiting
 */
async function handleLogin(
  request: Request,
  env: Env,
  trace: any
): Promise<Response> {
  if (request.method !== "POST") {
    return createErrorResponse("Method not allowed", 405, trace);
  }

  // Strict rate limiting for login attempts
  const rateLimiter = createRateLimiter(env);
  const key = getRateLimitKey(request, "login");

  const rateLimit = await rateLimiter.check({
    key,
    ...RATE_LIMIT_PROFILES.STRICT,
  });

  if (!rateLimit.allowed) {
    logTrace(trace, {
      rateLimit: "exceeded",
      profile: "strict",
      endpoint: "login",
    });
    return createErrorResponse(
      "Too many login attempts. Please try again later.",
      429,
      trace,
      { rateLimit }
    );
  }

  // In a real app, you'd validate credentials here
  const data = {
    message: "Login endpoint (demo)",
    note: "This is a demonstration. Real authentication would validate credentials.",
    attemptsRemaining: rateLimit.remaining,
  };

  return createSuccessResponse(data, trace, CORS_HEADERS);
}

/**
 * Status endpoint - shows service configuration
 */
async function handleStatus(
  request: Request,
  env: Env,
  trace: any
): Promise<Response> {
  const status = {
    service: "workers-security-example",
    environment: env.ENVIRONMENT,
    timestamp: Date.now(),
    features: {
      turnstile: {
        enabled: env.TURNSTILE_ENABLED === "true",
        configured: !!env.TURNSTILE_SECRET_KEY,
      },
      rateLimit: {
        enabled: true,
        backend: env.RATE_LIMIT_KV ? "kv" : "mock",
      },
      waf: {
        enabled: true,
        rulesCount: getWAFRules().length,
      },
      tracing: {
        enabled: true,
      },
    },
    cloudflare: {
      ray: trace.rayId,
      country: trace.country,
      colo: (request as RequestWithCf).cf?.colo,
    },
  };

  return createSuccessResponse(status, trace, CORS_HEADERS);
}

/**
 * Rules endpoint - list active WAF rules
 */
async function handleRules(
  request: Request,
  env: Env,
  trace: any
): Promise<Response> {
  const rules = getWAFRules();

  const data = {
    count: rules.length,
    rules: rules.map((rule) => ({
      id: rule.id,
      description: rule.description,
      action: rule.action,
      conditionsCount: rule.conditions.length,
    })),
  };

  return createSuccessResponse(data, trace, CORS_HEADERS);
}
