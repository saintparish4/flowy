import type { Env } from "../types";
import {
  createTraceInfo,
  createErrorResponse,
  createSuccessResponse,
  logTrace,
  addTraceHeaders,
  finalizePerformance,
  type EnhancedTraceInfo,
} from "../tracing/tracing";
import {
  createRateLimiter,
  getRateLimitKey,
  getRateLimitProfile,
  RATE_LIMIT_PROFILES,
} from "../rate-limiter/rate-limiter";
import {
  createBurstDetector,
  BURST_PROFILES,
  type BurstConfig,
} from "../rate-limiter/burst-detector";
import {
  checkWAF, 
  createWAFBlockResponse, 
  getWAFRules, 
  setWAFDebugMode, 
  generateWAFAnalysisReport,
  analyzeRequest 
} from "../rules/waf";
import { 
  getDebugLogger, 
  LatencyDebug,
  type DebugLogger,
  type DebugConfig,
} from "../utils/debug";

// Bot management imports
import {
  createBotProtectionManager,
  BotProtectionManager,
  type BotProtectionConfig,
} from "../bot";
import { TurnstileVerifier, requireTurnstile } from "../bot/turnstile";

// Geolocation and IP tracking imports
import { 
  GeolocationBlocker, 
  createGeolocationBlocker,
  type GeolocationConfig,
} from "../tracing/geolocation";
import { 
  IPTracker, 
  createIPTracker,
  getIPFromRequest,
  type IPTrackingConfig,
} from "../tracing/ip-tracking";

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

// Get CORS headers based on environment
function getCorsHeaders(env: Env, origin?: string | null): Record<string, string> {
  const isDevelopment = env.ENVIRONMENT === "development";

  // In development, allow all origins. In production, be more restrictive.
  const allowOrigin = isDevelopment
    ? "*"
    : (origin && isAllowedOrigin(origin) ? origin : "null");

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, CF-Turnstile-Token, X-Debug-Mode, X-Experiment-ID",
    "Access-Control-Max-Age": "86400", // 24 hours
  };
}

// Check if origin is allowed (customize this list for your needs)
function isAllowedOrigin(origin: string): boolean {
  const allowedOrigins = [
    "http://localhost:8787",
    "http://localhost:3000",
    "https://your-domain.com", // Replace with your actual domain
  ];
  return allowedOrigins.includes(origin);
}

// Debug mode can be enabled via environment or header
function isDebugEnabled(request: Request, env: Env): boolean {
  return (
    env.DEBUG_MODE === "true" || 
    request.headers.get("X-Debug-Mode") === "true" ||
    request.headers.get("X-Test-Traffic") === "true"
  );
}

// Get debug configuration from environment
function getDebugConfig(env: Env): Partial<DebugConfig> {
  const validLevels = ['off', 'error', 'warn', 'info', 'debug', 'trace'];
  const level = env.DEBUG_LEVEL && validLevels.includes(env.DEBUG_LEVEL)
    ? env.DEBUG_LEVEL
    : 'debug';

  return {
    enabled: env.DEBUG_MODE === "true",
    level: level as 'off' | 'error' | 'warn' | 'info' | 'debug' | 'trace',
    outputToConsole: env.DEBUG_CONSOLE !== "false",
  };
}

/**
 * Handle OPTIONS preflight requests
 */
function handleOptions(request: Request, env: Env): Response {
  const origin = request.headers.get("Origin");
  return new Response(null, {
    status: 204,
    headers: getCorsHeaders(env, origin),
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
      return handleOptions(request, env);
    }

    // Create trace for this request
    const trace = createTraceInfo(request);
    const traceId = trace.traceId;

    // Capture request timestamp at entry point (before any processing)
    // This ensures burst detection uses actual arrival time, not processing time
    const requestTimestamp = Date.now();
    trace.requestTimestamp = requestTimestamp;

    // Initialize debug logger
    const debugEnabled = isDebugEnabled(request, env);
    const logger = getDebugLogger(getDebugConfig(env));
    
    // Enable/disable WAF debug mode based on request
    setWAFDebugMode(debugEnabled);

    // Initialize security managers
    const geoBlocker = createGeolocationBlocker();
    const ipTracker = createIPTracker(env);
    const botManager = createBotProtectionManager(env);

    // Start request timing
    if (debugEnabled) {
      LatencyDebug.requestStart(logger, traceId, trace.url, trace.method);
    }

    logTrace(trace, { environment: env.ENVIRONMENT, debugEnabled });

    try {
      const url = new URL(request.url);
      const ip = getIPFromRequest(request);

      // ====================================================================
      // SECURITY LAYER 0: GEOLOCATION CHECK
      // ====================================================================
      const geoResult = geoBlocker.check(request);
      if (!geoResult.allowed) {
        if (debugEnabled) {
          logger.warn('security', `Geolocation blocked: ${geoResult.reason}`, {
            country: geoResult.country,
            riskLevel: geoResult.riskLevel,
          }, traceId);
        }
        
        // Track the blocked request
        await ipTracker.trackRequest(ip, request, { blocked: true });
        
        return createErrorResponse(
          `Access denied from your region`,
          403,
          trace,
          { geolocation: { country: geoResult.country, reason: geoResult.reason } }
        );
      }

      // ====================================================================
      // SECURITY LAYER 1: IP REPUTATION CHECK
      // ====================================================================
      const ipBlockCheck = await ipTracker.shouldBlock(ip);
      if (ipBlockCheck.blocked) {
        if (debugEnabled) {
          logger.warn('security', `IP blocked: ${ipBlockCheck.reason}`, {
            ip,
            reason: ipBlockCheck.reason,
          }, traceId);
        }
        
        return createErrorResponse(
          `Access denied`,
          403,
          trace,
          { ipBlocked: true, reason: ipBlockCheck.reason }
        );
      }

      // ====================================================================
      // SECURITY LAYER 2: WAF CHECK (XSS + Deserialization)
      // ====================================================================
      if (debugEnabled) {
        LatencyDebug.securityCheckStart(logger, 'waf', traceId);
        logger.info('security', '▶ Starting WAF check (XSS + Deserialization)', {
          url: url.pathname + url.search,
        }, traceId);
      }

      const wafResult = await checkWAF(request, traceId);
      
      if (debugEnabled) {
        const wafDuration = LatencyDebug.securityCheckEnd(logger, 'waf', traceId, wafResult);
        trace.performance.wafCheckTime = wafDuration;
        
        logger.info('security', `◀ WAF check complete`, {
          blocked: wafResult.blocked,
          rule: wafResult.rule?.id,
          reason: wafResult.reason,
          rulesEvaluated: wafResult.timing?.rulesEvaluated,
          duration: `${wafDuration.toFixed(3)}ms`,
        }, traceId);
      }

      if (wafResult.blocked) {
        const response = createWAFBlockResponse(wafResult);
        logTrace(trace, { waf: "blocked", rule: wafResult.rule?.id });
        
        // Track WAF violation
        await ipTracker.trackRequest(ip, request, { blocked: true, wafViolation: true });
        
        if (debugEnabled) {
          LatencyDebug.requestEnd(logger, traceId, 403);
          LatencyDebug.breakdown(logger, traceId);
        }
        
        finalizePerformance(trace);
        return addTraceHeaders(response, trace);
      }

      // Track normal request
      await ipTracker.trackRequest(ip, request);

      // ====================================================================
      // ROUTING
      // ====================================================================
      if (debugEnabled) {
        LatencyDebug.handlerStart(logger, url.pathname, traceId);
      }

      let response: Response;

      switch (url.pathname) {
        case "/":
          response = await handleRoot(request, env, trace, logger, debugEnabled, requestTimestamp);
          break;

        case "/api/public":
          response = await handlePublicAPI(request, env, trace, logger, debugEnabled, requestTimestamp, ipTracker);
          break;

        case "/api/protected":
          response = await handleProtectedAPI(request, env, trace, logger, debugEnabled, requestTimestamp, ipTracker);
          break;

        case "/api/login":
          response = await handleLogin(request, env, trace, logger, debugEnabled, requestTimestamp, ipTracker, botManager);
          break;

        case "/api/status":
          response = await handleStatus(request, env, trace, logger, debugEnabled, requestTimestamp, geoBlocker, ipTracker);
          break;

        case "/api/rules":
          response = await handleRules(request, env, trace, logger, debugEnabled, requestTimestamp);
          break;

        case "/api/debug/waf":
          response = await handleWAFDebug(request, env, trace, logger);
          break;

        case "/api/debug/timing":
          response = await handleTimingDebug(request, env, trace, logger);
          break;

        default:
          response = createErrorResponse("Not Found", 404, trace);
      }

      if (debugEnabled) {
        const handlerDuration = LatencyDebug.handlerEnd(logger, url.pathname, traceId, response.status);
        trace.performance.handlerTime = handlerDuration;
      }

      // Finalize timing and add debug info to response
      finalizePerformance(trace);
      
      if (debugEnabled) {
        LatencyDebug.requestEnd(logger, traceId, response.status);
        LatencyDebug.breakdown(logger, traceId);
        
        // Add debug timing headers
        const timingCheckpoints = logger.getTimingCheckpoints(traceId);
        const serverTimings = timingCheckpoints
          .map(cp => `${cp.name};dur=${cp.elapsed.toFixed(1)}`)
          .join(', ');
        
        const headers = new Headers(response.headers);
        if (serverTimings) {
          headers.set('Server-Timing', serverTimings);
        }
        headers.set('X-Debug-Entries', logger.getEntriesForTrace(traceId).length.toString());
        
        response = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers,
        });
      }

      return addTraceHeaders(response, trace);
    } catch (error) {
      console.error("Worker error:", error);
      logTrace(trace, { error: String(error) });

      if (debugEnabled) {
        logger.error('request', 'Worker error occurred', {
          error: String(error),
          stack: (error as Error).stack,
        }, traceId);
        LatencyDebug.requestEnd(logger, traceId, 500);
      }

      finalizePerformance(trace);
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
  trace: EnhancedTraceInfo,
  logger: DebugLogger,
  debugEnabled: boolean,
  requestTimestamp: number
): Promise<Response> {
  const docs = {
    name: "Cloudflare Workers Security Example",
    version: "2.0.0",
    endpoints: {
      "/": "API documentation (this page)",
      "/api/public": "Public endpoint with relaxed rate limiting",
      "/api/protected": "Protected endpoint requiring Turnstile verification",
      "/api/login": "Login endpoint with strict rate limiting and credential stuffing detection",
      "/api/status": "Service status and configuration info",
      "/api/rules": "List active WAF rules (XSS + Deserialization)",
      "/api/debug/waf": "WAF debug analysis (POST with URL to analyze)",
      "/api/debug/timing": "Request timing debug info",
    },
    features: [
      "Request tracing with unique trace IDs",
      "Rate limiting using Cloudflare KV (DoS/DDoS, brute force, scraping)",
      "Burst detection with queuing and throttling",
      "Turnstile bot protection",
      "WAF rules (XSS + Insecure Deserialization)",
      "Bot management (credential stuffing, spam detection)",
      "Geolocation blocking",
      "IP tracking and reputation",
      "Session-aware rate limiting",
      "Comprehensive debug logging",
    ],
    security: {
      turnstileEnabled: env.TURNSTILE_ENABLED === "true",
      wafEnabled: true,
      wafCategories: ["xss", "insecure-deserialization"],
      rateLimitingEnabled: true,
      geolocationBlockingEnabled: true,
      ipTrackingEnabled: true,
      botProtectionEnabled: true,
    },
    debug: {
      enabled: debugEnabled,
      hint: "Add X-Debug-Mode: true header to enable debug logging",
    },
  };

  return createSuccessResponse(docs, trace, getCorsHeaders(env, request.headers.get("Origin")));
}

/**
 * Public API endpoint with relaxed rate limiting
 */
async function handlePublicAPI(
  request: Request,
  env: Env,
  trace: EnhancedTraceInfo,
  logger: DebugLogger,
  debugEnabled: boolean,
  requestTimestamp: number,
  ipTracker: IPTracker
): Promise<Response> {
  const traceId = trace.traceId;
  const ip = getIPFromRequest(request);
  
  const rateLimiter = createRateLimiter(env);
  const burstDetector = createBurstDetector(env);
  const key = getRateLimitKey(request, "public");
  const url = new URL(request.url);
  
  // Get rate limit profile and burst detection for this endpoint
  const rateLimitProfile = getRateLimitProfile(url.pathname);
  const burstConfig: BurstConfig = BURST_PROFILES.RELAXED;

  // ====================================================================
  // SECURITY LAYER 3: BURST DETECTION
  // ====================================================================
  if (debugEnabled) {
    LatencyDebug.securityCheckStart(logger, 'burst', traceId);
  }

  const burstResult = await burstDetector.check(key, burstConfig, requestTimestamp);

  if (debugEnabled) {
    const burstDuration = LatencyDebug.securityCheckEnd(logger, 'burst', traceId, burstResult);
    trace.performance.burstCheckTime = burstDuration;
    logger.debug('security', 'Burst detection result', {
      isBurst: burstResult.isBurst,
      severity: burstResult.severity,
      recommendation: burstResult.recommendation,
      shortWindowCount: burstResult.shortWindowCount,
      shortWindowLimit: burstResult.shortWindowLimit,
      duration: `${burstDuration.toFixed(3)}ms`,
    }, traceId);
  }
  
  if (burstResult.isBurst) {
    if (burstResult.recommendation === 'block' || burstResult.severity === 'critical') {
      await ipTracker.trackRequest(ip, request, { blocked: true, burstViolation: true });
      
      logTrace(trace, { 
        burst: "blocked", 
        severity: burstResult.severity,
        shortWindowCount: burstResult.shortWindowCount,
        shortWindowLimit: burstResult.shortWindowLimit,
      });
      return createErrorResponse("Rate limit exceeded (burst detected)", 429, trace, {
        burst: {
          severity: burstResult.severity,
          shortWindowCount: burstResult.shortWindowCount,
          shortWindowLimit: burstResult.shortWindowLimit,
          recommendation: burstResult.recommendation,
        },
      });
    } else if (burstResult.recommendation === 'queue') {
      try {
        if (debugEnabled) {
          logger.debug('security', 'Request queued for throttling', { key }, traceId);
        }
        await burstDetector.queue(key, 5000);
      } catch (error: any) {
        if (error.message === 'Request queue timeout') {
          logTrace(trace, { burst: "queued_timeout" });
          return createErrorResponse("Request queued timeout", 429, trace);
        }
      }
    } else if (burstResult.recommendation === 'throttle') {
      if (debugEnabled) {
        logger.debug('security', 'Request throttled (burst smoothing)', {
          severity: burstResult.severity,
          shortWindowCount: burstResult.shortWindowCount,
          shortWindowLimit: burstResult.shortWindowLimit,
        }, traceId);
      }
      const throttleDelay = burstResult.severity === 'medium' ? 5 : 2;
      await new Promise(resolve => setTimeout(resolve, throttleDelay));
      logTrace(trace, { burst: "throttled", severity: burstResult.severity });
    }
  }

  // ====================================================================
  // SECURITY LAYER 4: RATE LIMITING
  // ====================================================================
  if (debugEnabled) {
    LatencyDebug.securityCheckStart(logger, 'rate-limit', traceId);
  }

  const rateLimit = await rateLimiter.check({
    key,
    ...rateLimitProfile,
  });

  if (debugEnabled) {
    const rlDuration = LatencyDebug.securityCheckEnd(logger, 'rate-limit', traceId, rateLimit);
    trace.performance.rateLimitCheckTime = rlDuration;
    logger.debug('security', 'Rate limit check result', {
      allowed: rateLimit.allowed,
      limit: rateLimit.limit,
      remaining: rateLimit.remaining,
      resetAt: new Date(rateLimit.resetAt * 1000).toISOString(),
      duration: `${rlDuration.toFixed(3)}ms`,
    }, traceId);
  }

  if (!rateLimit.allowed) {
    await ipTracker.trackRequest(ip, request, { blocked: true, rateLimitViolation: true });
    
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

  const response = createSuccessResponse(data, trace, getCorsHeaders(env, request.headers.get("Origin")));

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
  trace: EnhancedTraceInfo,
  logger: DebugLogger,
  debugEnabled: boolean,
  requestTimestamp: number,
  ipTracker: IPTracker
): Promise<Response> {
  const traceId = trace.traceId;
  const ip = getIPFromRequest(request);

  // ====================================================================
  // SECURITY LAYER 3: TURNSTILE VERIFICATION
  // ====================================================================
  if (debugEnabled) {
    LatencyDebug.securityCheckStart(logger, 'turnstile', traceId);
  }

  const turnstileResult = await requireTurnstile(request, env);

  if (debugEnabled) {
    const tsDuration = LatencyDebug.securityCheckEnd(logger, 'turnstile', traceId, turnstileResult);
    trace.performance.turnstileCheckTime = tsDuration;
    logger.debug('security', 'Turnstile verification result', {
      success: turnstileResult.success,
      error: turnstileResult.error,
      duration: `${tsDuration.toFixed(3)}ms`,
    }, traceId);
  }

  if (!turnstileResult.success) {
    await ipTracker.trackRequest(ip, request, { challenged: true });
    
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
  const burstDetector = createBurstDetector(env);
  const key = getRateLimitKey(request, "protected");
  const url = new URL(request.url);
  
  const rateLimitProfile = getRateLimitProfile(url.pathname);
  const burstConfig: BurstConfig = BURST_PROFILES.NORMAL;

  // Burst detection
  if (debugEnabled) {
    LatencyDebug.securityCheckStart(logger, 'burst', traceId);
  }

  const burstResult = await burstDetector.check(key, burstConfig, requestTimestamp);

  if (debugEnabled) {
    const burstDuration = LatencyDebug.securityCheckEnd(logger, 'burst', traceId, burstResult);
    trace.performance.burstCheckTime = burstDuration;
  }
  
  if (burstResult.isBurst) {
    if (burstResult.recommendation === 'block' || burstResult.severity === 'critical') {
      await ipTracker.trackRequest(ip, request, { blocked: true, burstViolation: true });
      
      logTrace(trace, { burst: "blocked", severity: burstResult.severity });
      return createErrorResponse("Rate limit exceeded (burst detected)", 429, trace, {
        burst: {
          severity: burstResult.severity,
          recommendation: burstResult.recommendation,
        },
      });
    } else if (burstResult.recommendation === 'queue') {
      try {
        await burstDetector.queue(key, 5000);
      } catch (error: any) {
        if (error.message === 'Request queue timeout') {
          return createErrorResponse("Request queued timeout", 429, trace);
        }
      }
    }
  }

  // Rate limiting
  if (debugEnabled) {
    LatencyDebug.securityCheckStart(logger, 'rate-limit', traceId);
  }

  const rateLimit = await rateLimiter.check({
    key,
    ...rateLimitProfile,
  });

  if (debugEnabled) {
    const rlDuration = LatencyDebug.securityCheckEnd(logger, 'rate-limit', traceId, rateLimit);
    trace.performance.rateLimitCheckTime = rlDuration;
  }

  if (!rateLimit.allowed) {
    await ipTracker.trackRequest(ip, request, { blocked: true, rateLimitViolation: true });
    
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

  return createSuccessResponse(data, trace, getCorsHeaders(env, request.headers.get("Origin")));
}

/**
 * Login endpoint with strict rate limiting and credential stuffing detection
 */
async function handleLogin(
  request: Request,
  env: Env,
  trace: EnhancedTraceInfo,
  logger: DebugLogger,
  debugEnabled: boolean,
  requestTimestamp: number,
  ipTracker: IPTracker,
  botManager: BotProtectionManager
): Promise<Response> {
  const traceId = trace.traceId;
  const ip = getIPFromRequest(request);

  if (request.method !== "POST") {
    return createErrorResponse("Method not allowed", 405, trace);
  }

  // ====================================================================
  // SECURITY LAYER 3: CREDENTIAL STUFFING DETECTION
  // ====================================================================
  const credentialDetector = botManager.getCredentialStuffingDetector();
  if (credentialDetector) {
    const credResult = await credentialDetector.check(ip);
    
    if (debugEnabled) {
      logger.debug('security', 'Credential stuffing check', {
        isAttack: credResult.isAttack,
        confidence: credResult.confidence,
        severity: credResult.severity,
        recommendation: credResult.recommendation,
      }, traceId);
    }
    
    if (credResult.recommendation === 'lockout' || credResult.recommendation === 'block') {
      await ipTracker.trackRequest(ip, request, { blocked: true, credentialStuffing: true });
      
      return createErrorResponse(
        "Too many login attempts. Your IP has been temporarily blocked.",
        403,
        trace,
        { credentialStuffing: { severity: credResult.severity, reason: credResult.reason } }
      );
    }
  }

  const rateLimiter = createRateLimiter(env);
  const burstDetector = createBurstDetector(env);
  const key = getRateLimitKey(request, "login");
  const url = new URL(request.url);
  
  const rateLimitProfile = getRateLimitProfile(url.pathname);
  const burstConfig: BurstConfig = BURST_PROFILES.STRICT;

  // ====================================================================
  // SECURITY LAYER 4: BURST DETECTION (STRICT)
  // ====================================================================
  if (debugEnabled) {
    LatencyDebug.securityCheckStart(logger, 'burst', traceId);
    logger.info('security', 'Login endpoint - applying STRICT burst detection', undefined, traceId);
  }

  const burstResult = await burstDetector.check(key, burstConfig, requestTimestamp);

  if (debugEnabled) {
    const burstDuration = LatencyDebug.securityCheckEnd(logger, 'burst', traceId, burstResult);
    trace.performance.burstCheckTime = burstDuration;
    logger.debug('security', 'Burst detection result (STRICT)', {
      isBurst: burstResult.isBurst,
      severity: burstResult.severity,
      recommendation: burstResult.recommendation,
      duration: `${burstDuration.toFixed(3)}ms`,
    }, traceId);
  }
  
  if (burstResult.isBurst) {
    if (burstResult.recommendation === 'block' || 
        burstResult.severity === 'critical' || 
        burstResult.severity === 'high') {
      await ipTracker.trackRequest(ip, request, { blocked: true, burstViolation: true });
      
      logTrace(trace, {
        burst: "blocked",
        severity: burstResult.severity,
        endpoint: "login",
      });
      return createErrorResponse(
        "Too many login attempts. Please try again later.",
        429,
        trace,
        {
          burst: {
            severity: burstResult.severity,
            shortWindowCount: burstResult.shortWindowCount,
            shortWindowLimit: burstResult.shortWindowLimit,
          },
        }
      );
    } else if (burstResult.recommendation === 'queue' || burstResult.recommendation === 'throttle') {
      try {
        await burstDetector.queue(key, 3000);
      } catch (error: any) {
        if (error.message === 'Request queue timeout') {
          return createErrorResponse(
            "Too many login attempts. Please try again later.",
            429,
            trace
          );
        }
      }
    }
  }

  // ====================================================================
  // SECURITY LAYER 5: RATE LIMITING (STRICT)
  // ====================================================================
  if (debugEnabled) {
    LatencyDebug.securityCheckStart(logger, 'rate-limit', traceId);
  }

  const rateLimit = await rateLimiter.check({
    key,
    ...rateLimitProfile,
  });

  if (debugEnabled) {
    const rlDuration = LatencyDebug.securityCheckEnd(logger, 'rate-limit', traceId, rateLimit);
    trace.performance.rateLimitCheckTime = rlDuration;
    logger.debug('security', 'Rate limit check result (STRICT)', {
      allowed: rateLimit.allowed,
      limit: rateLimit.limit,
      remaining: rateLimit.remaining,
      duration: `${rlDuration.toFixed(3)}ms`,
    }, traceId);
  }

  if (!rateLimit.allowed) {
    await ipTracker.trackRequest(ip, request, { blocked: true, rateLimitViolation: true });
    
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

  // Record login attempt for credential stuffing detection
  if (credentialDetector) {
    await credentialDetector.recordAttempt({
      timestamp: Date.now(),
      ip,
      success: true, // In real implementation, this would depend on actual login result
      userAgent: request.headers.get('User-Agent') || undefined,
      country: request.headers.get('CF-IPCountry') || undefined,
    });
  }

  const data = {
    message: "Login endpoint (demo)",
    note: "This is a demonstration. Real authentication would validate credentials.",
    attemptsRemaining: rateLimit.remaining,
  };

  return createSuccessResponse(data, trace, getCorsHeaders(env, request.headers.get("Origin")));
}

/**
 * Status endpoint - shows service configuration
 */
async function handleStatus(
  request: Request,
  env: Env,
  trace: EnhancedTraceInfo,
  logger: DebugLogger,
  debugEnabled: boolean,
  requestTimestamp: number,
  geoBlocker: GeolocationBlocker,
  ipTracker: IPTracker
): Promise<Response> {
  const status = {
    service: "workers-security-example",
    version: "2.0.0",
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
        profiles: ["AUTH", "API", "PUBLIC", "SEARCH", "UPLOAD"],
      },
      burstDetection: {
        enabled: true,
        backend: env.RATE_LIMIT_KV ? "kv" : "mock",
        profiles: ["STRICT", "NORMAL", "RELAXED"],
      },
      waf: {
        enabled: true,
        categories: ["xss", "insecure-deserialization"],
        rulesCount: getWAFRules().length,
        debugEnabled: debugEnabled,
      },
      botProtection: {
        enabled: true,
        features: ["credential-stuffing", "spam-detection", "session-management"],
      },
      geolocation: {
        enabled: true,
        blockedCountries: geoBlocker.getBlockedCountries(),
        challengedCountries: geoBlocker.getChallengedCountries(),
      },
      ipTracking: {
        enabled: true,
        features: ["reputation", "auto-block", "event-logging"],
      },
      tracing: {
        enabled: true,
      },
      debug: {
        enabled: debugEnabled,
        level: logger.getConfig().level,
      },
    },
    cloudflare: {
      ray: trace.rayId,
      country: trace.country,
      colo: (request as RequestWithCf).cf?.colo,
    },
  };

  return createSuccessResponse(status, trace, getCorsHeaders(env, request.headers.get("Origin")));
}

/**
 * Rules endpoint - list active WAF rules
 */
async function handleRules(
  request: Request,
  env: Env,
  trace: EnhancedTraceInfo,
  logger: DebugLogger,
  debugEnabled: boolean,
  requestTimestamp: number
): Promise<Response> {
  const rules = getWAFRules();

  const data = {
    count: rules.length,
    categories: {
      xss: rules.filter(r => r.category === 'xss').length,
      "insecure-deserialization": rules.filter(r => r.category === 'insecure-deserialization').length,
    },
    rules: rules.map((rule) => ({
      id: rule.id,
      description: rule.description,
      action: rule.action,
      category: rule.category,
      severity: rule.severity,
      conditionsCount: rule.conditions.length,
      conditions: debugEnabled ? rule.conditions : undefined,
    })),
  };

  return createSuccessResponse(data, trace, getCorsHeaders(env, request.headers.get("Origin")));
}

/**
 * WAF Debug endpoint - analyze why a URL would/wouldn't be blocked
 */
async function handleWAFDebug(
  request: Request,
  env: Env,
  trace: EnhancedTraceInfo,
  logger: DebugLogger
): Promise<Response> {
  if (request.method !== "POST") {
    return createErrorResponse("POST with JSON body required", 405, trace);
  }

  try {
    const body = await request.json() as { url?: string; method?: string; headers?: Record<string, string> };
    
    if (!body.url) {
      return createErrorResponse("Missing 'url' in request body", 400, trace);
    }

    // Create a mock request for analysis
    const mockRequest = new Request(body.url, {
      method: body.method || "GET",
      headers: body.headers || {},
    });

    const analysis = analyzeRequest(mockRequest);
    const report = generateWAFAnalysisReport(mockRequest);

    return createSuccessResponse({
      analysis: {
        wouldBeBlocked: analysis.wouldBeBlocked,
        matchingRulesCount: analysis.matchingRules.length,
        deserializationCheck: analysis.deserializationCheck,
        matchingRules: analysis.matchingRules.map(m => ({
          ruleId: m.rule.id,
          action: m.rule.action,
          category: m.rule.category,
          severity: m.rule.severity,
          description: m.rule.description,
          matchedConditions: m.matchedConditions.map(c => ({
            field: c.condition.field,
            operator: c.condition.operator,
            pattern: c.condition.value,
            matchedValue: c.fieldValue,
          })),
        })),
        totalRulesChecked: analysis.checkedRules.length,
      },
      report,
    }, trace, getCorsHeaders(env, request.headers.get("Origin")));
  } catch (error: any) {
    return createErrorResponse(`Invalid request: ${error.message}`, 400, trace);
  }
}

/**
 * Timing Debug endpoint - get timing breakdown for the current request
 */
async function handleTimingDebug(
  request: Request,
  env: Env,
  trace: EnhancedTraceInfo,
  logger: DebugLogger
): Promise<Response> {
  const traceId = trace.traceId;
  
  // Simulate some work to show timing
  const timings: Record<string, number> = {};
  
  // Measure WAF check
  const wafStart = performance.now();
  checkWAF(request, traceId);
  timings.waf = performance.now() - wafStart;

  // Get timing report
  const checkpoints = logger.getTimingCheckpoints(traceId);
  const report = logger.generateTimingReport(traceId);
  const entries = logger.getEntriesForTrace(traceId);

  return createSuccessResponse({
    traceId,
    simulated: timings,
    checkpoints: checkpoints.map(cp => ({
      name: cp.name,
      elapsed: cp.elapsed,
      total: cp.total,
    })),
    report,
    debugEntries: entries.map(e => ({
      timestamp: e.timestamp,
      level: e.level,
      category: e.category,
      message: e.message,
    })),
  }, trace, getCorsHeaders(env, request.headers.get("Origin")));
}
