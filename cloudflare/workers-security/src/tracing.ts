import { TraceInfo } from "./types";

// Performance timing data for a request
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

// Experiment correlation data
export interface ExperimentContext {
  experimentId?: string;
  profileName?: string;
  attackType?: string;
  isTestTraffic?: boolean;
}

// Enhanced trace info with performance and experiment data
export interface EnhancedTraceInfo extends TraceInfo {
  requestTimestamp: number; // Request arrival time (captured at entry point)
  performance: PerformanceMetrics;
  experiment?: ExperimentContext;
}

// Generate a unique trace ID for the request
// Uses crypto.randomUUID() if available, falls back to timestamp-based ID

export function generateTraceId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    // Fallback for environments without crypto.randomUUID()
    return `trace-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
  }
}

// Extract trace information from the request
// Includes Cloudflare-specific headers like CF-Ray

export function createTraceInfo(request: Request): EnhancedTraceInfo {
  const url = new URL(request.url);

  // Extract experiment context if present
  const experimentId = request.headers.get("X-Experiment-ID");
  const profileName = request.headers.get("X-Profile-Name");
  const attackType = request.headers.get("X-Attack-Type");
  const isTestTraffic = request.headers.get("X-Test-Traffic") === "true";

  const trace: EnhancedTraceInfo = {
    traceId: generateTraceId(),
    timestamp: Date.now(),
    requestTimestamp: 0, // Will be set at entry point in index.ts
    method: request.method,
    url: url.pathname + url.search,
    ip:
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For") ||
      "unknown",
    country: request.headers.get("CF-IPCountry") || undefined,
    rayId: request.headers.get("CF-Ray") || undefined,
    performance: {
      startTime: performance.now(),
      timings: {},
    },
  };

  if (experimentId || profileName || attackType || isTestTraffic) {
    trace.experiment = {
      experimentId: experimentId || undefined,
      profileName: profileName || undefined,
      attackType: attackType || undefined,
      isTestTraffic,
    };
  }

  return trace;
}

// Record a timing measurement for a specific operation
export function recordTiming(
  trace: EnhancedTraceInfo,
  name: string,
  startTime: number
): void {
  const duration = performance.now() - startTime;
  trace.performance.timings[name] = duration;

  // Also set specific fields for common operations
  switch (name) {
    case "rateLimit":
      trace.performance.rateLimitCheckTime = duration;
      break;
    case "turnstile":
      trace.performance.turnstileCheckTime = duration;
      break;
    case "waf":
      trace.performance.wafCheckTime = duration;
      break;
    case "handler":
      trace.performance.handlerTime = duration;
      break;
  }
}

// Finalize performance metrics
export function finalizePerformance(trace: EnhancedTraceInfo): void {
  trace.performance.endTime = performance.now();
  trace.performance.duration =
    trace.performance.endTime - trace.performance.startTime;
}

// Export metrics in structured format for analysis
export function exportMetrics(
  trace: EnhancedTraceInfo,
  additionalData?: Record<string, any>
): string {
  const metrics = {
    timestamp: trace.timestamp,
    traceId: trace.traceId,
    method: trace.method,
    url: trace.url,
    ip: trace.ip,
    country: trace.country,
    rayId: trace.rayId,
    performance: {
      total: trace.performance.duration,
      rateLimit: trace.performance.rateLimitCheckTime,
      turnstile: trace.performance.turnstileCheckTime,
      waf: trace.performance.wafCheckTime,
      handler: trace.performance.handlerTime,
      ...trace.performance.timings,
    },
    experiment: trace.experiment,
    ...additionalData,
  };

  return JSON.stringify(metrics);
}

// Add trace headers to the response
// This allows clients to track their requests through the system

export function addTraceHeaders(
  response: Response,
  trace: TraceInfo
): Response {
  const headers = new Headers(response.headers);

  headers.set("X-Trace-ID", trace.traceId);
  headers.set("X-Request-Timestamp", trace.timestamp.toString());

  if (trace.rayId) {
    headers.set("X-CF-Ray", trace.rayId);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// Log trace information (in production, this would send to logging service)

export function logTrace(
  trace: TraceInfo,
  additionalInfo?: Record<string, any>
): void {
  const logData = {
    ...trace,
    ...additionalInfo,
  };

  // In production, send to Cloudflare Logpush, Workers Analytics, or external logging service
  console.log("[TRACE]", JSON.stringify(logData));
}

// Create a standardized error response with trace information

export function createErrorResponse(
  message: string,
  status: number,
  trace: TraceInfo,
  additionalData?: Record<string, any>
): Response {
  const response = new Response(
    JSON.stringify({
      success: false,
      error: message,
      trace: {
        traceId: trace.traceId,
        timestamp: trace.timestamp,
      },
      ...additionalData,
    }),
    {
      status,
      headers: {
        "Content-Type": "application/json",
      },
    }
  );

  return addTraceHeaders(response, trace);
}

// Create a standardized success response with trace information

export function createSuccessResponse(
  data: any,
  trace: TraceInfo,
  additionalHeaders?: Record<string, string>
): Response {
  const response = new Response(
    JSON.stringify({
      success: true,
      data,
      trace: {
        traceId: trace.traceId,
        timestamp: trace.timestamp,
      },
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        ...additionalHeaders,
      },
    }
  );

  return addTraceHeaders(response, trace);
}
