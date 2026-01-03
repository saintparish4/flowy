import { TraceInfo } from "./types";

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

export function createTraceInfo(request: Request): TraceInfo {
  const url = new URL(request.url);

  return {
    traceId: generateTraceId(),
    timestamp: Date.now(),
    method: request.method,
    url: url.pathname + url.search,
    ip:
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For") ||
      "unknown",
    country: request.headers.get("CF-IPCountry") || undefined,
    rayId: request.headers.get("CF-Ray") || undefined,
  };
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
