import type { Env, TurnstileVerifyResponse } from "./types";

// Verify Cloudflare Turnstile token
// https://developers.cloudflare.com/turnstile/get-started/server-side-validation/

export class TurnstileVerifier {
  private secretKey: string | null;
  private enabled: boolean;
  private useMock: boolean;

  constructor(env: Env) {
    this.secretKey = env.TURNSTILE_SECRET_KEY || null;
    this.enabled = env.TURNSTILE_ENABLED === "true";
    this.useMock = !this.secretKey || !this.enabled;
  }

  /**
   * Verify a Turnstile token
   * @param token - The Turnstile token from the client
   * @param ip - The user's IP address (optional but recommended)
   * @returns Verification result
   */

  async verify(token: string, ip?: string): Promise<TurnstileVerifyResponse> {
    // Mock mode for local development
    if (this.useMock) {
      return this.verifyMock(token);
    }

    const verifyEndpoint =
      "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    const formData = new FormData();
    formData.append("secret", this.secretKey!);
    formData.append("response", token);

    if (ip) {
      formData.append("remoteip", ip);
    }

    try {
      const response = await fetch(verifyEndpoint, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        console.error("Turnstile verification failed:", response.status);
        return {
          success: false,
          "error-codes": ["verification-failed"],
        };
      }

      const result: TurnstileVerifyResponse = await response.json();
      return result;
    } catch (error) {
      console.error("Turnstile verification error:", error);
      return {
        success: false,
        "error-codes": ["network-error"],
      };
    }
  }

  // Mock verification for local development
  // Always returns success unless token is explicitly 'fail'
  private verifyMock(token: string): TurnstileVerifyResponse {
    console.log("[MOCK] Turnstile verification (always passes in dev mode)");

    // Allow testing failure case
    if (token === "fail" || token === "invalid") {
      return {
        success: false,
        "error-codes": ["invalid-input-response"],
      };
    }

    return {
      success: true,
      challenge_ts: new Date().toISOString(),
      hostname: "localhost",
      action: "submit",
    };
  }

  // Extract Turnstile token from request
  // Supports multiple input methods
  static async extractToken(request: Request): Promise<string | null> {
    // Check header first
    const headerToken = request.headers.get("CF-Turnstile-Token");
    if (headerToken) {
      return headerToken;
    }

    // Check POST body for form data or JSON
    if (request.method === "POST") {
      const contentType = request.headers.get("Content-Type") || "";

      if (contentType.includes("application/json")) {
        try {
          const body = await request.clone().json();
          return body["cf-turnstile-response"] || body.turnstileToken || null;
        } catch {
          return null;
        }
      }

      if (
        contentType.includes("application/x-www-form-urlencoded") ||
        contentType.includes("multipart/form-data")
      ) {
        try {
          const formData = await request.clone().formData();
          return formData.get("cf-turnstile-response")?.toString() || null;
        } catch {
          return null;
        }
      }
    }

    // Check query parameter
    const url = new URL(request.url);
    return url.searchParams.get("cf-turnstile-response");
  }
}

// Create a Turnstile verifier instance

export function createTurnstileVerifier(env: Env): TurnstileVerifier {
  return new TurnstileVerifier(env);
}

// Middleware to require Turnstile verificaiton

export async function requireTurnstile(
  request: Request,
  env: Env
): Promise<{
  success: boolean;
  error?: string;
  response?: TurnstileVerifyResponse;
}> {
  const verifier = createTurnstileVerifier(env);

  const token = await TurnstileVerifier.extractToken(request);

  if (!token) {
    return {
      success: false,
      error: "Missing Turnstile token",
    };
  }

  const ip = request.headers.get("CF-Connecting-IP") || undefined;
  const result = await verifier.verify(token, ip);

  if (!result.success) {
    return {
      success: false,
      error: "Turnstile verification failed",
      response: result,
    };
  }

  return {
    success: true,
    response: result,
  };
}
