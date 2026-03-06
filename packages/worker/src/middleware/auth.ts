/**
 * Authentication middleware: API key (X-API-key) and JWT (Bearer)
 * KV write-through cache for API keys; D1 on cache miss. Fail-closed on D1 error
 * Raw API key never stored in context or logged -- only SHA-256 hash
 */

import type { Context, Next } from "hono";
import * as jose from "jose";
import type { Env } from "../config";
import type { AuthContext } from "./auth-types";
import { parseConfig } from "../config";

const WWW_AUTHENTICATE = 'Bearer realm="Hexa", error="invalid_token"';

/** Hash raw API key to SHA-256 hex (same as stored in D1) */
export async function hashApiKey(raw: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(raw);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Parse Authorization or X-API-Key from request */
function getAuthFromRequest(
  request: Request,
): { type: "bearer"; token: string } | { type: "api-key"; key: string } | null {
  const authHeader = request.headers.get("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return { type: "bearer", token: authHeader.slice(7).trim() };
  }
  const apiKey = request.headers.get("X-API-Key")?.trim();
  if (apiKey) {
    return { type: "api-key", key: apiKey };
  }
  return null;
}

/** Validate API key: KV first, then D1; populate KV on miss. Returns key_hash if valid */
async function validateApiKey(
  keyHash: string,
  env: Env,
  config: ReturnType<typeof parseConfig>,
): Promise<{ valid: true; keyHash: string } | { valid: false }> {
  const cached = await env.AUTH_CACHE.get(keyHash);
  if (cached === "1") {
    return { valid: true, keyHash };
  }
  if (cached !== null) {
    return { valid: false };
  }

  let row: { key_hash: string; enabled: number } | null;
  try {
    const stmt = env.DB.prepare(
      "SELECT key_hash, enabled FROM api_keys WHERE key_hash = ? AND enabled = 1",
    ).bind(keyHash);
    row = await stmt.first<{ key_hash: string; enabled: number }>();
  } catch (e) {
    throw e;
  }

  if (!row) {
    return { valid: false };
  }

  await env.AUTH_CACHE.put(keyHash, "1", {
    expirationTtl: config.authCacheTtlSeconds,
  });
  return { valid: true, keyHash };
}

/** Verify JWT (RS256) and return sub; throws on invalid/expired */
async function verifyJwt(
  token: string,
  publicKeyPem: string,
): Promise<{ sub: string }> {
  const key = await jose.importSPKI(publicKeyPem, "RS256");
  const { payload } = await jose.jwtVerify(token, key);
  const sub = payload.sub;
  if (typeof sub !== "string") {
    throw new Error("JWT missing sub");
  }
  return { sub };
}

export function authMiddleware() {
  return async (
    c: Context<{ Bindings: Env; Variables: AuthContext }>,
    next: Next,
  ) => {
    const auth = getAuthFromRequest(c.req.raw);
    if (!auth) {
      return c.json(
        {
          error: "Unauthorized",
          message: "Missing Authorization or X-API-Key",
        },
        401,
        { "WWW-Authenticate": WWW_AUTHENTICATE },
      );
    }

    const config = parseConfig(c.env);

    if (auth.type === "bearer") {
      try {
        const { sub } = await verifyJwt(auth.token, config.jwtPublicKey);
        // Use a derived hash from JWT sub so apiKeyHash is always populated
        const derivedHash = await hashApiKey(`jwt:${sub}`);
        c.set("apiKeyHash", derivedHash);
        c.set("jwtSub", sub);
        return next();
      } catch {
        return c.json(
          { error: "Unauthorized", message: "Invalid or expired token" },
          401,
          { "WWW-Authenticate": WWW_AUTHENTICATE },
        );
      }
    }
    const keyHash = await hashApiKey(auth.key);
    try {
      const result = await validateApiKey(keyHash, c.env, config);
      if (!result.valid) {
        return c.json(
          { error: "Unauthorized", message: "Invalid API key" },
          401,
          { "WWW-Authenticate": WWW_AUTHENTICATE },
        );
      }
      c.set("apiKeyHash", result.keyHash as AuthContext["apiKeyHash"]);
      return next();
    } catch {
      return c.json(
        { error: "Unauthorized", message: "Authentication unavailable" },
        401,
        { "WWW-Authenticate": WWW_AUTHENTICATE },
      );
    }
  };
}

/** Helper: revoke API key from cache (call after disabling key in D1). */
export async function revokeApiKeyFromCache(
  env: Env,
  keyHash: string,
): Promise<void> {
  await env.AUTH_CACHE.delete(keyHash);
}
