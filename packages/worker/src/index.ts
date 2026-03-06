import { Hono } from "hono";
import { type Env, parseConfig } from "./config";
import { authMiddleware } from "./middleware/auth";
import type { AuthContext } from "./middleware/auth-types";

// RateLimiter Durable Object stub — full implementation in Phase 4.
// Exported here so wrangler can locate the class for DO binding registration.
export { RateLimiter } from "./durable-objects/rate-limiter";

const app = new Hono<{ Bindings: Env; Variables: AuthContext  }>(); 

app.use("*", authMiddleware());  

// ---------------------------------------------------------------------------
// Health check — must return 200 before Phase 2 begins
// ---------------------------------------------------------------------------

app.get("/healthz", (c) => {
  return c.json({ status: "ok", version: "0.1.0" }, 200);
});

// ---------------------------------------------------------------------------
// Default export: Workers fetch handler
// Config is validated on every cold start so misconfiguration is caught early.
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Throws ConfigError with a descriptive message if any required var is
    // missing or malformed. The error propagates as a 500, visible in logs.
    parseConfig(env);

    return app.fetch(request, env, ctx);
  },
};
