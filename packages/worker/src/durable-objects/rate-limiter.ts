/**
 * RateLimiter Durable Object — stub for Phase 1.
 * Full sliding-window implementation is built in Phase 4.
 *
 * Exported from src/index.ts so wrangler can register the DO class binding.
 */
export class RateLimiter implements DurableObject {
  constructor(
    _state: DurableObjectState,
    _env: unknown
  ) {}

  async fetch(_request: Request): Promise<Response> {
    // Phase 4 will implement sliding-window counter logic here.
    return new Response(JSON.stringify({ allowed: true, remaining: -1 }), {
      headers: { "Content-Type": "application/json" },
    });
  }
}
