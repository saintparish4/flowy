# ADR 001 — Component Fail Behavior (Fail-Open vs. Fail-Closed)

**Date:** 2026-03-05  
**Status:** Accepted  
**Deciders:** Hexa core team  

---

## Context

Hexa runs as a Cloudflare Worker on the request hot-path between a dApp client
and a backend RPC node. Each infrastructure dependency (D1, KV, Durable Objects,
WASM scorer) can independently degrade or become temporarily unavailable. We must
explicitly decide, for each component, whether a failure causes the request to be
rejected (fail-closed) or allowed through (fail-open).

The default choice — if left unspecified — tends to be "silently allow", which
creates security holes. This ADR makes every failure mode a deliberate choice,
documented and enforced in tests.

---

## Decision

| Component | Failure Mode | Behavior | Rationale |
|---|---|---|---|
| **D1 (auth)** | DB unavailable | **Fail-closed → `401`** | Never allow unauthenticated access through a degraded auth layer. An outage is less harmful than a security bypass. |
| **KV (blocklist)** | KV unavailable | **Fail-open → allow, log warning** | A brief KV outage should not drop legitimate traffic. Blocklist is a defense-in-depth layer; missing one lookup window is acceptable. |
| **WASM scorer** | Init or runtime failure | **Fail-open → score=0, log error reason** | Scoring is a heuristic layer. Taking down the entire proxy because the WASM module failed is a worse outcome than passing a request unscored. |
| **Durable Object (rate limiter)** | DO evicted mid-window | **Fail-open → treat as under-limit** | A brief free window is less harmful than a full proxy outage. Counters reset to 0 on eviction; the request is allowed. |
| **D1 (logging ring buffer)** | DB unavailable | **Fail-open → skip D1 write, Logpush continues** | Logpush is the primary high-volume log channel. D1 is a convenience store for the dashboard. Never block a request because a secondary log store is down. |

---

## Consequences

### Positive

- Every failure mode is an explicit, tested code path — no silent partial failures.
- Auth degradation is the most conservative choice: an outage is auditable and
  self-correcting once D1 recovers; a bypass is not.
- Fail-open components degrade gracefully under dependency outages without causing
  cascading failures across the pipeline.

### Negative

- Fail-open components can temporarily reduce security posture during infrastructure
  outages. This is mitigated by structured logging: every fail-open event emits a
  warning-level log record with the affected component and reason.
- Rate limiter fail-open means a DO eviction could briefly allow a burst above the
  configured limit. The window is bounded by the DO eviction frequency (rare in
  Cloudflare's infrastructure) and the sliding window size.

---

## Enforcement

- Each fail-open path is covered by a failure injection test using mock bindings
  (`packages/worker/src/test/mocks/bindings.ts`).
- Tests assert the exact HTTP status code and response body for both failure modes.
- CI fails if these tests are removed or disabled.

---

## Alternatives Considered

**Fail-closed on all components** — rejected. A blocklist KV outage failing closed
would drop all traffic globally, which is a significantly worse outcome than a
temporary gap in blocklist enforcement. Same logic applies to the WASM scorer.

**Circuit breaker on D1 auth** — rejected for MVP. A circuit breaker requires
persistent state to track failure counts, which itself depends on infrastructure
that could also fail. The simpler and safer policy is fail-closed on all D1 auth
reads until the system is healthy.
