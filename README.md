# Hexa — DeFi API Security Platform

> Open-source edge security layer for Web3 infrastructure, built on Cloudflare Workers.

Hexa sits between your dApp clients and your backend RPC node, enforcing authentication, rate limiting, calldata-level threat scoring, and blocklist checks — all at the edge, under 10ms added latency.

[![CI](https://github.com/OrdinalScale/hexa/actions/workflows/ci.yml/badge.svg)](https://github.com/OrdinalScale/hexa/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Architecture

```
dApp / Client
     │  JSON-RPC
     ▼
Cloudflare Worker (Hono.js)
     │
     ├── Auth          (Phase 2)  — API key / JWT · KV cache · D1 fallback
     ├── Blocklist     (Phase 6)  — KV wallets/domains · D1 IPs · LRU cache
     ├── Rate Limit    (Phase 4)  — Durable Objects · sliding window
     ├── Threat Score  (Phase 5)  — Rust/WASM calldata decoder · 0-100 score
     └── [Proxy]       (Phase 3)  — stream upstream · circuit breaker
          │
          ▼
     Backend RPC Node (Infura / Alchemy / self-hosted)

Logging via ctx.waitUntil() → D1 ring buffer + Cloudflare Logpush
```

**Middleware pipeline order** (canonical, never changes):
`Auth → Blocklist → Rate Limit → Threat Score → [Proxy] → Log (waitUntil)`

---

## Monorepo Structure

```
hexa/
├── packages/
│   ├── worker/          Cloudflare Worker — Hono.js + TypeScript
│   │   ├── src/
│   │   │   ├── config.ts          Zod-validated runtime config (single source of truth)
│   │   │   ├── index.ts           Worker entry point + /healthz
│   │   │   ├── durable-objects/   RateLimiter DO (Phase 4)
│   │   │   ├── middleware/        auth, blocklist, rate-limit, threat-score (Phases 2–5)
│   │   │   ├── routes/            rpc.ts, dashboard-api.ts (Phases 3, 8)
│   │   │   ├── lib/               json-rpc, circuit-breaker, lru-cache, logger, threat-score
│   │   │   └── db/migrations/     001_api_keys · 002_blocklist_ips · 003_request_logs
│   │   └── src/test/mocks/        Mock D1 / KV / DO bindings for failure-injection tests
│   └── detector/        Rust crate → WASM threat scoring engine (Phase 5)
├── apps/
│   └── dashboard/       Vite/React SPA (Phase 8 placeholder)
├── docs/
│   └── adr/             Architectural Decision Records
├── blocklist.config.json  Custom blocklist entries (merged at startup)
└── .github/workflows/ci.yml
```

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Node.js | ≥ 20 | [nodejs.org](https://nodejs.org) |
| npm | ≥ 10 | bundled with Node |
| Wrangler CLI | ≥ 3.80 | `npm i -g wrangler` |
| Rust | stable | [rustup.rs](https://rustup.rs) |
| wasm-pack | latest | `cargo install wasm-pack` |

---

## Local Development

### 1. Clone and install

```bash
git clone https://github.com/OrdinalScale/hexa.git
cd hexa
npm install
```

### 2. Configure environment

Create `packages/worker/.dev.vars` (never committed — see `.gitignore`):

```ini
BACKEND_RPC_URL=https://mainnet.infura.io/v3/YOUR_KEY
JWT_PUBLIC_KEY=your-rs256-public-key-pem
```

All other vars have defaults in `wrangler.toml` and work out of the box for local dev.

### 3. Run the Worker locally

```bash
cd packages/worker
npm run dev
# Worker starts at http://localhost:8787
```

Verify: `curl http://localhost:8787/healthz` → `{"status":"ok","version":"0.1.0"}`

### 4. Apply D1 migrations

```bash
wrangler d1 migrations apply hexa-db --local
```

This provisions all three tables (`api_keys`, `blocklist_ips`, `request_logs`) from a clean state.

### 5. Build the Rust detector

```bash
cd packages/detector
cargo build --target wasm32-unknown-unknown --release
# Or with wasm-pack for a browser-ready package:
wasm-pack build --target bundler
```

---

## Running Tests

```bash
# Worker unit tests (config validation, mock binding failure injection)
cd packages/worker
npm test

# Rust unit tests (signature detection, scorer)
cd packages/detector
cargo test
```

---

## Deployment

```bash
# Dry-run (CI uses this on every PR)
cd packages/worker
npm run build

# Deploy to Cloudflare Workers
npm run deploy
```

Required secrets in your Cloudflare dashboard or CI environment:
- `CLOUDFLARE_API_TOKEN` — for Wrangler deploy
- `BACKEND_RPC_URL` — your RPC provider URL
- `JWT_PUBLIC_KEY` — RS256 public key PEM

---

## Configuration

All runtime configuration is sourced from `packages/worker/src/config.ts` and validated with Zod at startup. See [docs/configuration.md](docs/configuration.md) for the full reference.

Custom blocklist entries go in `blocklist.config.json` at the repo root.

---

## Fail Behavior

See [docs/adr/001-fail-behavior.md](docs/adr/001-fail-behavior.md) for the canonical record of how each component behaves under failure. Short version:

- **Auth (D1)** — fail-closed → `401`
- **Blocklist (KV)** — fail-open → allow + log warning
- **Threat scorer (WASM)** — fail-open → score=0 + log error
- **Rate limiter (DO eviction)** — fail-open → treat as under-limit
- **Request log (D1)** — fail-open → skip D1, Logpush continues

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | ✅ Done | Foundation — monorepo, config, migrations, mocks, ADR, CI |
| 2 | Pending | Authentication — API key + JWT, KV cache, D1 |
| 3 | Pending | RPC Proxy Core — JSON-RPC, circuit breaker, streaming |
| 4 | Pending | Rate Limiting — Durable Objects, sliding window |
| 5 | Pending | Threat Scoring — Rust/WASM calldata decoder |
| 6 | Pending | Blocklist Integration — KV + D1, LRU cache |
| 7 | Pending | Logging, Observability, OSS Docs |
| 8 | Pending | Enterprise — Dashboard SPA, R2 audit log, SSO/RBAC |

---

## Contributing

PRs welcome. Please open an issue first for non-trivial changes. See [docs/contributing.md](docs/contributing.md) (Phase 7) for the full guide.

---

## License

MIT © OrdinalScale
