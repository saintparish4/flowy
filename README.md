# Cloudflare Security Framework

A comprehensive, production-ready security framework for Cloudflare Workers implementing multi-layered protection against common web attacks and threats.

## Overview

This repository contains a modular security framework designed for Cloudflare Workers, providing defense-in-depth protection through multiple security layers. The framework is built with TypeScript, fully typed, and includes comprehensive testing and load testing capabilities.

## Project Structure

```
cloudflare/
├── workers-security/     # Main security framework
│   ├── src/
│   │   ├── core/         # Worker entry point and routing
│   │   ├── bot/          # Bot management and detection
│   │   ├── rate-limiter/ # Rate limiting and burst detection
│   │   ├── rules/        # WAF rules and pattern matching
│   │   ├── tracing/      # Request tracing, geolocation, IP tracking
│   │   ├── utils/        # Debug and utility functions
│   │   └── types/        # TypeScript type definitions
│   ├── experiments/      # Load testing and attack simulation
│   └── README.md         # Detailed documentation
└── base/                 # Base configurations (if applicable)
```

## Key Features

### 🔒 Security Modules

- **Rate Limiting**: Sliding window counter with Cloudflare KV, burst detection for DoS/DDoS protection
- **Bot Management**: Credential stuffing detection, spam detection, session management, traffic classification
- **WAF Rules**: XSS protection, insecure deserialization detection (Java, Python, PHP, .NET, YAML)
- **Geolocation Blocking**: Country-based access control with configurable block/challenge lists
- **IP Tracking**: Reputation-based IP management with auto-blocking for low-reputation IPs
- **Request Tracing**: Unified trace ID system with performance metrics

### 🛠️ Development Features

- **Mock Mode**: Full local development without Cloudflare credentials
- **Load Testing**: Comprehensive test suite with 6 attack profiles
- **TypeScript**: Full type safety with Cloudflare Workers types
- **Debug Logging**: Detailed trace information and performance timing

## Quick Start

### Prerequisites

- Node.js 18+ and npm
- (Optional) Cloudflare account for production deployment

### Installation

```bash
cd workers-security
npm install
```

### Development

Run locally in mock mode (no Cloudflare credentials required):

```bash
npm run dev
```

Visit `http://localhost:8787` to see the API documentation.

### Production Deployment

1. Create KV namespace:
```bash
npm run kv:create
npm run kv:create:preview
```

2. Configure secrets:
```bash
npm run secret:put TURNSTILE_SECRET_KEY
```

3. Deploy:
```bash
npm run deploy:production
```

## API Endpoints

- `GET /` - API documentation
- `GET /api/public` - Public endpoint (relaxed rate limiting)
- `GET /api/protected` - Protected endpoint (requires Turnstile)
- `POST /api/login` - Login endpoint (strict rate limiting + bot protection)
- `GET /api/status` - Service status and configuration
- `GET /api/rules` - List active WAF rules
- `POST /api/debug/waf` - WAF debug analysis
- `GET /api/debug/timing` - Request timing breakdown

## Load Testing

The framework includes comprehensive load testing with attack simulation:

```bash
cd experiments
npm install
npm run load-test -- -p BOT_FOLDER_TEST -v
```

Available test profiles:
- `BOT_FOLDER_TEST` - Bot detection tests
- `RATE_LIMITER_TEST` - Rate limiting tests
- `RULES_FOLDER_TEST` - WAF rules tests
- `TRACING_FOLDER_TEST` - Geolocation and IP tracking tests
- `CORE_LEGITIMATE_TRAFFIC` - Legitimate traffic handling
- `CORE_MIXED_TRAFFIC` - Mixed legitimate + attack traffic

## Security Layers

The framework implements defense-in-depth with multiple security layers:

1. **Geolocation Check** - Block/challenge by country
2. **IP Reputation** - Auto-block low-reputation IPs
3. **WAF Rules** - XSS and deserialization attack detection
4. **Burst Detection** - DoS/DDoS protection with queuing/throttling
5. **Rate Limiting** - Sliding window counter per endpoint
6. **Bot Protection** - Credential stuffing and spam detection
7. **Turnstile** - Cloudflare's bot protection service

## Documentation

For detailed documentation, see:
- **[workers-security/README.md](cloudflare/workers-security/README.md)** - Complete API reference, configuration, and usage examples

## Key Learnings

- **Defense in Depth**: Combining multiple security layers provides better protection than any single mechanism
- **POST Body Scanning**: WAF rules must scan both query strings AND POST body content
- **Session-Aware Security**: Behavioral analysis enables more sophisticated bot detection
- **IP Reputation**: Auto-blocking low-reputation IPs provides additional protection
- **Load Testing**: Comprehensive testing with realistic attack profiles is essential

## License

MIT

## Author

Sharif Parish

