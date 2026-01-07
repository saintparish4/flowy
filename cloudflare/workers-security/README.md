# Cloudflare Workers Security

A comprehensive security framework for Cloudflare Workers implementing multi-layered protection including rate limiting, bot management, WAF rules, geolocation blocking, and IP tracking.

## Features

### 🔒 Security Modules

#### Rate Limiter (`src/rate-limiter/`)
- **Brute Force Protection**: Sliding window counter with Cloudflare KV
- **DoS/DDoS Protection**: Burst detection with short and medium window analysis
- **Web Scraping Prevention**: Adaptive rate limiting based on request patterns
- **Session-Aware**: Tracks user sessions for behavioral analysis

#### Bot Management (`src/bot/`)
- **Credential Stuffing Detection**: Identifies automated login attempts with leaked credentials
- **Spam Detection**: Detects promotional content, link spam, and automated posting
- **Session Management**: Behavioral analysis and session tracking
- **Traffic Classification**: Distinguishes legitimate, suspicious, and malicious traffic
- **Turnstile Integration**: Cloudflare's bot protection with automatic fallback
- **Adaptive Rate Limiting**: Dynamic rate limits based on traffic patterns

#### Rules/WAF (`src/rules/`)
- **XSS Protection**: Detects and blocks cross-site scripting attacks in query strings and POST bodies
- **Insecure Deserialization Protection**: Blocks Java, Python, PHP, .NET, and YAML deserialization attacks
- **Base64 Attack Detection**: Scans encoded payloads for malicious patterns
- **Pattern Matching**: Comprehensive regex and string-based detection

#### Tracing (`src/tracing/`)
- **Request Tracing**: Unified trace ID system for debugging and monitoring
- **Geolocation Blocking**: Block or challenge requests from high-threat countries/regions
- **IP Tracking**: IP reputation management with auto-blocking for low-reputation IPs
- **Performance Metrics**: Detailed timing and latency measurements

### 🛠️ Development Features
- **Mock Mode**: Fully functional local development without Cloudflare credentials
- **Load Testing**: Comprehensive test suite with 6 attack profiles
- **TypeScript**: Full type safety with Cloudflare Workers types
- **Comprehensive Logging**: Detailed trace information for every request

## Prerequisites

- Node.js 18+ and npm
- (Optional) Cloudflare account for production deployment

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Development Mode (Mock)

Run locally without any Cloudflare credentials:

```bash
npm run dev
```

The worker will start with mock implementations for:
- KV storage (in-memory)
- Turnstile verification (always passes)
- All security features fully functional

### 3. Access the API

Visit `http://localhost:8787` to see the API documentation.

## API Endpoints

### `GET /`
API documentation and service information.

**Example:**
```bash
curl http://localhost:8787/
```

### `GET /api/public`
Public endpoint with relaxed rate limiting.

**Example:**
```bash
curl http://localhost:8787/api/public
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "This is a public API endpoint",
    "timestamp": 1234567890,
    "yourIP": "127.0.0.1"
  },
  "trace": {
    "traceId": "trace-abc-123",
    "timestamp": 1234567890
  }
}
```

**Headers:**
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining in window
- `X-RateLimit-Reset`: Unix timestamp when limit resets
- `X-Trace-ID`: Unique trace ID for this request

### `GET /api/protected`
Protected endpoint requiring Turnstile verification.

**Example:**
```bash
curl -H "CF-Turnstile-Token: your-token-here" http://localhost:8787/api/protected
```

In mock mode, any token value works except "fail" or "invalid".

### `POST /api/login`
Login endpoint with strict rate limiting and bot protection.

**Example:**
```bash
curl -X POST http://localhost:8787/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"password123"}'
```

This endpoint is protected by:
- Strict rate limiting (prevents brute force)
- Credential stuffing detection
- Bot session management

### `GET /api/status`
Service status and configuration information.

**Example:**
```bash
curl http://localhost:8787/api/status
```

### `GET /api/rules`
List all active WAF rules.

**Example:**
```bash
curl http://localhost:8787/api/rules
```

## Project Structure

```
cloudflare/workers-security/
├── src/
│   ├── core/
│   │   └── index.ts              # Main worker entry point
│   ├── rate-limiter/
│   │   ├── rate-limiter.ts       # Core rate limiting logic
│   │   └── burst-detector.ts     # Burst detection for DoS/DDoS
│   ├── bot/
│   │   ├── index.ts              # Bot protection manager
│   │   ├── credential-stuffing-detector.ts
│   │   ├── spam-detector.ts
│   │   ├── session-manager.ts
│   │   ├── traffic-classifier.ts
│   │   ├── adaptive-rate-limiter.ts
│   │   └── turnstile.ts
│   ├── rules/
│   │   ├── waf.ts                # WAF rule engine
│   │   ├── waf-config.ts         # WAF rule definitions
│   │   └── deserialization-patterns.ts
│   ├── tracing/
│   │   ├── tracing.ts            # Request tracing system
│   │   ├── geolocation.ts        # Geolocation blocking
│   │   └── ip-tracking.ts        # IP reputation tracking
│   ├── types/
│   │   └── index.ts              # TypeScript types
│   └── utils/
│       └── debug.ts              # Debug logging utilities
├── experiments/
│   ├── profiles/
│   │   └── security-tests.ts     # Load test attack profiles
│   └── load-test/
│       └── index.ts              # Load testing framework
├── wrangler.toml                 # Cloudflare configuration
├── package.json                  # Dependencies
├── tsconfig.json                 # TypeScript config
└── README.md                     # This file
```

## Security Features

### Rate Limiting

The rate limiter protects against brute force, DoS, DDoS, and web scraping attacks using a sliding window counter stored in Cloudflare KV.

**Features:**
- Multiple rate limit profiles (strict, normal, relaxed)
- Burst detection with queuing and throttling
- Session-aware rate limiting
- Adaptive limits based on traffic patterns

**Example:**
```typescript
import { RateLimiter } from './rate-limiter/rate-limiter';

const rateLimiter = new RateLimiter(env.KV);
const result = await rateLimiter.check({
  key: `ip:${ip}`,
  limit: 100,
  window: 60, // 100 requests per minute
});

if (!result.allowed) {
  return new Response('Rate limit exceeded', { status: 429 });
}
```

### Bot Protection

The bot management system detects and mitigates automated attacks.

**Features:**
- **Credential Stuffing Detection**: Identifies rapid login attempts with different credentials
- **Spam Detection**: Detects promotional content, excessive links, and automated posting
- **Session Management**: Tracks user behavior across requests
- **Traffic Classification**: Categorizes traffic as legitimate, suspicious, or malicious
- **Turnstile Integration**: Cloudflare's bot protection service

**Example:**
```typescript
import { BotProtectionManager } from './bot';

const botManager = new BotProtectionManager(env);
const result = await botManager.analyzeRequest(request, sessionId);

if (result.blocked) {
  return new Response('Bot detected', { status: 403 });
}
```

### WAF Rules

The Web Application Firewall protects against XSS and insecure deserialization attacks.

**Features:**
- **XSS Protection**: Detects script injection, event handlers, JavaScript protocols
- **Deserialization Protection**: Blocks Java, Python, PHP, .NET, and YAML deserialization attacks
- **POST Body Scanning**: Scans both query strings and POST body content
- **Base64 Decoding**: Automatically decodes and scans base64-encoded payloads

**XSS Patterns Detected:**
- `<script>` tags
- Event handlers (`onerror=`, `onload=`, etc.)
- JavaScript protocol (`javascript:`, `vbscript:`)
- Data URIs (`data:text/html`)
- SVG/iframe injection

**Deserialization Patterns Detected:**
- Java serialization magic bytes (`rO0ABXNy...`)
- Python pickle exploits (`cos\nsystem\n`)
- PHP serialized objects (`O:8:"stdClass"`)
- .NET TypeNameHandling vulnerabilities
- YAML code execution (`!!python/object/apply`)

**Example:**
```typescript
import { checkWAF } from './rules/waf';

const wafResult = await checkWAF(request, traceId);
if (wafResult.blocked) {
  return createWAFBlockResponse(wafResult);
}
```

### Geolocation Blocking

Block or challenge requests from specific countries or regions.

**Configuration:**
```typescript
import { GeolocationBlocker } from './tracing/geolocation';

const geoBlocker = new GeolocationBlocker({
  blockedCountries: ['ZZ', 'XX', 'YY'], // Fake test countries
  challengedCountries: ['QQ', 'WW'],
  defaultAction: 'allow',
});
```

**Fake Test Countries (for load testing):**
- `ZZ`: Fakeland (blocked)
- `XX`: Testonia (blocked)
- `YY`: Malwaristan (blocked)
- `QQ`: Suspectia (challenged)
- `WW`: Botlandia (challenged)

### IP Tracking

Track IP reputation and automatically block low-reputation IPs.

**Features:**
- IP reputation scoring
- Auto-blocking for low-reputation IPs
- Request history tracking
- Violation counting

## Load Testing

The project includes a comprehensive load testing framework with 6 attack profiles.

### Running Load Tests

```bash
# Run a specific test profile
npm run load-test -- -p RULES_FOLDER_TEST -v

# Available profiles:
# - BOT_FOLDER_TEST: Tests bot detection
# - RATE_LIMITER_TEST: Tests rate limiting
# - RULES_FOLDER_TEST: Tests WAF rules
# - TRACING_FOLDER_TEST: Tests geolocation and IP tracking
# - CORE_LEGITIMATE_TRAFFIC: Tests legitimate traffic handling
# - CORE_MIXED_TRAFFIC: Tests mixed legitimate + attack traffic
```

### Test Profiles

| Profile | Description | Expected Block Rate |
|---------|-------------|---------------------|
| `BOT_FOLDER_TEST` | Credential stuffing, spam, bot user agents | 50-70% |
| `RATE_LIMITER_TEST` | Burst attacks, brute force, web scraping | 60-80% |
| `RULES_FOLDER_TEST` | XSS and deserialization attacks | 80-95% |
| `TRACING_FOLDER_TEST` | Geolocation blocking, IP tracking | 15-25% |
| `CORE_LEGITIMATE_TRAFFIC` | Real user traffic from legitimate countries | 0-10% |
| `CORE_MIXED_TRAFFIC` | 60% legitimate + 40% attack traffic | 30-50% |

## Turnstile Integration

### Setup

1. Get your Turnstile site key and secret key from [Cloudflare Dashboard](https://dash.cloudflare.com/?to=/:account/turnstile)

2. Add secret key to your worker:
```bash
wrangler secret put TURNSTILE_SECRET_KEY
```

3. Enable Turnstile in `wrangler.toml`:
```toml
[vars]
TURNSTILE_ENABLED = "true"
```

### Client-Side Integration

Add the Turnstile widget to your HTML:

```html
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<form id="myForm">
  <div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
  <button type="submit">Submit</button>
</form>

<script>
  document.getElementById('myForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const token = document.querySelector('[name="cf-turnstile-response"]').value;
    
    const response = await fetch('/api/protected', {
      headers: {
        'CF-Turnstile-Token': token
      }
    });
    
    const data = await response.json();
    console.log(data);
  });
</script>
```

### Mock Mode

In development, Turnstile is automatically mocked:
- Any token passes verification
- Use token "fail" or "invalid" to test failure cases

## Request Tracing

Every request gets a unique trace ID for debugging and monitoring.

### Trace Headers

Response includes these headers:
- `X-Trace-ID`: Unique identifier for this request
- `X-Request-Timestamp`: When the request was processed
- `X-CF-Ray`: Cloudflare Ray ID (in production)
- `Server-Timing`: Performance timing breakdown

### Trace Information

```json
{
  "trace": {
    "traceId": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": 1234567890,
    "method": "GET",
    "url": "/api/public",
    "ip": "203.0.113.1",
    "country": "US",
    "performance": {
      "totalTime": 45.2,
      "wafCheckTime": 2.1,
      "rateLimitTime": 1.5
    }
  }
}
```

## Production Deployment

### 1. Create KV Namespace

```bash
# Create production namespace
wrangler kv:namespace create "RATE_LIMIT_KV"

# Create preview namespace for testing
wrangler kv:namespace create "RATE_LIMIT_KV" --preview
```

Update `wrangler.toml` with the IDs returned.

### 2. Configure Secrets

```bash
# Add Turnstile secret key
wrangler secret put TURNSTILE_SECRET_KEY

# Verify
wrangler secret list
```

### 3. Deploy

```bash
npm run deploy
```

### 4. Test Production

```bash
# Get your worker URL from deployment output
curl https://workers-security-example.YOUR-SUBDOMAIN.workers.dev/api/status
```

## Key Learnings & Insights

### 1. Defense in Depth
Combining multiple security layers (WAF + rate limiting + bot protection + geolocation) provides better protection than any single mechanism alone.

### 2. POST Body Scanning
WAF rules must scan both query strings AND POST body content. Many attacks (especially deserialization) occur in POST bodies.

### 3. Session-Aware Security
Tracking user sessions enables behavioral analysis and more sophisticated bot detection.

### 4. IP Reputation
Auto-blocking low-reputation IPs provides an additional layer of protection against known bad actors.

### 5. Geolocation Blocking
Blocking high-threat countries/regions can significantly reduce attack traffic, but must be balanced against legitimate users.

### 6. Load Testing
Comprehensive load testing with realistic attack profiles is essential for validating security measures.

## Troubleshooting

### Rate limits not working
- Check that KV namespace is configured in `wrangler.toml`
- Verify KV namespace IDs are correct
- Check worker logs for KV errors

### Turnstile always failing
- Verify `TURNSTILE_SECRET_KEY` is set correctly
- Check that `TURNSTILE_ENABLED` is "true"
- Ensure client is sending token in correct header/field

### WAF not blocking POST body attacks
- Ensure `checkWAF()` is called with `await` (it's async)
- Verify POST body content is being read correctly
- Check WAF rules include patterns for your attack vectors

### All requests blocked in load tests
- Verify test traffic uses unique IP addresses per request
- Check that fake test countries (ZZ, XX, YY) are configured correctly
- Ensure legitimate traffic uses real country codes (US, CA, GB, etc.)

## Resources

- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Turnstile Docs](https://developers.cloudflare.com/turnstile/)
- [Workers KV Docs](https://developers.cloudflare.com/kv/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
