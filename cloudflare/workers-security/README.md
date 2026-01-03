# Example: Cloudflare Workers Security

A comprehensive example demonstrating Cloudflare Workers security features including rate limiting, Turnstile bot protection, WAF rules, and request tracing.

## Features

### 🔒 Security Features
- **Rate Limiting**: Token bucket algorithm using Cloudflare KV with multiple profiles
- **Bot Protection**: Cloudflare Turnstile integration with automatic fallback
- **WAF Rules**: Simulated Web Application Firewall with common attack patterns
- **Request Tracing**: Unified trace ID system for debugging and monitoring

### 🛠️ Development Features
- **Mock Mode**: Fully functional local development without Cloudflare credentials
- **Multiple Rate Limit Profiles**: Pre-configured profiles for different use cases
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
Public endpoint with relaxed rate limiting (1000 requests/minute).

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
Protected endpoint requiring Turnstile verification (100 requests/minute).

**Example:**
```bash
curl -H "CF-Turnstile-Token: your-token-here" http://localhost:8787/api/protected
```

In mock mode, any token value works except "fail" or "invalid".

### `POST /api/login`
Login endpoint with strict rate limiting (5 requests/minute).

**Example:**
```bash
curl -X POST http://localhost:8787/api/login
```

This demonstrates how to protect authentication endpoints from brute force attacks.

### `GET /api/status`
Service status and configuration information.

**Example:**
```bash
curl http://localhost:8787/api/status
```

**Response:**
```json
{
  "service": "workers-security-example",
  "environment": "development",
  "features": {
    "turnstile": {
      "enabled": false,
      "configured": false
    },
    "rateLimit": {
      "enabled": true,
      "backend": "mock"
    },
    "waf": {
      "enabled": true,
      "rulesCount": 5
    }
  }
}
```

### `GET /api/rules`
List all active WAF rules.

**Example:**
```bash
curl http://localhost:8787/api/rules
```

## Rate Limiting

### Profiles

The project includes pre-configured rate limit profiles:

| Profile | Limit | Window | Use Case |
|---------|-------|--------|----------|
| STRICT  | 5     | 60s    | Login/auth endpoints (prevents brute force) |
| NORMAL  | 100   | 60s    | General API endpoints |
| RELAXED | 1000  | 60s    | Public/static content |
| HOURLY  | 100   | 3600s  | Expensive operations |
| DAILY   | 1000  | 86400s | Very expensive operations |

### Implementation

Rate limiting uses a sliding window counter stored in Cloudflare KV (or in-memory for mock mode):

```typescript
const rateLimiter = createRateLimiter(env);
const key = getRateLimitKey(request, 'public');

const rateLimit = await rateLimiter.check({
  key,
  ...RATE_LIMIT_PROFILES.RELAXED,
});

if (!rateLimit.allowed) {
  // Return 429 Too Many Requests
}
```

### Customizing Rate Limits

Edit `src/rate-limiter.ts` to add custom profiles or modify the key generation logic:

```typescript
// Custom profile
export const RATE_LIMIT_PROFILES = {
  CUSTOM: { limit: 50, window: 120 }, // 50 requests per 2 minutes
};

// Custom key (e.g., by user ID instead of IP)
export function getRateLimitKey(request: Request, prefix: string = 'ip'): string {
  const userId = request.headers.get('X-User-ID');
  if (userId) {
    return `${prefix}:user:${userId}`;
  }
  // Fallback to IP
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  return `${prefix}:${ip}`;
}
```

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

## WAF Rules

The project includes simulated WAF rules that block common attack patterns:

### Built-in Rules

1. **SQL Injection**: Blocks patterns like `union select`, `drop table`, `' or '1'='1'`
2. **XSS**: Blocks `<script>`, `javascript:`, `onerror=`
3. **Path Traversal**: Blocks `../` and `..\`
4. **Suspicious User Agents**: Challenges requests with bot-like user agents
5. **Admin Protection**: Blocks unauthenticated access to `/admin` paths

### Testing WAF Rules

```bash
# SQL injection attempt (blocked)
curl "http://localhost:8787/api/public?id=1%20union%20select"

# XSS attempt (blocked)
curl "http://localhost:8787/api/public?q=%3Cscript%3E"

# Path traversal (blocked)
curl "http://localhost:8787/../etc/passwd"
```

### Adding Custom Rules

Edit `src/waf.ts`:

```typescript
const WAF_RULES: WAFRule[] = [
  {
    id: 'custom-rule',
    description: 'Block specific pattern',
    action: 'block',
    conditions: [
      {
        field: 'path',
        operator: 'contains',
        value: '/forbidden',
      },
    ],
  },
  // ... existing rules
];
```

## Request Tracing

Every request gets a unique trace ID for debugging and monitoring.

### Trace Headers

Response includes these headers:
- `X-Trace-ID`: Unique identifier for this request
- `X-Request-Timestamp`: When the request was processed
- `X-CF-Ray`: Cloudflare Ray ID (in production)

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
    "rayId": "7d9e8f7e6d5c4b3a"
  }
}
```

### Logging

All requests are logged with trace information:

```javascript
console.log('[TRACE]', JSON.stringify({
  traceId: "550e8400-e29b-41d4-a716-446655440000",
  timestamp: 1234567890,
  method: "GET",
  url: "/api/public",
  environment: "development"
}));
```

In production, connect this to:
- Cloudflare Logpush
- Workers Analytics Engine
- External logging services (Datadog, Splunk, etc.)

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

## Project Structure

```
example-1-workers-security/
├── src/
│   ├── index.ts           # Main worker entry point
│   ├── rate-limiter.ts    # Rate limiting logic
│   ├── turnstile.ts       # Turnstile verification
│   ├── tracing.ts         # Request tracing system
│   ├── waf.ts            # WAF rule simulation
│   └── types/
│       └── index.ts       # TypeScript types
├── wrangler.toml          # Cloudflare configuration
├── package.json           # Dependencies
├── tsconfig.json          # TypeScript config
└── README.md             # This file
```

## Key Learnings & Insights

### 1. Unified Trace IDs
Implementing trace IDs across all requests makes debugging significantly easier. When a user reports an issue, you can search logs by trace ID to see the complete request flow.

### 2. Rate Limiting Strategy
Different endpoints need different rate limits:
- Auth endpoints: Very strict (5/min) to prevent brute force
- API endpoints: Moderate (100/min) for normal usage
- Public content: Relaxed (1000/min) to avoid false positives

### 3. Mock Development
Being able to develop and test locally without Cloudflare credentials dramatically improves developer experience. The mock implementations should match production behavior as closely as possible.

### 4. Defense in Depth
Combining multiple security layers (WAF + rate limiting + bot protection) provides better protection than any single mechanism alone.

### 5. Fail Open vs Fail Closed
For rate limiting, we "fail open" (allow requests) if KV is unavailable to prevent service disruptions. For security-critical features like Turnstile, consider whether to "fail closed" (block requests).

## Troubleshooting

### Rate limits not working
- Check that KV namespace is configured in `wrangler.toml`
- Verify KV namespace IDs are correct
- Check worker logs for KV errors

### Turnstile always failing
- Verify `TURNSTILE_SECRET_KEY` is set correctly
- Check that `TURNSTILE_ENABLED` is "true"
- Ensure client is sending token in correct header/field

### WAF not blocking
- Check that patterns match exactly (case-insensitive)
- Verify URL encoding in test requests
- Review WAF rules in `src/waf.ts`

## Next Steps

- Add D1 database for persistent rate limit storage
- Implement more sophisticated bot detection
- Add metrics and monitoring dashboards
- Create admin API for managing rules
- Add request replay protection
- Implement geographic restrictions

## Resources

- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Turnstile Docs](https://developers.cloudflare.com/turnstile/)
- [Workers KV Docs](https://developers.cloudflare.com/kv/)
