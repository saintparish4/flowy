// Attack Profile Definitions
// Defines different types of attack patterns for load testing

export interface AttackProfile {
  name: string;
  description: string;
  type:
    | "burst"
    | "sustained"
    | "slow-drip"
    | "credential-stuffing"
    | "legitimate";

  // Request configuration
  requestsPerSecond: number;
  duration: number; // seconds
  concurrency: number; // parallel connections

  // Pattern configuration
  pattern: {
    distribution: "constant" | "linear" | "exponential" | "random" | "wave";
    burstSize?: number; // for burst attacks
    rampUpTime?: number; // for gradual attacks
    variance?: number; // randomness factor (0-1)
  };

  // Request characteristics
  requests: {
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: any;
    turnstileToken?: boolean;
  }[];

  // Expected outcomes for validation
  expected: {
    blockRate?: number; // expected percentage of blocked requests
    successRate?: number; // expected percentage of successful requests
    avgLatency?: number; // expected average latency (ms)
  };
}

/**
 * Pre-defined attack profiles
 */

// Burst attack: Sudden spike in traffic
export const BURST_ATTACK: AttackProfile = {
  name: "Burst Attack",
  description: "Sudden spike of traffic attempting to overwhelm rate limits",
  type: "burst",
  requestsPerSecond: 1000,
  duration: 10,
  concurrency: 100,
  pattern: {
    distribution: "exponential",
    burstSize: 500,
    rampUpTime: 1,
    variance: 0.2,
  },
  requests: [
    {
      method: "GET",
      path: "/api/public",
    },
  ],
  expected: {
    blockRate: 0.85, // Expect 85% to be rate limited
    avgLatency: 50,
  },
};

// Sustained attack: Consistent high traffic
export const SUSTAINED_ATTACK: AttackProfile = {
  name: "Sustained Attack",
  description: "Consistent high-volume traffic over extended period",
  type: "sustained",
  requestsPerSecond: 500,
  duration: 60,
  concurrency: 50,
  pattern: {
    distribution: "constant",
    variance: 0.1,
  },
  requests: [
    {
      method: "GET",
      path: "/api/public",
    },
  ],
  expected: {
    blockRate: 0.5,
    avgLatency: 100,
  },
};

// Slow drip attack: Low and slow to evade detection
export const SLOW_DRIP_ATTACK: AttackProfile = {
  name: "Slow Drip Attack",
  description: "Low-volume requests designed to evade rate limiting",
  type: "slow-drip",
  requestsPerSecond: 10,
  duration: 300,
  concurrency: 5,
  pattern: {
    distribution: "random",
    variance: 0.5,
  },
  requests: [
    {
      method: "POST",
      path: "/api/login",
      body: { username: "admin", password: "password123" },
    },
  ],
  expected: {
    blockRate: 0.1, // Most should get through
    avgLatency: 50,
  },
};

// Credential stuffing: Multiple login attempts
export const CREDENTIAL_STUFFING: AttackProfile = {
  name: "Credential Stuffing",
  description: "Automated login attempts with stolen credentials",
  type: "credential-stuffing",
  requestsPerSecond: 50,
  duration: 60,
  concurrency: 20,
  pattern: {
    distribution: "constant",
    variance: 0.15,
  },
  requests: [
    {
      method: "POST",
      path: "/api/login",
      body: { username: "user1@example.com", password: "password123" },
    },
    {
      method: "POST",
      path: "/api/login",
      body: { username: "user2@example.com", password: "letmein" },
    },
    {
      method: "POST",
      path: "/api/login",
      body: { username: "admin@example.com", password: "admin123" },
    },
  ],
  expected: {
    blockRate: 0.9, // Strict rate limiting should block most
    avgLatency: 30,
  },
};

// Legitimate traffic: Normal user behavior
export const LEGITIMATE_TRAFFIC: AttackProfile = {
  name: "Legitimate Traffic",
  description: "Simulated normal user traffic patterns",
  type: "legitimate",
  requestsPerSecond: 100,
  duration: 120,
  concurrency: 10,
  pattern: {
    distribution: "wave",
    variance: 0.3,
  },
  requests: [
    {
      method: "GET",
      path: "/api/public",
    },
    {
      method: "GET",
      path: "/api/status",
    },
    {
      method: "GET",
      path: "/api/protected",
      turnstileToken: true,
    },
  ],
  expected: {
    blockRate: 0.05, // Very few should be blocked
    successRate: 0.95,
    avgLatency: 100,
  },
};

// Mixed traffic: Combination of legitimate and attack traffic
export const MIXED_TRAFFIC: AttackProfile = {
  name: "Mixed Traffic",
  description: "Realistic mix of legitimate users and attackers",
  type: "sustained",
  requestsPerSecond: 200,
  duration: 180,
  concurrency: 30,
  pattern: {
    distribution: "wave",
    variance: 0.25,
  },
  requests: [
    // 70% legitimate
    {
      method: "GET",
      path: "/api/public",
      headers: { "User-Agent": "Mozilla/5.0 (Legitimate Browser)" },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { "User-Agent": "Mozilla/5.0 (Legitimate Browser)" },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { "User-Agent": "Mozilla/5.0 (Legitimate Browser)" },
    },
    // 30% attack
    {
      method: "POST",
      path: "/api/login",
      headers: { "User-Agent": "python-requests/2.28.0" },
      body: { username: "admin", password: "test123" },
    },
  ],
  expected: {
    blockRate: 0.3, // Should block attack traffic
    successRate: 0.7, // Should allow legitimate traffic
    avgLatency: 80,
  },
};

// SQL Injection attack pattern
export const SQL_INJECTION_ATTACK: AttackProfile = {
  name: "SQL Injection Attack",
  description: "Attempts to inject SQL commands",
  type: "sustained",
  requestsPerSecond: 100,
  duration: 30,
  concurrency: 20,
  pattern: {
    distribution: "constant",
    variance: 0.1,
  },
  requests: [
    {
      method: "GET",
      path: "/api/public?id=1' OR '1'='1",
    },
    {
      method: "GET",
      path: "/api/public?id=1 UNION SELECT * FROM users",
    },
    {
      method: "GET",
      path: "/api/public?id=1; DROP TABLE users--",
    },
  ],
  expected: {
    blockRate: 1.0, // WAF should block all
    avgLatency: 10,
  },
};

// WAF SQL Injection test profile
export const WAF_SQL_INJECTION_TEST: AttackProfile = {
  name: "WAF SQL Injection Test",
  description: "Comprehensive SQL injection test patterns for WAF validation",
  type: "sustained",
  requestsPerSecond: 100,
  duration: 30,
  concurrency: 20,
  pattern: {
    distribution: "constant",
    variance: 0.1,
  },
  requests: [
    {
      method: "GET",
      path: "/api/public?id=1' OR '1'='1",
    },
    {
      method: "GET",
      path: "/api/public?id=1 UNION SELECT * FROM users",
    },
    {
      method: "GET",
      path: "/api/public?id=1; DROP TABLE users--",
    },
    {
      method: "POST",
      path: "/api/login",
      body: { username: "admin'--", password: "password" },
    },
    {
      method: "GET",
      path: "/api/public?id=1' OR 1=1--",
    },
    {
      method: "GET",
      path: "/api/public?id=1' OR '1'='1' OR '1'='1",
    },
  ],
  expected: {
    blockRate: 1.0, // WAF should block all
    avgLatency: 10,
  },
};

// XSS attack pattern
export const XSS_ATTACK: AttackProfile = {
  name: "XSS Attack",
  description: "Cross-site scripting injection attempts",
  type: "sustained",
  requestsPerSecond: 100,
  duration: 30,
  concurrency: 20,
  pattern: {
    distribution: "constant",
    variance: 0.1,
  },
  requests: [
    {
      method: "GET",
      path: "/api/public?q=<script>alert(1)</script>",
    },
    {
      method: "GET",
      path: "/api/public?q=<img src=x onerror=alert(1)>",
    },
    {
      method: "GET",
      path: "/api/public?q=javascript:alert(1)",
    },
  ],
  expected: {
    blockRate: 1.0, // WAF should block all
    avgLatency: 10,
  },
};

/**
 * All available profiles
 */
export const ALL_PROFILES: Record<string, AttackProfile> = {
  BURST_ATTACK,
  SUSTAINED_ATTACK,
  SLOW_DRIP_ATTACK,
  CREDENTIAL_STUFFING,
  LEGITIMATE_TRAFFIC,
  MIXED_TRAFFIC,
  SQL_INJECTION_ATTACK,
  WAF_SQL_INJECTION_TEST,
  XSS_ATTACK,
};

/**
 * Get profile by name
 */
export function getProfile(name: string): AttackProfile | undefined {
  return ALL_PROFILES[name];
}

/**
 * List all profile names
 */
export function listProfiles(): string[] {
  return Object.keys(ALL_PROFILES);
}
