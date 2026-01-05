import type { WAFRule, WAFResult } from "./types";

/**
 * WAF Rule Categories
 */
export type WAFCategory =
  | "sql-injection"
  | "xss"
  | "path-traversal"
  | "command-injection"
  | "bot-detection"
  | "api-abuse"
  | "admin-protection"
  | "custom";

/**
 * WAF Rule Severity
 */
export type WAFSeverity = "critical" | "high" | "medium" | "low";

/**
 * Enhanced WAF rule with metadata
 */
export interface EnhancedWAFRule extends WAFRule {
  category: WAFCategory;
  severity: WAFSeverity;
  enabled: boolean;
  tags: string[];
  falsePositiveRate?: number; // Estimated false positive rate (0-1)
}

/**
 * WAF Statistics
 */
export interface WAFStats {
  totalRequests: number;
  blockedRequests: number;
  blockedByCategory: Record<WAFCategory, number>;
  blockedBySeverity: Record<WAFSeverity, number>;
  avgCheckTime: number;
  falsePositives: number;
}

/**
 * Comprehensive WAF rule set
 */
export const WAF_RULES: EnhancedWAFRule[] = [
  // ========================================================================
  // SQL INJECTION RULES (Critical)
  // ========================================================================
  {
    id: "sql-001",
    description: "Block SQL UNION attacks",
    action: "block",
    category: "sql-injection",
    severity: "critical",
    enabled: true,
    tags: ["sql", "union", "data-exfiltration"],
    conditions: [
      { field: "query", operator: "contains", value: "union select" },
      { field: "query", operator: "contains", value: "union all select" },
    ],
  },
  {
    id: "sql-002",
    description: "Block SQL authentication bypass",
    action: "block",
    category: "sql-injection",
    severity: "critical",
    enabled: true,
    tags: ["sql", "auth-bypass"],
    conditions: [
      { field: "query", operator: "contains", value: "' or '1'='1" },
      { field: "query", operator: "contains", value: '" or "1"="1' },
      { field: "query", operator: "contains", value: "' or 1=1--" },
      { field: "query", operator: "contains", value: "admin'--" },
    ],
  },
  {
    id: "sql-003",
    description: "Block SQL DROP/DELETE commands",
    action: "block",
    category: "sql-injection",
    severity: "critical",
    enabled: true,
    tags: ["sql", "destructive"],
    conditions: [
      { field: "query", operator: "contains", value: "drop table" },
      { field: "query", operator: "contains", value: "delete from" },
      { field: "query", operator: "contains", value: "truncate table" },
    ],
  },
  {
    id: "sql-004",
    description: "Block SQL comment injection",
    action: "block",
    category: "sql-injection",
    severity: "high",
    enabled: true,
    tags: ["sql", "comment"],
    conditions: [
      { field: "query", operator: "contains", value: "--" },
      { field: "query", operator: "contains", value: "/*" },
      { field: "query", operator: "contains", value: "*/" },
      { field: "query", operator: "contains", value: "xp_" },
    ],
  },

  // ========================================================================
  // XSS RULES (High)
  // ========================================================================
  {
    id: "xss-001",
    description: "Block inline script tags",
    action: "block",
    category: "xss",
    severity: "high",
    enabled: true,
    tags: ["xss", "script"],
    conditions: [
      { field: "query", operator: "contains", value: "<script" },
      { field: "query", operator: "contains", value: "</script>" },
    ],
  },
  {
    id: "xss-002",
    description: "Block JavaScript event handlers",
    action: "block",
    category: "xss",
    severity: "high",
    enabled: true,
    tags: ["xss", "events"],
    conditions: [
      { field: "query", operator: "contains", value: "onerror=" },
      { field: "query", operator: "contains", value: "onload=" },
      { field: "query", operator: "contains", value: "onclick=" },
      { field: "query", operator: "contains", value: "onmouseover=" },
    ],
  },
  {
    id: "xss-003",
    description: "Block JavaScript protocol handlers",
    action: "block",
    category: "xss",
    severity: "high",
    enabled: true,
    tags: ["xss", "protocol"],
    conditions: [
      { field: "query", operator: "contains", value: "javascript:" },
      { field: "query", operator: "contains", value: "vbscript:" },
      { field: "query", operator: "contains", value: "data:text/html" },
    ],
  },
  {
    id: "xss-004",
    description: "Block image-based XSS",
    action: "block",
    category: "xss",
    severity: "medium",
    enabled: true,
    tags: ["xss", "img"],
    conditions: [
      { field: "query", operator: "contains", value: "<img src=x onerror" },
      { field: "query", operator: "contains", value: "<svg onload" },
    ],
  },

  // ========================================================================
  // PATH TRAVERSAL RULES (High)
  // ========================================================================
  {
    id: "path-001",
    description: "Block directory traversal attempts",
    action: "block",
    category: "path-traversal",
    severity: "high",
    enabled: true,
    tags: ["path-traversal", "directory"],
    conditions: [
      { field: "path", operator: "contains", value: "../" },
      { field: "path", operator: "contains", value: "..\\" },
      { field: "query", operator: "contains", value: "../" },
      { field: "query", operator: "contains", value: "..\\" },
    ],
  },
  {
    id: "path-002",
    description: "Block absolute path access",
    action: "block",
    category: "path-traversal",
    severity: "high",
    enabled: true,
    tags: ["path-traversal", "absolute"],
    conditions: [
      { field: "path", operator: "contains", value: "/etc/passwd" },
      { field: "path", operator: "contains", value: "/etc/shadow" },
      { field: "path", operator: "contains", value: "c:\\windows" },
      { field: "query", operator: "contains", value: "/etc/passwd" },
    ],
  },

  // ========================================================================
  // COMMAND INJECTION RULES (Critical)
  // ========================================================================
  {
    id: "cmd-001",
    description: "Block shell command injection",
    action: "block",
    category: "command-injection",
    severity: "critical",
    enabled: true,
    tags: ["command-injection", "shell"],
    conditions: [
      { field: "query", operator: "contains", value: "| cat" },
      { field: "query", operator: "contains", value: "| nc" },
      { field: "query", operator: "contains", value: "; wget" },
      { field: "query", operator: "contains", value: "&& curl" },
      { field: "query", operator: "contains", value: "`" },
      { field: "query", operator: "contains", value: "$(" },
    ],
  },

  // ========================================================================
  // BOT DETECTION RULES (Medium)
  // ========================================================================
  {
    id: "bot-001",
    description: "Challenge suspicious user agents",
    action: "challenge",
    category: "bot-detection",
    severity: "medium",
    enabled: true,
    tags: ["bot", "user-agent"],
    falsePositiveRate: 0.05, // 5% false positive rate
    conditions: [
      { field: "user-agent", operator: "contains", value: "bot" },
      { field: "user-agent", operator: "contains", value: "crawler" },
      { field: "user-agent", operator: "contains", value: "spider" },
      { field: "user-agent", operator: "contains", value: "scraper" },
    ],
  },
  {
    id: "bot-002",
    description: "Block requests without user agent",
    action: "block",
    category: "bot-detection",
    severity: "medium",
    enabled: true,
    tags: ["bot", "user-agent"],
    conditions: [{ field: "user-agent", operator: "equals", value: "" }],
  },
  {
    id: "bot-003",
    description: "Challenge automation tools",
    action: "challenge",
    category: "bot-detection",
    severity: "medium",
    enabled: true,
    tags: ["bot", "automation"],
    conditions: [
      { field: "user-agent", operator: "contains", value: "python-requests" },
      { field: "user-agent", operator: "contains", value: "curl" },
      { field: "user-agent", operator: "contains", value: "wget" },
      { field: "user-agent", operator: "contains", value: "postman" },
    ],
  },

  // ========================================================================
  // API ABUSE RULES (Medium)
  // ========================================================================
  {
    id: "api-001",
    description: "Block mass data enumeration",
    action: "block",
    category: "api-abuse",
    severity: "medium",
    enabled: true,
    tags: ["api", "enumeration"],
    conditions: [
      { field: "query", operator: "contains", value: "limit=1000" },
      { field: "query", operator: "contains", value: "limit=9999" },
      { field: "query", operator: "contains", value: "per_page=1000" },
    ],
  },

  // ========================================================================
  // ADMIN PROTECTION RULES (High)
  // ========================================================================
  {
    id: "admin-001",
    description: "Protect admin endpoints",
    action: "block",
    category: "admin-protection",
    severity: "high",
    enabled: true,
    tags: ["admin", "unauthorized"],
    conditions: [
      { field: "path", operator: "starts-with", value: "/admin" },
      { field: "path", operator: "starts-with", value: "/wp-admin" },
      { field: "path", operator: "starts-with", value: "/.env" },
      { field: "path", operator: "starts-with", value: "/.git" },
    ],
  },
];

/**
 * WAF Configuration Manager
 */
export class WAFConfig {
  private rules: EnhancedWAFRule[] = WAF_RULES;
  private stats: WAFStats = {
    totalRequests: 0,
    blockedRequests: 0,
    blockedByCategory: {} as Record<WAFCategory, number>,
    blockedBySeverity: {} as Record<WAFSeverity, number>,
    avgCheckTime: 0,
    falsePositives: 0,
  };

  /**
   * Get all enabled rules
   */
  getEnabledRules(): EnhancedWAFRule[] {
    return this.rules.filter((r) => r.enabled);
  }

  /**
   * Get rules by category
   */
  getRulesByCategory(category: WAFCategory): EnhancedWAFRule[] {
    return this.rules.filter((r) => r.category === category && r.enabled);
  }

  /**
   * Get rules by severity
   */
  getRulesBySeverity(severity: WAFSeverity): EnhancedWAFRule[] {
    return this.rules.filter((r) => r.severity === severity && r.enabled);
  }

  /**
   * Enable/disable a rule
   */
  setRuleEnabled(ruleId: string, enabled: boolean): void {
    const rule = this.rules.find((r) => r.id === ruleId);
    if (rule) {
      rule.enabled = enabled;
    }
  }

  /**
   * Add custom rule
   */
  addCustomRule(rule: EnhancedWAFRule): void {
    this.rules.push(rule);
  }

  /**
   * Record WAF check result
   */
  recordCheck(result: WAFResult, checkTime: number): void {
    this.stats.totalRequests++;

    if (result.blocked) {
      this.stats.blockedRequests++;

      if (result.rule) {
        const rule = this.rules.find((r) => r.id === result.rule!.id);
        if (rule) {
          this.stats.blockedByCategory[rule.category] =
            (this.stats.blockedByCategory[rule.category] || 0) + 1;
          this.stats.blockedBySeverity[rule.severity] =
            (this.stats.blockedBySeverity[rule.severity] || 0) + 1;
        }
      }
    }

    // Update average check time
    this.stats.avgCheckTime =
      (this.stats.avgCheckTime * (this.stats.totalRequests - 1) + checkTime) /
      this.stats.totalRequests;
  }

  /**
   * Get statistics
   */
  getStats(): WAFStats {
    return { ...this.stats };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      totalRequests: 0,
      blockedRequests: 0,
      blockedByCategory: {} as Record<WAFCategory, number>,
      blockedBySeverity: {} as Record<WAFSeverity, number>,
      avgCheckTime: 0,
      falsePositives: 0,
    };
  }
}

/**
 * Create a WAF configuration instance
 */
export function createWAFConfig(): WAFConfig {
  return new WAFConfig();
}

/**
 * Export rule categories for convenience
 */
export const WAF_CATEGORIES: WAFCategory[] = [
  "sql-injection",
  "xss",
  "path-traversal",
  "command-injection",
  "bot-detection",
  "api-abuse",
  "admin-protection",
  "custom",
];

/**
 * Export severity levels
 */
export const WAF_SEVERITIES: WAFSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
];
