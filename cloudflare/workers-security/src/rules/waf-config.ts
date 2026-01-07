import type { WAFRule, WAFResult } from "../types";
import { DESERIALIZATION_PATTERNS } from "./deserialization-patterns";

/**
 * WAF Rule Categories
 * Now focused on XSS and insecure deserialization protection
 */
export type WAFCategory =
  | "xss"
  | "insecure-deserialization"
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
 * Focused on XSS and Insecure Deserialization protection
 */
export const WAF_RULES: EnhancedWAFRule[] = [
  // ========================================================================
  // XSS RULES (Cross-Site Scripting Protection)
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
      { field: "query", operator: "contains", value: "onfocus=" },
      { field: "query", operator: "contains", value: "onblur=" },
      { field: "query", operator: "contains", value: "onsubmit=" },
      { field: "query", operator: "contains", value: "onchange=" },
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
      { field: "query", operator: "contains", value: "data:application/javascript" },
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
      { field: "query", operator: "contains", value: "<svg/onload" },
      { field: "query", operator: "contains", value: "<body onload" },
    ],
  },
  {
    id: "xss-005",
    description: "Block iframe injection",
    action: "block",
    category: "xss",
    severity: "high",
    enabled: true,
    tags: ["xss", "iframe"],
    conditions: [
      { field: "query", operator: "contains", value: "<iframe" },
      { field: "query", operator: "contains", value: "<frame" },
      { field: "query", operator: "contains", value: "<embed" },
      { field: "query", operator: "contains", value: "<object" },
    ],
  },
  {
    id: "xss-006",
    description: "Block HTML5 XSS vectors",
    action: "block",
    category: "xss",
    severity: "high",
    enabled: true,
    tags: ["xss", "html5"],
    conditions: [
      { field: "query", operator: "contains", value: "<video" },
      { field: "query", operator: "contains", value: "<audio" },
      { field: "query", operator: "contains", value: "<source" },
      { field: "query", operator: "contains", value: "<track" },
      { field: "query", operator: "contains", value: "formaction=" },
    ],
  },
  {
    id: "xss-007",
    description: "Block expression-based XSS",
    action: "block",
    category: "xss",
    severity: "high",
    enabled: true,
    tags: ["xss", "expression"],
    conditions: [
      { field: "query", operator: "contains", value: "expression(" },
      { field: "query", operator: "contains", value: "document.cookie" },
      { field: "query", operator: "contains", value: "document.domain" },
      { field: "query", operator: "contains", value: "document.write" },
      { field: "query", operator: "contains", value: "window.location" },
    ],
  },
  {
    id: "xss-008",
    description: "Block eval and Function constructor",
    action: "block",
    category: "xss",
    severity: "critical",
    enabled: true,
    tags: ["xss", "eval"],
    conditions: [
      { field: "query", operator: "contains", value: "eval(" },
      { field: "query", operator: "contains", value: "Function(" },
      { field: "query", operator: "contains", value: "setTimeout(" },
      { field: "query", operator: "contains", value: "setInterval(" },
    ],
  },

  // ========================================================================
  // INSECURE DESERIALIZATION RULES
  // ========================================================================
  {
    id: "deser-001",
    description: "Block Java serialization magic bytes (base64)",
    action: "block",
    category: "insecure-deserialization",
    severity: "critical",
    enabled: true,
    tags: ["deserialization", "java", "base64"],
    conditions: [
      { field: "query", operator: "contains", value: "rO0AB" },
      { field: "query", operator: "contains", value: "aced0005" },
      { field: "query", operator: "contains", value: "sr00" },
    ],
  },
  {
    id: "deser-002",
    description: "Block Java gadget chain classes",
    action: "block",
    category: "insecure-deserialization",
    severity: "critical",
    enabled: true,
    tags: ["deserialization", "java", "gadget"],
    conditions: [
      { field: "query", operator: "contains", value: "InvokerTransformer" },
      { field: "query", operator: "contains", value: "ChainedTransformer" },
      { field: "query", operator: "contains", value: "ConstantTransformer" },
      { field: "query", operator: "contains", value: "TemplatesImpl" },
      { field: "query", operator: "contains", value: "org.apache.commons.collections" },
    ],
  },
  {
    id: "deser-003",
    description: "Block Python pickle attacks",
    action: "block",
    category: "insecure-deserialization",
    severity: "critical",
    enabled: true,
    tags: ["deserialization", "python", "pickle"],
    conditions: [
      { field: "query", operator: "contains", value: "__reduce__" },
      { field: "query", operator: "contains", value: "__reduce_ex__" },
      { field: "query", operator: "contains", value: "gASV" },
      { field: "query", operator: "contains", value: "Y3Bvc2l4" },
      { field: "query", operator: "contains", value: "posix.system" },
    ],
  },
  {
    id: "deser-004",
    description: "Block .NET deserialization attacks",
    action: "block",
    category: "insecure-deserialization",
    severity: "critical",
    enabled: true,
    tags: ["deserialization", "dotnet"],
    conditions: [
      { field: "query", operator: "contains", value: "ObjectDataProvider" },
      { field: "query", operator: "contains", value: "ObjectStateFormatter" },
      { field: "query", operator: "contains", value: "BinaryFormatter" },
      { field: "query", operator: "contains", value: "AAEAAAD" },
    ],
  },
  {
    id: "deser-005",
    description: "Block PHP object injection",
    action: "block",
    category: "insecure-deserialization",
    severity: "high",
    enabled: true,
    tags: ["deserialization", "php"],
    conditions: [
      { field: "query", operator: "regex", value: "O:\\d+:\"[^\"]+\"" },
      { field: "query", operator: "contains", value: "__destruct" },
      { field: "query", operator: "contains", value: "__wakeup" },
      { field: "query", operator: "contains", value: "Tzo0Oj" },
    ],
  },
  {
    id: "deser-006",
    description: "Block JSON polymorphic deserialization",
    action: "block",
    category: "insecure-deserialization",
    severity: "high",
    enabled: true,
    tags: ["deserialization", "json", "polymorphic"],
    conditions: [
      { field: "query", operator: "contains", value: "\"@type\"" },
      { field: "query", operator: "contains", value: "\"$type\"" },
      { field: "query", operator: "contains", value: "\"__type\"" },
      { field: "query", operator: "contains", value: "com.sun.org.apache" },
    ],
  },
  {
    id: "deser-007",
    description: "Block YAML code execution",
    action: "block",
    category: "insecure-deserialization",
    severity: "critical",
    enabled: true,
    tags: ["deserialization", "yaml"],
    conditions: [
      { field: "query", operator: "contains", value: "!!python/object" },
      { field: "query", operator: "contains", value: "!!python/module" },
      { field: "query", operator: "contains", value: "!ruby/object" },
      { field: "query", operator: "contains", value: "!!python/object/apply" },
    ],
  },
  {
    id: "deser-008",
    description: "Block XML External Entity (XXE) attacks",
    action: "block",
    category: "insecure-deserialization",
    severity: "critical",
    enabled: true,
    tags: ["deserialization", "xml", "xxe"],
    conditions: [
      { field: "query", operator: "contains", value: "<!ENTITY" },
      { field: "query", operator: "contains", value: "SYSTEM \"file:" },
      { field: "query", operator: "contains", value: "SYSTEM \"http:" },
      { field: "query", operator: "contains", value: "<!DOCTYPE" },
    ],
  },
  {
    id: "deser-009",
    description: "Block suspicious base64-encoded payloads",
    action: "block",
    category: "insecure-deserialization",
    severity: "medium",
    enabled: true,
    tags: ["deserialization", "base64"],
    conditions: [
      { field: "query", operator: "contains", value: "TVNGVFRDRw" }, // .NET pattern
      { field: "query", operator: "contains", value: "QklOQVJZU" }, // BINARY pattern
      { field: "query", operator: "contains", value: "gAJjcG9z" }, // Python pattern
    ],
  },
  {
    id: "deser-010",
    description: "Block dangerous code execution patterns",
    action: "block",
    category: "insecure-deserialization",
    severity: "critical",
    enabled: true,
    tags: ["deserialization", "code-execution"],
    conditions: [
      { field: "query", operator: "contains", value: "Runtime.getRuntime" },
      { field: "query", operator: "contains", value: "ProcessBuilder" },
      { field: "query", operator: "contains", value: "os.system" },
      { field: "query", operator: "contains", value: "subprocess.Popen" },
      { field: "query", operator: "contains", value: "exec(" },
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
  "xss",
  "insecure-deserialization",
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
