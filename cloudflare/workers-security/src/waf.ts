import type { WAFRule, WAFResult } from "./types";

/**
 * Simulated WAF rules
 * In production, these would be configured in Cloudflare Dashboard
 */
const WAF_RULES: WAFRule[] = [
  {
    id: "block-sql-injection",
    description: "Block common SQL injection patterns",
    action: "block",
    conditions: [
      {
        field: "query",
        operator: "contains",
        value: "union select",
      },
      {
        field: "query",
        operator: "contains",
        value: "' or '1'='1",
      },
      {
        field: "query",
        operator: "contains",
        value: "drop table",
      },
    ],
  },
  {
    id: "block-xss",
    description: "Block cross-site scripting attempts",
    action: "block",
    conditions: [
      {
        field: "query",
        operator: "contains",
        value: "<script>",
      },
      {
        field: "query",
        operator: "contains",
        value: "javascript:",
      },
      {
        field: "query",
        operator: "contains",
        value: "onerror=",
      },
    ],
  },
  {
    id: "block-path-traversal",
    description: "Block path traversal attempts",
    action: "block",
    conditions: [
      {
        field: "path",
        operator: "contains",
        value: "../",
      },
      {
        field: "path",
        operator: "contains",
        value: "..\\",
      },
      {
        field: "query",
        operator: "contains",
        value: "../",
      },
      {
        field: "query",
        operator: "contains",
        value: "..\\",
      },
      {
        field: "query",
        operator: "contains",
        value: "/etc/",
      },
      {
        field: "query",
        operator: "contains",
        value: "c:\\",
      },
    ],
  },
  {
    id: "challenge-suspicious-ua",
    description: "Challenge requests with suspicious user agents",
    action: "challenge",
    conditions: [
      {
        field: "user-agent",
        operator: "contains",
        value: "bot",
      },
      {
        field: "user-agent",
        operator: "contains",
        value: "crawler",
      },
      {
        field: "user-agent",
        operator: "equals",
        value: "",
      },
    ],
  },
  {
    id: "block-admin-unauthorized",
    description: "Block access to admin paths without proper authentication",
    action: "block",
    conditions: [
      {
        field: "path",
        operator: "starts-with",
        value: "/admin",
      },
    ],
  },
];

/**
 * Evaluate a WAF condition
 */
function evaluateCondition(
  condition: WAFRule["conditions"][0],
  request: Request,
  url: URL
): boolean {
  let fieldValue = "";

  switch (condition.field) {
    case "path":
      fieldValue = url.pathname;
      break;
    case "query":
      // Decode URL query string to check actual values, not encoded transport format
      try {
        fieldValue = decodeURIComponent(url.search);
      } catch {
        // If decoding fails, use raw value
        fieldValue = url.search;
      }
      break;
    case "user-agent":
      fieldValue = request.headers.get("User-Agent") || "";
      break;
    case "host":
      fieldValue = url.hostname;
      break;
    default:
      return false;
  }

  fieldValue = fieldValue.toLowerCase();
  const value = condition.value.toLowerCase();

  switch (condition.operator) {
    case "equals":
      return fieldValue === value;
    case "contains":
      return fieldValue.includes(value);
    case "starts-with":
      return fieldValue.startsWith(value);
    case "ends-with":
      return fieldValue.endsWith(value);
    case "regex":
      try {
        return new RegExp(value).test(fieldValue);
      } catch {
        return false;
      }
    default:
      return false;
  }
}

/**
 * Check if request matches any WAF rules
 */
export function checkWAF(request: Request): WAFResult {
  const startTime = performance.now();
  const url = new URL(request.url);
  let rulesEvaluated = 0;

  for (const rule of WAF_RULES) {
    rulesEvaluated++;
    // Check if any condition matches (OR logic)
    const matched = rule.conditions.some((condition) =>
      evaluateCondition(condition, request, url)
    );

    if (matched) {
      // Rule matched, return action
      if (rule.action === "block") {
        return {
          blocked: true,
          rule,
          reason: rule.description,
          timing: {
            checkDuration: performance.now() - startTime,
            rulesEvaluated,
          },
        };
      }

      if (rule.action === "challenge") {
        // In a real implementation, this would trigger Turnstile
        // For now, we just log it
        console.log(`[WAF] Challenge triggered: ${rule.description}`);
      }
    }
  }

  // No rules matched, allow request
  return {
    blocked: false,
    timing: {
      checkDuration: performance.now() - startTime,
      rulesEvaluated,
    },
  };
}

/**
 * Create a WAF block response
 */
export function createWAFBlockResponse(result: WAFResult): Response {
  return new Response(
    JSON.stringify({
      success: false,
      error: "Request blocked by WAF",
      rule: result.rule?.id,
      reason: result.reason,
    }),
    {
      status: 403,
      headers: {
        "Content-Type": "application/json",
        "X-WAF-Block": "true",
        "X-WAF-Rule": result.rule?.id || "unknown",
      },
    }
  );
}

/**
 * Get all WAF rules (for debugging/monitoring)
 */
export function getWAFRules(): WAFRule[] {
  return WAF_RULES;
}

/**
 * Add a custom WAF rule (runtime configuration)
 */
export function addWAFRule(rule: WAFRule): void {
  WAF_RULES.push(rule);
}
