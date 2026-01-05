import type { WAFRule, WAFResult } from './types';
import { WAF_RULES, createWAFConfig, type EnhancedWAFRule } from './waf-config';

// Global WAF configuration instance
const wafConfig = createWAFConfig();

/**
 * Evaluate a WAF condition
 */
function evaluateCondition(
  condition: WAFRule['conditions'][0],
  request: Request,
  url: URL
): boolean {
  let fieldValue = '';

  switch (condition.field) {
    case 'path':
      fieldValue = url.pathname;
      break;
    case 'query':
      fieldValue = url.search;
      break;
    case 'user-agent':
      fieldValue = request.headers.get('User-Agent') || '';
      break;
    case 'host':
      fieldValue = url.hostname;
      break;
    default:
      return false;
  }

  fieldValue = fieldValue.toLowerCase();
  const value = condition.value.toLowerCase();

  switch (condition.operator) {
    case 'equals':
      return fieldValue === value;
    case 'contains':
      return fieldValue.includes(value);
    case 'starts-with':
      return fieldValue.startsWith(value);
    case 'ends-with':
      return fieldValue.endsWith(value);
    case 'regex':
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
  const enabledRules = wafConfig.getEnabledRules();
  let rulesEvaluated = 0;

  for (const rule of enabledRules) {
    rulesEvaluated++;
    
    // Check if any condition matches (OR logic)
    const matched = rule.conditions.some(condition => 
      evaluateCondition(condition, request, url)
    );

    if (matched) {
      const checkDuration = performance.now() - startTime;
      
      // Record the check
      const result: WAFResult = {
        blocked: rule.action === 'block',
        rule,
        reason: rule.description,
        timing: {
          checkDuration,
          rulesEvaluated,
        },
      };
      
      wafConfig.recordCheck(result, checkDuration);
      
      // Rule matched, return action
      if (rule.action === 'block') {
        return result;
      }
      
      if (rule.action === 'challenge') {
        // In a real implementation, this would trigger Turnstile
        console.log(`[WAF] Challenge triggered: ${rule.description}`);
      }
    }
  }

  const checkDuration = performance.now() - startTime;
  
  // No rules matched, allow request
  const result: WAFResult = {
    blocked: false,
    timing: {
      checkDuration,
      rulesEvaluated,
    },
  };
  
  wafConfig.recordCheck(result, checkDuration);
  
  return result;
}

/**
 * Create a WAF block response
 */
export function createWAFBlockResponse(result: WAFResult): Response {
  return new Response(
    JSON.stringify({
      success: false,
      error: 'Request blocked by WAF',
      rule: result.rule?.id,
      reason: result.reason,
    }),
    {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        'X-WAF-Block': 'true',
        'X-WAF-Rule': result.rule?.id || 'unknown',
      },
    }
  );
}

/**
 * Get all WAF rules (for debugging/monitoring)
 */
export function getWAFRules(): EnhancedWAFRule[] {
  return wafConfig.getEnabledRules();
}

/**
 * Get WAF statistics
 */
export function getWAFStats() {
  return wafConfig.getStats();
}

/**
 * Get WAF configuration instance
 */
export function getWAFConfig() {
  return wafConfig;
}

/**
 * Add a custom WAF rule (runtime configuration)
 */
export function addWAFRule(rule: EnhancedWAFRule): void {
  wafConfig.addCustomRule(rule);
}
