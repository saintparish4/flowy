import type { WAFRule, WAFResult } from './types';
import { WAF_RULES, createWAFConfig, type EnhancedWAFRule } from './waf-config';
import { getDebugLogger, WAFDebug, type DebugLogger } from './debug';

// Global WAF configuration instance
const wafConfig = createWAFConfig();

// Debug mode flag - can be set via environment or headers
let debugModeEnabled = false;

/**
 * Enable or disable WAF debug mode
 */
export function setWAFDebugMode(enabled: boolean): void {
  debugModeEnabled = enabled;
}

/**
 * Get current debug mode status
 */
export function isWAFDebugEnabled(): boolean {
  return debugModeEnabled;
}

/**
 * Evaluate a WAF condition with detailed debugging
 */
function evaluateCondition(
  condition: WAFRule['conditions'][0],
  request: Request,
  url: URL,
  logger?: DebugLogger,
  ruleId?: string,
  traceId?: string
): boolean {
  let fieldValue = '';
  let fieldSource = '';

  switch (condition.field) {
    case 'path':
      fieldValue = url.pathname;
      fieldSource = 'URL pathname';
      break;
    case 'query':
      fieldValue = url.search;
      fieldSource = 'URL query string';
      break;
    case 'user-agent':
      fieldValue = request.headers.get('User-Agent') || '';
      fieldSource = 'User-Agent header';
      break;
    case 'host':
      fieldValue = url.hostname;
      fieldSource = 'URL hostname';
      break;
    default:
      if (logger && debugModeEnabled) {
        logger.warn('waf-condition', `Unknown field type: ${condition.field}`, {
          ruleId,
          field: condition.field,
        }, traceId);
      }
      return false;
  }

  // Convert to lowercase for case-insensitive matching
  const originalFieldValue = fieldValue;
  fieldValue = fieldValue.toLowerCase();
  const conditionValue = condition.value.toLowerCase();

  let matched = false;

  switch (condition.operator) {
    case 'equals':
      matched = fieldValue === conditionValue;
      break;
    case 'contains':
      matched = fieldValue.includes(conditionValue);
      break;
    case 'starts-with':
      matched = fieldValue.startsWith(conditionValue);
      break;
    case 'ends-with':
      matched = fieldValue.endsWith(conditionValue);
      break;
    case 'regex':
      try {
        matched = new RegExp(conditionValue).test(fieldValue);
      } catch (e) {
        if (logger && debugModeEnabled) {
          logger.error('waf-condition', `Invalid regex pattern`, {
            ruleId,
            pattern: condition.value,
            error: String(e),
          }, traceId);
        }
        matched = false;
      }
      break;
    default:
      if (logger && debugModeEnabled) {
        logger.warn('waf-condition', `Unknown operator: ${condition.operator}`, {
          ruleId,
          operator: condition.operator,
        }, traceId);
      }
      return false;
  }

  // Log condition evaluation
  if (logger && debugModeEnabled) {
    WAFDebug.conditionEvaluated(
      logger,
      ruleId || 'unknown',
      condition,
      originalFieldValue,
      matched,
      traceId
    );
  }

  return matched;
}

/**
 * Check if request matches any WAF rules with comprehensive debugging
 */
export function checkWAF(request: Request, traceId?: string): WAFResult {
  const startTime = performance.now();
  const url = new URL(request.url);
  const enabledRules = wafConfig.getEnabledRules();
  let rulesEvaluated = 0;

  // Get debug logger if debug mode is enabled
  const logger = debugModeEnabled ? getDebugLogger() : undefined;
  
  // Extract trace ID from request headers if not provided
  const requestTraceId = traceId || request.headers.get('X-Trace-ID') || undefined;

  if (logger && debugModeEnabled) {
    logger.info('waf', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', undefined, requestTraceId);
    logger.info('waf', 'Starting WAF evaluation', {
      url: url.pathname + url.search,
      method: request.method,
      totalRules: enabledRules.length,
      userAgent: request.headers.get('User-Agent')?.slice(0, 50),
    }, requestTraceId);
    logger.startTiming('waf-total', requestTraceId);
  }

  // Log request details for debugging
  if (logger && debugModeEnabled) {
    logger.debug('waf', 'Request details for WAF evaluation', {
      pathname: url.pathname,
      search: url.search,
      searchDecoded: decodeURIComponent(url.search),
      userAgent: request.headers.get('User-Agent'),
      contentType: request.headers.get('Content-Type'),
      method: request.method,
    }, requestTraceId);
  }

  for (const rule of enabledRules) {
    rulesEvaluated++;
    
    if (logger && debugModeEnabled) {
      WAFDebug.ruleEvaluationStart(logger, rule.id, requestTraceId);
      logger.trace('waf-rule', `Evaluating rule`, {
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        action: rule.action,
        conditionsCount: rule.conditions.length,
        description: rule.description,
      }, requestTraceId);
    }

    // Check if any condition matches (OR logic)
    let matchedCondition: WAFRule['conditions'][0] | undefined;
    const matched = rule.conditions.some(condition => {
      const conditionMatched = evaluateCondition(
        condition, 
        request, 
        url, 
        logger, 
        rule.id, 
        requestTraceId
      );
      if (conditionMatched) {
        matchedCondition = condition;
      }
      return conditionMatched;
    });

    if (logger && debugModeEnabled) {
      WAFDebug.ruleEvaluationEnd(logger, rule.id, matched, requestTraceId, {
        matchedCondition: matchedCondition ? {
          field: matchedCondition.field,
          operator: matchedCondition.operator,
          value: matchedCondition.value,
        } : undefined,
      });
    }

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
        if (logger && debugModeEnabled) {
          logger.endTiming('waf-total', requestTraceId);
          WAFDebug.requestBlocked(logger, rule.id, rule.description, requestTraceId, {
            category: rule.category,
            severity: rule.severity,
            matchedCondition: matchedCondition ? {
              field: matchedCondition.field,
              operator: matchedCondition.operator,
              pattern: matchedCondition.value,
            } : undefined,
            rulesEvaluated,
            checkDuration: `${checkDuration.toFixed(3)}ms`,
          });
          
          WAFDebug.summary(logger, {
            blocked: true,
            ruleId: rule.id,
            reason: rule.description,
            rulesEvaluated,
            totalDuration: checkDuration,
          }, requestTraceId);
          
          logger.info('waf', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', undefined, requestTraceId);
        }
        return result;
      }
      
      if (rule.action === 'challenge') {
        if (logger && debugModeEnabled) {
          logger.info('waf', `Challenge triggered (not blocking)`, {
            ruleId: rule.id,
            reason: rule.description,
          }, requestTraceId);
        }
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
  
  if (logger && debugModeEnabled) {
    logger.endTiming('waf-total', requestTraceId);
    WAFDebug.requestAllowed(logger, rulesEvaluated, checkDuration, requestTraceId);
    
    WAFDebug.summary(logger, {
      blocked: false,
      rulesEvaluated,
      totalDuration: checkDuration,
    }, requestTraceId);
    
    logger.info('waf', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', undefined, requestTraceId);
  }
  
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
      ...(debugModeEnabled && {
        debug: {
          rulesEvaluated: result.timing?.rulesEvaluated,
          checkDuration: result.timing?.checkDuration,
        },
      }),
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

/**
 * Debug: Analyze why a request would or wouldn't be blocked
 */
export function analyzeRequest(request: Request): {
  wouldBeBlocked: boolean;
  matchingRules: Array<{
    rule: EnhancedWAFRule;
    matchedConditions: Array<{
      condition: WAFRule['conditions'][0];
      fieldValue: string;
    }>;
  }>;
  checkedRules: Array<{
    rule: EnhancedWAFRule;
    conditionResults: Array<{
      condition: WAFRule['conditions'][0];
      fieldValue: string;
      matched: boolean;
    }>;
  }>;
} {
  const url = new URL(request.url);
  const enabledRules = wafConfig.getEnabledRules();
  
  const matchingRules: Array<{
    rule: EnhancedWAFRule;
    matchedConditions: Array<{
      condition: WAFRule['conditions'][0];
      fieldValue: string;
    }>;
  }> = [];
  
  const checkedRules: Array<{
    rule: EnhancedWAFRule;
    conditionResults: Array<{
      condition: WAFRule['conditions'][0];
      fieldValue: string;
      matched: boolean;
    }>;
  }> = [];

  for (const rule of enabledRules) {
    const conditionResults: Array<{
      condition: WAFRule['conditions'][0];
      fieldValue: string;
      matched: boolean;
    }> = [];
    
    const matchedConditions: Array<{
      condition: WAFRule['conditions'][0];
      fieldValue: string;
    }> = [];

    for (const condition of rule.conditions) {
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
      }

      const matched = evaluateCondition(condition, request, url);
      
      conditionResults.push({
        condition,
        fieldValue,
        matched,
      });

      if (matched) {
        matchedConditions.push({
          condition,
          fieldValue,
        });
      }
    }

    checkedRules.push({
      rule,
      conditionResults,
    });

    if (matchedConditions.length > 0) {
      matchingRules.push({
        rule,
        matchedConditions,
      });
    }
  }

  const wouldBeBlocked = matchingRules.some(m => m.rule.action === 'block');

  return {
    wouldBeBlocked,
    matchingRules,
    checkedRules,
  };
}

/**
 * Generate a detailed WAF analysis report for a request
 */
export function generateWAFAnalysisReport(request: Request): string {
  const analysis = analyzeRequest(request);
  const url = new URL(request.url);
  
  const lines: string[] = [
    '╔════════════════════════════════════════════════════════════════════════╗',
    '║                     WAF REQUEST ANALYSIS REPORT                        ║',
    '╚════════════════════════════════════════════════════════════════════════╝',
    '',
    '┌─ Request Details ──────────────────────────────────────────────────────┐',
    `│ URL:        ${url.pathname}${url.search}`.padEnd(75) + '│',
    `│ Method:     ${request.method}`.padEnd(75) + '│',
    `│ User-Agent: ${(request.headers.get('User-Agent') || 'N/A').slice(0, 55)}`.padEnd(75) + '│',
    '└─────────────────────────────────────────────────────────────────────────┘',
    '',
    `┌─ Result: ${analysis.wouldBeBlocked ? '🚫 WOULD BE BLOCKED' : '✅ WOULD BE ALLOWED'} ${'─'.repeat(50)}┐`,
    '',
  ];

  if (analysis.matchingRules.length > 0) {
    lines.push('┌─ Matching Rules ────────────────────────────────────────────────────────┐');
    analysis.matchingRules.forEach(({ rule, matchedConditions }) => {
      lines.push(`│ [${rule.action.toUpperCase()}] ${rule.id}: ${rule.description.slice(0, 50)}`.padEnd(75) + '│');
      lines.push(`│   Category: ${rule.category} | Severity: ${rule.severity}`.padEnd(75) + '│');
      matchedConditions.forEach(({ condition, fieldValue }) => {
        lines.push(`│   └─ ${condition.field} ${condition.operator} "${condition.value}"`.padEnd(75) + '│');
        lines.push(`│      Matched value: "${fieldValue.slice(0, 50)}"`.padEnd(75) + '│');
      });
      lines.push('│'.padEnd(75) + '│');
    });
    lines.push('└─────────────────────────────────────────────────────────────────────────┘');
  } else {
    lines.push('┌─ No Matching Rules ─────────────────────────────────────────────────────┐');
    lines.push('│ No WAF rules matched this request.'.padEnd(75) + '│');
    lines.push('└─────────────────────────────────────────────────────────────────────────┘');
  }

  lines.push('');
  lines.push(`Total rules evaluated: ${analysis.checkedRules.length}`);
  
  // Show which conditions came close to matching
  const nearMatches = analysis.checkedRules
    .filter(r => r.conditionResults.some(c => !c.matched))
    .map(r => ({
      rule: r.rule,
      unmatched: r.conditionResults.filter(c => !c.matched),
    }))
    .slice(0, 5);

  if (nearMatches.length > 0 && !analysis.wouldBeBlocked) {
    lines.push('');
    lines.push('┌─ Sample Unmatched Conditions (first 5 rules) ───────────────────────────┐');
    nearMatches.forEach(({ rule, unmatched }) => {
      lines.push(`│ ${rule.id}: ${rule.description.slice(0, 55)}`.padEnd(75) + '│');
      unmatched.slice(0, 2).forEach(({ condition, fieldValue }) => {
        lines.push(`│   Expected: ${condition.field} ${condition.operator} "${condition.value.slice(0, 30)}"`.padEnd(75) + '│');
        lines.push(`│   Actual:   "${fieldValue.slice(0, 50)}"`.padEnd(75) + '│');
      });
    });
    lines.push('└─────────────────────────────────────────────────────────────────────────┘');
  }

  return lines.join('\n');
}
