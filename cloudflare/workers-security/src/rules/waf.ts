import type { WAFRule, WAFResult } from '../types';
import { WAF_RULES, createWAFConfig, type EnhancedWAFRule } from './waf-config';
import { getDebugLogger, WAFDebug, type DebugLogger } from '../utils/debug';
import { checkDeserializationPatterns, getHighestSeverity } from './deserialization-patterns';

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
  requestBody: string,
  logger?: DebugLogger,
  ruleId?: string,
  traceId?: string
): boolean {
  // For 'query' field, check both query string AND body (XSS can be in either)
  // For 'body' field, only check body
  let fieldsToCheck: Array<{ value: string; source: string }> = [];

  switch (condition.field) {
    case 'path':
      fieldsToCheck = [{ value: url.pathname, source: 'URL pathname' }];
      break;
    case 'query':
      // Check both query string AND body for XSS patterns
      fieldsToCheck = [
        { value: url.search, source: 'URL query string' },
        { value: requestBody, source: 'Request body' },
      ];
      break;
    case 'user-agent':
      fieldsToCheck = [{ value: request.headers.get('User-Agent') || '', source: 'User-Agent header' }];
      break;
    case 'host':
      fieldsToCheck = [{ value: url.hostname, source: 'URL hostname' }];
      break;
    case 'body':
      // Only check body content
      fieldsToCheck = [{ value: requestBody, source: 'Request body' }];
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

  // Check each field value against the condition
  const conditionValue = condition.value.toLowerCase();
  let matched = false;
  let matchedField: { value: string; source: string } | undefined;

  for (const field of fieldsToCheck) {
    const originalFieldValue = field.value;
    const fieldValue = field.value.toLowerCase();

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
          matched = new RegExp(conditionValue, 'i').test(fieldValue);
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
        matched = false;
    }

    if (matched) {
      matchedField = field;
      break; // Found a match, stop checking other fields
    }
  }

  // Use the matched field for logging, or first field if no match
  const logFieldValue = matchedField?.value || fieldsToCheck[0]?.value || '';
  const logFieldSource = matchedField?.source || fieldsToCheck[0]?.source || 'unknown';

  // Log condition evaluation
  if (logger && debugModeEnabled) {
    WAFDebug.conditionEvaluated(
      logger,
      ruleId || 'unknown',
      condition,
      logFieldValue,
      matched,
      traceId
    );
    
    if (matched && matchedField) {
      logger.debug('waf-condition', `Pattern matched in ${matchedField.source}`, {
        ruleId,
        field: condition.field,
        operator: condition.operator,
        pattern: condition.value,
        source: matchedField.source,
      }, traceId);
    }
  }

  return matched;
}

/**
 * Check if request matches any WAF rules with comprehensive debugging
 * Focused on XSS and insecure deserialization detection
 * Now supports POST body scanning
 */
export async function checkWAF(request: Request, traceId?: string): Promise<WAFResult> {
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
    logger.info('waf', 'Starting WAF evaluation (XSS + Deserialization)', {
      url: url.pathname + url.search,
      method: request.method,
      totalRules: enabledRules.length,
      userAgent: request.headers.get('User-Agent')?.slice(0, 50),
    }, requestTraceId);
    logger.startTiming('waf-total', requestTraceId);
  }

  // Read request body for POST/PUT/PATCH requests (clone to avoid consuming original)
  let requestBody = '';
  const contentType = request.headers.get('Content-Type') || '';
  const isBodyRequest = ['POST', 'PUT', 'PATCH'].includes(request.method);
  
  if (isBodyRequest) {
    try {
      const clonedRequest = request.clone();
      if (contentType.includes('application/json')) {
        const json = await clonedRequest.json().catch(() => null);
        requestBody = json ? JSON.stringify(json) : '';
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        requestBody = await clonedRequest.text().catch(() => '');
      } else if (contentType.includes('text/') || contentType.includes('application/xml')) {
        requestBody = await clonedRequest.text().catch(() => '');
      } else {
        // Try to read as text for other content types
        requestBody = await clonedRequest.text().catch(() => '');
      }
    } catch (error) {
      if (logger && debugModeEnabled) {
        logger.warn('waf', 'Failed to read request body', {
          error: String(error),
        }, requestTraceId);
      }
      requestBody = '';
    }
  }

  // Log request details for debugging
  if (logger && debugModeEnabled) {
    logger.debug('waf', 'Request details for WAF evaluation', {
      pathname: url.pathname,
      search: url.search,
      searchDecoded: decodeURIComponent(url.search),
      userAgent: request.headers.get('User-Agent'),
      contentType,
      method: request.method,
      hasBody: isBodyRequest,
      bodyLength: requestBody.length,
      bodyPreview: requestBody.slice(0, 200),
    }, requestTraceId);
  }

  // Check query string for deserialization patterns
  const queryString = url.search;
  if (queryString.length > 10) {
    const deserCheck = checkDeserializationPatterns(queryString, { checkBase64: true });
    if (deserCheck.detected) {
      const severity = getHighestSeverity(deserCheck.matches);
      if (severity === 'critical' || severity === 'high') {
        const checkDuration = performance.now() - startTime;
        const matchedPattern = deserCheck.matches[0]?.pattern;
        
        if (logger && debugModeEnabled) {
          logger.warn('waf', `Deserialization attack pattern detected in query string`, {
            patternId: matchedPattern?.id,
            patternName: matchedPattern?.name,
            severity,
          }, requestTraceId);
        }
        
        return {
          blocked: true,
          rule: {
            id: matchedPattern?.id || 'deser-pattern',
            description: matchedPattern?.description || 'Deserialization attack detected',
            action: 'block',
            conditions: [],
          },
          reason: matchedPattern?.description || 'Insecure deserialization pattern detected in query string',
          timing: {
            checkDuration,
            rulesEvaluated: 0,
          },
        };
      }
    }
  }

  // Check POST body for deserialization patterns
  if (requestBody.length > 10) {
    const deserCheck = checkDeserializationPatterns(requestBody, { checkBase64: true });
    if (deserCheck.detected) {
      const severity = getHighestSeverity(deserCheck.matches);
      if (severity === 'critical' || severity === 'high') {
        const checkDuration = performance.now() - startTime;
        const matchedPattern = deserCheck.matches[0]?.pattern;
        
        if (logger && debugModeEnabled) {
          logger.warn('waf', `Deserialization attack pattern detected in POST body`, {
            patternId: matchedPattern?.id,
            patternName: matchedPattern?.name,
            severity,
          }, requestTraceId);
        }
        
        return {
          blocked: true,
          rule: {
            id: matchedPattern?.id || 'deser-pattern',
            description: matchedPattern?.description || 'Deserialization attack detected',
            action: 'block',
            conditions: [],
          },
          reason: matchedPattern?.description || 'Insecure deserialization pattern detected in POST body',
          timing: {
            checkDuration,
            rulesEvaluated: 0,
          },
        };
      }
    }
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
        requestBody,
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
  deserializationCheck?: {
    detected: boolean;
    matches: Array<{ patternId: string; patternName: string }>;
  };
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

  // Check deserialization patterns
  const queryString = url.search;
  let deserializationCheck;
  if (queryString.length > 10) {
    const deserCheck = checkDeserializationPatterns(queryString, { checkBase64: true });
    deserializationCheck = {
      detected: deserCheck.detected,
      matches: deserCheck.matches.map(m => ({
        patternId: m.pattern.id,
        patternName: m.pattern.name,
      })),
    };
  }

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

      // analyzeRequest is synchronous and doesn't read body, pass empty string
      const matched = evaluateCondition(condition, request, url, '');
      
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

  const wouldBeBlocked = matchingRules.some(m => m.rule.action === 'block') ||
                         (deserializationCheck?.detected === true && deserializationCheck.matches.length > 0);

  return {
    wouldBeBlocked,
    matchingRules,
    checkedRules,
    deserializationCheck,
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
    '║            WAF REQUEST ANALYSIS REPORT (XSS + Deserialization)         ║',
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

  // Deserialization check results
  if (analysis.deserializationCheck?.detected) {
    lines.push('┌─ Deserialization Patterns Detected ─────────────────────────────────────┐');
    analysis.deserializationCheck.matches.forEach(m => {
      lines.push(`│ [BLOCK] ${m.patternId}: ${m.patternName.slice(0, 55)}`.padEnd(75) + '│');
    });
    lines.push('└─────────────────────────────────────────────────────────────────────────┘');
    lines.push('');
  }

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
  } else if (!analysis.deserializationCheck?.detected) {
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
