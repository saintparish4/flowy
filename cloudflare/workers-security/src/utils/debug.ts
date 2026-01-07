/**
 * Comprehensive Debug Logging Utility
 * Provides detailed logging for WAF, latency analysis, and security layer debugging
 */

// Debug log levels
export type DebugLevel = 'off' | 'error' | 'warn' | 'info' | 'debug' | 'trace';

// Debug categories for filtering
export type DebugCategory = 
  | 'waf'           // WAF rule evaluation
  | 'waf-rule'      // Individual WAF rule matching
  | 'waf-condition' // WAF condition evaluation
  | 'rate-limit'    // Rate limiting
  | 'burst'         // Burst detection
  | 'turnstile'     // Turnstile verification
  | 'latency'       // Latency measurements
  | 'request'       // Request handling
  | 'security'      // General security
  | 'timing';       // Timing breakdowns

// Debug entry structure
export interface DebugEntry {
  timestamp: number;
  level: DebugLevel;
  category: DebugCategory;
  message: string;
  data?: Record<string, any>;
  traceId?: string;
  duration?: number;
}

// Timing checkpoint
export interface TimingCheckpoint {
  name: string;
  timestamp: number;
  elapsed: number;    // Time since previous checkpoint
  total: number;      // Time since start
  metadata?: Record<string, any>;
}

// Debug configuration
export interface DebugConfig {
  enabled: boolean;
  level: DebugLevel;
  categories: DebugCategory[] | 'all';
  includeTimestamps: boolean;
  includeStackTraces: boolean;
  maxEntries: number;
  outputToConsole: boolean;
}

// Default configuration
const DEFAULT_CONFIG: DebugConfig = {
  enabled: true,
  level: 'debug',
  categories: 'all',
  includeTimestamps: true,
  includeStackTraces: false,
  maxEntries: 1000,
  outputToConsole: true,
};

// Log level hierarchy
const LEVEL_HIERARCHY: Record<DebugLevel, number> = {
  'off': 0,
  'error': 1,
  'warn': 2,
  'info': 3,
  'debug': 4,
  'trace': 5,
};

/**
 * Debug Logger Class
 * Collects and manages debug logs with timing information
 */
export class DebugLogger {
  private config: DebugConfig;
  private entries: DebugEntry[] = [];
  private timingCheckpoints: Map<string, TimingCheckpoint[]> = new Map();
  private startTimes: Map<string, number> = new Map();

  constructor(config?: Partial<DebugConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Check if a log should be recorded based on level and category
   */
  private shouldLog(level: DebugLevel, category: DebugCategory): boolean {
    if (!this.config.enabled) return false;
    if (LEVEL_HIERARCHY[level] > LEVEL_HIERARCHY[this.config.level]) return false;
    if (this.config.categories !== 'all' && !this.config.categories.includes(category)) return false;
    return true;
  }

  /**
   * Add a debug entry
   */
  log(
    level: DebugLevel,
    category: DebugCategory,
    message: string,
    data?: Record<string, any>,
    traceId?: string
  ): void {
    if (!this.shouldLog(level, category)) return;

    const entry: DebugEntry = {
      timestamp: Date.now(),
      level,
      category,
      message,
      data,
      traceId,
    };

    this.entries.push(entry);

    // Trim old entries
    if (this.entries.length > this.config.maxEntries) {
      this.entries = this.entries.slice(-this.config.maxEntries);
    }

    // Output to console if enabled
    if (this.config.outputToConsole) {
      this.consoleOutput(entry);
    }
  }

  /**
   * Console output with formatting
   */
  private consoleOutput(entry: DebugEntry): void {
    const timestamp = this.config.includeTimestamps 
      ? `[${new Date(entry.timestamp).toISOString()}]` 
      : '';
    const prefix = `${timestamp}[${entry.level.toUpperCase()}][${entry.category}]`;
    const traceInfo = entry.traceId ? `[${entry.traceId.slice(0, 8)}]` : '';
    
    const message = `${prefix}${traceInfo} ${entry.message}`;
    
    switch (entry.level) {
      case 'error':
        console.error(message, entry.data || '');
        break;
      case 'warn':
        console.warn(message, entry.data || '');
        break;
      case 'trace':
        console.debug(message, entry.data || '');
        break;
      default:
        console.log(message, entry.data || '');
    }
  }

  // Convenience methods
  error(category: DebugCategory, message: string, data?: Record<string, any>, traceId?: string): void {
    this.log('error', category, message, data, traceId);
  }

  warn(category: DebugCategory, message: string, data?: Record<string, any>, traceId?: string): void {
    this.log('warn', category, message, data, traceId);
  }

  info(category: DebugCategory, message: string, data?: Record<string, any>, traceId?: string): void {
    this.log('info', category, message, data, traceId);
  }

  debug(category: DebugCategory, message: string, data?: Record<string, any>, traceId?: string): void {
    this.log('debug', category, message, data, traceId);
  }

  trace(category: DebugCategory, message: string, data?: Record<string, any>, traceId?: string): void {
    this.log('trace', category, message, data, traceId);
  }

  /**
   * Start a timing measurement
   */
  startTiming(key: string, traceId?: string): void {
    const startKey = traceId ? `${traceId}:${key}` : key;
    this.startTimes.set(startKey, performance.now());
    
    if (traceId) {
      if (!this.timingCheckpoints.has(traceId)) {
        this.timingCheckpoints.set(traceId, []);
      }
    }
  }

  /**
   * End a timing measurement and log it
   */
  endTiming(key: string, traceId?: string, metadata?: Record<string, any>): number {
    const startKey = traceId ? `${traceId}:${key}` : key;
    const startTime = this.startTimes.get(startKey);
    
    if (!startTime) {
      this.warn('timing', `No start time found for timing key: ${key}`, { traceId });
      return 0;
    }

    const endTime = performance.now();
    const duration = endTime - startTime;
    
    this.startTimes.delete(startKey);

    // Record checkpoint
    if (traceId) {
      const checkpoints = this.timingCheckpoints.get(traceId) || [];
      const lastCheckpoint = checkpoints[checkpoints.length - 1];
      const totalStart = checkpoints[0]?.timestamp || startTime;
      
      checkpoints.push({
        name: key,
        timestamp: endTime,
        elapsed: duration,
        total: endTime - totalStart,
        metadata,
      });
      
      this.timingCheckpoints.set(traceId, checkpoints);
    }

    this.debug('timing', `${key} completed`, {
      duration: `${duration.toFixed(3)}ms`,
      ...metadata,
    }, traceId);

    return duration;
  }

  /**
   * Get timing checkpoints for a trace
   */
  getTimingCheckpoints(traceId: string): TimingCheckpoint[] {
    return this.timingCheckpoints.get(traceId) || [];
  }

  /**
   * Generate timing report for a trace
   */
  generateTimingReport(traceId: string): string {
    const checkpoints = this.getTimingCheckpoints(traceId);
    if (checkpoints.length === 0) {
      return `No timing data for trace: ${traceId}`;
    }

    const lines: string[] = [
      '═'.repeat(70),
      `TIMING REPORT - Trace: ${traceId}`,
      '═'.repeat(70),
      '',
      'Checkpoint'.padEnd(30) + 'Duration (ms)'.padStart(15) + 'Total (ms)'.padStart(15),
      '─'.repeat(70),
    ];

    checkpoints.forEach(cp => {
      lines.push(
        cp.name.padEnd(30) + 
        cp.elapsed.toFixed(3).padStart(15) + 
        cp.total.toFixed(3).padStart(15)
      );
    });

    const totalDuration = checkpoints[checkpoints.length - 1]?.total || 0;
    lines.push('─'.repeat(70));
    lines.push('TOTAL'.padEnd(30) + ''.padStart(15) + totalDuration.toFixed(3).padStart(15));
    lines.push('═'.repeat(70));

    return lines.join('\n');
  }

  /**
   * Get all entries for a trace
   */
  getEntriesForTrace(traceId: string): DebugEntry[] {
    return this.entries.filter(e => e.traceId === traceId);
  }

  /**
   * Get entries by category
   */
  getEntriesByCategory(category: DebugCategory): DebugEntry[] {
    return this.entries.filter(e => e.category === category);
  }

  /**
   * Generate full debug report
   */
  generateReport(traceId?: string): string {
    const entries = traceId 
      ? this.getEntriesForTrace(traceId) 
      : this.entries;

    const lines: string[] = [
      '═'.repeat(80),
      traceId ? `DEBUG REPORT - Trace: ${traceId}` : 'DEBUG REPORT - All Entries',
      '═'.repeat(80),
      '',
    ];

    // Group by category
    const byCategory = new Map<DebugCategory, DebugEntry[]>();
    entries.forEach(entry => {
      if (!byCategory.has(entry.category)) {
        byCategory.set(entry.category, []);
      }
      byCategory.get(entry.category)!.push(entry);
    });

    byCategory.forEach((catEntries, category) => {
      lines.push(`\n[${'CATEGORY: ' + category.toUpperCase()}]`);
      lines.push('─'.repeat(70));
      
      catEntries.forEach(entry => {
        const time = new Date(entry.timestamp).toISOString().split('T')[1];
        const levelIcon = {
          'error': '❌',
          'warn': '⚠️',
          'info': 'ℹ️',
          'debug': '🔍',
          'trace': '📝',
          'off': '',
        }[entry.level];
        
        lines.push(`  ${time} ${levelIcon} ${entry.message}`);
        if (entry.data) {
          Object.entries(entry.data).forEach(([key, value]) => {
            lines.push(`    └─ ${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}`);
          });
        }
      });
    });

    // Add timing report if available
    if (traceId) {
      lines.push('\n');
      lines.push(this.generateTimingReport(traceId));
    }

    return lines.join('\n');
  }

  /**
   * Export entries as JSON
   */
  exportJSON(): string {
    return JSON.stringify({
      config: this.config,
      entries: this.entries,
      timingCheckpoints: Object.fromEntries(this.timingCheckpoints),
    }, null, 2);
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.entries = [];
    this.timingCheckpoints.clear();
    this.startTimes.clear();
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<DebugConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get current configuration
   */
  getConfig(): DebugConfig {
    return { ...this.config };
  }
}

// Global debug logger instance
let globalLogger: DebugLogger | null = null;

/**
 * Get or create the global debug logger
 */
export function getDebugLogger(config?: Partial<DebugConfig>): DebugLogger {
  if (!globalLogger) {
    globalLogger = new DebugLogger(config);
  } else if (config) {
    globalLogger.updateConfig(config);
  }
  return globalLogger;
}

/**
 * Reset the global debug logger
 */
export function resetDebugLogger(): void {
  if (globalLogger) {
    globalLogger.clear();
  }
  globalLogger = null;
}

/**
 * WAF-specific debug helpers
 */
export const WAFDebug = {
  ruleEvaluationStart: (logger: DebugLogger, ruleId: string, traceId?: string) => {
    logger.startTiming(`waf-rule-${ruleId}`, traceId);
    logger.trace('waf-rule', `Evaluating rule: ${ruleId}`, { ruleId }, traceId);
  },

  ruleEvaluationEnd: (
    logger: DebugLogger, 
    ruleId: string, 
    matched: boolean, 
    traceId?: string,
    matchDetails?: Record<string, any>
  ) => {
    const duration = logger.endTiming(`waf-rule-${ruleId}`, traceId);
    logger.debug('waf-rule', `Rule ${ruleId} evaluation complete`, {
      ruleId,
      matched,
      duration: `${duration.toFixed(3)}ms`,
      ...matchDetails,
    }, traceId);
  },

  conditionEvaluated: (
    logger: DebugLogger,
    ruleId: string,
    condition: { field: string; operator: string; value: string },
    fieldValue: string,
    matched: boolean,
    traceId?: string
  ) => {
    logger.trace('waf-condition', `Condition evaluated`, {
      ruleId,
      field: condition.field,
      operator: condition.operator,
      pattern: condition.value,
      actualValue: fieldValue.length > 100 ? fieldValue.slice(0, 100) + '...' : fieldValue,
      matched,
    }, traceId);
  },

  requestBlocked: (
    logger: DebugLogger,
    ruleId: string,
    reason: string,
    traceId?: string,
    details?: Record<string, any>
  ) => {
    logger.warn('waf', `🚫 Request BLOCKED by WAF`, {
      ruleId,
      reason,
      ...details,
    }, traceId);
  },

  requestAllowed: (
    logger: DebugLogger,
    rulesEvaluated: number,
    totalDuration: number,
    traceId?: string
  ) => {
    logger.info('waf', `✅ Request ALLOWED by WAF`, {
      rulesEvaluated,
      totalDuration: `${totalDuration.toFixed(3)}ms`,
    }, traceId);
  },

  summary: (
    logger: DebugLogger,
    result: {
      blocked: boolean;
      ruleId?: string;
      reason?: string;
      rulesEvaluated: number;
      totalDuration: number;
    },
    traceId?: string
  ) => {
    const lines = [
      '┌─────────────────────────────────────────────────────────────────┐',
      `│  WAF EVALUATION SUMMARY                                         │`,
      '├─────────────────────────────────────────────────────────────────┤',
      `│  Result: ${result.blocked ? '🚫 BLOCKED' : '✅ ALLOWED'}`.padEnd(66) + '│',
      `│  Rules Evaluated: ${result.rulesEvaluated}`.padEnd(66) + '│',
      `│  Duration: ${result.totalDuration.toFixed(3)}ms`.padEnd(66) + '│',
    ];
    
    if (result.blocked && result.ruleId) {
      lines.push(`│  Blocking Rule: ${result.ruleId}`.padEnd(66) + '│');
      lines.push(`│  Reason: ${result.reason?.slice(0, 50) || 'N/A'}`.padEnd(66) + '│');
    }
    
    lines.push('└─────────────────────────────────────────────────────────────────┘');
    
    logger.info('waf', lines.join('\n'), undefined, traceId);
  },
};

/**
 * Latency-specific debug helpers
 */
export const LatencyDebug = {
  requestStart: (logger: DebugLogger, traceId: string, url: string, method: string) => {
    logger.startTiming('request-total', traceId);
    logger.info('latency', `Request started: ${method} ${url}`, { method, url }, traceId);
  },

  securityCheckStart: (logger: DebugLogger, checkName: string, traceId: string) => {
    logger.startTiming(`security-${checkName}`, traceId);
    logger.debug('latency', `Security check started: ${checkName}`, undefined, traceId);
  },

  securityCheckEnd: (logger: DebugLogger, checkName: string, traceId: string, result?: any) => {
    const duration = logger.endTiming(`security-${checkName}`, traceId);
    logger.debug('latency', `Security check completed: ${checkName}`, { 
      duration: `${duration.toFixed(3)}ms`,
      result: result?.blocked !== undefined ? (result.blocked ? 'blocked' : 'allowed') : undefined,
    }, traceId);
    return duration;
  },

  handlerStart: (logger: DebugLogger, handler: string, traceId: string) => {
    logger.startTiming(`handler-${handler}`, traceId);
    logger.debug('latency', `Handler started: ${handler}`, undefined, traceId);
  },

  handlerEnd: (logger: DebugLogger, handler: string, traceId: string, statusCode?: number) => {
    const duration = logger.endTiming(`handler-${handler}`, traceId);
    logger.debug('latency', `Handler completed: ${handler}`, {
      duration: `${duration.toFixed(3)}ms`,
      statusCode,
    }, traceId);
    return duration;
  },

  requestEnd: (logger: DebugLogger, traceId: string, statusCode: number) => {
    const duration = logger.endTiming('request-total', traceId);
    logger.info('latency', `Request completed`, {
      totalDuration: `${duration.toFixed(3)}ms`,
      statusCode,
    }, traceId);
    return duration;
  },

  breakdown: (logger: DebugLogger, traceId: string) => {
    const checkpoints = logger.getTimingCheckpoints(traceId);
    if (checkpoints.length === 0) return;

    const breakdown: Record<string, string> = {};
    checkpoints.forEach(cp => {
      breakdown[cp.name] = `${cp.elapsed.toFixed(3)}ms`;
    });

    logger.info('latency', 'Latency breakdown', breakdown, traceId);
  },
};

/**
 * Create a debug-enabled response that includes debug data
 * Note: This version does not modify body to avoid async complexity
 */
export function createDebugResponse(
  response: Response,
  logger: DebugLogger,
  traceId: string,
  _includeInBody: boolean = false
): Response {
  const headers = new Headers(response.headers);
  
  // Add debug timing header
  const checkpoints = logger.getTimingCheckpoints(traceId);
  const timings = checkpoints.map(cp => `${cp.name};dur=${cp.elapsed.toFixed(1)}`).join(', ');
  if (timings) {
    headers.set('Server-Timing', timings);
  }

  // Add debug entry count
  const entries = logger.getEntriesForTrace(traceId);
  headers.set('X-Debug-Entries', entries.length.toString());

  // Note: includeInBody is disabled to avoid async Response handling complexity
  // Debug data is available via Server-Timing header instead

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

