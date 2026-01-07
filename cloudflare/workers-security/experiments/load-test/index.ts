#!/usr/bin/env node

// Load Testing Framework
// Generates synthetic traffic to test security controls

import { AttackProfile } from "../profiles/index.js";
import {
  MetricsCollector,
  RequestMetric,
  formatSnapshot,
} from "../metrics/index.js";

export interface LoadTestConfig {
  targetUrl: string;
  profile: AttackProfile;
  experimentId?: string;
  verbose?: boolean;
  realtime?: boolean; // Show realtime metrics
  debug?: boolean;    // Enable debug mode for detailed WAF/latency logging
}

export interface RequestGenerator {
  profile: AttackProfile;
  startTime: number;
  requestsSent: number;
}

interface ResponseData {
  trace?: {
    performance?: {
      rateLimitCheckTime?: number;
      burstCheckTime?: number;
      turnstileCheckTime?: number;
      wafCheckTime?: number;
    };
  };
  __debug?: {
    timing?: Record<string, number>;
    entries?: Array<{
      level: string;
      category: string;
      message: string;
    }>;
  };
}

// Debug log storage for analysis
export interface DebugRequestLog {
  timestamp: number;
  url: string;
  method: string;
  statusCode: number;
  wafBlocked: boolean;
  serverTiming?: Record<string, number>;
  debugEntries?: number;
  traceId?: string;
  wafRule?: string;
  debugData?: ResponseData['__debug'];
}

/**
 * Main load testing class
 */
export class LoadTester {
  private config: LoadTestConfig;
  private metrics: MetricsCollector;
  private experimentId: string;
  private running: boolean = false;
  private abortController?: AbortController;
  private debugLogs: DebugRequestLog[] = [];

  constructor(config: LoadTestConfig) {
    this.config = config;
    this.experimentId = config.experimentId || this.generateExperimentId();
    this.metrics = new MetricsCollector(this.experimentId, config.profile.name);
  }

  /**
   * Generate a unique experiment ID
   */
  private generateExperimentId(): string {
    return `exp-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * Calculate delay based on distribution pattern
   */
  private calculateDelay(generator: RequestGenerator): number {
    const { profile } = generator;
    const elapsed = (Date.now() - generator.startTime) / 1000;
    const baseDelay = 1000 / profile.requestsPerSecond;

    switch (profile.pattern.distribution) {
      case "constant":
        return (
          baseDelay *
          (1 + (Math.random() - 0.5) * (profile.pattern.variance || 0))
        );

      case "linear":
        // Gradually increase rate
        const progress = elapsed / profile.duration;
        const rampFactor = profile.pattern.rampUpTime
          ? Math.min(1, elapsed / profile.pattern.rampUpTime)
          : progress;
        return baseDelay / rampFactor;

      case "exponential":
        // Exponential growth
        const expProgress = elapsed / profile.duration;
        const expFactor = Math.pow(2, expProgress * 5);
        return baseDelay / Math.min(expFactor, 10);

      case "random":
        return baseDelay * (Math.random() * 2);

      case "wave":
        // Sine wave pattern
        const waveProgress = (elapsed / profile.duration) * Math.PI * 2;
        const waveFactor = (Math.sin(waveProgress) + 1) / 2 + 0.5; // 0.5 to 1.5
        return baseDelay / waveFactor;

      default:
        return baseDelay;
    }
  }

  /**
   * Select a request from the profile (round-robin)
   */
  private selectRequest(generator: RequestGenerator) {
    const index = generator.requestsSent % this.config.profile.requests.length;
    return this.config.profile.requests[index];
  }

  /**
   * Parse Server-Timing header
   */
  private parseServerTiming(header: string | null): Record<string, number> | undefined {
    if (!header) return undefined;
    
    const timings: Record<string, number> = {};
    header.split(',').forEach(entry => {
      const match = entry.trim().match(/^([^;]+);dur=(\d+(?:\.\d+)?)/);
      if (match) {
        timings[match[1]] = parseFloat(match[2]);
      }
    });
    
    return Object.keys(timings).length > 0 ? timings : undefined;
  }

  /**
   * Execute a single request
   */
  private async executeRequest(generator: RequestGenerator): Promise<void> {
    const request = this.selectRequest(generator);
    const startTime = Date.now();

    try {
      const url = `${this.config.targetUrl}${request.path}`;
      const headers: Record<string, string> = {
        "X-Experiment-ID": this.experimentId,
        "X-Profile-Name": this.config.profile.name,
        "X-Attack-Type": this.config.profile.type,
        "X-Test-Traffic": "true",
        ...(request.headers || {}),
      };

      // Enable debug mode if configured
      if (this.config.debug) {
        headers["X-Debug-Mode"] = "true";
      }

      // Add Turnstile token if required
      if (request.turnstileToken) {
        headers["CF-Turnstile-Token"] = "load-test-token";
      }

      const options: RequestInit = {
        method: request.method,
        headers,
        signal: this.abortController?.signal,
      };

      if (request.body) {
        options.body = JSON.stringify(request.body);
        headers["Content-Type"] = "application/json";
      }

      const response = await fetch(url, options);
      const endTime = Date.now();
      const latency = endTime - startTime;

      // Parse response to extract security information
      let blocked = false;
      let rateLimited = false;
      let wafBlocked = false;
      let securityTiming: RequestMetric["securityTiming"] = {};
      let debugData: ResponseData['__debug'] | undefined;

      // Extract debug timing from Server-Timing header
      const serverTiming = this.parseServerTiming(response.headers.get('Server-Timing'));

      try {
        const data = (await response.json()) as ResponseData;

        // Check if request was blocked
        blocked = response.status === 403 || response.status === 429;
        rateLimited = response.status === 429;
        wafBlocked = response.headers.get("X-WAF-Block") === "true";

        // Extract security timing if available
        if (data.trace?.performance) {
          securityTiming = {
            rateLimit: data.trace.performance.rateLimitCheckTime,
            burst: data.trace.performance.burstCheckTime,
            turnstile: data.trace.performance.turnstileCheckTime,
            waf: data.trace.performance.wafCheckTime,
          };
        }

        // Extract debug data if available
        if (data.__debug) {
          debugData = data.__debug;
        }
      } catch {
        // Response wasn't JSON or couldn't be parsed
      }

      const metric: RequestMetric = {
        timestamp: startTime,
        traceId: response.headers.get("X-Trace-ID") || "unknown",
        url: request.path,
        method: request.method,
        statusCode: response.status,
        latency,
        blocked,
        rateLimited,
        wafBlocked,
        timing: {
          total: latency,
        },
        securityTiming,
      };

      this.metrics.record(metric);

      // Store debug log if debug mode is enabled
      if (this.config.debug) {
        const debugLog: DebugRequestLog = {
          timestamp: startTime,
          url: request.path,
          method: request.method,
          statusCode: response.status,
          wafBlocked,
          serverTiming,
          debugEntries: parseInt(response.headers.get('X-Debug-Entries') || '0'),
          traceId: response.headers.get("X-Trace-ID") || undefined,
          wafRule: response.headers.get("X-WAF-Rule") || undefined,
          debugData,
        };
        this.debugLogs.push(debugLog);
      }

      if (this.config.verbose) {
        const status = blocked ? "🚫" : response.ok ? "✓" : "✗";
        const wafInfo = wafBlocked ? ` [WAF:${response.headers.get("X-WAF-Rule")}]` : '';
        const serverTimingInfo = serverTiming 
          ? ` [ST: ${Object.entries(serverTiming).map(([k, v]) => `${k}=${v.toFixed(1)}ms`).join(', ')}]` 
          : '';
        console.log(
          `${status} ${request.method} ${request.path} - ${response.status} (${latency}ms)${wafInfo}${serverTimingInfo}`
        );
      }
    } catch (error: any) {
      const endTime = Date.now();
      const latency = endTime - startTime;

      const metric: RequestMetric = {
        timestamp: startTime,
        traceId: "error",
        url: request.path,
        method: request.method,
        statusCode: 0,
        latency,
        blocked: false,
        rateLimited: false,
        wafBlocked: false,
        error: error.message,
      };

      this.metrics.record(metric);

      if (this.config.verbose && error.name !== "AbortError") {
        console.error(
          `✗ ${request.method} ${request.path} - ERROR: ${error.message}`
        );
      }
    }
  }

  /**
   * Generate traffic for a single concurrent worker
   */
  private async generateTraffic(generator: RequestGenerator): Promise<void> {
    const { profile } = this.config;
    const endTime = generator.startTime + profile.duration * 1000;

    while (this.running && Date.now() < endTime) {
      await this.executeRequest(generator);
      generator.requestsSent++;

      // Calculate and wait for next request
      const delay = this.calculateDelay(generator);
      await this.sleep(delay);
    }
  }

  /**
   * Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Display realtime metrics
   */
  private startRealtimeDisplay(): NodeJS.Timeout | undefined {
    if (!this.config.realtime) return undefined;

    return setInterval(() => {
      const snapshot = this.metrics.snapshot(10); // Last 10 seconds
      console.clear();
      console.log(formatSnapshot(snapshot));
    }, 1000);
  }

  /**
   * Run the load test
   */
  async run(): Promise<void> {
    console.log(`\n🚀 Starting Load Test`);
    console.log(`   Experiment ID: ${this.experimentId}`);
    console.log(`   Profile: ${this.config.profile.name}`);
    console.log(`   Target: ${this.config.targetUrl}`);
    console.log(`   Duration: ${this.config.profile.duration}s`);
    console.log(
      `   Request Rate: ${this.config.profile.requestsPerSecond} req/s`
    );
    console.log(`   Concurrency: ${this.config.profile.concurrency}`);
    console.log(
      `   Distribution: ${this.config.profile.pattern.distribution}`
    );
    console.log(`   Debug Mode: ${this.config.debug ? 'ENABLED' : 'disabled'}\n`);

    this.running = true;
    this.abortController = new AbortController();
    this.debugLogs = [];

    const generator: RequestGenerator = {
      profile: this.config.profile,
      startTime: Date.now(),
      requestsSent: 0,
    };

    // Start realtime display if enabled
    const displayInterval = this.startRealtimeDisplay();

    try {
      // Create concurrent workers
      const workers = Array.from(
        { length: this.config.profile.concurrency },
        () => this.generateTraffic({ ...generator })
      );

      // Wait for all workers to complete
      await Promise.all(workers);

      console.log("\n✓ Load test completed\n");
    } catch (error: any) {
      console.error(`\n✗ Load test failed: ${error.message}\n`);
    } finally {
      this.running = false;
      if (displayInterval) {
        clearInterval(displayInterval);
      }
    }
  }

  /**
   * Stop the load test
   */
  stop(): void {
    console.log("\n⚠ Stopping load test...\n");
    this.running = false;
    this.abortController?.abort();
  }

  /**
   * Get the metrics collector
   */
  getMetrics(): MetricsCollector {
    return this.metrics;
  }

  /**
   * Get debug logs
   */
  getDebugLogs(): DebugRequestLog[] {
    return this.debugLogs;
  }

  /**
   * Generate WAF debug analysis
   */
  generateWAFDebugReport(): string {
    const lines: string[] = [
      '═'.repeat(80),
      'WAF DEBUG ANALYSIS REPORT',
      '═'.repeat(80),
      '',
    ];

    // Group by URL
    const byUrl = new Map<string, DebugRequestLog[]>();
    this.debugLogs.forEach(log => {
      if (!byUrl.has(log.url)) {
        byUrl.set(log.url, []);
      }
      byUrl.get(log.url)!.push(log);
    });

    lines.push(`Total requests logged: ${this.debugLogs.length}`);
    lines.push(`Unique URLs: ${byUrl.size}`);
    lines.push('');

    // WAF block summary
    const wafBlocked = this.debugLogs.filter(l => l.wafBlocked);
    const wafAllowed = this.debugLogs.filter(l => !l.wafBlocked);
    
    lines.push('┌─ WAF Block Summary ──────────────────────────────────────────────────────┐');
    lines.push(`│ WAF Blocked: ${wafBlocked.length} (${(wafBlocked.length / this.debugLogs.length * 100).toFixed(1)}%)`.padEnd(75) + '│');
    lines.push(`│ WAF Allowed: ${wafAllowed.length} (${(wafAllowed.length / this.debugLogs.length * 100).toFixed(1)}%)`.padEnd(75) + '│');
    lines.push('└──────────────────────────────────────────────────────────────────────────┘');
    lines.push('');

    // URL breakdown
    lines.push('┌─ URL Breakdown ──────────────────────────────────────────────────────────┐');
    byUrl.forEach((logs, url) => {
      const blocked = logs.filter(l => l.wafBlocked).length;
      const total = logs.length;
      const blockRate = (blocked / total * 100).toFixed(1);
      lines.push(`│ ${url.padEnd(40)} ${total.toString().padStart(5)} reqs, ${blocked.toString().padStart(4)} blocked (${blockRate}%)`.padEnd(75) + '│');
    });
    lines.push('└──────────────────────────────────────────────────────────────────────────┘');
    lines.push('');

    // WAF rule breakdown
    const byRule = new Map<string, number>();
    wafBlocked.forEach(log => {
      const rule = log.wafRule || 'unknown';
      byRule.set(rule, (byRule.get(rule) || 0) + 1);
    });

    if (byRule.size > 0) {
      lines.push('┌─ WAF Rule Breakdown ─────────────────────────────────────────────────────┐');
      Array.from(byRule.entries())
        .sort((a, b) => b[1] - a[1])
        .forEach(([rule, count]) => {
          lines.push(`│ ${rule.padEnd(30)} ${count.toString().padStart(5)} blocks`.padEnd(75) + '│');
        });
      lines.push('└──────────────────────────────────────────────────────────────────────────┘');
    } else {
      lines.push('┌─ WAF Rule Breakdown ─────────────────────────────────────────────────────┐');
      lines.push('│ No WAF blocks recorded'.padEnd(75) + '│');
      lines.push('└──────────────────────────────────────────────────────────────────────────┘');
    }
    lines.push('');

    // Latency breakdown from server timing
    const timingLogs = this.debugLogs.filter(l => l.serverTiming);
    if (timingLogs.length > 0) {
      lines.push('┌─ Server Timing Analysis (from X-Debug-Mode) ─────────────────────────────┐');
      
      const timingKeys = new Set<string>();
      timingLogs.forEach(l => Object.keys(l.serverTiming!).forEach(k => timingKeys.add(k)));
      
      timingKeys.forEach(key => {
        const values = timingLogs
          .map(l => l.serverTiming![key])
          .filter(v => v !== undefined);
        
        if (values.length > 0) {
          const avg = values.reduce((a, b) => a + b, 0) / values.length;
          const max = Math.max(...values);
          const min = Math.min(...values);
          
          lines.push(`│ ${key.padEnd(25)} avg: ${avg.toFixed(2)}ms, min: ${min.toFixed(2)}ms, max: ${max.toFixed(2)}ms`.padEnd(75) + '│');
        }
      });
      
      lines.push('└──────────────────────────────────────────────────────────────────────────┘');
    }
    lines.push('');

    // Sample blocked requests
    if (wafBlocked.length > 0) {
      lines.push('┌─ Sample WAF Blocked Requests ───────────────────────────────────────────┐');
      wafBlocked.slice(0, 5).forEach(log => {
        lines.push(`│ ${log.method} ${log.url.slice(0, 50)} -> Rule: ${log.wafRule || 'unknown'}`.padEnd(75) + '│');
      });
      lines.push('└──────────────────────────────────────────────────────────────────────────┘');
    }
    lines.push('');

    // Sample allowed requests that might have been expected to be blocked
    if (wafAllowed.length > 0) {
      lines.push('┌─ Sample WAF Allowed Requests ───────────────────────────────────────────┐');
      wafAllowed.slice(0, 10).forEach(log => {
        lines.push(`│ ${log.method} ${log.url.slice(0, 60)} -> ${log.statusCode}`.padEnd(75) + '│');
      });
      lines.push('└──────────────────────────────────────────────────────────────────────────┘');
    }

    lines.push('');
    lines.push('═'.repeat(80));

    return lines.join('\n');
  }

  /**
   * Generate latency debug report
   */
  generateLatencyDebugReport(): string {
    const lines: string[] = [
      '═'.repeat(80),
      'LATENCY DEBUG ANALYSIS REPORT',
      '═'.repeat(80),
      '',
    ];

    const timingLogs = this.debugLogs.filter(l => l.serverTiming);
    
    if (timingLogs.length === 0) {
      lines.push('No server timing data available.');
      lines.push('Enable debug mode (-d/--debug) to collect latency data.');
      return lines.join('\n');
    }

    lines.push(`Requests with timing data: ${timingLogs.length}`);
    lines.push('');

    // Aggregate timing by operation
    const timingKeys = new Set<string>();
    timingLogs.forEach(l => Object.keys(l.serverTiming!).forEach(k => timingKeys.add(k)));

    const timingStats: Record<string, { values: number[]; avg: number; min: number; max: number; p50: number; p95: number; p99: number }> = {};

    timingKeys.forEach(key => {
      const values = timingLogs
        .map(l => l.serverTiming![key])
        .filter(v => v !== undefined)
        .sort((a, b) => a - b);
      
      if (values.length > 0) {
        const percentile = (p: number) => values[Math.floor(values.length * p / 100)] || values[values.length - 1];
        
        timingStats[key] = {
          values,
          avg: values.reduce((a, b) => a + b, 0) / values.length,
          min: values[0],
          max: values[values.length - 1],
          p50: percentile(50),
          p95: percentile(95),
          p99: percentile(99),
        };
      }
    });

    lines.push('┌─ Timing Statistics ──────────────────────────────────────────────────────┐');
    lines.push('│ Operation'.padEnd(25) + 'Avg (ms)'.padStart(12) + 'P50'.padStart(10) + 'P95'.padStart(10) + 'P99'.padStart(10) + 'Max'.padStart(10) + ' │');
    lines.push('├' + '─'.repeat(76) + '┤');
    
    Object.entries(timingStats)
      .sort((a, b) => b[1].avg - a[1].avg)
      .forEach(([key, stats]) => {
        lines.push(
          '│ ' + 
          key.padEnd(23) + 
          stats.avg.toFixed(2).padStart(12) + 
          stats.p50.toFixed(2).padStart(10) + 
          stats.p95.toFixed(2).padStart(10) + 
          stats.p99.toFixed(2).padStart(10) + 
          stats.max.toFixed(2).padStart(10) + 
          ' │'
        );
      });
    
    lines.push('└──────────────────────────────────────────────────────────────────────────┘');
    lines.push('');

    // Identify slow operations
    const slowThreshold = 100; // ms
    const slowOps = Object.entries(timingStats).filter(([_, stats]) => stats.p95 > slowThreshold);
    
    if (slowOps.length > 0) {
      lines.push('┌─ ⚠️ Slow Operations (P95 > 100ms) ────────────────────────────────────────┐');
      slowOps.forEach(([key, stats]) => {
        lines.push(`│ ${key}: P95=${stats.p95.toFixed(2)}ms, Max=${stats.max.toFixed(2)}ms`.padEnd(75) + '│');
      });
      lines.push('└──────────────────────────────────────────────────────────────────────────┘');
    }
    lines.push('');

    // Timing breakdown by status code
    const byStatus = new Map<number, number[]>();
    timingLogs.forEach(log => {
      if (!byStatus.has(log.statusCode)) {
        byStatus.set(log.statusCode, []);
      }
      const total = Object.values(log.serverTiming!).reduce((a, b) => a + b, 0);
      byStatus.get(log.statusCode)!.push(total);
    });

    lines.push('┌─ Timing by Status Code ──────────────────────────────────────────────────┐');
    Array.from(byStatus.entries())
      .sort((a, b) => a[0] - b[0])
      .forEach(([status, values]) => {
        const avg = values.reduce((a, b) => a + b, 0) / values.length;
        const max = Math.max(...values);
        lines.push(`│ ${status.toString().padEnd(5)} ${values.length.toString().padStart(6)} reqs, avg: ${avg.toFixed(2)}ms, max: ${max.toFixed(2)}ms`.padEnd(75) + '│');
      });
    lines.push('└──────────────────────────────────────────────────────────────────────────┘');

    lines.push('');
    lines.push('═'.repeat(80));

    return lines.join('\n');
  }

  /**
   * Generate and display the final report
   */
  report(): void {
    const { profile } = this.config;
    const report = this.metrics.report(
      profile.expected.blockRate ? profile.expected.blockRate * 100 : undefined,
      profile.expected.avgLatency
    );

    console.log("\n" + "=".repeat(80));
    console.log("LOAD TEST REPORT");
    console.log("=".repeat(80));
    console.log(`\nExperiment ID: ${report.experimentId}`);
    console.log(`Profile: ${report.profileName}`);
    console.log(`Duration: ${report.duration.toFixed(2)}s`);
    console.log(`Start: ${new Date(report.startTime).toISOString()}`);
    console.log(`End: ${new Date(report.endTime).toISOString()}`);

    console.log(formatSnapshot(report.summary));

    if (report.comparison) {
      console.log("\nComparison with Expected Results:");
      console.log("─".repeat(60));
      console.log(
        `Block Rate:  Expected ${report.comparison.expectedBlockRate.toFixed(
          1
        )}%, Got ${report.comparison.actualBlockRate.toFixed(1)}%`
      );
      if (report.comparison.expectedLatency > 0) {
        console.log(
          `Latency:     Expected ${report.comparison.expectedLatency.toFixed(
            0
          )}ms, Got ${report.comparison.actualLatency.toFixed(0)}ms`
        );
      }
      console.log(
        `Result:      ${report.comparison.passed ? "✓ PASSED" : "✗ FAILED"}`
      );
    }

    if (report.errors.length > 0) {
      console.log("\nTop Errors:");
      console.log("─".repeat(60));
      report.errors.slice(0, 5).forEach((e) => {
        console.log(`  ${e.error}: ${e.count} (${e.percentage.toFixed(1)}%)`);
      });
    }

    // If debug mode was enabled, show debug reports
    if (this.config.debug && this.debugLogs.length > 0) {
      console.log("\n");
      console.log(this.generateWAFDebugReport());
      console.log("\n");
      console.log(this.generateLatencyDebugReport());
    }

    console.log("\n" + "=".repeat(80) + "\n");
  }
}

/**
 * Create a load tester with the specified profile
 */
export function createLoadTest(
  targetUrl: string,
  profile: AttackProfile,
  options?: Partial<LoadTestConfig>
): LoadTester {
  return new LoadTester({
    targetUrl,
    profile,
    ...options,
  });
}
