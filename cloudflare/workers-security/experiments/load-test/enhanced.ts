#!/usr/bin/env node

/**
 * Enhanced Load Testing Framework
 * Fixes traffic timing issues, adds warmup, and improves request distribution
 */

import { AttackProfile } from "../profiles/index.js";
import { MetricsCollector, RequestMetric } from "../metrics/index.js";

export interface EnhancedLoadTestConfig {
  targetUrl: string;
  profile: AttackProfile;
  experimentId?: string;
  verbose?: boolean;
  realtime?: boolean;
  warmupDuration?: number; // seconds of warmup before real test
  cooldownDuration?: number; // seconds of cooldown after test
  strictTiming?: boolean; // Enforce precise timing vs best-effort
}

interface RequestSchedule {
  timestamp: number;
  requestIndex: number;
}

/**
 * Enhanced Load Tester with improved timing and distribution
 */
export class EnhancedLoadTester {
  private config: EnhancedLoadTestConfig;
  private metrics: MetricsCollector;
  private warmupMetrics?: MetricsCollector;
  private experimentId: string;
  private running: boolean = false;
  private abortController?: AbortController;
  private requestSchedule: RequestSchedule[] = [];

  constructor(config: EnhancedLoadTestConfig) {
    this.config = {
      warmupDuration: 5, // Default 5 second warmup
      cooldownDuration: 2, // Default 2 second cooldown
      strictTiming: true, // Default to strict timing
      ...config,
    };
    this.experimentId = config.experimentId || this.generateExperimentId();
    this.metrics = new MetricsCollector(this.experimentId, config.profile.name);

    if (this.config.warmupDuration! > 0) {
      this.warmupMetrics = new MetricsCollector(
        `${this.experimentId}-warmup`,
        `${config.profile.name} (Warmup)`
      );
    }
  }

  /**
   * Generate a unique experiment ID
   */
  private generateExperimentId(): string {
    return `exp-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * Pre-calculate request schedule for precise timing
   * This ensures requests are evenly distributed across the test duration
   */
  private calculateRequestSchedule(): RequestSchedule[] {
    const { profile } = this.config;
    const schedule: RequestSchedule[] = [];

    const totalRequests = Math.floor(
      profile.requestsPerSecond * profile.duration
    );
    const baseInterval = 1000 / profile.requestsPerSecond; // ms between requests

    let currentTime = 0;

    for (let i = 0; i < totalRequests; i++) {
      // Calculate delay based on distribution pattern
      const progress = i / totalRequests;
      let delay = baseInterval;

      switch (profile.pattern.distribution) {
        case "constant":
          // Add variance around base interval
          const variance = profile.pattern.variance || 0;
          delay = baseInterval * (1 + (Math.random() - 0.5) * variance * 2);
          break;

        case "linear":
          // Linearly increase rate over time
          const rampProgress = profile.pattern.rampUpTime
            ? Math.min(1, currentTime / 1000 / profile.pattern.rampUpTime)
            : progress;
          delay = baseInterval / (rampProgress * 0.5 + 0.5); // Ramp from 0.5x to 1x rate
          break;

        case "exponential":
          // Exponential increase
          const expFactor = Math.pow(2, progress * 3); // 2^(0 to 3)
          delay = baseInterval / Math.min(expFactor, 8);
          break;

        case "random":
          // Random delay
          delay = baseInterval * Math.random() * 2;
          break;

        case "wave":
          // Sine wave
          const waveProgress = progress * Math.PI * 2;
          const waveFactor = (Math.sin(waveProgress) + 1) / 2 + 0.5; // 0.5 to 1.5
          delay = baseInterval / waveFactor;
          break;
      }

      currentTime += delay;
      schedule.push({
        timestamp: Math.floor(currentTime),
        requestIndex: i % profile.requests.length,
      });
    }

    return schedule;
  }

  /**
   * Execute a single request with timing enforcement
   */
  private async executeRequest(
    requestTemplate: any,
    isWarmup: boolean = false
  ): Promise<RequestMetric | null> {
    const startTime = Date.now();

    try {
      const url = `${this.config.targetUrl}${requestTemplate.path}`;
      const headers: Record<string, string> = {
        "X-Experiment-ID": this.experimentId,
        "X-Profile-Name": this.config.profile.name,
        "X-Attack-Type": this.config.profile.type,
        "X-Test-Traffic": "true",
        "X-Phase": isWarmup ? "warmup" : "test",
        ...(requestTemplate.headers || {}),
      };

      // Add Turnstile token if required
      if (requestTemplate.turnstileToken) {
        headers["CF-Turnstile-Token"] = "load-test-token";
      }

      const options: RequestInit = {
        method: requestTemplate.method,
        headers,
        signal: this.abortController?.signal,
      };

      if (requestTemplate.body) {
        options.body = JSON.stringify(requestTemplate.body);
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

      try {
        const data = await response.json() as any;

        blocked = response.status === 403 || response.status === 429;
        rateLimited = response.status === 429;
        wafBlocked = response.headers.get("X-WAF-Block") === "true";

        if (data?.trace?.performance) {
          securityTiming = {
            rateLimit: data.trace.performance.rateLimitCheckTime,
            turnstile: data.trace.performance.turnstileCheckTime,
            waf: data.trace.performance.wafCheckTime,
          };
        }
      } catch {
        // Response wasn't JSON or couldn't be parsed
      }

      const metric: RequestMetric = {
        timestamp: startTime,
        traceId: response.headers.get("X-Trace-ID") || "unknown",
        url: requestTemplate.path,
        method: requestTemplate.method,
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

      if (this.config.verbose) {
        const phase = isWarmup ? "[WARMUP]" : "[TEST]";
        const status = blocked ? "🚫" : response.ok ? "✓" : "✗";
        console.log(
          `${phase} ${status} ${requestTemplate.method} ${requestTemplate.path} - ${response.status} (${latency}ms)`
        );
      }

      return metric;
    } catch (error: any) {
      if (error.name === "AbortError") {
        return null; // Graceful shutdown
      }

      const endTime = Date.now();
      const latency = endTime - startTime;

      const metric: RequestMetric = {
        timestamp: startTime,
        traceId: "error",
        url: requestTemplate.path,
        method: requestTemplate.method,
        statusCode: 0,
        latency,
        blocked: false,
        rateLimited: false,
        wafBlocked: false,
        error: error.message,
      };

      if (this.config.verbose && !isWarmup) {
        console.error(
          `[ERROR] ${requestTemplate.method} ${requestTemplate.path} - ${error.message}`
        );
      }

      return metric;
    }
  }

  /**
   * Run warmup phase
   */
  private async runWarmup(): Promise<void> {
    if (!this.config.warmupDuration || this.config.warmupDuration <= 0) {
      return;
    }

    console.log(`\n🔥 Warmup Phase (${this.config.warmupDuration}s)`);
    console.log("   Warming up connections and establishing baseline...\n");

    const warmupProfile = {
      ...this.config.profile,
      duration: this.config.warmupDuration,
      requestsPerSecond: Math.min(
        this.config.profile.requestsPerSecond / 2,
        10
      ), // Lower rate for warmup
    };

    const warmupRequests = Math.floor(
      warmupProfile.requestsPerSecond * warmupProfile.duration
    );
    const warmupInterval = 1000 / warmupProfile.requestsPerSecond;

    for (let i = 0; i < warmupRequests && this.running; i++) {
      const requestTemplate =
        this.config.profile.requests[i % this.config.profile.requests.length];
      const metric = await this.executeRequest(requestTemplate, true);

      if (metric && this.warmupMetrics) {
        this.warmupMetrics.record(metric);
      }

      await this.sleep(warmupInterval);
    }

    console.log("✓ Warmup complete\n");
  }

  /**
   * Run scheduled requests with precise timing
   */
  private async runScheduledRequests(): Promise<void> {
    const startTime = Date.now();
    const promises: Promise<void>[] = [];
    let completedRequests = 0;

    // Group requests by timestamp for concurrent execution
    const timestampGroups = new Map<number, number[]>();
    this.requestSchedule.forEach(({ timestamp, requestIndex }) => {
      if (!timestampGroups.has(timestamp)) {
        timestampGroups.set(timestamp, []);
      }
      timestampGroups.get(timestamp)!.push(requestIndex);
    });

    // Execute requests at scheduled times
    for (const [timestamp, requestIndices] of Array.from(
      timestampGroups.entries()
    ).sort((a, b) => a[0] - b[0])) {
      if (!this.running) break;

      // Wait until scheduled time
      const elapsed = Date.now() - startTime;
      const waitTime = timestamp - elapsed;

      if (waitTime > 0) {
        await this.sleep(waitTime);
      } else if (this.config.strictTiming && waitTime < -100) {
        // We're falling behind schedule by >100ms
        console.warn(`⚠ Running ${Math.abs(waitTime)}ms behind schedule`);
      }

      // Execute all requests scheduled for this timestamp
      for (const requestIndex of requestIndices) {
        const requestTemplate = this.config.profile.requests[requestIndex];

        const promise = this.executeRequest(requestTemplate, false).then(
          (metric) => {
            if (metric) {
              this.metrics.record(metric);
              completedRequests++;

              // Show progress every 10% or every second for high-volume tests
              const progress =
                (completedRequests / this.requestSchedule.length) * 100;
              if (
                completedRequests %
                  Math.max(1, Math.floor(this.requestSchedule.length / 10)) ===
                0
              ) {
                if (!this.config.verbose && !this.config.realtime) {
                  console.log(
                    `Progress: ${progress.toFixed(0)}% (${completedRequests}/${
                      this.requestSchedule.length
                    } requests)`
                  );
                }
              }
            }
          }
        );

        promises.push(promise);
      }
    }

    // Wait for all requests to complete
    await Promise.all(promises);
  }

  /**
   * Run cooldown phase
   */
  private async runCooldown(): Promise<void> {
    if (!this.config.cooldownDuration || this.config.cooldownDuration <= 0) {
      return;
    }

    console.log(`\n❄️  Cooldown Phase (${this.config.cooldownDuration}s)`);
    console.log("   Allowing system to stabilize...\n");

    await this.sleep(this.config.cooldownDuration * 1000);

    console.log("✓ Cooldown complete\n");
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
      const snapshot = this.metrics.snapshot(5); // Last 5 seconds

      console.clear();
      console.log("=".repeat(80));
      console.log(`Real-time Metrics - ${this.config.profile.name}`);
      console.log("=".repeat(80));
      console.log(`\nExperiment: ${this.experimentId}`);
      console.log(
        `Elapsed: ${Math.floor(
          (Date.now() - this.metrics["startTime"]) / 1000
        )}s / ${this.config.profile.duration}s`
      );
      console.log(`\nLast 5 seconds:`);
      console.log(`  Requests: ${snapshot.totalRequests}`);
      console.log(`  Rate: ${snapshot.requestRate.toFixed(1)} req/s`);
      console.log(
        `  Success: ${snapshot.successfulRequests} (${(
          (snapshot.successfulRequests / snapshot.totalRequests) *
          100
        ).toFixed(1)}%)`
      );
      console.log(
        `  Blocked: ${snapshot.blockedRequests} (${snapshot.blockRate.toFixed(
          1
        )}%)`
      );
      console.log(`  Latency P95: ${snapshot.latency.p95.toFixed(1)}ms`);
      console.log(`  Latency P99: ${snapshot.latency.p99.toFixed(1)}ms`);
    }, 1000);
  }

  /**
   * Run the enhanced load test
   */
  async run(): Promise<void> {
    console.log(`\n${"=".repeat(80)}`);
    console.log("🚀 ENHANCED LOAD TEST");
    console.log("=".repeat(80));
    console.log(`\nExperiment ID: ${this.experimentId}`);
    console.log(`Profile: ${this.config.profile.name}`);
    console.log(`Target: ${this.config.targetUrl}`);
    console.log(`\nTest Configuration:`);
    console.log(`  Duration: ${this.config.profile.duration}s`);
    console.log(
      `  Request Rate: ${this.config.profile.requestsPerSecond} req/s`
    );
    console.log(`  Distribution: ${this.config.profile.pattern.distribution}`);
    console.log(`  Warmup: ${this.config.warmupDuration}s`);
    console.log(`  Cooldown: ${this.config.cooldownDuration}s`);
    console.log(`  Strict Timing: ${this.config.strictTiming ? "Yes" : "No"}`);

    this.running = true;
    this.abortController = new AbortController();

    // Calculate request schedule
    console.log(`\n📋 Calculating request schedule...`);
    this.requestSchedule = this.calculateRequestSchedule();
    console.log(`   Scheduled ${this.requestSchedule.length} requests`);

    try {
      // Phase 1: Warmup
      if (this.config.warmupDuration! > 0) {
        await this.runWarmup();
      }

      // Phase 2: Main test
      console.log(`\n⚡ Test Phase (${this.config.profile.duration}s)`);
      console.log("   Executing load test...\n");

      const displayInterval = this.startRealtimeDisplay();

      const testStart = Date.now();
      await this.runScheduledRequests();
      const testEnd = Date.now();

      if (displayInterval) {
        clearInterval(displayInterval);
      }

      const actualDuration = (testEnd - testStart) / 1000;
      const expectedDuration = this.config.profile.duration;
      const timingDrift = Math.abs(actualDuration - expectedDuration);

      console.log(`\n✓ Test complete`);
      console.log(`   Expected duration: ${expectedDuration}s`);
      console.log(`   Actual duration: ${actualDuration.toFixed(2)}s`);
      console.log(
        `   Timing drift: ${timingDrift.toFixed(2)}s (${(
          (timingDrift / expectedDuration) *
          100
        ).toFixed(1)}%)`
      );

      // Phase 3: Cooldown
      if (this.config.cooldownDuration! > 0) {
        await this.runCooldown();
      }
    } catch (error: any) {
      console.error(`\n✗ Load test failed: ${error.message}\n`);
      throw error;
    } finally {
      this.running = false;
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
   * Get warmup metrics if available
   */
  getWarmupMetrics(): MetricsCollector | undefined {
    return this.warmupMetrics;
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
    console.log("ENHANCED LOAD TEST REPORT");
    console.log("=".repeat(80));
    console.log(`\nExperiment ID: ${report.experimentId}`);
    console.log(`Profile: ${report.profileName}`);
    console.log(`Duration: ${report.duration.toFixed(2)}s`);
    console.log(`Start: ${new Date(report.startTime).toISOString()}`);
    console.log(`End: ${new Date(report.endTime).toISOString()}`);

    // Summary
    const s = report.summary;
    console.log(`\n${"─".repeat(80)}`);
    console.log("SUMMARY");
    console.log("─".repeat(80));
    console.log(`\nRequests:`);
    console.log(`  Total:        ${s.totalRequests}`);
    console.log(
      `  Successful:   ${s.successfulRequests} (${(
        (s.successfulRequests / s.totalRequests) *
        100
      ).toFixed(1)}%)`
    );
    console.log(
      `  Failed:       ${s.failedRequests} (${s.errorRate.toFixed(1)}%)`
    );
    console.log(
      `  Blocked:      ${s.blockedRequests} (${s.blockRate.toFixed(1)}%)`
    );
    console.log(`  Rate Limited: ${s.rateLimitedRequests}`);
    console.log(`  WAF Blocked:  ${s.wafBlockedRequests}`);

    console.log(`\nRates:`);
    console.log(`  Request Rate: ${s.requestRate.toFixed(2)} req/s`);
    console.log(`  Error Rate:   ${s.errorRate.toFixed(2)}%`);
    console.log(`  Block Rate:   ${s.blockRate.toFixed(2)}%`);

    console.log(`\nLatency (ms):`);
    console.log(`  Min:    ${s.latency.min.toFixed(2)}`);
    console.log(`  Mean:   ${s.latency.mean.toFixed(2)}`);
    console.log(`  Median: ${s.latency.median.toFixed(2)}`);
    console.log(`  P95:    ${s.latency.p95.toFixed(2)}`);
    console.log(`  P99:    ${s.latency.p99.toFixed(2)}`);
    console.log(`  Max:    ${s.latency.max.toFixed(2)}`);
    console.log(`  StdDev: ${s.latency.stdDev.toFixed(2)}`);

    if (report.comparison) {
      console.log(`\n${"─".repeat(80)}`);
      console.log("COMPARISON WITH EXPECTED RESULTS");
      console.log("─".repeat(80));
      console.log(
        `\nBlock Rate:  Expected ${report.comparison.expectedBlockRate.toFixed(
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
        `\nResult:      ${report.comparison.passed ? "✓ PASSED" : "✗ FAILED"}`
      );
    }

    if (report.errors.length > 0) {
      console.log(`\n${"─".repeat(80)}`);
      console.log("TOP ERRORS");
      console.log("─".repeat(80));
      report.errors.slice(0, 5).forEach((e) => {
        console.log(`  ${e.error}: ${e.count} (${e.percentage.toFixed(1)}%)`);
      });
    }

    // Warmup summary if available
    if (this.warmupMetrics) {
      const warmupReport = this.warmupMetrics.report();
      console.log(`\n${"─".repeat(80)}`);
      console.log("WARMUP PHASE SUMMARY");
      console.log("─".repeat(80));
      console.log(`  Requests: ${warmupReport.summary.totalRequests}`);
      console.log(
        `  Success Rate: ${(
          (warmupReport.summary.successfulRequests /
            warmupReport.summary.totalRequests) *
          100
        ).toFixed(1)}%`
      );
      console.log(
        `  Mean Latency: ${warmupReport.summary.latency.mean.toFixed(2)}ms`
      );
    }

    console.log("\n" + "=".repeat(80) + "\n");
  }
}

/**
 * Create an enhanced load test
 */
export function createEnhancedLoadTest(
  targetUrl: string,
  profile: AttackProfile,
  options?: Partial<EnhancedLoadTestConfig>
): EnhancedLoadTester {
  return new EnhancedLoadTester({
    targetUrl,
    profile,
    ...options,
  });
}
