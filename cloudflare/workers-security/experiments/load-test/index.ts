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
      turnstileCheckTime?: number;
      wafCheckTime?: number;
    };
  };
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

      if (this.config.verbose) {
        const status = blocked ? "🚫" : response.ok ? "✓" : "✗";
        console.log(
          `${status} ${request.method} ${request.path} - ${response.status} (${latency}ms)`
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
      `   Distribution: ${this.config.profile.pattern.distribution}\n`
    );

    this.running = true;
    this.abortController = new AbortController();

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
