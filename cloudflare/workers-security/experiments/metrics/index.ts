// Metrics Collection and Analysis 
// Collects, aggregates, and analyzes performance metrics from load tests 

export interface RequestMetric {
  timestamp: number;
  traceId: string;
  url: string;
  method: string;
  statusCode: number;
  latency: number; // milliseconds
  blocked: boolean;
  rateLimited: boolean;
  wafBlocked: boolean;
  error?: string;

  // Detailed timing breakdown
  timing?: {
    dns?: number;
    tcp?: number;
    tls?: number;
    ttfb?: number; // Time to first byte
    download?: number;
    total: number;
  };

  // Security check timings
  securityTiming?: {
    rateLimit?: number;
    burst?: number;
    turnstile?: number;
    waf?: number;
  };
}

export interface MetricsSnapshot {
  timestamp: number;
  windowSize: number; // seconds

  // Request counts
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  blockedRequests: number;
  rateLimitedRequests: number;
  wafBlockedRequests: number;

  // Rates
  requestRate: number; // req/sec
  errorRate: number; // percentage
  blockRate: number; // percentage

  // Latency statistics (milliseconds)
  latency: {
    min: number;
    max: number;
    mean: number;
    median: number;
    p50: number;
    p95: number;
    p99: number;
    p999: number;
    stdDev: number;
  };

  // Security check timing stats
  securityLatency?: {
    rateLimit?: LatencyStats;
    burst?: LatencyStats;
    turnstile?: LatencyStats;
    waf?: LatencyStats;
  };

  // HTTP status code distribution
  statusCodes: Record<number, number>;
}

export interface LatencyStats {
  min: number;
  max: number;
  mean: number;
  p50: number;
  p95: number;
  p99: number;
}

export interface ExperimentReport {
  experimentId: string;
  profileName: string;
  startTime: number;
  endTime: number;
  duration: number;

  // Overall statistics
  summary: MetricsSnapshot;

  // Time-series data (snapshots over time)
  timeSeries: MetricsSnapshot[];

  // Top errors
  errors: Array<{
    error: string;
    count: number;
    percentage: number;
  }>;

  // Performance vs expectations
  comparison?: {
    expectedBlockRate: number;
    actualBlockRate: number;
    expectedLatency: number;
    actualLatency: number;
    passed: boolean;
  };
}

/**
 * Metrics collector that aggregates request data
 */
export class MetricsCollector {
  private metrics: RequestMetric[] = [];
  private experimentId: string;
  private profileName: string;
  private startTime: number;

  constructor(experimentId: string, profileName: string) {
    this.experimentId = experimentId;
    this.profileName = profileName;
    this.startTime = Date.now();
  }

  /**
   * Record a single request metric
   */
  record(metric: RequestMetric): void {
    this.metrics.push(metric);
  }

  /**
   * Calculate percentile value
   */
  private percentile(values: number[], p: number): number {
    if (values.length === 0) return 0;

    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  }

  /**
   * Calculate standard deviation
   */
  private stdDev(values: number[], mean: number): number {
    if (values.length === 0) return 0;

    const squaredDiffs = values.map((v) => Math.pow(v - mean, 2));
    const avgSquaredDiff =
      squaredDiffs.reduce((a, b) => a + b, 0) / values.length;
    return Math.sqrt(avgSquaredDiff);
  }

  /**
   * Calculate latency statistics from values
   */
  private calculateLatencyStats(values: number[]): LatencyStats | undefined {
    if (values.length === 0) return undefined;

    const sorted = [...values].sort((a, b) => a - b);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;

    return {
      min: sorted[0],
      max: sorted[sorted.length - 1],
      mean,
      p50: this.percentile(values, 50),
      p95: this.percentile(values, 95),
      p99: this.percentile(values, 99),
    };
  }

  /**
   * Generate a snapshot of current metrics
   */
  snapshot(windowSize: number = 0): MetricsSnapshot {
    const now = Date.now();
    const windowStart = windowSize > 0 ? now - windowSize * 1000 : 0;

    // Filter metrics within window
    const windowMetrics =
      windowSize > 0
        ? this.metrics.filter((m) => m.timestamp >= windowStart)
        : this.metrics;

    const totalRequests = windowMetrics.length;
    const successfulRequests = windowMetrics.filter(
      (m) => m.statusCode >= 200 && m.statusCode < 300
    ).length;
    const failedRequests = windowMetrics.filter(
      (m) => m.statusCode >= 400
    ).length;
    const blockedRequests = windowMetrics.filter((m) => m.blocked).length;
    const rateLimitedRequests = windowMetrics.filter(
      (m) => m.rateLimited
    ).length;
    const wafBlockedRequests = windowMetrics.filter((m) => m.wafBlocked).length;

    // Calculate rates
    const duration =
      windowSize > 0 ? windowSize : (now - this.startTime) / 1000;
    const requestRate = totalRequests / duration;
    const errorRate =
      totalRequests > 0 ? (failedRequests / totalRequests) * 100 : 0;
    const blockRate =
      totalRequests > 0 ? (blockedRequests / totalRequests) * 100 : 0;

    // Latency statistics
    const latencies = windowMetrics.map((m) => m.latency);
    const sortedLatencies = [...latencies].sort((a, b) => a - b);
    const meanLatency =
      latencies.length > 0
        ? latencies.reduce((a, b) => a + b, 0) / latencies.length
        : 0;

    // Status code distribution
    const statusCodes: Record<number, number> = {};
    windowMetrics.forEach((m) => {
      statusCodes[m.statusCode] = (statusCodes[m.statusCode] || 0) + 1;
    });

    // Security timing stats
    const rateLimitTimings = windowMetrics
      .map((m) => m.securityTiming?.rateLimit)
      .filter((t) => t !== undefined) as number[];
    const burstTimings = windowMetrics
      .map((m) => m.securityTiming?.burst)
      .filter((t) => t !== undefined) as number[];
    const turnstileTimings = windowMetrics
      .map((m) => m.securityTiming?.turnstile)
      .filter((t) => t !== undefined) as number[];
    const wafTimings = windowMetrics
      .map((m) => m.securityTiming?.waf)
      .filter((t) => t !== undefined) as number[];

    return {
      timestamp: now,
      windowSize,
      totalRequests,
      successfulRequests,
      failedRequests,
      blockedRequests,
      rateLimitedRequests,
      wafBlockedRequests,
      requestRate,
      errorRate,
      blockRate,
      latency: {
        min: sortedLatencies[0] || 0,
        max: sortedLatencies[sortedLatencies.length - 1] || 0,
        mean: meanLatency,
        median: this.percentile(latencies, 50),
        p50: this.percentile(latencies, 50),
        p95: this.percentile(latencies, 95),
        p99: this.percentile(latencies, 99),
        p999: this.percentile(latencies, 99.9),
        stdDev: this.stdDev(latencies, meanLatency),
      },
      securityLatency: {
        rateLimit: this.calculateLatencyStats(rateLimitTimings),
        burst: this.calculateLatencyStats(burstTimings),
        turnstile: this.calculateLatencyStats(turnstileTimings),
        waf: this.calculateLatencyStats(wafTimings),
      },
      statusCodes,
    };
  }

  /**
   * Generate a full experiment report
   */
  report(
    expectedBlockRate?: number,
    expectedLatency?: number
  ): ExperimentReport {
    const endTime = Date.now();
    const duration = (endTime - this.startTime) / 1000;

    // Generate overall summary
    const summary = this.snapshot();

    // Generate time-series snapshots (every 10 seconds)
    const timeSeries: MetricsSnapshot[] = [];
    const intervalSize = 10; // seconds
    const intervals = Math.floor(duration / intervalSize);

    for (let i = 0; i < intervals; i++) {
      const windowEnd = this.startTime + (i + 1) * intervalSize * 1000;
      const windowMetrics = this.metrics.filter(
        (m) =>
          m.timestamp >= this.startTime + i * intervalSize * 1000 &&
          m.timestamp < windowEnd
      );

      if (windowMetrics.length > 0) {
        // Create a temporary collector for this window
        const windowCollector = new MetricsCollector(
          this.experimentId,
          this.profileName
        );
        windowCollector.metrics = windowMetrics;
        windowCollector.startTime = this.startTime + i * intervalSize * 1000;
        timeSeries.push(windowCollector.snapshot(intervalSize));
      }
    }

    // Top errors
    const errorMap: Record<string, number> = {};
    this.metrics.forEach((m) => {
      if (m.error) {
        errorMap[m.error] = (errorMap[m.error] || 0) + 1;
      }
    });

    const errors = Object.entries(errorMap)
      .map(([error, count]) => ({
        error,
        count,
        percentage: (count / this.metrics.length) * 100,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Comparison with expectations
    let comparison;
    if (expectedBlockRate !== undefined || expectedLatency !== undefined) {
      const actualBlockRate = summary.blockRate;
      const actualLatency = summary.latency.mean;

      const blockRatePassed =
        expectedBlockRate !== undefined
          ? Math.abs(actualBlockRate - expectedBlockRate) <= 10 // Within 10% tolerance
          : true;

      const latencyPassed =
        expectedLatency !== undefined
          ? actualLatency <= expectedLatency * 1.5 // Within 150% of expected
          : true;

      comparison = {
        expectedBlockRate: expectedBlockRate || 0,
        actualBlockRate,
        expectedLatency: expectedLatency || 0,
        actualLatency,
        passed: blockRatePassed && latencyPassed,
      };
    }

    return {
      experimentId: this.experimentId,
      profileName: this.profileName,
      startTime: this.startTime,
      endTime,
      duration,
      summary,
      timeSeries,
      errors,
      comparison,
    };
  }

  /**
   * Export raw metrics as JSON
   */
  exportRaw(): string {
    return JSON.stringify(this.metrics, null, 2);
  }

  /**
   * Clear all collected metrics
   */
  clear(): void {
    this.metrics = [];
  }
}

/**
 * Format a metrics snapshot as a readable string
 */
export function formatSnapshot(snapshot: MetricsSnapshot): string {
  return `
  Metrics Snapshot (${new Date(snapshot.timestamp).toISOString()})
  ${"=".repeat(60)}
  
  Requests:
    Total:        ${snapshot.totalRequests}
    Successful:   ${snapshot.successfulRequests} (${(
    (snapshot.successfulRequests / snapshot.totalRequests) *
    100
  ).toFixed(1)}%)
    Failed:       ${snapshot.failedRequests} (${snapshot.errorRate.toFixed(1)}%)
    Blocked:      ${snapshot.blockedRequests} (${snapshot.blockRate.toFixed(
    1
  )}%)
    Rate Limited: ${snapshot.rateLimitedRequests}
    WAF Blocked:  ${snapshot.wafBlockedRequests}
  
  Rates:
    Request Rate: ${snapshot.requestRate.toFixed(2)} req/s
    Error Rate:   ${snapshot.errorRate.toFixed(2)}%
    Block Rate:   ${snapshot.blockRate.toFixed(2)}%
  
  Latency (ms):
    Min:    ${snapshot.latency.min.toFixed(2)}
    Mean:   ${snapshot.latency.mean.toFixed(2)}
    Median: ${snapshot.latency.median.toFixed(2)}
    P95:    ${snapshot.latency.p95.toFixed(2)}
    P99:    ${snapshot.latency.p99.toFixed(2)}
    P99.9:  ${snapshot.latency.p999.toFixed(2)}
    Max:    ${snapshot.latency.max.toFixed(2)}
    StdDev: ${snapshot.latency.stdDev.toFixed(2)}
  
  Status Codes:
  ${Object.entries(snapshot.statusCodes)
    .sort(([a], [b]) => parseInt(a) - parseInt(b))
    .map(([code, count]) => `  ${code}: ${count}`)
    .join("\n")}
    `;
}
