#!/usr/bin/env node

// Load Test CLI Runner
// Command-line interface for running load tests

/**
 * Load Test CLI Runner
 * Command-line interface for running load tests
 */

import { createLoadTest } from "./index.js";
import { ALL_PROFILES, listProfiles, getProfile } from "../profiles/index.js";
import { promises as fs } from "fs"; // TODO: Fix 
import path from "path";
import type { ExperimentReport } from "../metrics/index.js";

interface CLIOptions {
  target?: string;
  profile?: string;
  duration?: number;
  rps?: number; // requests per second
  concurrency?: number;
  verbose?: boolean;
  realtime?: boolean;
  saveReport?: boolean;
  list?: boolean;
}

/**
 * Parse command line arguments
 */
function parseArgs(): CLIOptions {
  const args = process.argv.slice(2);
  const options: CLIOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case "--target":
      case "-t":
        options.target = args[++i];
        break;

      case "--profile":
      case "-p":
        options.profile = args[++i];
        break;

      case "--duration":
      case "-d":
        options.duration = parseInt(args[++i]);
        break;

      case "--rps":
      case "-r":
        options.rps = parseInt(args[++i]);
        break;

      case "--concurrency":
      case "-c":
        options.concurrency = parseInt(args[++i]);
        break;

      case "--verbose":
      case "-v":
        options.verbose = true;
        break;

      case "--realtime":
        options.realtime = true;
        break;

      case "--save":
      case "-s":
        options.saveReport = true;
        break;

      case "--list":
      case "-l":
        options.list = true;
        break;

      case "--help":
      case "-h":
        printHelp();
        process.exit(0);
        break;

      default:
        console.error(`Unknown option: ${arg}`);
        printHelp();
        process.exit(1);
    }
  }

  return options;
}

/**
 * Print help message
 */
function printHelp(): void {
  console.log(`
Load Test Runner - Cloudflare Workers Security Testing

Usage:
  npm run load-test -- [options]

Options:
  -t, --target <url>        Target URL (default: http://localhost:8787)
  -p, --profile <name>      Attack profile name (see --list)
  -d, --duration <seconds>  Test duration in seconds
  -r, --rps <number>        Requests per second
  -c, --concurrency <num>   Number of concurrent workers
  -v, --verbose             Show individual request logs
  --realtime                Display realtime metrics
  -s, --save                Save report to file
  -l, --list                List available profiles
  -h, --help                Show this help message

Examples:
  # Run burst attack against local server
  npm run load-test -- -p BURST_ATTACK

  # Run credential stuffing against deployed worker
  npm run load-test -- -t https://worker.example.com -p CREDENTIAL_STUFFING

  # Custom test with realtime metrics
  npm run load-test -- -p SUSTAINED_ATTACK --realtime --verbose

  # List all available profiles
  npm run load-test -- --list

Available Profiles:
  ${listProfiles().join(", ")}
  `);
}

/**
 * List all available profiles
 */
function listAvailableProfiles(): void {
  console.log("\nAvailable Attack Profiles:\n");
  console.log("─".repeat(80));

  Object.entries(ALL_PROFILES).forEach(([name, profile]) => {
    console.log(`\n${name}`);
    console.log(`  Description: ${profile.description}`);
    console.log(`  Type: ${profile.type}`);
    console.log(`  Request Rate: ${profile.requestsPerSecond} req/s`);
    console.log(`  Duration: ${profile.duration}s`);
    console.log(`  Concurrency: ${profile.concurrency}`);
    console.log(`  Distribution: ${profile.pattern.distribution}`);
    if (profile.expected.blockRate) {
      console.log(
        `  Expected Block Rate: ${(profile.expected.blockRate * 100).toFixed(
          0
        )}%`
      );
    }
  });

  console.log("\n" + "─".repeat(80) + "\n");
}

/**
 * Format report as human-readable text
 */
function formatReport(report: ExperimentReport): string {
  const lines: string[] = [];
  
  // Header
  lines.push("=".repeat(80));
  lines.push("EXPERIMENT REPORT");
  lines.push("=".repeat(80));
  lines.push("");
  
  // Experiment Info
  lines.push("Experiment Information");
  lines.push("-".repeat(80));
  lines.push(`Experiment ID:    ${report.experimentId}`);
  lines.push(`Profile:          ${report.profileName}`);
  lines.push(`Start Time:       ${new Date(report.startTime).toISOString()}`);
  lines.push(`End Time:         ${new Date(report.endTime).toISOString()}`);
  lines.push(`Duration:         ${report.duration.toFixed(2)}s`);
  lines.push("");
  
  // Summary Statistics
  lines.push("Summary Statistics");
  lines.push("-".repeat(80));
  lines.push(`Total Requests:        ${report.summary.totalRequests.toLocaleString()}`);
  lines.push(`Successful:            ${report.summary.successfulRequests.toLocaleString()}`);
  lines.push(`Failed:                ${report.summary.failedRequests.toLocaleString()}`);
  lines.push(`Blocked:               ${report.summary.blockedRequests.toLocaleString()}`);
  lines.push(`Rate Limited:          ${report.summary.rateLimitedRequests.toLocaleString()}`);
  lines.push(`WAF Blocked:           ${report.summary.wafBlockedRequests.toLocaleString()}`);
  lines.push("");
  lines.push(`Request Rate:          ${report.summary.requestRate.toFixed(2)} req/s`);
  lines.push(`Block Rate:            ${report.summary.blockRate.toFixed(2)}%`);
  lines.push(`Error Rate:            ${report.summary.errorRate.toFixed(2)}%`);
  lines.push("");
  
  // Latency Statistics
  lines.push("Latency Statistics (ms)");
  lines.push("-".repeat(80));
  lines.push(`Min:                  ${report.summary.latency.min.toFixed(2)}`);
  lines.push(`Max:                  ${report.summary.latency.max.toFixed(2)}`);
  lines.push(`Mean:                 ${report.summary.latency.mean.toFixed(2)}`);
  lines.push(`Median:               ${report.summary.latency.median.toFixed(2)}`);
  lines.push(`P50:                  ${report.summary.latency.p50.toFixed(2)}`);
  lines.push(`P95:                  ${report.summary.latency.p95.toFixed(2)}`);
  lines.push(`P99:                  ${report.summary.latency.p99.toFixed(2)}`);
  lines.push(`P99.9:                ${report.summary.latency.p999.toFixed(2)}`);
  lines.push(`Std Dev:              ${report.summary.latency.stdDev.toFixed(2)}`);
  lines.push("");
  
  // Security Latency (if available)
  if (report.summary.securityLatency) {
    lines.push("Security Check Latency (ms)");
    lines.push("-".repeat(80));
    if (report.summary.securityLatency.rateLimit) {
      const rl = report.summary.securityLatency.rateLimit;
      lines.push(`Rate Limit - Mean: ${rl.mean.toFixed(2)}, P95: ${rl.p95.toFixed(2)}, P99: ${rl.p99.toFixed(2)}`);
    }
    if (report.summary.securityLatency.turnstile) {
      const ts = report.summary.securityLatency.turnstile;
      lines.push(`Turnstile - Mean: ${ts.mean.toFixed(2)}, P95: ${ts.p95.toFixed(2)}, P99: ${ts.p99.toFixed(2)}`);
    }
    if (report.summary.securityLatency.waf) {
      const waf = report.summary.securityLatency.waf;
      lines.push(`WAF - Mean: ${waf.mean.toFixed(2)}, P95: ${waf.p95.toFixed(2)}, P99: ${waf.p99.toFixed(2)}`);
    }
    lines.push("");
  }
  
  // Status Code Distribution
  const statusCodes = Object.entries(report.summary.statusCodes)
    .sort(([a], [b]) => parseInt(a) - parseInt(b));
  if (statusCodes.length > 0) {
    lines.push("HTTP Status Code Distribution");
    lines.push("-".repeat(80));
    statusCodes.forEach(([code, count]) => {
      const percentage = ((count / report.summary.totalRequests) * 100).toFixed(2);
      lines.push(`  ${code.padStart(3)}: ${count.toLocaleString().padStart(10)} (${percentage}%)`);
    });
    lines.push("");
  }
  
  // Comparison with Expectations
  if (report.comparison) {
    lines.push("Performance vs Expectations");
    lines.push("-".repeat(80));
    const passed = report.comparison.passed ? "✓ PASSED" : "✗ FAILED";
    lines.push(`Status:              ${passed}`);
    lines.push("");
    lines.push(`Block Rate:`);
    lines.push(`  Expected:          ${report.comparison.expectedBlockRate.toFixed(2)}%`);
    lines.push(`  Actual:            ${report.comparison.actualBlockRate.toFixed(2)}%`);
    lines.push(`  Difference:        ${(report.comparison.actualBlockRate - report.comparison.expectedBlockRate).toFixed(2)}%`);
    lines.push("");
    lines.push(`Latency:`);
    lines.push(`  Expected:          ${report.comparison.expectedLatency.toFixed(2)}ms`);
    lines.push(`  Actual:            ${report.comparison.actualLatency.toFixed(2)}ms`);
    lines.push(`  Difference:        ${(report.comparison.actualLatency - report.comparison.expectedLatency).toFixed(2)}ms`);
    lines.push("");
  }
  
  // Top Errors
  if (report.errors.length > 0) {
    lines.push("Top Errors");
    lines.push("-".repeat(80));
    report.errors.forEach((err, idx) => {
      lines.push(`${(idx + 1).toString().padStart(2)}. ${err.error}`);
      lines.push(`    Count: ${err.count.toLocaleString()} (${err.percentage.toFixed(2)}%)`);
    });
    lines.push("");
  }
  
  // Time Series Summary
  if (report.timeSeries.length > 0) {
    lines.push("Time Series Summary (10s intervals)");
    lines.push("-".repeat(80));
    lines.push("Interval | Requests | Rate (req/s) | Block % | Error % | P95 (ms)");
    lines.push("-".repeat(80));
    report.timeSeries.forEach((snapshot, idx) => {
      const interval = `${(idx * 10).toString().padStart(3)}-${((idx + 1) * 10).toString().padStart(3)}s`;
      lines.push(
        `${interval.padEnd(9)} | ${snapshot.totalRequests.toString().padStart(8)} | ${snapshot.requestRate.toFixed(2).padStart(12)} | ${snapshot.blockRate.toFixed(2).padStart(7)} | ${snapshot.errorRate.toFixed(2).padStart(7)} | ${snapshot.latency.p95.toFixed(0).padStart(8)}`
      );
    });
    lines.push("");
  }
  
  // JSON Data Separator
  lines.push("=".repeat(80));
  lines.push("JSON DATA");
  lines.push("=".repeat(80));
  lines.push("");
  
  return lines.join("\n");
}

/**
 * Save report to file
 */
async function saveReport(
  report: ExperimentReport
): Promise<void> {
  const reportsDir = path.join(process.cwd(), "reports");

  try {
    await fs.mkdir(reportsDir, { recursive: true });
    const filename = `${report.experimentId}-${Date.now()}.txt`;
    const filepath = path.join(reportsDir, filename);

    // Format as human-readable text with JSON appended
    const formattedText = formatReport(report);
    const jsonData = JSON.stringify(report, null, 2);
    const content = formattedText + jsonData;

    await fs.writeFile(filepath, content);
    console.log(`\n📄 Report saved to: ${filepath}\n`);
  } catch (error: any) {
    console.error(`\n✗ Failed to save report: ${error.message}\n`);
  }
}

/**
 * Main execution
 */
async function main(): Promise<void> {
  const options = parseArgs();

  // List profiles if requested
  if (options.list) {
    listAvailableProfiles();
    return;
  }

  // Validate required options
  const target = options.target || "http://localhost:8787";
  const profileName = options.profile || "LEGITIMATE_TRAFFIC";

  let profile = getProfile(profileName);
  if (!profile) {
    console.error(`\n✗ Unknown profile: ${profileName}`);
    console.log("\nUse --list to see available profiles\n");
    process.exit(1);
  }

  // Apply overrides if provided
  if (options.duration || options.rps || options.concurrency) {
    profile = { ...profile };
    if (options.duration) profile.duration = options.duration;
    if (options.rps) profile.requestsPerSecond = options.rps;
    if (options.concurrency) profile.concurrency = options.concurrency;
  }

  // Create and run load test
  const tester = createLoadTest(target, profile, {
    verbose: options.verbose,
    realtime: options.realtime,
  });

  // Handle Ctrl+C gracefully
  process.on("SIGINT", () => {
    tester.stop();
  });

  try {
    await tester.run();
    tester.report();

    // Save report if requested
    if (options.saveReport) {
      const metrics = tester.getMetrics();
      const report = metrics.report(
        profile.expected.blockRate
          ? profile.expected.blockRate * 100
          : undefined,
        profile.expected.avgLatency
      );

      await saveReport(report);
    }
  } catch (error: any) {
    console.error(`\n✗ Load test failed: ${error.message}\n`);
    process.exit(1);
  }
}

// Run main function
main().catch((error) => {
  console.error(error);
  process.exit(1);
});

export { main };
