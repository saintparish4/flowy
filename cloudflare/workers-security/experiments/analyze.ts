#!/usr/bin/env node

/**
 * Report Analyzer
 * Analyzes and compares load test reports
 */

import { promises as fs } from "fs";
import path from "path";

interface ReportSummary {
  experimentId: string;
  profileName: string;
  duration: number;
  totalRequests: number;
  requestRate: number;
  blockRate: number;
  errorRate: number;
  p50: number;
  p95: number;
  p99: number;
  passed?: boolean;
}

/**
 * Load a report from file
 * Supports both formatted reports (with JSON at the end) and pure JSON files
 */
async function loadReport(filepath: string): Promise<any> {
  const content = await fs.readFile(filepath, "utf-8");
  
  // Check if this is a formatted report (contains "JSON DATA" separator)
  // Look for the separator pattern: "JSON DATA" followed by "=" separator
  const jsonSeparator = "JSON DATA";
  const jsonIndex = content.indexOf(jsonSeparator);
  
  if (jsonIndex !== -1) {
    // Find the start of JSON (after the separator section)
    // Pattern is: "JSON DATA" -> "=" separator -> empty line -> JSON starts
    const afterSeparator = content.substring(jsonIndex);
    const lines = afterSeparator.split('\n');
    
    // Find where JSON actually starts (first line that looks like JSON: starts with { or [)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line === '{' || line.startsWith('{')) {
        // Found start of JSON, extract from here
        const jsonContent = lines.slice(i).join('\n').trim();
        return JSON.parse(jsonContent);
      }
    }
    
    // Fallback: if we can't find {, try to parse everything after separator
    const jsonContent = afterSeparator.split('\n').slice(3).join('\n').trim();
    return JSON.parse(jsonContent);
  }
  
  // Fall back to parsing entire content as JSON (backward compatibility)
  return JSON.parse(content);
}

/**
 * Extract summary from report
 */
function extractSummary(report: any): ReportSummary {
  return {
    experimentId: report.experimentId,
    profileName: report.profileName,
    duration: report.duration,
    totalRequests: report.summary.totalRequests,
    requestRate: report.summary.requestRate,
    blockRate: report.summary.blockRate,
    errorRate: report.summary.errorRate,
    p50: report.summary.latency.p50,
    p95: report.summary.latency.p95,
    p99: report.summary.latency.p99,
    passed: report.comparison?.passed,
  };
}

/**
 * Compare two reports
 */
function compareReports(baseline: ReportSummary, current: ReportSummary): void {
  console.log("\nReport Comparison\n");
  console.log("=".repeat(80));
  console.log(
    `\nBaseline:  ${baseline.experimentId} (${baseline.profileName})`
  );
  console.log(`Current:   ${current.experimentId} (${current.profileName})`);
  console.log("\n" + "-".repeat(80));

  const metrics = [
    ["Request Rate", baseline.requestRate, current.requestRate, "req/s"],
    ["Block Rate", baseline.blockRate, current.blockRate, "%"],
    ["Error Rate", baseline.errorRate, current.errorRate, "%"],
    ["P50 Latency", baseline.p50, current.p95, "ms"],
    ["P95 Latency", baseline.p95, current.p95, "ms"],
    ["P99 Latency", baseline.p99, current.p99, "ms"],
  ];

  console.log("\nMetric               Baseline      Current       Change");
  console.log("-".repeat(80));

  metrics.forEach(([name, baseVal, currVal, unit]) => {
    const change =
      (((currVal as number) - (baseVal as number)) / (baseVal as number)) * 100;
    const arrow = change > 0 ? "↑" : change < 0 ? "↓" : "→";
    const changeStr =
      change !== 0 ? `${arrow} ${Math.abs(change).toFixed(1)}%` : "→ 0%";
    const unitStr = unit as string;

    console.log(
      `${(name as string).padEnd(20)} ` +
        `${(baseVal as number).toFixed(2).padStart(10)} ${unitStr.padEnd(4)} ` +
        `${(currVal as number).toFixed(2).padStart(10)} ${unitStr.padEnd(4)} ` +
        `${changeStr}`
    );
  });

  console.log("\n" + "=".repeat(80) + "\n");
}

/**
 * List all reports
 */
async function listReports(dir: string): Promise<void> {
  try {
    const files = await fs.readdir(dir);
    const reportFiles = files.filter((f) => f.endsWith(".txt"));

    console.log(`\nFound ${reportFiles.length} reports:\n`);
    console.log("-".repeat(80));

    const summaries: ReportSummary[] = [];

    for (const file of reportFiles) {
      const filepath = path.join(dir, file);
      try {
        const report = await loadReport(filepath);
        const summary = extractSummary(report);
        summaries.push(summary);

        const passedIcon =
          summary.passed === undefined ? "○" : summary.passed ? "✓" : "✗";
        console.log(`${passedIcon} ${file}`);
        console.log(`   Profile: ${summary.profileName}`);
        console.log(
          `   Requests: ${
            summary.totalRequests
          } @ ${summary.requestRate.toFixed(0)} req/s`
        );
        console.log(`   Block Rate: ${summary.blockRate.toFixed(1)}%`);
        console.log(`   P95: ${summary.p95.toFixed(0)}ms\n`);
      } catch (error: any) {
        console.log(`✗ ${file} - ERROR: ${error.message}\n`);
      }
    }

    console.log("-".repeat(80) + "\n");
  } catch (error: any) {
    console.error(`Error listing reports: ${error.message}`);
  }
}

/**
 * Main execution
 */
async function main() {
  const args = process.argv.slice(2);
  const reportsDir = path.join(process.cwd(), "reports");

  if (args.length === 0 || args[0] === "--list" || args[0] === "-l") {
    await listReports(reportsDir);
    return;
  }

  if (args[0] === "--compare" || args[0] === "-c") {
    if (args.length < 3) {
      console.error(
        "\nUsage: npm run analyze -- --compare <baseline-file> <current-file>\n"
      );
      process.exit(1);
    }

    const baselinePath = path.join(reportsDir, args[1]);
    const currentPath = path.join(reportsDir, args[2]);

    try {
      const baselineReport = await loadReport(baselinePath);
      const currentReport = await loadReport(currentPath);

      const baselineSummary = extractSummary(baselineReport);
      const currentSummary = extractSummary(currentReport);

      compareReports(baselineSummary, currentSummary);
    } catch (error: any) {
      console.error(`\nError comparing reports: ${error.message}\n`);
      process.exit(1);
    }
    return;
  }

  console.log("\nLoad Test Report Analyzer\n");
  console.log("Usage:");
  console.log("  npm run analyze              # List all reports");
  console.log("  npm run analyze -- -l        # List all reports");
  console.log(
    "  npm run analyze -- -c <baseline> <current>  # Compare reports\n"
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
