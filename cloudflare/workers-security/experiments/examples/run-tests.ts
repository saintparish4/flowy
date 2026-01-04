/// <reference types="node" />

/**
 * Example Load Test Script
 * Demonstrates programmatic usage of the load testing framework
 */

import { createLoadTest } from "../load-test/index.js";
import {
  BURST_ATTACK,
  CREDENTIAL_STUFFING,
  LEGITIMATE_TRAFFIC,
} from "../profiles/index.js";

async function runExample() {
  const targetUrl = process.env.TARGET_URL || "http://localhost:8787";

  console.log("Running example load tests...\n");

  // Example 1: Burst Attack
  console.log("Example 1: Testing burst attack protection\n");
  const burstTest = createLoadTest(targetUrl, BURST_ATTACK, {
    verbose: false,
    realtime: false,
  });

  await burstTest.run();
  burstTest.report();

  // Wait a bit between tests
  await new Promise((resolve) => setTimeout(resolve, 5000));

  // Example 2: Credential Stuffing
  console.log("\nExample 2: Testing credential stuffing protection\n");
  const credentialTest = createLoadTest(targetUrl, CREDENTIAL_STUFFING, {
    verbose: false,
    realtime: false,
  });

  await credentialTest.run();
  credentialTest.report();

  // Wait a bit between tests
  await new Promise((resolve) => setTimeout(resolve, 5000));

  // Example 3: Legitimate Traffic (should mostly succeed)
  console.log("\nExample 3: Testing legitimate traffic handling\n");
  const legitTest = createLoadTest(targetUrl, LEGITIMATE_TRAFFIC, {
    verbose: false,
    realtime: false,
  });

  await legitTest.run();
  legitTest.report();

  console.log("\n✓ All example tests completed!\n");
}

runExample().catch((error) => {
  console.error("Error running examples:", error);
  process.exit(1);
});
