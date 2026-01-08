# Cloudflare Rate Limiter

A thread-safe sliding window rate limiter implementation in Scala 3.

## Overview

This implementation provides a concurrent, per-key rate limiter using a sliding window algorithm. It is designed for high-throughput, revenue-critical APIs where correctness under concurrency is paramount.

### Key Features

- **Sliding Window Algorithm**: More accurate than fixed windows, prevents burst allowance at window boundaries
- **Thread-Safe**: Fine-grained per-key synchronization using `AtomicReference` with compare-and-swap
- **No Global Locks**: Independent keys can be processed concurrently without contention
- **Accurate Retry-After**: Precise calculation of when the next request can be attempted
- **Deterministic**: Same inputs always produce same outputs

## Quick Start

### Prerequisites

- Java 11 or higher
- sbt 1.9.x

### Build and Test

```bash
# Compile
sbt compile

# Run tests
sbt test

# Run specific test
sbt "testOnly com.cloudflare.ratelimiter.SlidingWindowRateLimiterSpec"

# Continuous testing
sbt ~test
```