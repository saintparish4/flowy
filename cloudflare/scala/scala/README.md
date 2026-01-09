# Cloudflare Rate Limiter & Idempotency Store

A thread-safe implementation of rate limiting and idempotency for revenue-critical APIs in Scala 3.

## Purpose Contract

This project implements **three core capabilities** for revenue-critical, high-throughput APIs:

### X: Capabilities

1. **Rate Limiter**: A sliding-window rate limiter that enforces request limits per key, protecting infrastructure from traffic spikes
2. **Idempotency Store**: An idempotency store that ensures duplicate requests do not produce duplicate side effects, protecting business correctness
3. **Request Processor**: A composition layer that combines rate limiting and idempotency with per-key synchronization, guaranteeing exactly-once processing

### Y: Constraints

This implementation operates under the following constraints:

- **Correctness under concurrency**: Must be deterministic and thread-safe without data races
- **No global locks**: Fine-grained per-key synchronization only
- **Fully testable**: No external dependencies required for testing
- **Deterministic behavior**: Same inputs always produce same outputs
- **Library-style**: Test-driven, composable components
- **Performance**: O(1)–O(log n) per operation
- **Thread-safe**: Concurrent access must be safe without global synchronization
- **Exactly-once processing**: Per-key locks ensure business logic executes only once per idempotency key

### Z: Non-Goals

This project explicitly does **not** implement:

- HTTP server implementation
- Database or external persistence
- Akka, Play, Spark, or streaming frameworks
- Distributed consensus
- UI or dashboards
- Persistent storage
- Networking
- HTTP handlers
- Framework-specific integrations

The focus is on correctness, clarity, and tradeoff reasoning for high-throughput API platforms, independent of HTTP frameworks or infrastructure.

## Overview

This implementation provides three core components and their composition:

1. **Rate Limiter** - Sliding window algorithm for request volume control
2. **Idempotency Store** - First-writer-wins deduplication with TTL support
3. **Request Processor** - Composition layer combining both concerns with per-key synchronization

Designed for high-throughput, revenue-critical APIs where correctness under concurrency is paramount.

### Key Features

**Rate Limiter:**
- **Sliding Window Algorithm**: More accurate than fixed windows, prevents burst allowance at window boundaries
- **Thread-Safe**: Fine-grained per-key synchronization using `AtomicReference` with compare-and-swap
- **No Global Locks**: Independent keys can be processed concurrently without contention
- **Accurate Retry-After**: Precise calculation of when the next request can be attempted
- **Deterministic**: Same inputs always produce same outputs

**Idempotency Store:**
- **First-Writer-Wins**: Guarantees exactly-once processing even under retry storms
- **TTL Support**: Automatic expiry with lazy cleanup
- **Atomic Operations**: `ConcurrentHashMap.putIfAbsent` ensures no partial state
- **Thread-Safe**: No locks required, built on concurrent collections
- **Duplicate Detection**: Returns cached responses for duplicate requests

**Request Processor:**
- **Unified Processing**: Single interface for rate limiting + idempotency
- **Per-Key Synchronization**: Ensures exactly-once processing via fine-grained locks
- **Two Strategies**: Choose between idempotency-first (recommended) or rate-limit-first
- **Race Condition Free**: Per-key locks eliminate wasted computation
- **Battle-Tested**: Comprehensive test coverage including concurrent scenarios

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
sbt "testOnly composition.RequestProcessorSpec"

# Continuous testing
sbt ~test
```

### Usage Example

#### Complete System (Recommended)

```scala
import composition.{RequestProcessor, Processed, Duplicate, RateLimited}
import rateLimiter.SlidingWindowRateLimiter
import idempotency.{InMemoryIdempotencyStore, StoredResponse}
import java.time.{Duration, Instant}

// Create components
val rateLimiter = SlidingWindowRateLimiter(
  maxRequests = 100,
  windowSize = Duration.ofMinutes(1)
)

val idempotencyStore = InMemoryIdempotencyStore()

// Compose them
val processor = RequestProcessor(rateLimiter, idempotencyStore)

// Process requests with unified handling
processor.process(
  idempotencyKey = "payment-123",
  rateLimitKey = "api-key-456",
  ttl = Duration.ofHours(24)
) { () =>
  // Your business logic here
  val result = processPayment()
  
  StoredResponse(
    status = 201,
    body = result.toJson,
    headers = Map("Content-Type" -> "application/json"),
    createdAt = Instant.now()
  )
} match {
  case Processed(response) =>
    // First request - processed successfully
    respondWith(201, response.body)
    
  case Duplicate(response) =>
    // Duplicate request - return cached response (no rate limit consumed)
    respondWith(200, response.body)
    
  case RateLimited(retryAfter) =>
    // Rate limited - tell client to retry
    respondWith(429, s"Retry after ${retryAfter.getSeconds}s")
}
```

#### Rate Limiter Only

```scala
import rateLimiter.{SlidingWindowRateLimiter, Allow, Rejected}
import java.time.{Duration, Instant}

// Create a rate limiter: 100 requests per minute
val limiter = SlidingWindowRateLimiter(
  maxRequests = 100,
  windowSize = Duration.ofMinutes(1)
)

// Check if a request is allowed
val decision = limiter.allow("api-key-123", Instant.now())

decision match {
  case Allow =>
    println("Request allowed - proceed with processing")
    
  case Rejected(retryAfter) =>
    println(s"Request rejected - retry after $retryAfter")
    println(s"Retry after ${retryAfter.getSeconds} seconds")
}
```

#### Idempotency Store Only

```scala
import idempotency.{InMemoryIdempotencyStore, StoredResponse, Stored, AlreadyExists}
import java.time.{Duration, Instant}

val store = InMemoryIdempotencyStore()

val response = StoredResponse(
  status = 201,
  body = """{"id": 123, "status": "created"}""",
  headers = Map("Content-Type" -> "application/json"),
  createdAt = Instant.now()
)

store.putIfAbsent("request-123", response, Duration.ofHours(24)) match {
  case Stored => 
    println("First request - processed")
  case AlreadyExists(cached) => 
    println(s"Duplicate request - returning cached: ${cached.body}")
}
```

## Algorithm Details

### Sliding Window Rate Limiter

The sliding window algorithm works as follows:

1. **Track timestamps**: Each key maintains a vector of request timestamps
2. **Expire old entries**: Timestamps older than `now - windowSize` are removed
3. **Count check**: If count < `maxRequests`, request is allowed
4. **Rejection**: If over limit, calculate exact retry-after duration

**Thread Safety:**
- Uses `ConcurrentHashMap` for per-key storage isolation
- Each key has an `AtomicReference[Vector[Instant]]`
- Updates use compare-and-swap (CAS) for lock-free concurrency
- Failed CAS operations retry automatically

**Time Complexity:**
- `allow()`: O(n) where n = requests in current window (typically small)
- **Worst case**: O(maxRequests)
- **Amortized**: O(1) with cleanup

### Idempotency Store

**First-Writer-Wins Pattern:**
- Uses `ConcurrentHashMap.putIfAbsent` for atomic insertion
- Returns `null` if inserted (first writer), existing value otherwise
- Handles expired entries via atomic `replace` operation
- Lazy cleanup on access (expired entries removed when accessed)

**Thread Safety:**
- Built on `ConcurrentHashMap` (thread-safe by design)
- Atomic operations guarantee no partial state
- No locks required

**Time Complexity:**
- `get()`: O(1) - HashMap lookup
- `putIfAbsent()`: O(1) - Atomic HashMap operation
- `cleanupExpired()`: O(total_keys) - Iterates all entries

### Request Processor - Per-Key Synchronization

**Critical Design Decision:**
```scala
// Per-key locks for fine-grained synchronization
private val processingLocks = new ConcurrentHashMap[String, Object]()

// Get or create lock for this specific idempotency key
val lock = processingLocks.computeIfAbsent(idempotencyKey, _ => new Object())

lock.synchronized {
    // Double-check idempotency inside lock
    // Process request
    // Store response
}
```

**Why This Works:**
1. **Fine-grained**: Only locks per idempotency key, not globally
2. **Eliminates race**: Only one thread can process per key
3. **Double-check pattern**: Verifies idempotency after acquiring lock
4. **No wasted computation**: Guarantees exactly-once processing

**Flow (Idempotency First):**
```
Request → Idempotency Check → Rate Limit Check → [Per-Key Lock] → Process → Store
```

**Alternative (Rate Limit First):**
```
Request → Rate Limit Check → Idempotency Check → Process → Store
```

See `scala-findings.md` for detailed comparison of strategies.

## Testing

The test suite covers all three components with comprehensive scenarios:

**Rate Limiter (10 tests):**
- ✅ Burst traffic within limit
- ✅ Burst traffic exceeding limit
- ✅ Boundary window behavior
- ✅ Window sliding behavior
- ✅ Accurate retry-after calculation
- ✅ Concurrent access correctness
- ✅ Large burst scenario
- ✅ Time moves backward handling
- ✅ Zero millisecond precision
- ✅ Single request limit

**Idempotency Store (15 tests):**
- ✅ Duplicate retries with same key
- ✅ Concurrent duplicate writes (first writer wins)
- ✅ Different keys are isolated
- ✅ Clear() resets all keys
- ✅ Expired entry allows reprocessing
- ✅ TTL expiry correctness
- ✅ TTL expiry - putIfAbsent on expired key
- ✅ Retry storm handling (100 concurrent requests)
- ✅ Partial failure simulation (no partial state)
- ✅ Get on non-existent key returns None
- ✅ Multiple keys are isolated
- ✅ Response fields preserved correctly
- ✅ CleanupExpired removes only expired entries
- ✅ ValidSize counts only non-expired entries
- ✅ Constructor validation (null checks)
- ✅ Concurrent get and putIfAbsent are safe

**Request Processor (12 tests):**
- ✅ First request processes and stores
- ✅ Duplicate request returns cached response
- ✅ Duplicate request does not consume rate limit quota
- ✅ Rate limited request rejects without processing
- ✅ Concurrent requests with same idempotency key (exactly one processes)
- ✅ Different idempotency keys are independent
- ✅ Race condition - concurrent processing stores first response
- ✅ Validation - null parameters rejected
- ✅ Retry storm handling
- ✅ Strategy comparison (IdempotencyFirst vs RateLimitFirst)

**Total: 37 tests, all passing ✅**

Run tests:

```bash
sbt test
```

## Project Structure

```
cloudflare/scala/scala/
├── build.sbt                                      # Build configuration
├── scala-findings.md                              # Design tradeoffs & analysis
├── README.md                                      # This file
└── src/
    ├── main/scala/
    │   ├── rateLimiter/                          # Rate Limiting
    │   │   ├── RateLimiter.scala                 # Core trait
    │   │   ├── RateLimitDecision.scala           # ADT for decisions
    │   │   ├── SlidingWindowRateLimiter.scala    # Implementation
    │   │   └── package.scala                     # Package docs
    │   │
    │   ├── idempotency/                          # Idempotency
    │   │   ├── IdempotencyStore.scala            # Core trait
    │   │   ├── IdempotencyResult.scala           # ADT for results
    │   │   ├── StoredResponse.scala              # Response model
    │   │   ├── InMemoryIdempotencyStore.scala    # Implementation
    │   │   └── package.scala                     # Package docs
    │   │
    │   └── composition/                          # Composition
    │       ├── RequestProcessor.scala            # Idempotency-first (default)
    │       └── RateLimitFirstProcessor.scala     # Rate-limit-first (alternative)
    │
    └── test/scala/
        ├── rateLimiter/
        │   └── SlidingWindowRateLimiterSpec.scala  # 10 tests
        ├── idempotency/
        │   └── IdempotencyStoreSpec.scala          # 15 tests
        └── composition/
            └── RequestProcessorSpec.scala           # 12 tests
```

## Design Decisions

### Composition: Idempotency First (Recommended)

**Why check idempotency before rate limiting?**

- **Pros**: Duplicate requests don't consume rate limit quota, better efficiency under retry storms, improved user experience, guaranteed exactly-once processing via per-key locks
- **Cons**: Vulnerable to abuse via unique idempotency keys, rate limit can be bypassed if keys are never duplicated
- **Trade-off**: User experience and retry storm protection vs abuse prevention

**Alternative**: Rate Limit First (`RateLimitFirstProcessor`)
- Check rate limit before idempotency
- Duplicates consume quota
- Better protection against abuse
- See `scala-findings.md` for detailed comparison

### Rate Limiter: AtomicReference[Vector[Instant]]

**Pros:**
- Immutable data structure (easier to reason about)
- Thread-safe updates via CAS
- Efficient filter/append operations
- No manual synchronization needed

**Cons:**
- Memory overhead from copying
- O(n) copy on each update
- Acceptable for typical request counts

**Alternative considered:** Mutable circular buffer with locks
**Decision:** Immutability wins for correctness

### Idempotency Store: ConcurrentHashMap.putIfAbsent

**Pros:**
- Built-in thread-safe key insertion
- `putIfAbsent` eliminates race conditions
- Returns `null` if inserted, existing value otherwise
- Per-bucket locking (fine-grained)
- Standard library reliability

**Cons:**
- No automatic eviction
- Keys remain until accessed

**Alternative considered:** Custom striped locks
**Decision:** Standard library wins for reliability

### Request Processor: Per-Key Synchronization

**Decision:** Use `ConcurrentHashMap[String, Object]` for per-key locks

**Rationale:**
- Ensures exactly-once processing per idempotency key
- Fine-grained (no global locks)
- Eliminates race conditions completely
- Acceptable memory overhead (one lock object per unique key)

**Alternative Considered:** Lock-free with CAS
- ❌ More complex
- ❌ Still allows wasted computation
- ❌ Harder to verify correctness

**Verdict:** Per-key locks provide strongest correctness guarantee.

### Sliding Window vs Token Bucket

**Pros:**
- More accurate than fixed window
- No burst allowance at boundaries
- Smooth rate enforcement

**Cons:**
- More memory than token bucket
- O(n) filtering cost

**Alternative considered:** Token bucket
**Decision:** Precision requirements favor sliding window

See `scala-findings.md` for comprehensive tradeoff analysis, race condition handling, and performance characteristics.

## Limitations

### Current Scope

- **In-memory only**: Not distributed, no persistence
- **Memory usage**: Grows with active keys and request rate
- **Lock map growth**: One lock object per unique idempotency key (unbounded)
- **No automatic cleanup**: Old keys and expired entries remain until accessed
- **No key TTL**: Rate limiter keys don't expire automatically
- **Single-node**: No distributed coordination
- **No observability**: Metrics hooks not implemented

### By Design (Per Requirements)

- ✅ No HTTP server implementation
- ✅ No database or external persistence
- ✅ No Akka, Play, Spark, or streaming frameworks
- ✅ No distributed consensus
- ✅ No UI or dashboards

See `scala-findings.md` for detailed discussion of limitations, failure modes, and future enhancements.

## Future Enhancements

Potential improvements (not currently implemented):

- **Lock Map Eviction**: Remove locks for keys that haven't been used recently
- **Background Cleanup**: Periodic cleanup of expired timestamps and entries
- **Distributed Coordination**: Redis-backed storage, distributed locks
- **Advanced Rate Limiting**: Token bucket algorithm, hierarchical limits
- **Observability**: Prometheus metrics export, detailed logging hooks
- **Performance Optimizations**: Lock-free alternatives, reduced memory footprint

## Documentation

- **README.md** (this file): Quick start, usage examples, project structure
- **scala-findings.md**: Comprehensive analysis of design decisions, tradeoffs, race condition handling, performance characteristics, and test results

## Contributing

This is a demonstration implementation. For production use cases, consider additional features like:

- Persistence layer integration
- Distributed rate limiting
- Advanced cleanup strategies
- Comprehensive metrics
- Lock map eviction policies
