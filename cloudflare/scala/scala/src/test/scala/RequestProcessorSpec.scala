package composition

import munit.FunSuite
import rateLimiter.SlidingWindowRateLimiter
import idempotency.{InMemoryIdempotencyStore, StoredResponse}
import java.time.{Duration, Instant}
import scala.concurrent.{Await, Future}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration._

class RequestProcessorSpec extends FunSuite {
  
  // Helper to create a test response
  def createResponse(body: String = "success"): StoredResponse = {
    StoredResponse(
      status = 200,
      body = body,
      headers = Map("Content-Type" -> "application/json"),
      createdAt = Instant.now()
    )
  }
  
  // Helper to create a fresh processor
  def createProcessor(): RequestProcessor = {
    val rateLimiter = SlidingWindowRateLimiter(
      maxRequests = 5,
      windowSize = Duration.ofSeconds(10)
    )
    val idempotencyStore = InMemoryIdempotencyStore()
    RequestProcessor(rateLimiter, idempotencyStore)
  }
  
  test("first request - processes and stores") {
    val processor = createProcessor()
    var processedCount = 0
    
    val result = processor.process(
      idempotencyKey = "req-1",
      rateLimitKey = "user-1",
      ttl = Duration.ofMinutes(5)
    ) { () =>
      processedCount += 1
      createResponse("result-1")
    }
    
    result match {
      case Processed(response) =>
        assertEquals(response.body, "result-1")
        assertEquals(processedCount, 1, "Should process exactly once")
        
      case _ =>
        fail(s"Expected Processed, got $result")
    }
  }
  
  test("duplicate request - returns cached response without processing") {
    val processor = createProcessor()
    var processedCount = 0
    
    // First request
    val result1 = processor.process(
      idempotencyKey = "req-2",
      rateLimitKey = "user-2",
      ttl = Duration.ofMinutes(5)
    ) { () =>
      processedCount += 1
      createResponse("first-response")
    }
    
    assertEquals(processedCount, 1)
    
    // Second request (duplicate)
    val result2 = processor.process(
      idempotencyKey = "req-2", // Same key
      rateLimitKey = "user-2",
      ttl = Duration.ofMinutes(5)
    ) { () =>
      processedCount += 1
      createResponse("second-response") // Different response
    }
    
    result2 match {
      case Duplicate(response) =>
        assertEquals(response.body, "first-response", "Should return first response")
        assertEquals(processedCount, 1, "Should NOT process duplicate")
        
      case _ =>
        fail(s"Expected Duplicate, got $result2")
    }
  }
  
  test("duplicate request does not consume rate limit quota") {
    val rateLimiter = SlidingWindowRateLimiter(
      maxRequests = 2, // Very low limit
      windowSize = Duration.ofSeconds(10)
    )
    val idempotencyStore = InMemoryIdempotencyStore()
    val processor = RequestProcessor(rateLimiter, idempotencyStore)
    
    // First request - consumes 1 quota
    processor.process("req-3", "user-3", Duration.ofMinutes(5)) { () =>
      createResponse("first")
    }
    
    // Second unique request - consumes 1 quota (now at limit)
    processor.process("req-4", "user-3", Duration.ofMinutes(5)) { () =>
      createResponse("second")
    }
    
    // Third unique request - should be rate limited
    val result3 = processor.process("req-5", "user-3", Duration.ofMinutes(5)) { () =>
      createResponse("third")
    }
    
    assert(result3.isInstanceOf[RateLimited], "Should be rate limited")
    
    // But duplicate of first request should still work (no quota consumed)
    val result4 = processor.process("req-3", "user-3", Duration.ofMinutes(5)) { () =>
      createResponse("duplicate")
    }
    
    result4 match {
      case Duplicate(response) =>
        assertEquals(response.body, "first")
        
      case _ =>
        fail(s"Duplicate should bypass rate limit, got $result4")
    }
  }
  
  test("rate limited request - rejects without processing") {
    val rateLimiter = SlidingWindowRateLimiter(
      maxRequests = 1, // Only 1 request allowed
      windowSize = Duration.ofSeconds(10)
    )
    val idempotencyStore = InMemoryIdempotencyStore()
    val processor = RequestProcessor(rateLimiter, idempotencyStore)
    
    var processedCount = 0
    
    // First request - allowed
    processor.process("req-6", "user-4", Duration.ofMinutes(5)) { () =>
      processedCount += 1
      createResponse("first")
    }
    
    // Second request - rate limited
    val result = processor.process("req-7", "user-4", Duration.ofMinutes(5)) { () =>
      processedCount += 1
      createResponse("second")
    }
    
    result match {
      case RateLimited(retryAfter) =>
        assert(retryAfter.getSeconds > 0, "Should have positive retry-after")
        assertEquals(processedCount, 1, "Should NOT process rate limited request")
        
      case _ =>
        fail(s"Expected RateLimited, got $result")
    }
  }
  
  test("concurrent requests with same idempotency key - exactly one processes") {
    // Use a rate limiter that allows all 20 requests through
    val rateLimiter = SlidingWindowRateLimiter(
      maxRequests = 100,
      windowSize = Duration.ofSeconds(10)
    )
    val idempotencyStore = InMemoryIdempotencyStore()
    val processor = RequestProcessor(rateLimiter, idempotencyStore)
    var processedCount = 0
    val lock = new Object()
    
    // Spawn 20 concurrent requests with same idempotency key
    val futures = (1 to 20).map { i =>
      Future {
        processor.process(
          idempotencyKey = "concurrent-req",
          rateLimitKey = "user-5",
          ttl = Duration.ofMinutes(5)
        ) { () =>
          lock.synchronized {
            processedCount += 1
          }
          Thread.sleep(10) // Simulate processing time
          createResponse(s"result-$i")
        }
      }
    }
    
    val results = Await.result(Future.sequence(futures), 10.seconds)
    
    // Exactly one should be Processed
    val processedResults = results.collect { case p: Processed => p }
    val duplicateResults = results.collect { case d: Duplicate => d }
    
    assertEquals(processedResults.size, 1, "Exactly one should process")
    assertEquals(duplicateResults.size, 19, "Others should be duplicates")
    assertEquals(processedCount, 1, "Business logic should execute exactly once")
    
    // All results should have the same response body
    val allBodies = results.collect {
      case Processed(r) => r.body
      case Duplicate(r) => r.body
    }
    
    assertEquals(allBodies.distinct.size, 1, "All should return same response")
  }
  
  test("different idempotency keys are independent") {
    val processor = createProcessor()
    
    val result1 = processor.process("key-1", "user-6", Duration.ofMinutes(5)) { () =>
      createResponse("response-1")
    }
    
    val result2 = processor.process("key-2", "user-6", Duration.ofMinutes(5)) { () =>
      createResponse("response-2")
    }
    
    // Both should be Processed (different keys)
    assert(result1.isInstanceOf[Processed])
    assert(result2.isInstanceOf[Processed])
    
    result1 match {
      case Processed(r) => assertEquals(r.body, "response-1")
      case _ => fail("Expected Processed")
    }
    
    result2 match {
      case Processed(r) => assertEquals(r.body, "response-2")
      case _ => fail("Expected Processed")
    }
  }
  
  test("expired idempotency entry allows reprocessing") {
    val processor = createProcessor()
    var processedCount = 0
    
    // First request with short TTL
    val result1 = processor.process(
      idempotencyKey = "expiring-req",
      rateLimitKey = "user-7",
      ttl = Duration.ofMillis(500)
    ) { () =>
      processedCount += 1
      createResponse("first")
    }
    
    assert(result1.isInstanceOf[Processed])
    assertEquals(processedCount, 1)
    
    // Wait for expiry
    Thread.sleep(600)
    
    // Same key should now process again
    val result2 = processor.process(
      idempotencyKey = "expiring-req",
      rateLimitKey = "user-7",
      ttl = Duration.ofMinutes(5)
    ) { () =>
      processedCount += 1
      createResponse("second")
    }
    
    result2 match {
      case Processed(r) =>
        assertEquals(r.body, "second")
        assertEquals(processedCount, 2, "Should process again after expiry")
        
      case _ =>
        fail(s"Expected Processed after expiry, got $result2")
    }
  }
  
  test("race condition - concurrent processing stores first response") {
    val rateLimiter = SlidingWindowRateLimiter(100, Duration.ofSeconds(10))
    val idempotencyStore = InMemoryIdempotencyStore()
    val processor = RequestProcessor(rateLimiter, idempotencyStore)
    
    // Simulate slow processing with concurrent requests
    val futures = (1 to 10).map { i =>
      Future {
        processor.process(
          idempotencyKey = "race-req",
          rateLimitKey = "user-8",
          ttl = Duration.ofMinutes(5)
        ) { () =>
          Thread.sleep(50) // All requests processing concurrently
          createResponse(s"response-$i")
        }
      }
    }
    
    val results = Await.result(Future.sequence(futures), 10.seconds)
    
    // One Processed, rest Duplicate
    val processedCount = results.count(_.isInstanceOf[Processed])
    val duplicateCount = results.count(_.isInstanceOf[Duplicate])
    
    assertEquals(processedCount, 1, "Exactly one should complete processing")
    assertEquals(duplicateCount, 9, "Others should get duplicate")
    
    // All should return the same response
    val bodies = results.collect {
      case Processed(r) => r.body
      case Duplicate(r) => r.body
    }.distinct
    
    assertEquals(bodies.size, 1, "All should have same response")
  }
  
  test("validation - null parameters rejected") {
    val processor = createProcessor()
    
    intercept[IllegalArgumentException] {
      processor.process(null, "user", Duration.ofMinutes(5)) { () =>
        createResponse()
      }
    }
    
    intercept[IllegalArgumentException] {
      processor.process("key", null, Duration.ofMinutes(5)) { () =>
        createResponse()
      }
    }
    
    intercept[IllegalArgumentException] {
      processor.process("key", "user", null) { () =>
        createResponse()
      }
    }
    
    intercept[IllegalArgumentException] {
      processor.process("key", "user", Duration.ofMinutes(5))(null)
    }
  }
}

/**
 * Tests for the alternative RateLimitFirstProcessor
 */
class RateLimitFirstProcessorSpec extends FunSuite {
  
  def createResponse(body: String = "success"): StoredResponse = {
    StoredResponse(
      status = 200,
      body = body,
      headers = Map("Content-Type" -> "application/json"),
      createdAt = Instant.now()
    )
  }
  
  test("RateLimitFirst - duplicate requests consume rate limit quota") {
    val rateLimiter = SlidingWindowRateLimiter(
      maxRequests = 2, // Very low limit
      windowSize = Duration.ofSeconds(10)
    )
    val idempotencyStore = InMemoryIdempotencyStore()
    val processor = RateLimitFirstProcessor(rateLimiter, idempotencyStore)
    
    // First request - consumes 1 quota
    val result1 = processor.process("req-1", "user-1", Duration.ofMinutes(5)) { () =>
      createResponse("first")
    }
    
    assert(result1.isInstanceOf[Processed])
    
    // Duplicate request - STILL consumes 1 quota (now at limit)
    val result2 = processor.process("req-1", "user-1", Duration.ofMinutes(5)) { () =>
      createResponse("duplicate")
    }
    
    result2 match {
      case Duplicate(_) =>
        // Got duplicate, but consumed quota
        
      case _ =>
        fail(s"Expected Duplicate, got $result2")
    }
    
    // Third request (new key) - should be rate limited
    val result3 = processor.process("req-2", "user-1", Duration.ofMinutes(5)) { () =>
      createResponse("third")
    }
    
    assert(result3.isInstanceOf[RateLimited], 
      "Should be rate limited because duplicates consumed quota")
  }
  
  test("RateLimitFirst vs IdempotencyFirst - quota consumption comparison") {
    // Setup: limit of 3 requests
    val rateLimiter1 = SlidingWindowRateLimiter(3, Duration.ofSeconds(10))
    val rateLimiter2 = SlidingWindowRateLimiter(3, Duration.ofSeconds(10))
    val store1 = InMemoryIdempotencyStore()
    val store2 = InMemoryIdempotencyStore()
    
    val idempotencyFirst = RequestProcessor(rateLimiter1, store1)
    val rateLimitFirst = RateLimitFirstProcessor(rateLimiter2, store2)
    
    // Scenario: 1 unique request + 3 duplicates
    
    // IdempotencyFirst processor
    idempotencyFirst.process("req-1", "user-A", Duration.ofMinutes(5)) { () =>
      createResponse("first")
    }
    idempotencyFirst.process("req-1", "user-A", Duration.ofMinutes(5)) { () =>
      createResponse("dup1")
    }
    idempotencyFirst.process("req-1", "user-A", Duration.ofMinutes(5)) { () =>
      createResponse("dup2")
    }
    idempotencyFirst.process("req-1", "user-A", Duration.ofMinutes(5)) { () =>
      createResponse("dup3")
    }
    
    // Should still have quota for new request (only 1 consumed)
    val resultIdempFirst = idempotencyFirst.process("req-2", "user-A", Duration.ofMinutes(5)) { () =>
      createResponse("second")
    }
    assert(resultIdempFirst.isInstanceOf[Processed], 
      "IdempotencyFirst should have quota remaining")
    
    // RateLimitFirst processor - same scenario
    rateLimitFirst.process("req-1", "user-B", Duration.ofMinutes(5)) { () =>
      createResponse("first")
    }
    rateLimitFirst.process("req-1", "user-B", Duration.ofMinutes(5)) { () =>
      createResponse("dup1")
    }
    rateLimitFirst.process("req-1", "user-B", Duration.ofMinutes(5)) { () =>
      createResponse("dup2")
    }
    
    // Now at limit (3 requests, even though 2 were duplicates)
    val resultRateLimitFirst = rateLimitFirst.process("req-2", "user-B", Duration.ofMinutes(5)) { () =>
      createResponse("second")
    }
    assert(resultRateLimitFirst.isInstanceOf[RateLimited],
      "RateLimitFirst should be at limit due to duplicates")
  }
}