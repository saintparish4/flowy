package composition

import rateLimiter.{RateLimiter, RateLimitDecision, Allow, Rejected}
import idempotency.{IdempotencyStore, IdempotencyResult, StoredResponse, AlreadyExists, Stored}
import java.time.{Duration, Instant}
import java.util.concurrent.ConcurrentHashMap

/**
  * Result of request processing 
  */
sealed trait ProcessingResult 

/**
  * Request processed successfully (first attempt) 
  */
case class Processed(response: StoredResponse) extends ProcessingResult 

/**
  * Request was a duplicate - returning cached response 
  */
case class Duplicate(response: StoredResponse) extends ProcessingResult  

/**
  * Request was rate limited 
  */
case class RateLimited(retryAfter: Duration) extends ProcessingResult  

/**
  * Request Processor that composes rate limiting and idempotency 
  * Execution Flow:
    ```
  * Request -> 
  *   Idempotency Check -> 
  *     Rate Limit Check -> 
  *       Process -> 
  *         Store Response
  * ``` 
  * 
  * This flow prioritizes idempotency over rate limiting:
  * - Duplicate requests return cached response immediately (no rate limit consumed) 
  * - Only new requests consume rate limit quota 
  * - Guarantees exactly-once processing even during rate limit events
  * 
  * @param rateLimiter The rate limiter to use 
  * @param idempotencyStore The idempotency store to use 
  */
class RequestProcessor(
    rateLimiter: RateLimiter, 
    idempotencyStore: IdempotencyStore 
) {
    // Per-key locks for fine-grained synchronization
    // This ensures only one thread processes per idempotency key
    private val processingLocks = new ConcurrentHashMap[String, Object]()

    /**
     * Process a request with rate limiting and idempotency.
     * 
     * Flow:
     * 1. Check idempotency store for existing response
     * 2. If found, return it immediately (skip rate limit)
     * 3. If not found, check rate limit
     * 4. If rate limited, reject
     * 5. If allowed, process request
     * 6. Store response in idempotency store
     * 
     * @param idempotencyKey Unique key for idempotency
     * @param rateLimitKey Key for rate limiting (e.g., API key, user ID)
     * @param ttl How long to store the response
     * @param processor Function that processes the request and returns a response
     * @return ProcessingResult indicating what happened
     */
    def process(
        idempotencyKey: String,
        rateLimitKey: String, 
        ttl: Duration 
    )(
        processor: () => StoredResponse 
    ): ProcessingResult = {
        require(idempotencyKey != null, "idempotencyKey cannot be null") 
        require(rateLimitKey != null, "rateLimitKey cannot be null") 
        require(ttl != null, "ttl cannot be null") 
        require(processor != null, "processor cannot be null") 

        val now = Instant.now() 

        // Step 1: Check for existing response (idempotency check)
        idempotencyStore.get(idempotencyKey) match {
            case Some(cachedResponse) => 
                // Duplicate request - return cached response 
                // This does NOT consume rate limit quota 
                return Duplicate(cachedResponse) 

            case None => 
                // New request - continue to rate limiting 
        }

        // Step 2: Check rate limit 
        rateLimiter.allow(rateLimitKey, now) match {
            case Allow => 
                // Rate limit OK - continue

            case Rejected(retryAfter) => 
                // Rate limited - reject without processing 
                return RateLimited(retryAfter)
        }

        // Step 2.5: Use per-key lock to ensure only one thread processes per idempotency key
        // Get or create a lock for this specific idempotency key
        val lock = processingLocks.computeIfAbsent(idempotencyKey, _ => new Object())
        
        // Synchronize on the per-key lock to ensure only one thread processes
        lock.synchronized {
            // Double-check idempotency inside the lock (another thread may have stored while we waited)
            idempotencyStore.get(idempotencyKey) match {
                case Some(cachedResponse) => 
                    // Another request stored it - return cached response
                    return Duplicate(cachedResponse)

                case None => 
                    // Still not stored - we have the lock, so we can safely process
            }

            // Step 3: Process the request 
            // We hold the per-key lock, so no other thread can process the same key
            val response = processor()

            // Step 4: Store in idempotency store 
            // This should always succeed since we hold the lock, but we handle the case anyway
            return idempotencyStore.putIfAbsent(idempotencyKey, response, ttl) match {
                case Stored => 
                    // We successfully stored it 
                    Processed(response) 

                case AlreadyExists(existingResponse) => 
                    // This shouldn't happen since we hold the lock, but handle it gracefully
                    // Return the existing response 
                    Duplicate(existingResponse) 
            }
        }
    }
}

object RequestProcessor {
    /**
      * Create a request processor with the given components
      */
    def apply(
        rateLimiter: RateLimiter, 
        idempotencyStore: IdempotencyStore 
    ): RequestProcessor = {
        new RequestProcessor(rateLimiter, idempotencyStore) 
    }
}

/**
 * Alternative composition: Rate Limit First
 * 
 * This alternative checks rate limits before idempotency.
 * 
 * Flow:
 * ```
 * Request →
 *   Rate Limit Check →
 *     Idempotency Check →
 *       Process →
 *         Store Response
 * ```
 * 
 * Tradeoffs:
 * 
 * Pros:
 * - Protects against abuse via duplicate keys
 * - Rate limit enforced even on retries
 * - Simpler to reason about rate limit quotas
 * 
 * Cons:
 * - Duplicate requests consume rate limit quota
 * - Client may be rate limited even when returning cached response
 * - Less efficient under retry storms
 * 
 * Use when:
 * - Rate limit quota is the primary concern
 * - You want to limit retries themselves
 * - Protection from idempotency key abuse is needed
 */
class RateLimitFirstProcessor(
    rateLimiter: RateLimiter,
    idempotencyStore: IdempotencyStore
) {

    def process(
        idempotencyKey: String,
        rateLimitKey: String,
        ttl: Duration
    )(
        processor: () => StoredResponse
    ): ProcessingResult = {
        val now = Instant.now()

        // Step 1: Check rate limit FIRST
        rateLimiter.allow(rateLimitKey, now) match {
            case Allow => 
                // Rate limit OK - continue

            case Rejected(retryAfter) => 
                // Rate limited - reject even for duplicates
                return RateLimited(retryAfter)
        }

        // Step 2: Check idempotency
        idempotencyStore.get(idempotencyKey) match {
            case Some(cachedResponse) => 
                // Duplicate - but we already consumed rate limit quota
                return Duplicate(cachedResponse)

            case None => 
                // New request - continue
        }

        // Step 3: Process
        val response = processor()

        // Step 4: Store
        idempotencyStore.putIfAbsent(idempotencyKey, response, ttl) match {
            case Stored => 
                Processed(response)

            case AlreadyExists(existingResponse) => 
                Duplicate(existingResponse)
        }
    }
}

object RateLimitFirstProcessor {
    def apply(
        rateLimiter: RateLimiter,
        idempotencyStore: IdempotencyStore
    ): RateLimitFirstProcessor = {
        new RateLimitFirstProcessor(rateLimiter, idempotencyStore)
    }
}