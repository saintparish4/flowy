package rateLimiter

import java.time.{Duration, Instant} 
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import scala.annotation.tailrec
import scala.jdk.CollectionConverters._

/**
  * Sliding window rate limiter implementation using fine-grained per-key synchronization 
  * 
  * Thread-safe without global locks, Uses ConcurrentHashMap for key isolation and
  * AtomicReference with compare-and-swap FOR per-key updates 
  * 
  * @param maxRequests Maximum number of requests allowed within the window 
  * @param windowSize Duration of the sliding window 
  */
class SlidingWindowRateLimiter(
    maxRequests: Int, 
    windowSize: Duration 
) extends RateLimiter {

    require(maxRequests > 0, "maxRequests must be positive") 
    require(!windowSize.isNegative && !windowSize.isZero, "windowSize must be positive") 

    // Per-key storage: each key has an atomic reference to a vector of timestamps 
    private val keyTimestamps = new ConcurrentHashMap[String, AtomicReference[Vector[Instant]]]()

    /**
   * Determines if a request is allowed using a sliding window algorithm.
   * 
   * Algorithm:
   * 1. Get or create the key's timestamp vector
   * 2. Remove timestamps older than (now - windowSize)
   * 3. If count < maxRequests: add current timestamp, return Allowed
   * 4. Else: compute retryAfter as time until oldest timestamp expires
   * 
   * Thread-safety: Uses AtomicReference with compare-and-swap for lock-free updates.
   */
  override def allow(key: String, now: Instant): RateLimitDecision = {
    require(key != null, "key cannot be null") 
    require(now != null, "now cannot be null") 

    // Get or create atomic reference for this key 
    val atomicTimestamps = keyTimestamps.computeIfAbsent(
        key, 
        _ => new AtomicReference(Vector.empty[Instant]) 
    )

    // Sliding window start time 
    val windowStart = now.minus(windowSize) 

    // Compare-and-swap loop for thread-safe update 
    @tailrec 
    def updateTimestamps(): RateLimitDecision = {
        val currentTimestamps = atomicTimestamps.get() 

        // Remove timestamps older than window 
        val validTimestamps = currentTimestamps.filter(_.isAfter(windowStart)) 

        if (validTimestamps.size < maxRequests) {
            // Under limit - try to add this timestamp 
            val newTimestamps = validTimestamps :+ now 

            if (atomicTimestamps.compareAndSet(currentTimestamps, newTimestamps)) {
                // Successfully added - request is allowed 
                Allowed 
            } else {
                // Another thread modified the timestamps - retry 
                updateTimestamps()  
            }
        } else {
            // Over limit - compute retry-after 
            // The oldest timestamp will expire first 
            val oldestTimestamp = validTimestamps.head 
            val expiresAt = oldestTimestamp.plus(windowSize) 
            val retryAfter = Duration.between(now, expiresAt) 

            // Update to remove stale timestamps (don't add new one) 
            // This is an optimization to keep the vector clean 
            atomicTimestamps.compareAndSet(currentTimestamps, validTimestamps) 

            Rejected(retryAfter)  
        }
    }

    updateTimestamps()  
  } 

  /**
    * Clear all stored timestamps 
    * Useful for testing 
    */
    def clear(): Unit = {
        KeyTimestamps.clear() 
    }
}

object SlidingWindowRateLimiter {
    /**
      * Create a rate limiter with the given configuration 
      * 
      * @param maxRequests Maximum requests per window 
      * @param windowSize Window duration 
      * @return A new SlidingWindowRateLimiter instance 
      */
      def apply(maxRequests: Int, windowSize: Duration): SlidingWindowRateLimiter = {
        new SlidingWindowRateLimiter(maxRequests, windowSize) 
      }
}