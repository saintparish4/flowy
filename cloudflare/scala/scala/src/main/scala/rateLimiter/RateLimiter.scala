package rateLimiter

import java.time.Instant

/**
 * Rate limiter that determines whether a request identified by a key 
 * is allowed based on a sliding time window
 */
trait RateLimiter {
    /**
      * Determines if a request is allowed for the given key at the given time
      * 
      * @param key The identifier for rate limiting 
      * @param now The current time 
      * @return RateLimitDecision indicating whether the request is allowed or rejected 
      */
    def allow(key: String, now: Instant): RateLimitDecision  
}