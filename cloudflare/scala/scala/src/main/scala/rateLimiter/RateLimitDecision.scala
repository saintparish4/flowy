package rateLimiter

import java.time.Duration 

/**
  * Represents the decision made by the rate limiter 
*/
sealed trait RateLimitDecision 

/**
  * Request is allowed to proceed 
*/
case object Allow extends RateLimitDecision 

/**
  * Request is rejected due to rate limit 
  * 
  * @param retryAfter Duration to wait before the request can be retried 
*/
case class Rejected(retryAfter: Duration) extends RateLimitDecision 