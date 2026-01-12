/**
 * Cloudflare Workers Rate Limiter & Idempotency Store
 * 
 * Token Bucket implementation optimized for KV storage.
 * 
 * Usage:
 * ```typescript
 * import {
 *   createTokenBucketRateLimiter,
 *   createIdempotencyStore,
 *   createKVLock
 * } from './index';
 * 
 * export default {
 *   async fetch(request, env) {
 *     const rateLimiter = createTokenBucketRateLimiter({
 *       capacity: 100,
 *       refillRate: 10,
 *       kv: env.RATE_LIMIT_KV
 *     });
 *     
 *     const idempotencyStore = createIdempotencyStore(env.RATE_LIMIT_KV);
 *     
 *     // Use components...
 *   }
 * }
 * ```
 */

// Rate Limiter
export {
    TokenBucketRateLimiter,
    createTokenBucketRateLimiter
  } from './rateLimiter/token-bucket-rate-limiter';
  
  export type {
    RateLimiter,
    RateLimitDecision,
    TokenBucketState,
    TokenBucketConfig,
    RateLimiterType
  } from './rateLimiter/types';
  
  export { RateLimitDecision as RateLimitDecisionHelper } from './rateLimiter/types';
  
  // Idempotency Store
  export {
    KVIdempotencyStore,
    createIdempotencyStore
  } from './idempotency/kv-idempotency-store';
  
  export type {
    IdempotencyStore,
    StoredResponse,
    IdempotencyResult,
    KVStoredEntry
  } from './idempotency/types';
  
  export { IdempotencyResult as IdempotencyResultHelper } from './idempotency/types';
  
  // Utilities
  export {
    KVLock,
    createKVLock
  } from './utils/kv-lock';
  
  export type {
    LockOptions,
    LockResult
  } from './utils/kv-lock';
  
  // Configuration
  export type {
    Env,
    SecurityConfig
  } from './types/index_s';
  
  export {
    parseSecurityConfig,
    DEFAULT_CONFIG
  } from './types/index_s';