/**
 * Idempotency Store Types for Cloudflare Workers
 *
 * Ensures requests with the same idempotency key produce exactly one result
 */

/**
 * Represents a stored response in the idempotency store
 */
export interface StoredResponse {
  // HTTP status code
  status: number;

  // Response body
  body: string;

  // HTTP headers
  headers: Record<string, string>;

  // Timestamp when the response was created (milliseconds since epoch)
  createdAt: number;
}

/**
 * Result of attempting to store a response in the idempotency store
 */
export type IdempotencyResult =
  | { type: "Stored" }
  | { type: "AlreadyExists"; response: StoredResponse };

/**
 * Helper constructors for IdempotencyResult
 */
export const IdempotencyResult = {
  Stored: (): IdempotencyResult => ({ type: "Stored" }),

  AlreadyExists: (response: StoredResponse): IdempotencyResult => ({
    type: "AlreadyExists",
    response,
  }),
};

/**
 * Idempotency store interface
 *
 * Semantics:
 * - First writer wins
 * - Duplicate keys return stored response
 * - Expired keys may be reused
 * - No partial or in-progress state allowed
 */
export interface IdempotencyStore {
  /**
   * Retrieve a stored response for the given key
   *
   * @param key The idempotency key
   * @returns Promise<StoredResponse | null> - response if exists and not expired, null otherwise
   */
  get(key: string): Promise<StoredResponse | null>;

  /**
   * Store a response only if the key does not already exist
   *
   * This operation is atomic - concurrent calls with the same key will result
   * in exactly one successful store
   *
   * @param key The idempotency key
   * @param response The response to store
   * @param ttlSeconds Time-to-live in seconds
   * @returns Promise<IdempotencyResult>
   */
  putIfAbsent(
    key: string,
    response: StoredResponse,
    ttlSeconds: number
  ): Promise<IdempotencyResult>;
}

/**
 * Internal storage format in KV
 *
 * Stored as: `idempotency:{key}~ -> KVStoredEntry
 */
export interface KVStoredEntry {
  response: StoredResponse;
  expiryTime: number; // milliseconds since epoch
}
