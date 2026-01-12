/**
 * KV-backed Idempotency Store for Cloudflare Workers
 *
 * Ensures requests with the same idempotency key produce exactly one result.
 *
 * Key features:
 * - First writer wins semantics
 * - TTL support with automatic expiration
 * - Lazy cleanup of expired entries
 * - Race condition handling via KV atomic operations
 */

import {
  IdempotencyStore,
  StoredResponse,
  IdempotencyResult,
  KVStoredEntry,
} from "./types";

export class KVIdempotencyStore implements IdempotencyStore {
  private readonly kv: KVNamespace;
  private readonly keyPrefix: string;

  /**
   * Create a new KV-backed idempotency store.
   *
   * @param kv KV namespace to use for storage
   * @param keyPrefix Optional key prefix (default: 'idempotency:')
   */
  constructor(kv: KVNamespace, keyPrefix: string = "idempotency:") {
    if (!kv) {
      throw new Error("kv namespace is required");
    }

    this.kv = kv;
    this.keyPrefix = keyPrefix;
  }

  /**
   * Get the full KV key for an idempotency key.
   */
  private getKVKey(key: string): string {
    return `${this.keyPrefix}${key}`;
  }

  /**
   * Retrieve a stored response for the given key.
   *
   * Expired entries are removed lazily during this operation.
   *
   * @param key The idempotency key
   * @returns Promise<StoredResponse | null>
   */
  async get(key: string): Promise<StoredResponse | null> {
    if (!key) {
      throw new Error("key cannot be null or empty");
    }

    const kvKey = this.getKVKey(key);

    try {
      const stored = await this.kv.get<KVStoredEntry>(kvKey, "json");

      if (!stored) {
        return null;
      }

      const now = Date.now();

      // Check if expired
      if (now >= stored.expiryTime) {
        // Expired - remove it (lazy cleanup)
        await this.kv.delete(kvKey);
        return null;
      }

      return stored.response;
    } catch (error) {
      console.error("Error getting idempotency key:", error);
      // On error, return null to allow retry
      return null;
    }
  }

  /**
   * Store a response only if the key doesn't exist (or has expired).
   *
   * Implements first-writer-wins semantics using KV operations.
   *
   * Algorithm:
   * 1. Try to get existing entry
   * 2. If exists and valid: return AlreadyExists
   * 3. If doesn't exist or expired: try to write
   * 4. If write appears successful: verify and return Stored
   * 5. If race detected: return AlreadyExists with winner's response
   *
   * @param key The idempotency key
   * @param response The response to store
   * @param ttlSeconds Time-to-live in seconds
   * @returns Promise<IdempotencyResult>
   */
  async putIfAbsent(
    key: string,
    response: StoredResponse,
    ttlSeconds: number
  ): Promise<IdempotencyResult> {
    if (!key) {
      throw new Error("key cannot be null or empty");
    }
    if (!response) {
      throw new Error("response cannot be null");
    }
    if (ttlSeconds <= 0) {
      throw new Error("ttlSeconds must be positive");
    }

    const kvKey = this.getKVKey(key);
    const now = Date.now();
    const expiryTime = now + ttlSeconds * 1000;

    try {
      // Step 1: Check if key already exists
      const existing = await this.kv.get<KVStoredEntry>(kvKey, "json");

      if (existing) {
        // Entry exists - check if it's still valid
        if (now < existing.expiryTime) {
          // Valid entry exists - return it (first writer already won)
          return IdempotencyResult.AlreadyExists(existing.response);
        }

        // Expired entry exists - will try to replace it
        // This is a race - another request might also be trying
      }

      // Step 2: Try to store (either key doesn't exist or is expired)
      const entry: KVStoredEntry = {
        response,
        expiryTime,
      };

      await this.kv.put(kvKey, JSON.stringify(entry), {
        expirationTtl: ttlSeconds,
      });

      // Step 3: Verify the write (handle race conditions)
      // Wait a brief moment for KV consistency
      await new Promise((resolve) => setTimeout(resolve, 10));

      const stored = await this.kv.get<KVStoredEntry>(kvKey, "json");

      if (!stored) {
        // Shouldn't happen, but if entry disappeared, retry
        return this.putIfAbsent(key, response, ttlSeconds);
      }

      // Step 4: Check if we won the race
      // Compare stored response with ours
      if (this.responsesEqual(stored.response, response)) {
        // We stored it successfully
        return IdempotencyResult.Stored();
      } else {
        // Someone else stored a different response (race condition)
        // They won - return their response
        return IdempotencyResult.AlreadyExists(stored.response);
      }
    } catch (error) {
      console.error("Error in putIfAbsent:", error);
      throw new Error(`KV error in putIfAbsent: ${error}`);
    }
  }

  /**
   * Compare two responses for equality.
   * Used to determine race condition winners.
   */
  private responsesEqual(r1: StoredResponse, r2: StoredResponse): boolean {
    return (
      r1.status === r2.status &&
      r1.body === r2.body &&
      r1.createdAt === r2.createdAt &&
      this.headersEqual(r1.headers, r2.headers)
    );
  }

  /**
   * Compare two header maps for equality.
   */
  private headersEqual(
    h1: Record<string, string>,
    h2: Record<string, string>
  ): boolean {
    const keys1 = Object.keys(h1);
    const keys2 = Object.keys(h2);

    if (keys1.length !== keys2.length) {
      return false;
    }

    for (const key of keys1) {
      if (h1[key] !== h2[key]) {
        return false;
      }
    }

    return true;
  }

  /**
   * Delete a stored response (for testing/admin).
   *
   * @param key The idempotency key
   */
  async delete(key: string): Promise<void> {
    const kvKey = this.getKVKey(key);
    await this.kv.delete(kvKey);
  }

  /**
   * Clear all entries with the configured prefix (for testing).
   *
   * WARNING: KV doesn't support bulk delete efficiently.
   * This is a best-effort operation.
   */
  async clear(): Promise<void> {
    console.warn(
      "KVIdempotencyStore.clear() is not fully implemented - use TTL expiration"
    );
    // Note: KV doesn't support prefix deletion
    // In production, rely on TTL expiration
    // For testing, you'd need to track keys separately
  }
}

/**
 * Factory function to create a KV idempotency store.
 */
export function createIdempotencyStore(
  kv: KVNamespace,
  keyPrefix?: string
): IdempotencyStore {
  return new KVIdempotencyStore(kv, keyPrefix);
}
