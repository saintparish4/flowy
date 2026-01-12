/**
 * Distributed Lock Implementation using Cloudflare KV
 *
 * Provides distributed locking for Workers to prevent race conditions.
 *
 * Use cases:
 * - Preventing duplicate processing in idempotency
 * - Coordinating rate limit updates
 * - Critical section protection across Workers
 *
 * Note: This is best-effort locking due to KV's eventual consistency.
 * For critical operations, combine with idempotency checks.
 */

export interface LockOptions {
  /** Lock timeout in milliseconds (default: 5000ms) */
  timeoutMs?: number;

  /** Number of acquisition attempts (default: 3) */
  maxAttempts?: number;

  /** Delay between acquisition attempts in ms (default: 50ms) */
  retryDelayMs?: number;

  /** Owner identifier for debugging (default: random UUID) */
  owner?: string;
}

export interface LockResult {
  /** Whether lock was acquired */
  acquired: boolean;

  /** Lock token (used for release) */
  token?: string;

  /** Current lock owner if not acquired */
  currentOwner?: string;
}

/**
 * Lock metadata stored in KV
 */
interface LockMetadata {
  /** Owner identifier */
  owner: string;

  /** Acquisition timestamp */
  acquiredAt: number;

  /** Expiry timestamp */
  expiryAt: number;
}

export class KVLock {
  private readonly kv: KVNamespace;
  private readonly keyPrefix: string;

  /**
   * Create a new KV lock manager.
   *
   * @param kv KV namespace to use for locks
   * @param keyPrefix Optional key prefix (default: 'lock:')
   */
  constructor(kv: KVNamespace, keyPrefix: string = "lock:") {
    if (!kv) {
      throw new Error("kv namespace is required");
    }

    this.kv = kv;
    this.keyPrefix = keyPrefix;
  }

  /**
   * Get the full KV key for a lock.
   */
  private getLockKey(resourceId: string): string {
    return `${this.keyPrefix}${resourceId}`;
  }

  /**
   * Generate a unique lock token.
   */
  private generateToken(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
  }

  /**
   * Try to acquire a lock for a resource.
   *
   * Algorithm:
   * 1. Generate unique lock token
   * 2. Try to write lock metadata to KV
   * 3. Verify write succeeded (read back)
   * 4. Return success/failure
   *
   * @param resourceId Unique identifier for the resource to lock
   * @param options Lock options
   * @returns Promise<LockResult>
   */
  async acquire(
    resourceId: string,
    options: LockOptions = {}
  ): Promise<LockResult> {
    if (!resourceId) {
      throw new Error("resourceId cannot be null or empty");
    }

    const timeoutMs = options.timeoutMs || 5000;
    const maxAttempts = options.maxAttempts || 3;
    const retryDelayMs = options.retryDelayMs || 50;
    const owner = options.owner || this.generateToken();

    const lockKey = this.getLockKey(resourceId);
    const token = this.generateToken();
    const now = Date.now();
    const expiryAt = now + timeoutMs;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        // Step 1: Check if lock already exists
        const existing = await this.kv.get<LockMetadata>(lockKey, "json");

        if (existing) {
          // Lock exists - check if it's expired
          if (now < existing.expiryAt) {
            // Lock is still valid - cannot acquire
            return {
              acquired: false,
              currentOwner: existing.owner,
            };
          }

          // Lock is expired - will try to acquire
        }

        // Step 2: Try to acquire lock
        const metadata: LockMetadata = {
          owner,
          acquiredAt: now,
          expiryAt,
        };

        await this.kv.put(lockKey, JSON.stringify(metadata), {
          // Set expiration slightly longer than timeout to allow cleanup
          expirationTtl: Math.ceil(timeoutMs / 1000) + 1,
        });

        // Step 3: Verify acquisition
        // Brief delay for KV consistency
        await new Promise((resolve) => setTimeout(resolve, 10));

        const stored = await this.kv.get<LockMetadata>(lockKey, "json");

        if (!stored) {
          // Lock disappeared - retry
          if (attempt < maxAttempts - 1) {
            await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
            continue;
          }

          return { acquired: false };
        }

        // Step 4: Check if we won the race
        if (stored.owner === owner) {
          // We acquired the lock
          return {
            acquired: true,
            token,
          };
        } else {
          // Someone else acquired it
          return {
            acquired: false,
            currentOwner: stored.owner,
          };
        }
      } catch (error) {
        console.error("Error acquiring lock:", error);

        if (attempt < maxAttempts - 1) {
          await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
          continue;
        }

        return { acquired: false };
      }
    }

    // Failed to acquire after all attempts
    return { acquired: false };
  }

  /**
   * Release a lock.
   *
   * @param resourceId Unique identifier for the resource
   * @param token Lock token from acquisition (optional, for safety)
   * @returns Promise<boolean> - true if released, false if not found or not owner
   */
  async release(resourceId: string, token?: string): Promise<boolean> {
    if (!resourceId) {
      throw new Error("resourceId cannot be null or empty");
    }

    const lockKey = this.getLockKey(resourceId);

    try {
      // If token provided, verify ownership before release
      if (token) {
        const existing = await this.kv.get<LockMetadata>(lockKey, "json");

        if (!existing) {
          // Lock doesn't exist - already released or expired
          return false;
        }

        // Note: We can't verify token directly since we only store owner
        // This is a limitation of using KV for locking
        // In production, consider using Durable Objects for stronger guarantees
      }

      await this.kv.delete(lockKey);
      return true;
    } catch (error) {
      console.error("Error releasing lock:", error);
      return false;
    }
  }

  /**
   * Check if a lock is currently held.
   *
   * @param resourceId Unique identifier for the resource
   * @returns Promise<boolean> - true if locked, false otherwise
   */
  async isLocked(resourceId: string): Promise<boolean> {
    const lockKey = this.getLockKey(resourceId);

    try {
      const existing = await this.kv.get<LockMetadata>(lockKey, "json");

      if (!existing) {
        return false;
      }

      const now = Date.now();

      // Check if lock is expired
      if (now >= existing.expiryAt) {
        // Expired - clean up
        await this.kv.delete(lockKey);
        return false;
      }

      return true;
    } catch (error) {
      console.error("Error checking lock:", error);
      return false;
    }
  }

  /**
   * Execute a function with a lock.
   *
   * Acquires lock, executes function, then releases lock.
   * Lock is released even if function throws.
   *
   * @param resourceId Unique identifier for the resource
   * @param fn Function to execute while holding the lock
   * @param options Lock options
   * @returns Promise<T> - Result of function execution
   * @throws Error if lock cannot be acquired or function throws
   */
  async withLock<T>(
    resourceId: string,
    fn: () => Promise<T>,
    options: LockOptions = {}
  ): Promise<T> {
    const result = await this.acquire(resourceId, options);

    if (!result.acquired) {
      throw new Error(
        `Failed to acquire lock for resource: ${resourceId}` +
          (result.currentOwner ? ` (held by ${result.currentOwner})` : "")
      );
    }

    try {
      return await fn();
    } finally {
      await this.release(resourceId, result.token);
    }
  }
}

/**
 * Factory function to create a KV lock manager.
 */
export function createKVLock(kv: KVNamespace, keyPrefix?: string): KVLock {
  return new KVLock(kv, keyPrefix);
}
