/**
 * Mock KV Namespace for Testing
 *
 * Provides an in-memory implementation of KVNamespace for testing
 * without requiring a real Cloudflare Workers environment
 */

export class MockKVNamespace {
  private store: Map<string, { value: string; expiration?: number }> =
    new Map();

  /**
   * Get a value from the mock KV store
   */
  async get(
    key: string,
    options?: Partial<KVNamespaceGetOptions<undefined>>
  ): Promise<string | null>;
  async get(key: string, type: "text"): Promise<string | null>;
  async get<ExpectedValue = unknown>(
    key: string,
    type: "json"
  ): Promise<ExpectedValue | null>;
  async get(key: string, type: "arrayBuffer"): Promise<ArrayBuffer | null>;
  async get(key: string, type: "stream"): Promise<ReadableStream | null>;
  async get(
    key: string,
    typeOrOptions?:
      | "text"
      | "json"
      | "arrayBuffer"
      | "stream"
      | Partial<KVNamespaceGetOptions<undefined>>
  ): Promise<any> {
    const entry = this.store.get(key);

    if (!entry) {
      return null;
    }

    // Check if expired
    if (entry.expiration && Date.now() > entry.expiration) {
      this.store.delete(key);
      return null;
    }

    // Handle options object
    let type: "text" | "json" | "arrayBuffer" | "stream" | undefined;
    if (typeof typeOrOptions === "string") {
      type = typeOrOptions;
    } else if (
      typeOrOptions &&
      typeof typeOrOptions === "object" &&
      "type" in typeOrOptions
    ) {
      type = typeOrOptions.type;
    }

    if (type === "json") {
      return JSON.parse(entry.value);
    }

    return entry.value;
  }

  /**
   * Get a value with metadata
   */
  async getWithMetadata<Metadata = unknown>(
    key: string,
    options?: Partial<KVNamespaceGetOptions<Metadata>>
  ): Promise<KVNamespaceGetWithMetadataResult<string, Metadata>>;
  async getWithMetadata<Metadata = unknown>(
    key: string,
    type: "text"
  ): Promise<KVNamespaceGetWithMetadataResult<string, Metadata>>;
  async getWithMetadata<ExpectedValue = unknown, Metadata = unknown>(
    key: string,
    type: "json"
  ): Promise<KVNamespaceGetWithMetadataResult<ExpectedValue, Metadata>>;
  async getWithMetadata<Metadata = unknown>(
    key: string,
    type: "arrayBuffer"
  ): Promise<KVNamespaceGetWithMetadataResult<ArrayBuffer, Metadata>>;
  async getWithMetadata<Metadata = unknown>(
    key: string,
    type: "stream"
  ): Promise<KVNamespaceGetWithMetadataResult<ReadableStream, Metadata>>;
  async getWithMetadata<Metadata = unknown>(
    key: string,
    typeOrOptions?:
      | "text"
      | "json"
      | "arrayBuffer"
      | "stream"
      | Partial<KVNamespaceGetOptions<Metadata>>
  ): Promise<any> {
    const value = await this.get(key, typeOrOptions as any);
    return { value, metadata: null, cacheStatus: null };
  }

  /**
   * Put a value into the mock KV store
   */
  async put(
    key: string,
    value: string | ArrayBuffer | ReadableStream,
    options?: {
      expiration?: number;
      expirationTtl?: number;
      metadata?: unknown;
    }
  ): Promise<void> {
    const valueStr = typeof value === "string" ? value : String(value);

    let expiration: number | undefined;

    if (options?.expiration) {
      expiration = options.expiration * 1000; // Convert to ms
    } else if (options?.expirationTtl) {
      expiration = Date.now() + options.expirationTtl * 1000; // Convert to ms
    }

    this.store.set(key, { value: valueStr, expiration });
  }

  /**
   * Delete a value from the mock KV store.
   */
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  /**
   * List keys in the mock KV store.
   */
  async list<Metadata = unknown>(
    options?: KVNamespaceListOptions
  ): Promise<KVNamespaceListResult<Metadata, string>> {
    const keys = Array.from(this.store.keys())
      .filter((key) => !options?.prefix || key.startsWith(options.prefix))
      .slice(0, options?.limit || 1000)
      .map((name) => ({ name }));

    return {
      keys,
      list_complete: true,
      cacheStatus: null,
    } as KVNamespaceListResult<Metadata, string>;
  }

  /**
   * Clear all entries (for testing).
   */
  clear(): void {
    this.store.clear();
  }

  /**
   * Get the number of entries in the store.
   */
  size(): number {
    return this.store.size;
  }
}

/**
 * Create a new mock KV namespace.
 */
export function createMockKV(): KVNamespace {
  // @ts-expect-error - Mock implementation doesn't match all overloads exactly, but is functionally compatible
  return new MockKVNamespace();
}
