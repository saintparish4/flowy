/**
 * Mock infrastructure bindings for unit and failure-injection tests.
 *
 * Each mock implements the minimum surface area needed to test Hexa's
 * middleware without real Cloudflare infrastructure. Failure modes are
 * injected by calling the appropriate `simulateFailure` helpers.
 *
 * Design: avoid over-engineering a full in-memory DB — these mocks exist to
 * verify fail-open / fail-closed behavior from ADR 001, not to replicate D1.
 */

import type { Env } from "../../config";

// ---------------------------------------------------------------------------
// D1 mock
// ---------------------------------------------------------------------------

export type D1Row = Record<string, unknown>;

// D1DatabaseSession is abstract — cast is required to satisfy the return type.
class MockD1DatabaseSession {
  constructor(
    private readonly store: Map<string, D1Row[]>,
    private readonly checkFailure: () => void
  ) {}

  prepare(query: string): D1PreparedStatement {
    return new MockD1PreparedStatement(query, this.store, this.checkFailure);
  }

  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    return Promise.all(statements.map((s) => s.all<T>()));
  }

  getBookmark(): string | null {
    return null;
  }
}

export class MockD1Database implements D1Database {
  private store = new Map<string, D1Row[]>();
  private _shouldFail = false;
  private _failMessage = "D1 mock: simulated failure";

  simulateFailure(message = "D1 mock: simulated failure"): void {
    this._shouldFail = true;
    this._failMessage = message;
  }

  resetFailure(): void {
    this._shouldFail = false;
  }

  seed(table: string, rows: D1Row[]): void {
    this.store.set(table, rows);
  }

  prepare(query: string): D1PreparedStatement {
    return new MockD1PreparedStatement(query, this.store, () => {
      if (this._shouldFail) throw new Error(this._failMessage);
    });
  }

  withSession(_constraintOrBookmark?: D1SessionBookmark | D1SessionConstraint): D1DatabaseSession {
    return new MockD1DatabaseSession(this.store, () => {
      if (this._shouldFail) throw new Error(this._failMessage);
    }) as unknown as D1DatabaseSession;
  }

  // Unused in tests but required by the interface
  dump(): Promise<ArrayBuffer> {
    return Promise.resolve(new ArrayBuffer(0));
  }

  batch<T = unknown>(
    statements: D1PreparedStatement[]
  ): Promise<D1Result<T>[]> {
    if (this._shouldFail) return Promise.reject(new Error(this._failMessage));
    return Promise.all(statements.map((s) => s.all<T>()));
  }

  exec(query: string): Promise<D1ExecResult> {
    if (this._shouldFail) return Promise.reject(new Error(this._failMessage));
    void query;
    return Promise.resolve({ count: 0, duration: 0 });
  }
}

class MockD1PreparedStatement implements D1PreparedStatement {
   _bindings: unknown[] = [];

  constructor(
    private readonly query: string,
    private readonly store: Map<string, D1Row[]>,
    private readonly checkFailure: () => void
  ) {}

  bind(...values: unknown[]): D1PreparedStatement {
    this._bindings = values;
    return this;
  }

  async first<T = D1Row>(colName?: string): Promise<T | null> {
    this.checkFailure();
    const rows = this._matchingRows();
    if (rows.length === 0) return null;
    const row = rows[0];
    if (colName !== undefined) {
      return (row[colName] ?? null) as T;
    }
    return row as T;
  }

  async all<T = D1Row>(): Promise<D1Result<T>> {
    this.checkFailure();
    return {
      results: this._matchingRows() as T[],
      success: true,
      meta: { duration: 0, size_after: 0, rows_read: 0, rows_written: 0, last_row_id: 0, changed_db: false, changes: 0 },
    };
  }

  async run(): Promise<D1Result<never>> {
    this.checkFailure();
    return {
      results: [],
      success: true,
      meta: { duration: 0, size_after: 0, rows_read: 0, rows_written: 1, last_row_id: 0, changed_db: true, changes: 1 },
    };
  }

  raw<T = unknown[]>(options: { columnNames: true }): Promise<[string[], ...T[]]>;
  raw<T = unknown[]>(options?: { columnNames?: false }): Promise<T[]>;
  raw(options?: { columnNames?: boolean }): Promise<unknown[]> {
    this.checkFailure();
    const rows = this._matchingRows();
    if (options?.columnNames === true) {
      const headers = rows.length > 0 ? Object.keys(rows[0]) : [];
      return Promise.resolve([headers, ...rows.map(Object.values)]);
    }
    return Promise.resolve(rows.map(Object.values));
  }

  private _matchingRows(): D1Row[] {
    // Simple table scan — extracts table name from "SELECT ... FROM <table>"
    const match = this.query.match(/FROM\s+(\w+)/i);
    if (!match) return [];
    return this.store.get(match[1]) ?? [];
  }
}

// ---------------------------------------------------------------------------
// KV mock
// ---------------------------------------------------------------------------

// KVNamespace defines 10+ overloads for get() (including array-key variants) that
// would be pure boilerplate to replicate. The mock satisfies the same runtime contract
// used by the middleware; strict interface conformance is verified via integration tests.
export class MockKVNamespace {
  private store = new Map<string, string>();
  private _shouldFail = false;
  private _failMessage = "KV mock: simulated failure";

  simulateFailure(message = "KV mock: simulated failure"): void {
    this._shouldFail = true;
    this._failMessage = message;
  }

  resetFailure(): void {
    this._shouldFail = false;
  }

  async get(key: string, _optionsOrType?: unknown): Promise<string | null> {
    if (this._shouldFail) throw new Error(this._failMessage);
    return this.store.get(key) ?? null;
  }

  async put(
    key: string,
    value: string | ArrayBuffer | ArrayBufferView | ReadableStream,
    _options?: KVNamespacePutOptions
  ): Promise<void> {
    if (this._shouldFail) throw new Error(this._failMessage);
    this.store.set(key, value as string);
  }

  async delete(key: string): Promise<void> {
    if (this._shouldFail) throw new Error(this._failMessage);
    this.store.delete(key);
  }

  async list<M = unknown>(
    _options?: KVNamespaceListOptions
  ): Promise<KVNamespaceListResult<M, string>> {
    if (this._shouldFail) throw new Error(this._failMessage);
    const keys = Array.from(this.store.keys()).map((name) => ({
      name,
      expiration: undefined,
      metadata: undefined as M,
    }));
    return { keys, list_complete: true, cacheStatus: null };
  }

  async getWithMetadata<M = unknown>(
    key: string,
    _optionsOrType?: unknown
  ): Promise<KVNamespaceGetWithMetadataResult<string, M>> {
    if (this._shouldFail) throw new Error(this._failMessage);
    return { value: this.store.get(key) ?? null, metadata: null, cacheStatus: null };
  }
}

// ---------------------------------------------------------------------------
// Durable Object mock
// ---------------------------------------------------------------------------

export class MockDurableObjectNamespace implements DurableObjectNamespace {
  private _shouldFail = false;
  private _failMessage = "DO mock: simulated failure";
  private _stub: MockDurableObjectStub;

  constructor() {
    this._stub = new MockDurableObjectStub(
      { id: "mock-do-id", toString: () => "mock-do-id", equals: () => true, name: "mock" },
      () => {
        if (this._shouldFail) throw new Error(this._failMessage);
      }
    );
  }

  simulateFailure(message = "DO mock: simulated failure"): void {
    this._shouldFail = true;
    this._failMessage = message;
  }

  resetFailure(): void {
    this._shouldFail = false;
  }

  newUniqueId(_options?: DurableObjectNamespaceNewUniqueIdOptions): DurableObjectId {
    return { id: "mock-unique-id", toString: () => "mock-unique-id", equals: () => true } as unknown as DurableObjectId;
  }

  idFromName(_name: string): DurableObjectId {
    return { id: "mock-named-id", toString: () => "mock-named-id", equals: () => true } as unknown as DurableObjectId;
  }

  idFromString(_id: string): DurableObjectId {
    return { id: _id, toString: () => _id, equals: () => true } as unknown as DurableObjectId;
  }

  get(_id: DurableObjectId): DurableObjectStub {
    return this._stub as unknown as DurableObjectStub;
  }

  getByName(_name: string): DurableObjectStub {
    return this._stub as unknown as DurableObjectStub;
  }

  jurisdiction(_jurisdiction: DurableObjectJurisdiction): DurableObjectNamespace {
    return this;
  }
}

class MockDurableObjectStub {
  readonly id: DurableObjectId;

  constructor(
    id: unknown,
    private readonly checkFailure: () => void
  ) {
    this.id = id as DurableObjectId;
  }

  async fetch(
    _input: RequestInfo,
    _init?: RequestInit
  ): Promise<Response> {
    this.checkFailure();
    return new Response(JSON.stringify({ allowed: true, remaining: -1 }), {
      headers: { "Content-Type": "application/json" },
    });
  }
}

// ---------------------------------------------------------------------------
// Composite mock env builder
// ---------------------------------------------------------------------------

export interface MockEnvOptions {
  vars?: Record<string, string>;
}

/**
 * Returns a mock Env object suitable for unit tests.
 * Bindings are real mock instances; vars default to valid values.
 */
export function buildMockEnv(options: MockEnvOptions = {}): {
  db: MockD1Database;
  authCache: MockKVNamespace;
  blocklistWallets: MockKVNamespace;
  blocklistDomains: MockKVNamespace;
  rateLimiter: MockDurableObjectNamespace;
  env: Env;
} {
  const db = new MockD1Database();
  const authCache = new MockKVNamespace();
  const blocklistWallets = new MockKVNamespace();
  const blocklistDomains = new MockKVNamespace();
  const rateLimiter = new MockDurableObjectNamespace();

  const env = {
    DB: db,
    AUTH_CACHE: authCache,
    BLOCKLIST_WALLETS: blocklistWallets,
    BLOCKLIST_DOMAINS: blocklistDomains,
    RATE_LIMITER: rateLimiter,
    ENVIRONMENT: "development",
    BACKEND_RPC_URL: "http://localhost:9545",
    JWT_PUBLIC_KEY: "test-public-key",
    UPSTREAM_TIMEOUT_MS: "10000",
    AUTH_CACHE_TTL_SECONDS: "300",
    BLOCKLIST_IP_CACHE_TTL_SECONDS: "30",
    BLOCKLIST_WALLET_CACHE_TTL_SECONDS: "60",
    BLOCKLIST_LRU_MAX_SIZE: "10000",
    CIRCUIT_BREAKER_FAILURE_THRESHOLD: "5",
    CIRCUIT_BREAKER_OPEN_DURATION_MS: "30000",
    THREAT_SCORE_BLOCK_THRESHOLD: "80",
    ...options.vars,
  } as unknown as Env;

  return { db, authCache, blocklistWallets, blocklistDomains, rateLimiter, env };
}
