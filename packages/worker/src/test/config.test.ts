import { describe, it, expect } from "vitest";
import { parseConfig, ConfigError } from "../config";
import { buildMockEnv } from "./mocks/bindings";

describe("parseConfig", () => {
  it("returns a valid config when all required vars are present", () => {
    const { env } = buildMockEnv();
    const config = parseConfig(env as never);

    expect(config.environment).toBe("development");
    expect(config.backendRpcUrl).toBe("http://localhost:9545");
    expect(config.upstreamTimeoutMs).toBe(10_000);
    expect(config.authCacheTtlSeconds).toBe(300);
    expect(config.threatScoreBlockThreshold).toBe(80);
  });

  it("throws ConfigError when BACKEND_RPC_URL is missing", () => {
    const { env } = buildMockEnv({ vars: { BACKEND_RPC_URL: undefined as unknown as string } });
    expect(() => parseConfig(env as never)).toThrow(ConfigError);
  });

  it("throws ConfigError when BACKEND_RPC_URL is not a valid URL", () => {
    const { env } = buildMockEnv({ vars: { BACKEND_RPC_URL: "not-a-url" } });
    expect(() => parseConfig(env as never)).toThrow(ConfigError);
  });

  it("throws ConfigError when JWT_PUBLIC_KEY is missing", () => {
    const { env } = buildMockEnv({ vars: { JWT_PUBLIC_KEY: "" } });
    expect(() => parseConfig(env as never)).toThrow(ConfigError);
  });

  it("throws ConfigError when UPSTREAM_TIMEOUT_MS is not a positive integer", () => {
    const { env } = buildMockEnv({ vars: { UPSTREAM_TIMEOUT_MS: "0" } });
    expect(() => parseConfig(env as never)).toThrow(ConfigError);
  });

  it("throws ConfigError when ENVIRONMENT is not a valid enum value", () => {
    const { env } = buildMockEnv({ vars: { ENVIRONMENT: "local" } });
    expect(() => parseConfig(env as never)).toThrow(ConfigError);
  });

  it("throws ConfigError when THREAT_SCORE_BLOCK_THRESHOLD is out of 0-100 range", () => {
    const { env } = buildMockEnv({ vars: { THREAT_SCORE_BLOCK_THRESHOLD: "101" } });
    expect(() => parseConfig(env as never)).toThrow(ConfigError);
  });

  it("includes all missing field names in the error message", () => {
    const { env } = buildMockEnv({
      vars: {
        BACKEND_RPC_URL: "not-a-url",
        JWT_PUBLIC_KEY: "",
      },
    });

    let message = "";
    try {
      parseConfig(env as never);
    } catch (err) {
      if (err instanceof ConfigError) message = err.message;
    }

    expect(message).toContain("backendRpcUrl");
    expect(message).toContain("jwtPublicKey");
  });
});

describe("MockD1Database failure injection", () => {
  it("throws when simulateFailure is set and prepare().first() is called", async () => {
    const { db } = buildMockEnv();
    db.simulateFailure("D1 is down");

    await expect(db.prepare("SELECT * FROM api_keys WHERE key_hash = ?").bind("abc").first()).rejects.toThrow(
      "D1 is down"
    );
  });

  it("recovers after resetFailure()", async () => {
    const { db } = buildMockEnv();
    db.simulateFailure();
    db.resetFailure();

    const result = await db.prepare("SELECT * FROM api_keys").all();
    expect(result.success).toBe(true);
  });
});
