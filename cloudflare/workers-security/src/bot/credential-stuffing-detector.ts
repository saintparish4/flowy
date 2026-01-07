/**
 * Credential Stuffing Detector
 * Detects and prevents credential stuffing attacks
 * Monitors login patterns, failed attempts, and suspicious behavior
 */

import type { Env } from "../types";

// Cloudflare Workers KV type
type KVNamespace = {
  get(key: string, type?: string): Promise<any>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
};

/**
 * Login attempt record
 */
export interface LoginAttempt {
  timestamp: number;
  ip: string;
  success: boolean;
  username?: string;
  userAgent?: string;
  country?: string;
}

/**
 * Credential stuffing detection result
 */
export interface CredentialStuffingResult {
  isAttack: boolean;
  confidence: number; // 0-1
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  reason: string;
  recommendation: 'allow' | 'challenge' | 'block' | 'lockout';
  metrics: {
    failedAttempts: number;
    successRate: number;
    uniqueUsernames: number;
    requestRate: number; // req/sec
    ipReputation: number; // 0-100
  };
}

/**
 * IP reputation data for credential stuffing
 */
export interface IPCredentialReputation {
  ip: string;
  firstSeen: number;
  lastSeen: number;
  totalAttempts: number;
  failedAttempts: number;
  successfulAttempts: number;
  uniqueUsernames: Set<string>;
  consecutiveFailures: number;
  reputation: number; // 0-100
  isBlocked: boolean;
  lockoutUntil?: number;
}

/**
 * Credential stuffing detection configuration
 */
export interface CredentialStuffingConfig {
  // Time windows (in seconds)
  shortWindow: number;      // Short-term analysis window
  longWindow: number;       // Long-term analysis window
  
  // Thresholds
  maxFailedAttempts: number;       // Max failed attempts in short window
  maxAttemptsPerMinute: number;    // Max total attempts per minute
  maxUniqueUsernamesPerIP: number; // Max unique usernames from single IP
  suspiciousSuccessRate: number;   // Success rate below this is suspicious
  
  // Lockout settings
  lockoutDuration: number;          // Lockout duration in seconds
  lockoutThreshold: number;         // Failed attempts before lockout
  consecutiveFailuresThreshold: number; // Consecutive failures before escalation
}

/**
 * Default configuration
 */
export const DEFAULT_CREDENTIAL_STUFFING_CONFIG: CredentialStuffingConfig = {
  shortWindow: 60,            // 1 minute
  longWindow: 3600,           // 1 hour
  maxFailedAttempts: 5,       // 5 failed attempts in short window
  maxAttemptsPerMinute: 10,   // 10 attempts per minute
  maxUniqueUsernamesPerIP: 3, // 3 different usernames per IP
  suspiciousSuccessRate: 0.1, // <10% success is suspicious
  lockoutDuration: 900,       // 15 minute lockout
  lockoutThreshold: 10,       // 10 failures before lockout
  consecutiveFailuresThreshold: 5, // 5 consecutive failures escalates
};

/**
 * Credential Stuffing Detector
 */
export class CredentialStuffingDetector {
  private kv: KVNamespace | null;
  private mockStore: Map<string, any>;
  private useMock: boolean;
  private config: CredentialStuffingConfig;
  private attemptLog: Map<string, LoginAttempt[]>;

  constructor(kv?: KVNamespace, config?: Partial<CredentialStuffingConfig>) {
    this.kv = kv || null;
    this.mockStore = new Map();
    this.useMock = !kv;
    this.config = { ...DEFAULT_CREDENTIAL_STUFFING_CONFIG, ...config };
    this.attemptLog = new Map();
  }

  /**
   * Get IP reputation data
   */
  private async getIPReputation(ip: string): Promise<IPCredentialReputation> {
    const key = `cred-rep:${ip}`;
    
    let data: IPCredentialReputation | null = null;
    
    if (this.useMock) {
      data = this.mockStore.get(key);
    } else {
      try {
        const stored = await this.kv!.get(key, 'json');
        if (stored) {
          data = stored as IPCredentialReputation;
          // Reconstitute Set from array
          if (Array.isArray((data as any).uniqueUsernames)) {
            data.uniqueUsernames = new Set((data as any).uniqueUsernames);
          }
        }
      } catch (error) {
        console.error('Error loading IP reputation:', error);
      }
    }
    
    if (!data) {
      data = {
        ip,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        totalAttempts: 0,
        failedAttempts: 0,
        successfulAttempts: 0,
        uniqueUsernames: new Set(),
        consecutiveFailures: 0,
        reputation: 50, // Start neutral
        isBlocked: false,
      };
    }
    
    return data;
  }

  /**
   * Save IP reputation data
   */
  private async saveIPReputation(data: IPCredentialReputation): Promise<void> {
    const key = `cred-rep:${data.ip}`;
    
    // Convert Set to array for storage
    const storageData = {
      ...data,
      uniqueUsernames: Array.from(data.uniqueUsernames),
    };
    
    if (this.useMock) {
      this.mockStore.set(key, storageData);
    } else {
      try {
        await this.kv!.put(key, JSON.stringify(storageData), {
          expirationTtl: this.config.longWindow + 3600, // Keep for long window + 1 hour
        });
      } catch (error) {
        console.error('Error saving IP reputation:', error);
      }
    }
  }

  /**
   * Record a login attempt
   */
  async recordAttempt(attempt: LoginAttempt): Promise<void> {
    const ip = attempt.ip;
    const reputation = await this.getIPReputation(ip);
    
    // Update reputation data
    reputation.lastSeen = attempt.timestamp;
    reputation.totalAttempts++;
    
    if (attempt.success) {
      reputation.successfulAttempts++;
      reputation.consecutiveFailures = 0;
      reputation.reputation = Math.min(100, reputation.reputation + 5);
    } else {
      reputation.failedAttempts++;
      reputation.consecutiveFailures++;
      reputation.reputation = Math.max(0, reputation.reputation - 10);
    }
    
    if (attempt.username) {
      reputation.uniqueUsernames.add(attempt.username);
    }
    
    // Check for lockout
    if (reputation.failedAttempts >= this.config.lockoutThreshold) {
      reputation.isBlocked = true;
      reputation.lockoutUntil = Date.now() + (this.config.lockoutDuration * 1000);
    }
    
    // Save updated reputation
    await this.saveIPReputation(reputation);
    
    // Add to attempt log
    if (!this.attemptLog.has(ip)) {
      this.attemptLog.set(ip, []);
    }
    const log = this.attemptLog.get(ip)!;
    log.push(attempt);
    
    // Cleanup old entries
    const cutoff = Date.now() - (this.config.longWindow * 1000);
    this.attemptLog.set(ip, log.filter(a => a.timestamp > cutoff));
  }

  /**
   * Check if an IP is exhibiting credential stuffing behavior
   */
  async check(ip: string, username?: string): Promise<CredentialStuffingResult> {
    const reputation = await this.getIPReputation(ip);
    const attempts = this.attemptLog.get(ip) || [];
    
    // Check for active lockout
    if (reputation.isBlocked && reputation.lockoutUntil && reputation.lockoutUntil > Date.now()) {
      return {
        isAttack: true,
        confidence: 1.0,
        severity: 'critical',
        reason: 'IP is currently locked out due to excessive failed attempts',
        recommendation: 'lockout',
        metrics: {
          failedAttempts: reputation.failedAttempts,
          successRate: reputation.successfulAttempts / Math.max(1, reputation.totalAttempts),
          uniqueUsernames: reputation.uniqueUsernames.size,
          requestRate: this.calculateRequestRate(attempts),
          ipReputation: reputation.reputation,
        },
      };
    }
    
    // Reset lockout if expired
    if (reputation.isBlocked && reputation.lockoutUntil && reputation.lockoutUntil <= Date.now()) {
      reputation.isBlocked = false;
      reputation.lockoutUntil = undefined;
      reputation.consecutiveFailures = 0;
      await this.saveIPReputation(reputation);
    }
    
    // Calculate metrics
    const now = Date.now();
    const shortWindowCutoff = now - (this.config.shortWindow * 1000);
    const recentAttempts = attempts.filter(a => a.timestamp > shortWindowCutoff);
    const recentFailed = recentAttempts.filter(a => !a.success).length;
    const requestRate = this.calculateRequestRate(attempts);
    const successRate = reputation.successfulAttempts / Math.max(1, reputation.totalAttempts);
    
    // Analyze for credential stuffing
    let isAttack = false;
    let confidence = 0;
    let severity: CredentialStuffingResult['severity'] = 'none';
    let reason = 'No credential stuffing detected';
    let recommendation: CredentialStuffingResult['recommendation'] = 'allow';
    
    // Check various indicators
    const indicators: string[] = [];
    
    // Too many failed attempts in short window
    if (recentFailed >= this.config.maxFailedAttempts) {
      isAttack = true;
      confidence += 0.3;
      indicators.push(`${recentFailed} failed attempts in ${this.config.shortWindow}s`);
    }
    
    // Too many unique usernames from single IP
    if (reputation.uniqueUsernames.size >= this.config.maxUniqueUsernamesPerIP) {
      isAttack = true;
      confidence += 0.3;
      indicators.push(`${reputation.uniqueUsernames.size} unique usernames from single IP`);
    }
    
    // Suspiciously low success rate with many attempts
    if (reputation.totalAttempts >= 10 && successRate < this.config.suspiciousSuccessRate) {
      isAttack = true;
      confidence += 0.2;
      indicators.push(`${(successRate * 100).toFixed(1)}% success rate with ${reputation.totalAttempts} attempts`);
    }
    
    // High request rate
    if (requestRate > this.config.maxAttemptsPerMinute / 60) {
      isAttack = true;
      confidence += 0.2;
      indicators.push(`${requestRate.toFixed(2)} req/sec exceeds threshold`);
    }
    
    // Consecutive failures
    if (reputation.consecutiveFailures >= this.config.consecutiveFailuresThreshold) {
      isAttack = true;
      confidence += 0.2;
      indicators.push(`${reputation.consecutiveFailures} consecutive failures`);
    }
    
    // Low reputation
    if (reputation.reputation < 20) {
      isAttack = true;
      confidence += 0.1;
      indicators.push(`Low IP reputation: ${reputation.reputation}`);
    }
    
    // Determine severity and recommendation
    confidence = Math.min(1, confidence);
    
    if (isAttack) {
      if (confidence >= 0.8) {
        severity = 'critical';
        recommendation = 'lockout';
        reason = `Critical credential stuffing attack: ${indicators.join(', ')}`;
      } else if (confidence >= 0.6) {
        severity = 'high';
        recommendation = 'block';
        reason = `High confidence credential stuffing: ${indicators.join(', ')}`;
      } else if (confidence >= 0.4) {
        severity = 'medium';
        recommendation = 'challenge';
        reason = `Suspected credential stuffing: ${indicators.join(', ')}`;
      } else {
        severity = 'low';
        recommendation = 'challenge';
        reason = `Possible credential stuffing: ${indicators.join(', ')}`;
      }
    }
    
    return {
      isAttack,
      confidence,
      severity,
      reason,
      recommendation,
      metrics: {
        failedAttempts: reputation.failedAttempts,
        successRate,
        uniqueUsernames: reputation.uniqueUsernames.size,
        requestRate,
        ipReputation: reputation.reputation,
      },
    };
  }

  /**
   * Calculate request rate (req/sec) from attempts
   */
  private calculateRequestRate(attempts: LoginAttempt[]): number {
    if (attempts.length < 2) return 0;
    
    const sorted = [...attempts].sort((a, b) => a.timestamp - b.timestamp);
    const duration = (sorted[sorted.length - 1].timestamp - sorted[0].timestamp) / 1000;
    
    if (duration <= 0) return attempts.length;
    
    return attempts.length / duration;
  }

  /**
   * Check if IP should be challenged
   */
  async shouldChallenge(ip: string): Promise<boolean> {
    const result = await this.check(ip);
    return result.recommendation === 'challenge' || 
           result.recommendation === 'block' || 
           result.recommendation === 'lockout';
  }

  /**
   * Check if IP should be blocked
   */
  async shouldBlock(ip: string): Promise<boolean> {
    const result = await this.check(ip);
    return result.recommendation === 'block' || result.recommendation === 'lockout';
  }

  /**
   * Manually unlock an IP
   */
  async unlockIP(ip: string): Promise<void> {
    const reputation = await this.getIPReputation(ip);
    reputation.isBlocked = false;
    reputation.lockoutUntil = undefined;
    reputation.consecutiveFailures = 0;
    await this.saveIPReputation(reputation);
  }

  /**
   * Reset IP reputation
   */
  async resetIP(ip: string): Promise<void> {
    const key = `cred-rep:${ip}`;
    if (this.useMock) {
      this.mockStore.delete(key);
    } else {
      await this.kv!.delete(key);
    }
    this.attemptLog.delete(ip);
  }

  /**
   * Get IP statistics
   */
  async getIPStats(ip: string): Promise<IPCredentialReputation> {
    return this.getIPReputation(ip);
  }
}

/**
 * Create a credential stuffing detector
 */
export function createCredentialStuffingDetector(
  env: Env,
  config?: Partial<CredentialStuffingConfig>
): CredentialStuffingDetector {
  return new CredentialStuffingDetector(env.RATE_LIMIT_KV, config);
}

