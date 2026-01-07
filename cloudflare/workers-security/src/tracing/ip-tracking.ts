/**
 * IP Tracking Module
 * Tracks IP addresses, their behavior, and manages reputation
 */

import type { Env } from "../types";

// Cloudflare Workers KV type
type KVNamespace = {
  get(key: string, type?: string): Promise<any>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
};

/**
 * IP tracking record
 */
export interface IPTrackingRecord {
  ip: string;
  firstSeen: number;
  lastSeen: number;
  
  // Request metrics
  totalRequests: number;
  blockedRequests: number;
  challengedRequests: number;
  
  // Geographic info
  country?: string;
  region?: string;
  city?: string;
  asn?: string;
  asnOrg?: string;
  
  // Security metrics
  reputation: number;  // 0-100, higher is better
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Threat indicators
  wafViolations: number;
  rateLimitViolations: number;
  burstViolations: number;
  credentialStuffingAttempts: number;
  spamAttempts: number;
  
  // Historical events
  events: IPEvent[];
  
  // Flags
  isBlocked: boolean;
  blockReason?: string;
  blockUntil?: number;
  isTrusted: boolean;
  trustReason?: string;
}

/**
 * IP event types
 */
export type IPEventType = 
  | 'request'
  | 'blocked'
  | 'challenged'
  | 'waf_violation'
  | 'rate_limit'
  | 'burst_detected'
  | 'credential_stuffing'
  | 'spam_detected'
  | 'reputation_change'
  | 'blocked_manually'
  | 'unblocked'
  | 'trusted'
  | 'untrusted';

/**
 * IP event record
 */
export interface IPEvent {
  timestamp: number;
  type: IPEventType;
  details?: string;
  metadata?: Record<string, any>;
}

/**
 * IP tracking configuration
 */
export interface IPTrackingConfig {
  // Enable/disable tracking
  enabled: boolean;
  
  // How long to keep IP records (seconds)
  recordTTL: number;
  
  // Maximum events to keep per IP
  maxEvents: number;
  
  // Reputation thresholds
  reputationThresholds: {
    trusted: number;      // Above this = trusted
    suspicious: number;   // Below this = suspicious
    blocked: number;      // Below this = auto-block
  };
  
  // Auto-block settings
  autoBlockEnabled: boolean;
  autoBlockDuration: number; // seconds
  
  // Reputation decay (how fast reputation recovers)
  reputationDecayRate: number; // per hour
}

/**
 * Default IP tracking configuration
 */
export const DEFAULT_IP_TRACKING_CONFIG: IPTrackingConfig = {
  enabled: true,
  recordTTL: 86400,  // 24 hours
  maxEvents: 100,
  reputationThresholds: {
    trusted: 80,
    suspicious: 40,
    blocked: 20,
  },
  autoBlockEnabled: true,
  autoBlockDuration: 3600, // 1 hour
  reputationDecayRate: 5, // 5 points per hour recovery
};

/**
 * IP Tracker
 */
export class IPTracker {
  private kv: KVNamespace | null;
  private mockStore: Map<string, any>;
  private useMock: boolean;
  private config: IPTrackingConfig;
  private localCache: Map<string, IPTrackingRecord>;

  constructor(kv?: KVNamespace, config?: Partial<IPTrackingConfig>) {
    this.kv = kv || null;
    this.mockStore = new Map();
    this.useMock = !kv;
    this.config = { ...DEFAULT_IP_TRACKING_CONFIG, ...config };
    this.localCache = new Map();
  }

  /**
   * Get IP record from storage
   */
  private async getRecord(ip: string): Promise<IPTrackingRecord | null> {
    // Check local cache first
    const cached = this.localCache.get(ip);
    if (cached) return cached;

    const key = `ip-track:${ip}`;
    
    if (this.useMock) {
      return this.mockStore.get(key) || null;
    }
    
    try {
      const data = await this.kv!.get(key, 'json');
      if (data) {
        this.localCache.set(ip, data as IPTrackingRecord);
        return data as IPTrackingRecord;
      }
    } catch (error) {
      console.error('Error loading IP record:', error);
    }
    
    return null;
  }

  /**
   * Save IP record to storage
   */
  private async saveRecord(record: IPTrackingRecord): Promise<void> {
    const key = `ip-track:${record.ip}`;
    
    // Update local cache
    this.localCache.set(record.ip, record);
    
    // Trim events if needed
    if (record.events.length > this.config.maxEvents) {
      record.events = record.events.slice(-this.config.maxEvents);
    }
    
    if (this.useMock) {
      this.mockStore.set(key, record);
      return;
    }
    
    try {
      await this.kv!.put(key, JSON.stringify(record), {
        expirationTtl: this.config.recordTTL,
      });
    } catch (error) {
      console.error('Error saving IP record:', error);
    }
  }

  /**
   * Get or create IP record
   */
  async getOrCreateRecord(ip: string, request?: Request): Promise<IPTrackingRecord> {
    let record = await this.getRecord(ip);
    
    if (!record) {
      record = {
        ip,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        totalRequests: 0,
        blockedRequests: 0,
        challengedRequests: 0,
        reputation: 50, // Start neutral
        riskLevel: 'low',
        wafViolations: 0,
        rateLimitViolations: 0,
        burstViolations: 0,
        credentialStuffingAttempts: 0,
        spamAttempts: 0,
        events: [],
        isBlocked: false,
        isTrusted: false,
      };
      
      // Extract geographic info from request if available
      if (request) {
        record.country = request.headers.get('CF-IPCountry') || undefined;
        record.asn = request.headers.get('CF-ASN') || undefined;
        // City and region might be available in CF Enterprise
      }
    }
    
    return record;
  }

  /**
   * Track a request from an IP
   */
  async trackRequest(
    ip: string,
    request: Request,
    options?: {
      blocked?: boolean;
      challenged?: boolean;
      wafViolation?: boolean;
      rateLimitViolation?: boolean;
      burstViolation?: boolean;
      credentialStuffing?: boolean;
      spam?: boolean;
    }
  ): Promise<IPTrackingRecord> {
    if (!this.config.enabled) {
      return this.getOrCreateRecord(ip, request);
    }

    const record = await this.getOrCreateRecord(ip, request);
    
    // Update basic metrics
    record.lastSeen = Date.now();
    record.totalRequests++;
    
    // Update blocked/challenged counts
    if (options?.blocked) {
      record.blockedRequests++;
      this.addEvent(record, 'blocked');
    }
    if (options?.challenged) {
      record.challengedRequests++;
      this.addEvent(record, 'challenged');
    }
    
    // Update violation counts
    if (options?.wafViolation) {
      record.wafViolations++;
      record.reputation = Math.max(0, record.reputation - 15);
      this.addEvent(record, 'waf_violation');
    }
    if (options?.rateLimitViolation) {
      record.rateLimitViolations++;
      record.reputation = Math.max(0, record.reputation - 10);
      this.addEvent(record, 'rate_limit');
    }
    if (options?.burstViolation) {
      record.burstViolations++;
      record.reputation = Math.max(0, record.reputation - 10);
      this.addEvent(record, 'burst_detected');
    }
    if (options?.credentialStuffing) {
      record.credentialStuffingAttempts++;
      record.reputation = Math.max(0, record.reputation - 20);
      this.addEvent(record, 'credential_stuffing');
    }
    if (options?.spam) {
      record.spamAttempts++;
      record.reputation = Math.max(0, record.reputation - 15);
      this.addEvent(record, 'spam_detected');
    }
    
    // Positive signal: normal request
    if (!options?.blocked && !options?.challenged && !options?.wafViolation &&
        !options?.rateLimitViolation && !options?.burstViolation &&
        !options?.credentialStuffing && !options?.spam) {
      record.reputation = Math.min(100, record.reputation + 1);
    }
    
    // Update risk level
    record.riskLevel = this.calculateRiskLevel(record);
    
    // Check for auto-block
    if (this.config.autoBlockEnabled && 
        record.reputation <= this.config.reputationThresholds.blocked &&
        !record.isBlocked) {
      record.isBlocked = true;
      record.blockReason = 'Auto-blocked due to low reputation';
      record.blockUntil = Date.now() + (this.config.autoBlockDuration * 1000);
      this.addEvent(record, 'blocked_manually', 'Auto-blocked due to low reputation');
    }
    
    // Check for auto-unblock
    if (record.isBlocked && record.blockUntil && record.blockUntil <= Date.now()) {
      record.isBlocked = false;
      record.blockReason = undefined;
      record.blockUntil = undefined;
      this.addEvent(record, 'unblocked', 'Auto-unblocked after timeout');
    }
    
    // Save updated record
    await this.saveRecord(record);
    
    return record;
  }

  /**
   * Calculate risk level based on record
   */
  private calculateRiskLevel(record: IPTrackingRecord): 'low' | 'medium' | 'high' | 'critical' {
    if (record.reputation <= this.config.reputationThresholds.blocked) {
      return 'critical';
    }
    if (record.reputation <= this.config.reputationThresholds.suspicious) {
      return 'high';
    }
    if (record.reputation < this.config.reputationThresholds.trusted) {
      return 'medium';
    }
    return 'low';
  }

  /**
   * Add event to record
   */
  private addEvent(
    record: IPTrackingRecord,
    type: IPEventType,
    details?: string,
    metadata?: Record<string, any>
  ): void {
    record.events.push({
      timestamp: Date.now(),
      type,
      details,
      metadata,
    });
  }

  /**
   * Check if IP should be blocked
   */
  async shouldBlock(ip: string): Promise<{
    blocked: boolean;
    reason?: string;
    record?: IPTrackingRecord;
  }> {
    const record = await this.getRecord(ip);
    
    if (!record) {
      return { blocked: false };
    }
    
    // Check explicit block
    if (record.isBlocked) {
      // Check if block has expired
      if (record.blockUntil && record.blockUntil <= Date.now()) {
        record.isBlocked = false;
        record.blockReason = undefined;
        record.blockUntil = undefined;
        await this.saveRecord(record);
        return { blocked: false, record };
      }
      return { blocked: true, reason: record.blockReason, record };
    }
    
    // Check reputation-based block
    if (this.config.autoBlockEnabled &&
        record.reputation <= this.config.reputationThresholds.blocked) {
      return {
        blocked: true,
        reason: 'Reputation too low',
        record,
      };
    }
    
    return { blocked: false, record };
  }

  /**
   * Manually block an IP
   */
  async blockIP(
    ip: string,
    reason: string,
    duration?: number
  ): Promise<void> {
    const record = await this.getOrCreateRecord(ip);
    
    record.isBlocked = true;
    record.blockReason = reason;
    if (duration) {
      record.blockUntil = Date.now() + (duration * 1000);
    }
    
    this.addEvent(record, 'blocked_manually', reason);
    await this.saveRecord(record);
  }

  /**
   * Unblock an IP
   */
  async unblockIP(ip: string): Promise<void> {
    const record = await this.getRecord(ip);
    
    if (record) {
      record.isBlocked = false;
      record.blockReason = undefined;
      record.blockUntil = undefined;
      this.addEvent(record, 'unblocked', 'Manually unblocked');
      await this.saveRecord(record);
    }
  }

  /**
   * Mark IP as trusted
   */
  async trustIP(ip: string, reason: string): Promise<void> {
    const record = await this.getOrCreateRecord(ip);
    
    record.isTrusted = true;
    record.trustReason = reason;
    record.isBlocked = false;
    record.blockReason = undefined;
    record.blockUntil = undefined;
    record.reputation = 100;
    record.riskLevel = 'low';
    
    this.addEvent(record, 'trusted', reason);
    await this.saveRecord(record);
  }

  /**
   * Remove trusted status from IP
   */
  async untrustIP(ip: string): Promise<void> {
    const record = await this.getRecord(ip);
    
    if (record) {
      record.isTrusted = false;
      record.trustReason = undefined;
      this.addEvent(record, 'untrusted');
      await this.saveRecord(record);
    }
  }

  /**
   * Get IP record (public interface)
   */
  async getIPInfo(ip: string): Promise<IPTrackingRecord | null> {
    return this.getRecord(ip);
  }

  /**
   * Update IP reputation manually
   */
  async updateReputation(
    ip: string,
    delta: number,
    reason?: string
  ): Promise<IPTrackingRecord | null> {
    const record = await this.getRecord(ip);
    
    if (record) {
      const oldReputation = record.reputation;
      record.reputation = Math.max(0, Math.min(100, record.reputation + delta));
      record.riskLevel = this.calculateRiskLevel(record);
      
      this.addEvent(record, 'reputation_change', reason, {
        oldReputation,
        newReputation: record.reputation,
        delta,
      });
      
      await this.saveRecord(record);
    }
    
    return record;
  }

  /**
   * Delete IP record
   */
  async deleteRecord(ip: string): Promise<void> {
    const key = `ip-track:${ip}`;
    
    this.localCache.delete(ip);
    
    if (this.useMock) {
      this.mockStore.delete(key);
    } else {
      await this.kv!.delete(key);
    }
  }

  /**
   * Get all blocked IPs (from local cache)
   */
  getBlockedIPs(): IPTrackingRecord[] {
    return Array.from(this.localCache.values()).filter(r => r.isBlocked);
  }

  /**
   * Get all trusted IPs (from local cache)
   */
  getTrustedIPs(): IPTrackingRecord[] {
    return Array.from(this.localCache.values()).filter(r => r.isTrusted);
  }

  /**
   * Cleanup old entries from local cache
   */
  cleanupCache(): void {
    const cutoff = Date.now() - (this.config.recordTTL * 1000);
    
    for (const [ip, record] of this.localCache.entries()) {
      if (record.lastSeen < cutoff) {
        this.localCache.delete(ip);
      }
    }
  }

  /**
   * Get configuration
   */
  getConfig(): IPTrackingConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<IPTrackingConfig>): void {
    this.config = { ...this.config, ...config };
  }
}

/**
 * Create an IP tracker instance
 */
export function createIPTracker(
  env: Env,
  config?: Partial<IPTrackingConfig>
): IPTracker {
  return new IPTracker(env.RATE_LIMIT_KV, config);
}

/**
 * Extract IP from request
 */
export function getIPFromRequest(request: Request): string {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Forwarded-For')?.split(',')[0].trim() ||
         'unknown';
}

