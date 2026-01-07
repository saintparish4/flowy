/**
 * Spam Detector
 * Detects and prevents spam posting attacks
 * Monitors posting frequency, content patterns, and automated behavior
 */

import type { Env } from "../types";

// Cloudflare Workers KV type
type KVNamespace = {
  get(key: string, type?: string): Promise<any>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
};

/**
 * Post attempt record
 */
export interface PostAttempt {
  timestamp: number;
  ip: string;
  contentHash?: string;  // Hash of content for duplicate detection
  contentLength: number;
  endpoint: string;
  userAgent?: string;
  hasLinks: boolean;
  linkCount: number;
}

/**
 * Spam detection result
 */
export interface SpamDetectionResult {
  isSpam: boolean;
  confidence: number; // 0-1
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  reason: string;
  recommendation: 'allow' | 'challenge' | 'throttle' | 'block';
  metrics: {
    postsInWindow: number;
    duplicateRatio: number;
    averageInterval: number; // ms between posts
    linkRatio: number;
    ipReputation: number;
  };
}

/**
 * IP spam reputation data
 */
export interface IPSpamReputation {
  ip: string;
  firstSeen: number;
  lastSeen: number;
  totalPosts: number;
  blockedPosts: number;
  duplicatePosts: number;
  linkPosts: number;
  reputation: number; // 0-100
  isBlocked: boolean;
  cooldownUntil?: number;
  contentHashes: Set<string>;
  postIntervals: number[]; // Last 10 intervals
}

/**
 * Spam detection configuration
 */
export interface SpamDetectionConfig {
  // Time windows (in seconds)
  shortWindow: number;      // Short-term analysis window
  cooldownDuration: number; // Cooldown duration after spam detection
  
  // Thresholds
  maxPostsPerMinute: number;     // Max posts per minute
  maxDuplicateRatio: number;     // Max ratio of duplicate content
  minPostInterval: number;       // Minimum ms between posts (human threshold)
  maxLinksPerPost: number;       // Max links per post
  maxLinkRatio: number;          // Max ratio of posts with links
  
  // Content patterns
  suspiciousPatterns: RegExp[];  // Patterns to flag
  blockPatterns: RegExp[];       // Patterns to block immediately
}

/**
 * Default spam patterns
 */
const DEFAULT_SUSPICIOUS_PATTERNS: RegExp[] = [
  /\b(buy|cheap|discount|free|winner|prize|congratulations)\b/i,
  /click\s*here/i,
  /\$\d+[,.]?\d*\s*(off|discount|saving)/i,
  /limited\s*time\s*offer/i,
  /act\s*now/i,
  /\b(viagra|cialis|pharmacy)\b/i,
  /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, // Email patterns in posts
];

const DEFAULT_BLOCK_PATTERNS: RegExp[] = [
  /<script[^>]*>/i,
  /javascript:/i,
  /data:text\/html/i,
  /on\w+\s*=/i, // Event handlers
];

/**
 * Default configuration
 */
export const DEFAULT_SPAM_CONFIG: SpamDetectionConfig = {
  shortWindow: 60,           // 1 minute
  cooldownDuration: 300,     // 5 minute cooldown
  maxPostsPerMinute: 5,      // 5 posts per minute max
  maxDuplicateRatio: 0.3,    // >30% duplicates is suspicious
  minPostInterval: 3000,     // Minimum 3 seconds between posts
  maxLinksPerPost: 5,        // Max 5 links per post
  maxLinkRatio: 0.5,         // >50% posts with links is suspicious
  suspiciousPatterns: DEFAULT_SUSPICIOUS_PATTERNS,
  blockPatterns: DEFAULT_BLOCK_PATTERNS,
};

/**
 * Spam Detector
 */
export class SpamDetector {
  private kv: KVNamespace | null;
  private mockStore: Map<string, any>;
  private useMock: boolean;
  private config: SpamDetectionConfig;
  private postLog: Map<string, PostAttempt[]>;

  constructor(kv?: KVNamespace, config?: Partial<SpamDetectionConfig>) {
    this.kv = kv || null;
    this.mockStore = new Map();
    this.useMock = !kv;
    this.config = { ...DEFAULT_SPAM_CONFIG, ...config };
    this.postLog = new Map();
  }

  /**
   * Get IP spam reputation data
   */
  private async getIPReputation(ip: string): Promise<IPSpamReputation> {
    const key = `spam-rep:${ip}`;
    
    let data: IPSpamReputation | null = null;
    
    if (this.useMock) {
      data = this.mockStore.get(key);
    } else {
      try {
        const stored = await this.kv!.get(key, 'json');
        if (stored) {
          data = stored as IPSpamReputation;
          // Reconstitute Set from array
          if (Array.isArray((data as any).contentHashes)) {
            data.contentHashes = new Set((data as any).contentHashes);
          }
        }
      } catch (error) {
        console.error('Error loading spam reputation:', error);
      }
    }
    
    if (!data) {
      data = {
        ip,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        totalPosts: 0,
        blockedPosts: 0,
        duplicatePosts: 0,
        linkPosts: 0,
        reputation: 50, // Start neutral
        isBlocked: false,
        contentHashes: new Set(),
        postIntervals: [],
      };
    }
    
    return data;
  }

  /**
   * Save IP spam reputation data
   */
  private async saveIPReputation(data: IPSpamReputation): Promise<void> {
    const key = `spam-rep:${data.ip}`;
    
    // Convert Set to array for storage
    const storageData = {
      ...data,
      contentHashes: Array.from(data.contentHashes).slice(-100), // Keep last 100 hashes
    };
    
    if (this.useMock) {
      this.mockStore.set(key, storageData);
    } else {
      try {
        await this.kv!.put(key, JSON.stringify(storageData), {
          expirationTtl: 3600, // Keep for 1 hour
        });
      } catch (error) {
        console.error('Error saving spam reputation:', error);
      }
    }
  }

  /**
   * Simple hash function for content deduplication
   */
  private hashContent(content: string): string {
    let hash = 0;
    const normalized = content.toLowerCase().replace(/\s+/g, ' ').trim();
    
    for (let i = 0; i < normalized.length; i++) {
      const char = normalized.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    
    return hash.toString(16);
  }

  /**
   * Count links in content
   */
  private countLinks(content: string): number {
    const urlPattern = /https?:\/\/[^\s]+/gi;
    const matches = content.match(urlPattern);
    return matches ? matches.length : 0;
  }

  /**
   * Check content against patterns
   */
  private checkPatterns(content: string): { suspicious: boolean; shouldBlock: boolean; matchedPatterns: string[] } {
    const matchedPatterns: string[] = [];
    
    // Check block patterns first
    for (const pattern of this.config.blockPatterns) {
      if (pattern.test(content)) {
        return { suspicious: true, shouldBlock: true, matchedPatterns: [pattern.source] };
      }
    }
    
    // Check suspicious patterns
    for (const pattern of this.config.suspiciousPatterns) {
      if (pattern.test(content)) {
        matchedPatterns.push(pattern.source);
      }
    }
    
    return {
      suspicious: matchedPatterns.length > 0,
      shouldBlock: false,
      matchedPatterns,
    };
  }

  /**
   * Record a post attempt
   */
  async recordPost(post: PostAttempt, content?: string): Promise<void> {
    const ip = post.ip;
    const reputation = await this.getIPReputation(ip);
    const now = Date.now();
    
    // Calculate interval from last post
    const posts = this.postLog.get(ip) || [];
    if (posts.length > 0) {
      const lastPost = posts[posts.length - 1];
      const interval = now - lastPost.timestamp;
      reputation.postIntervals.push(interval);
      // Keep last 10 intervals
      if (reputation.postIntervals.length > 10) {
        reputation.postIntervals = reputation.postIntervals.slice(-10);
      }
    }
    
    // Update reputation data
    reputation.lastSeen = now;
    reputation.totalPosts++;
    
    // Check for duplicate content
    if (post.contentHash) {
      if (reputation.contentHashes.has(post.contentHash)) {
        reputation.duplicatePosts++;
        reputation.reputation = Math.max(0, reputation.reputation - 5);
      }
      reputation.contentHashes.add(post.contentHash);
    }
    
    // Track link posts
    if (post.hasLinks) {
      reputation.linkPosts++;
    }
    
    // Update reputation based on behavior
    if (post.hasLinks && post.linkCount > this.config.maxLinksPerPost) {
      reputation.reputation = Math.max(0, reputation.reputation - 10);
    }
    
    // Save updated reputation
    await this.saveIPReputation(reputation);
    
    // Add to post log
    if (!this.postLog.has(ip)) {
      this.postLog.set(ip, []);
    }
    const log = this.postLog.get(ip)!;
    log.push(post);
    
    // Cleanup old entries
    const cutoff = now - (this.config.shortWindow * 1000);
    this.postLog.set(ip, log.filter(p => p.timestamp > cutoff));
  }

  /**
   * Check if content/IP is exhibiting spam behavior
   */
  async check(ip: string, content?: string, endpoint?: string): Promise<SpamDetectionResult> {
    const reputation = await this.getIPReputation(ip);
    const posts = this.postLog.get(ip) || [];
    const now = Date.now();
    
    // Check for active cooldown
    if (reputation.isBlocked && reputation.cooldownUntil && reputation.cooldownUntil > now) {
      return {
        isSpam: true,
        confidence: 1.0,
        severity: 'critical',
        reason: 'IP is in cooldown due to spam detection',
        recommendation: 'block',
        metrics: {
          postsInWindow: posts.length,
          duplicateRatio: reputation.duplicatePosts / Math.max(1, reputation.totalPosts),
          averageInterval: this.calculateAverageInterval(reputation.postIntervals),
          linkRatio: reputation.linkPosts / Math.max(1, reputation.totalPosts),
          ipReputation: reputation.reputation,
        },
      };
    }
    
    // Reset cooldown if expired
    if (reputation.isBlocked && reputation.cooldownUntil && reputation.cooldownUntil <= now) {
      reputation.isBlocked = false;
      reputation.cooldownUntil = undefined;
      await this.saveIPReputation(reputation);
    }
    
    // Analyze indicators
    let isSpam = false;
    let confidence = 0;
    const indicators: string[] = [];
    
    // Check content patterns if provided
    if (content) {
      const patternCheck = this.checkPatterns(content);
      if (patternCheck.shouldBlock) {
        return {
          isSpam: true,
          confidence: 1.0,
          severity: 'critical',
          reason: `Blocked pattern detected: ${patternCheck.matchedPatterns.join(', ')}`,
          recommendation: 'block',
          metrics: {
            postsInWindow: posts.length,
            duplicateRatio: reputation.duplicatePosts / Math.max(1, reputation.totalPosts),
            averageInterval: this.calculateAverageInterval(reputation.postIntervals),
            linkRatio: reputation.linkPosts / Math.max(1, reputation.totalPosts),
            ipReputation: reputation.reputation,
          },
        };
      }
      if (patternCheck.suspicious) {
        isSpam = true;
        confidence += 0.2;
        indicators.push(`Suspicious patterns: ${patternCheck.matchedPatterns.length}`);
      }
      
      // Check for excessive links
      const linkCount = this.countLinks(content);
      if (linkCount > this.config.maxLinksPerPost) {
        isSpam = true;
        confidence += 0.2;
        indicators.push(`${linkCount} links exceeds max of ${this.config.maxLinksPerPost}`);
      }
    }
    
    // Check post frequency
    const shortWindowCutoff = now - (this.config.shortWindow * 1000);
    const recentPosts = posts.filter(p => p.timestamp > shortWindowCutoff);
    const postsPerMinute = (recentPosts.length / this.config.shortWindow) * 60;
    
    if (postsPerMinute > this.config.maxPostsPerMinute) {
      isSpam = true;
      confidence += 0.3;
      indicators.push(`${postsPerMinute.toFixed(1)} posts/min exceeds limit`);
    }
    
    // Check duplicate ratio
    const duplicateRatio = reputation.duplicatePosts / Math.max(1, reputation.totalPosts);
    if (duplicateRatio > this.config.maxDuplicateRatio && reputation.totalPosts >= 3) {
      isSpam = true;
      confidence += 0.25;
      indicators.push(`${(duplicateRatio * 100).toFixed(1)}% duplicate content`);
    }
    
    // Check post intervals (too fast = bot)
    const avgInterval = this.calculateAverageInterval(reputation.postIntervals);
    if (avgInterval > 0 && avgInterval < this.config.minPostInterval && reputation.postIntervals.length >= 3) {
      isSpam = true;
      confidence += 0.3;
      indicators.push(`${avgInterval.toFixed(0)}ms average interval (bot-like speed)`);
    }
    
    // Check link ratio
    const linkRatio = reputation.linkPosts / Math.max(1, reputation.totalPosts);
    if (linkRatio > this.config.maxLinkRatio && reputation.totalPosts >= 5) {
      isSpam = true;
      confidence += 0.15;
      indicators.push(`${(linkRatio * 100).toFixed(1)}% posts contain links`);
    }
    
    // Check reputation
    if (reputation.reputation < 20) {
      isSpam = true;
      confidence += 0.1;
      indicators.push(`Low IP reputation: ${reputation.reputation}`);
    }
    
    // Determine severity and recommendation
    confidence = Math.min(1, confidence);
    let severity: SpamDetectionResult['severity'] = 'none';
    let recommendation: SpamDetectionResult['recommendation'] = 'allow';
    let reason = 'No spam detected';
    
    if (isSpam) {
      if (confidence >= 0.8) {
        severity = 'critical';
        recommendation = 'block';
        reason = `Critical spam detected: ${indicators.join(', ')}`;
        // Apply cooldown
        reputation.isBlocked = true;
        reputation.cooldownUntil = now + (this.config.cooldownDuration * 1000);
        await this.saveIPReputation(reputation);
      } else if (confidence >= 0.6) {
        severity = 'high';
        recommendation = 'block';
        reason = `High confidence spam: ${indicators.join(', ')}`;
      } else if (confidence >= 0.4) {
        severity = 'medium';
        recommendation = 'throttle';
        reason = `Suspected spam: ${indicators.join(', ')}`;
      } else {
        severity = 'low';
        recommendation = 'challenge';
        reason = `Possible spam: ${indicators.join(', ')}`;
      }
    }
    
    return {
      isSpam,
      confidence,
      severity,
      reason,
      recommendation,
      metrics: {
        postsInWindow: recentPosts.length,
        duplicateRatio,
        averageInterval: avgInterval,
        linkRatio,
        ipReputation: reputation.reputation,
      },
    };
  }

  /**
   * Calculate average interval from array
   */
  private calculateAverageInterval(intervals: number[]): number {
    if (intervals.length === 0) return 0;
    return intervals.reduce((a, b) => a + b, 0) / intervals.length;
  }

  /**
   * Check if IP should be throttled
   */
  async shouldThrottle(ip: string): Promise<boolean> {
    const result = await this.check(ip);
    return result.recommendation === 'throttle' || 
           result.recommendation === 'block';
  }

  /**
   * Check if IP should be blocked
   */
  async shouldBlock(ip: string): Promise<boolean> {
    const result = await this.check(ip);
    return result.recommendation === 'block';
  }

  /**
   * Check content before posting
   */
  async checkContent(ip: string, content: string, endpoint: string): Promise<SpamDetectionResult> {
    // Create a content hash for this check
    const contentHash = this.hashContent(content);
    const linkCount = this.countLinks(content);
    
    // Temporarily record this post for accurate checking
    const post: PostAttempt = {
      timestamp: Date.now(),
      ip,
      contentHash,
      contentLength: content.length,
      endpoint,
      hasLinks: linkCount > 0,
      linkCount,
    };
    
    // Check against current state
    return this.check(ip, content, endpoint);
  }

  /**
   * Reset IP spam reputation
   */
  async resetIP(ip: string): Promise<void> {
    const key = `spam-rep:${ip}`;
    if (this.useMock) {
      this.mockStore.delete(key);
    } else {
      await this.kv!.delete(key);
    }
    this.postLog.delete(ip);
  }

  /**
   * Get IP statistics
   */
  async getIPStats(ip: string): Promise<IPSpamReputation> {
    return this.getIPReputation(ip);
  }
}

/**
 * Create a spam detector
 */
export function createSpamDetector(
  env: Env,
  config?: Partial<SpamDetectionConfig>
): SpamDetector {
  return new SpamDetector(env.RATE_LIMIT_KV, config);
}

