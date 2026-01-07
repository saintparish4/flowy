/**
 * Bot Management Module
 * Unified exports for bot detection and protection functionality
 * 
 * This module handles:
 * - Credential stuffing detection
 * - Spam posting prevention
 * - Session management and behavioral analysis
 * - Traffic classification
 * - Turnstile integration for bot challenges
 * - Adaptive rate limiting based on traffic patterns
 */

// Session Management
export {
  BotSessionManager,
  SessionAwareRateLimiter,
  getSessionId,
  createBotSessionManager,
  createSessionRateLimiter,
  TRUST_MULTIPLIERS,
  BEHAVIORAL_THRESHOLDS,
  type Session,
  type TrustLevel,
  type BehavioralSignals,
} from './session-manager';

// Credential Stuffing Detection
export {
  CredentialStuffingDetector,
  createCredentialStuffingDetector,
  DEFAULT_CREDENTIAL_STUFFING_CONFIG,
  type LoginAttempt,
  type CredentialStuffingResult,
  type IPCredentialReputation,
  type CredentialStuffingConfig,
} from './credential-stuffing-detector';

// Spam Detection
export {
  SpamDetector,
  createSpamDetector,
  DEFAULT_SPAM_CONFIG,
  type PostAttempt,
  type SpamDetectionResult,
  type IPSpamReputation,
  type SpamDetectionConfig,
} from './spam-detector';

// Traffic Classification
export {
  TrafficClassifier,
  createTrafficClassifier,
  type TrafficClass,
  type TrafficSignals,
  type ClassificationResult,
  type TrafficReputation,
} from './traffic-classifier';

// Adaptive Rate Limiting
export {
  AdaptiveRateLimiter,
  createAdaptiveRateLimiter,
  ADAPTIVE_CONFIGS,
  type TrafficComposition,
  type AdaptiveAdjustment,
  type AdaptiveConfig,
} from './adaptive-rate-limiter';

// Turnstile Integration
export {
  TurnstileVerifier,
  createTurnstileVerifier,
  requireTurnstile,
} from './turnstile';

// Re-export TurnstileVerifyResponse from types
export type { TurnstileVerifyResponse } from '../types';

// Re-export TurnstileVerifyResponse from types for convenience
import type { TurnstileVerifyResponse as TurnstileResponse } from '../types';
export type { TurnstileResponse };

/**
 * Bot Protection Configuration
 * Combined configuration for all bot protection features
 */
export interface BotProtectionConfig {
  // Session management
  sessionTracking: boolean;
  sessionTTL: number; // seconds
  
  // Credential stuffing
  credentialStuffingDetection: boolean;
  credentialStuffingConfig?: Partial<import('./credential-stuffing-detector').CredentialStuffingConfig>;
  
  // Spam detection
  spamDetection: boolean;
  spamConfig?: Partial<import('./spam-detector').SpamDetectionConfig>;
  
  // Traffic classification
  trafficClassification: boolean;
  
  // Adaptive rate limiting
  adaptiveRateLimiting: boolean;
  adaptiveConfig?: Partial<import('./adaptive-rate-limiter').AdaptiveConfig>;
  
  // Turnstile
  turnstileEnabled: boolean;
  turnstileSecretKey?: string;
}

/**
 * Default bot protection configuration
 */
export const DEFAULT_BOT_PROTECTION_CONFIG: BotProtectionConfig = {
  sessionTracking: true,
  sessionTTL: 3600,
  credentialStuffingDetection: true,
  spamDetection: true,
  trafficClassification: true,
  adaptiveRateLimiting: true,
  turnstileEnabled: false,
};

/**
 * Unified Bot Protection Manager
 * Provides a single interface for all bot protection features
 */
export class BotProtectionManager {
  private config: BotProtectionConfig;
  private sessionManager?: BotSessionManager;
  private credentialStuffingDetector?: CredentialStuffingDetector;
  private spamDetector?: SpamDetector;
  private trafficClassifier?: TrafficClassifier;
  private adaptiveRateLimiter?: AdaptiveRateLimiter;
  private turnstileVerifier?: TurnstileVerifier;

  constructor(
    env: { RATE_LIMIT_KV?: KVNamespace; TURNSTILE_SECRET_KEY?: string; TURNSTILE_ENABLED?: string },
    config?: Partial<BotProtectionConfig>
  ) {
    this.config = { ...DEFAULT_BOT_PROTECTION_CONFIG, ...config };
    
    // Initialize components based on configuration
    if (this.config.sessionTracking) {
      this.sessionManager = new BotSessionManager(env.RATE_LIMIT_KV);
    }
    
    if (this.config.credentialStuffingDetection) {
      this.credentialStuffingDetector = new CredentialStuffingDetector(
        env.RATE_LIMIT_KV,
        this.config.credentialStuffingConfig
      );
    }
    
    if (this.config.spamDetection) {
      this.spamDetector = new SpamDetector(
        env.RATE_LIMIT_KV,
        this.config.spamConfig
      );
    }
    
    if (this.config.trafficClassification) {
      this.trafficClassifier = new TrafficClassifier();
    }
    
    if (this.config.adaptiveRateLimiting) {
      this.adaptiveRateLimiter = new AdaptiveRateLimiter(this.config.adaptiveConfig);
    }
    
    if (this.config.turnstileEnabled || env.TURNSTILE_ENABLED === 'true') {
      this.turnstileVerifier = new TurnstileVerifier({
        TURNSTILE_SECRET_KEY: this.config.turnstileSecretKey || env.TURNSTILE_SECRET_KEY,
        TURNSTILE_ENABLED: 'true',
      } as any);
    }
  }

  /**
   * Check all bot protection measures for a request
   */
  async checkRequest(
    request: Request,
    options?: {
      checkCredentialStuffing?: boolean;
      checkSpam?: boolean;
      content?: string;
      endpoint?: string;
    }
  ): Promise<{
    allowed: boolean;
    reason?: string;
    challenges: string[];
    session?: Session;
    classification?: ClassificationResult;
  }> {
    const ip = request.headers.get('CF-Connecting-IP') || 
               request.headers.get('X-Forwarded-For') || 
               'unknown';
    
    const challenges: string[] = [];
    let allowed = true;
    let reason: string | undefined;
    let session: Session | undefined;
    let classification: ClassificationResult | undefined;
    
    // Get session
    if (this.sessionManager) {
      const sessionId = getSessionId(request);
      session = await this.sessionManager.getSession(sessionId, request);
      
      // Check if session is blocked
      if (session.trustLevel === 'blocked') {
        allowed = false;
        reason = 'Session blocked due to suspicious behavior';
        challenges.push('session_blocked');
      }
    }
    
    // Traffic classification
    if (this.trafficClassifier && allowed) {
      classification = this.trafficClassifier.classify(request, session);
      
      if (classification.class === 'malicious') {
        allowed = false;
        reason = `Malicious traffic: ${classification.reasons.join(', ')}`;
        challenges.push('traffic_classification');
      } else if (classification.class === 'suspicious') {
        challenges.push('traffic_suspicious');
      }
      
      // Feed to adaptive rate limiter
      if (this.adaptiveRateLimiter) {
        this.adaptiveRateLimiter.recordClassification(classification);
      }
    }
    
    // Credential stuffing check
    if (this.credentialStuffingDetector && options?.checkCredentialStuffing && allowed) {
      const credResult = await this.credentialStuffingDetector.check(ip);
      
      if (credResult.recommendation === 'lockout' || credResult.recommendation === 'block') {
        allowed = false;
        reason = credResult.reason;
        challenges.push('credential_stuffing');
      } else if (credResult.recommendation === 'challenge') {
        challenges.push('credential_stuffing_challenge');
      }
    }
    
    // Spam check
    if (this.spamDetector && options?.checkSpam && options.content && allowed) {
      const spamResult = await this.spamDetector.checkContent(
        ip,
        options.content,
        options.endpoint || request.url
      );
      
      if (spamResult.recommendation === 'block') {
        allowed = false;
        reason = spamResult.reason;
        challenges.push('spam_detection');
      } else if (spamResult.recommendation === 'throttle') {
        challenges.push('spam_throttle');
      } else if (spamResult.recommendation === 'challenge') {
        challenges.push('spam_challenge');
      }
    }
    
    return {
      allowed,
      reason,
      challenges,
      session,
      classification,
    };
  }

  /**
   * Get adaptive rate limit adjustment
   */
  getAdaptiveAdjustment(): AdaptiveAdjustment | null {
    if (!this.adaptiveRateLimiter) return null;
    return this.adaptiveRateLimiter.getAdjustment();
  }

  /**
   * Get session manager
   */
  getSessionManager(): BotSessionManager | undefined {
    return this.sessionManager;
  }

  /**
   * Get credential stuffing detector
   */
  getCredentialStuffingDetector(): CredentialStuffingDetector | undefined {
    return this.credentialStuffingDetector;
  }

  /**
   * Get spam detector
   */
  getSpamDetector(): SpamDetector | undefined {
    return this.spamDetector;
  }

  /**
   * Get traffic classifier
   */
  getTrafficClassifier(): TrafficClassifier | undefined {
    return this.trafficClassifier;
  }

  /**
   * Get turnstile verifier
   */
  getTurnstileVerifier(): TurnstileVerifier | undefined {
    return this.turnstileVerifier;
  }
}

// Import classes for the manager (not just types - needed at runtime)
import { BotSessionManager, getSessionId } from './session-manager';
import { CredentialStuffingDetector } from './credential-stuffing-detector';
import { SpamDetector } from './spam-detector';
import { TrafficClassifier } from './traffic-classifier';
import type { ClassificationResult } from './traffic-classifier';
import { AdaptiveRateLimiter } from './adaptive-rate-limiter';
import type { AdaptiveAdjustment } from './adaptive-rate-limiter';
import { TurnstileVerifier } from './turnstile';
import type { Session } from './session-manager';

// KV type for the manager
type KVNamespace = {
  get(key: string, type?: string): Promise<any>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
};

/**
 * Create a bot protection manager
 */
export function createBotProtectionManager(
  env: { RATE_LIMIT_KV?: KVNamespace; TURNSTILE_SECRET_KEY?: string; TURNSTILE_ENABLED?: string },
  config?: Partial<BotProtectionConfig>
): BotProtectionManager {
  return new BotProtectionManager(env, config);
}

