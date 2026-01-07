/**
 * Adaptive Rate Limiting System
 * Dynamically adjusts rate limits based on traffic composition and patterns
 * Used for bot management and adaptive response to attack patterns
 */

import type { RateLimitConfig } from "../types";
import type { TrafficClass, ClassificationResult } from "./traffic-classifier";

/**
 * Traffic composition metrics
 */
export interface TrafficComposition {
  totalRequests: number;
  legitimate: number;
  suspicious: number;
  malicious: number;
  unknown: number;

  // Percentages
  legitimatePercent: number;
  suspiciousPercent: number;
  maliciousPercent: number;
  unknownPercent: number;

  // Trends
  trend: "improving" | "degrading" | "stable";
  attackIntensity: number; // 0-1, 0=no attack, 1=severe attack
}

/**
 * Adaptive rate limit adjustment
 */
export interface AdaptiveAdjustment {
  multiplier: number; // Applied to base rate limits
  reason: string;
  composition: TrafficComposition;
}

/**
 * Adaptive Rate Limiting Configuration
 */
export interface AdaptiveConfig {
  // Enable/disable adaptive adjustments
  enabled: boolean;

  // Adjustment thresholds
  maliciousThreshold: number; // % of traffic that triggers tightening
  legitimateThreshold: number; // % of traffic that triggers relaxing

  // Adjustment limits
  minMultiplier: number; // Minimum adjustment (0.1 = 10% of base)
  maxMultiplier: number; // Maximum adjustment (5.0 = 500% of base)

  // Adjustment speed
  adjustmentRate: number; // How quickly to adjust (0-1)

  // Window for composition analysis
  analysisWindow: number; // seconds
}

/**
 * Adaptive Rate Limiter
 */
export class AdaptiveRateLimiter {
  private config: AdaptiveConfig;
  private composition: TrafficComposition;
  private currentMultiplier: number = 1.0;
  private adjustmentHistory: Array<{
    timestamp: number;
    multiplier: number;
    composition: TrafficComposition;
  }> = [];

  private classificationLog: Array<{
    timestamp: number;
    class: TrafficClass;
  }> = [];

  constructor(config?: Partial<AdaptiveConfig>) {
    this.config = {
      enabled: true,
      maliciousThreshold: 0.2, // >20% malicious traffic
      legitimateThreshold: 0.8, // >80% legitimate traffic
      minMultiplier: 0.1,
      maxMultiplier: 5.0,
      adjustmentRate: 0.2, // Adjust 20% towards target each time
      analysisWindow: 60, // Last 60 seconds
      ...config,
    };

    this.composition = {
      totalRequests: 0,
      legitimate: 0,
      suspicious: 0,
      malicious: 0,
      unknown: 0,
      legitimatePercent: 0,
      suspiciousPercent: 0,
      maliciousPercent: 0,
      unknownPercent: 0,
      trend: "stable",
      attackIntensity: 0,
    };
  }

  /**
   * Record a classification
   */
  recordClassification(classification: ClassificationResult): void {
    this.classificationLog.push({
      timestamp: Date.now(),
      class: classification.class,
    });

    // Clean up old entries
    const cutoff = Date.now() - this.config.analysisWindow * 1000;
    this.classificationLog = this.classificationLog.filter(
      (entry) => entry.timestamp >= cutoff
    );

    // Update composition
    this.updateComposition();

    // Calculate adjustment
    if (this.config.enabled) {
      this.calculateAdjustment();
    }
  }

  /**
   * Update traffic composition metrics
   */
  private updateComposition(): void {
    const total = this.classificationLog.length;

    if (total === 0) {
      this.composition = {
        totalRequests: 0,
        legitimate: 0,
        suspicious: 0,
        malicious: 0,
        unknown: 0,
        legitimatePercent: 0,
        suspiciousPercent: 0,
        maliciousPercent: 0,
        unknownPercent: 0,
        trend: "stable",
        attackIntensity: 0,
      };
      return;
    }

    const counts = {
      legitimate: 0,
      suspicious: 0,
      malicious: 0,
      unknown: 0,
    };

    this.classificationLog.forEach((entry) => {
      counts[entry.class]++;
    });

    this.composition = {
      totalRequests: total,
      legitimate: counts.legitimate,
      suspicious: counts.suspicious,
      malicious: counts.malicious,
      unknown: counts.unknown,
      legitimatePercent: (counts.legitimate / total) * 100,
      suspiciousPercent: (counts.suspicious / total) * 100,
      maliciousPercent: (counts.malicious / total) * 100,
      unknownPercent: (counts.unknown / total) * 100,
      trend: this.calculateTrend(),
      attackIntensity: this.calculateAttackIntensity(counts, total),
    };
  }

  /**
   * Calculate trend (improving/degrading/stable)
   */
  private calculateTrend(): "improving" | "degrading" | "stable" {
    if (this.adjustmentHistory.length < 2) {
      return "stable";
    }

    const current = this.composition.maliciousPercent;
    const previous =
      this.adjustmentHistory[this.adjustmentHistory.length - 1].composition
        .maliciousPercent;

    const change = current - previous;

    if (change > 10) return "degrading"; // +10% malicious
    if (change < -10) return "improving"; // -10% malicious
    return "stable";
  }

  /**
   * Calculate attack intensity (0-1)
   */
  private calculateAttackIntensity(
    counts: Record<TrafficClass, number>,
    total: number
  ): number {
    const maliciousRatio = counts.malicious / total;
    const suspiciousRatio = counts.suspicious / total;

    // Combine malicious and suspicious traffic
    const badTrafficRatio = maliciousRatio + suspiciousRatio * 0.5;

    // Scale to 0-1
    return Math.min(1, badTrafficRatio * 2);
  }

  /**
   * Calculate adaptive adjustment
   */
  private calculateAdjustment(): void {
    const { maliciousThreshold, legitimateThreshold, adjustmentRate } =
      this.config;
    const { maliciousPercent, legitimatePercent } = this.composition;

    let targetMultiplier = 1.0;
    let reason = "Normal traffic composition";

    // Under attack - tighten limits
    if (maliciousPercent > maliciousThreshold * 100) {
      // More severe attacks = tighter limits
      const severity = maliciousPercent / 100;
      targetMultiplier = 1.0 - severity * 0.8; // Down to 0.2x in severe attacks
      reason = `Attack detected: ${maliciousPercent.toFixed(
        1
      )}% malicious traffic`;
    }
    // Mostly legitimate - relax limits
    else if (legitimatePercent > legitimateThreshold * 100) {
      // More legitimate traffic = more relaxed limits
      const legitimacy = legitimatePercent / 100;
      targetMultiplier = 1.0 + (legitimacy - legitimateThreshold) * 3;
      reason = `Healthy traffic: ${legitimatePercent.toFixed(1)}% legitimate`;
    }
    // Mixed traffic - slight tightening
    else if (maliciousPercent + this.composition.suspiciousPercent > 40) {
      targetMultiplier = 0.7;
      reason = "Mixed traffic with suspicious patterns";
    }

    // Apply bounds
    targetMultiplier = Math.max(
      this.config.minMultiplier,
      Math.min(this.config.maxMultiplier, targetMultiplier)
    );

    // Gradually adjust towards target (smooth transitions)
    this.currentMultiplier =
      this.currentMultiplier +
      (targetMultiplier - this.currentMultiplier) * adjustmentRate;

    // Record adjustment
    this.adjustmentHistory.push({
      timestamp: Date.now(),
      multiplier: this.currentMultiplier,
      composition: { ...this.composition },
    });

    // Keep last 100 adjustments
    if (this.adjustmentHistory.length > 100) {
      this.adjustmentHistory = this.adjustmentHistory.slice(-100);
    }
  }

  /**
   * Get current adjustment to apply to rate limits
   */
  getAdjustment(): AdaptiveAdjustment {
    return {
      multiplier: this.currentMultiplier,
      reason: this.getAdjustmentReason(),
      composition: { ...this.composition },
    };
  }

  /**
   * Get explanation for current adjustment
   */
  private getAdjustmentReason(): string {
    const m = this.currentMultiplier;

    if (m < 0.5) {
      return `Severe attack detected - limits tightened to ${(m * 100).toFixed(
        0
      )}%`;
    } else if (m < 0.8) {
      return `Attack detected - limits reduced to ${(m * 100).toFixed(0)}%`;
    } else if (m > 2.0) {
      return `Healthy traffic - limits relaxed to ${(m * 100).toFixed(0)}%`;
    } else if (m > 1.2) {
      return `Good traffic - limits increased to ${(m * 100).toFixed(0)}%`;
    } else {
      return "Normal traffic - standard limits applied";
    }
  }

  /**
   * Apply adjustment to rate limit configuration
   */
  adjustRateLimit(baseConfig: RateLimitConfig): RateLimitConfig {
    if (!this.config.enabled) {
      return baseConfig;
    }

    return {
      ...baseConfig,
      limit: Math.floor(baseConfig.limit * this.currentMultiplier),
    };
  }

  /**
   * Get current traffic composition
   */
  getComposition(): TrafficComposition {
    return { ...this.composition };
  }

  /**
   * Get adjustment history
   */
  getHistory(): Array<{
    timestamp: number;
    multiplier: number;
    composition: TrafficComposition;
  }> {
    return [...this.adjustmentHistory];
  }

  /**
   * Reset adaptive state
   */
  reset(): void {
    this.currentMultiplier = 1.0;
    this.classificationLog = [];
    this.adjustmentHistory = [];
    this.updateComposition();
  }

  /**
   * Enable/disable adaptive adjustments
   */
  setEnabled(enabled: boolean): void {
    this.config.enabled = enabled;
    if (!enabled) {
      this.currentMultiplier = 1.0;
    }
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<AdaptiveConfig>): void {
    this.config = { ...this.config, ...config };
  }
}

/**
 * Create an adaptive rate limiter instance
 */
export function createAdaptiveRateLimiter(
  config?: Partial<AdaptiveConfig>
): AdaptiveRateLimiter {
  return new AdaptiveRateLimiter(config);
}

/**
 * Predefined adaptive configurations
 */
export const ADAPTIVE_CONFIGS = {
  // Aggressive - quickly tighten during attacks
  AGGRESSIVE: {
    maliciousThreshold: 0.1, // Tighten at 10% malicious
    legitimateThreshold: 0.9, // Relax at 90% legitimate
    adjustmentRate: 0.5, // Fast adjustment
    minMultiplier: 0.1,
    maxMultiplier: 3.0,
  },

  // Balanced - moderate adjustments
  BALANCED: {
    maliciousThreshold: 0.2,
    legitimateThreshold: 0.8,
    adjustmentRate: 0.2,
    minMultiplier: 0.2,
    maxMultiplier: 5.0,
  },

  // Conservative - slow to adjust, wide range
  CONSERVATIVE: {
    maliciousThreshold: 0.3,
    legitimateThreshold: 0.7,
    adjustmentRate: 0.1,
    minMultiplier: 0.3,
    maxMultiplier: 10.0,
  },
};

