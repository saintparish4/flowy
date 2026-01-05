/**
 * Traffic Classification and Reputation System
 * Classifies traffic as legitimate, suspicious, or malicious
 * Uses multiple signals for accurate classification
 */

/**
 * Traffic classification result
 */
export type TrafficClass =
  | "legitimate"
  | "suspicious"
  | "malicious"
  | "unknown";

/**
 * Traffic signals for classification
 */
export interface TrafficSignals {
  // Request characteristics
  hasValidUserAgent: boolean;
  userAgentType: "browser" | "bot" | "tool" | "unknown";
  hasCommonHeaders: boolean; // Accept, Accept-Language, etc.
  usesHTTPS: boolean;

  // Behavioral signals
  requestRate: number; // requests per second
  burstiness: number; // variance in timing (0-1)
  endpointDiversity: number; // unique endpoints accessed
  sequentialPatterns: boolean; // accessing /page/1, /page/2, etc.

  // Content signals
  hasWAFViolations: boolean;
  hasSQLPatterns: boolean;
  hasXSSPatterns: boolean;
  hasPathTraversal: boolean;

  // Session signals
  sessionAge: number; // milliseconds
  sessionRequestCount: number;
  sessionBlockedRatio: number;
  sessionReputation: number; // 0-100

  // Geographic/network signals
  country?: string;
  asn?: string;
  knownVPN: boolean;
  knownDatacenter: boolean;
}

/**
 * Classification result with confidence score
 */
export interface ClassificationResult {
  class: TrafficClass;
  confidence: number; // 0-1
  signals: TrafficSignals;
  reasons: string[];
  score: number; // Composite score (-100 to 100)
}

/**
 * Traffic reputation tracker
 */
export interface TrafficReputation {
  id: string;
  class: TrafficClass;
  score: number; // -100 (malicious) to 100 (legitimate)
  confidence: number;
  firstSeen: number;
  lastSeen: number;
  requestCount: number;
  blockedCount: number;
  wafViolations: number;
  history: Array<{
    timestamp: number;
    event: "request" | "block" | "waf-violation" | "suspicious-behavior";
    detail?: string;
  }>;
}

/**
 * Traffic Classifier
 */
export class TrafficClassifier {
  private reputations: Map<string, TrafficReputation> = new Map();

  // Known bad patterns
  private knownBotUserAgents = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /python-requests/i,
    /curl/i,
    /wget/i,
    /httpclient/i,
  ];

  private knownBrowserUserAgents = [
    /Mozilla/i,
    /Chrome/i,
    /Safari/i,
    /Firefox/i,
    /Edge/i,
  ];

  // Known datacenter ASNs (simplified - in production, use full list)
  private knownDatacenterASNs = new Set([
    "AS16509", // Amazon
    "AS15169", // Google
    "AS8075", // Microsoft
    "AS14061", // DigitalOcean
  ]);

  /**
   * Extract signals from request
   */
  extractSignals(
    request: Request,
    session?: any,
    wafResult?: any,
    burstResult?: any
  ): TrafficSignals {
    const userAgent = request.headers.get("User-Agent") || "";
    const url = new URL(request.url);

    // User agent analysis
    const hasValidUserAgent = userAgent.length > 10;
    let userAgentType: TrafficSignals["userAgentType"] = "unknown";

    if (this.knownBrowserUserAgents.some((p) => p.test(userAgent))) {
      userAgentType = "browser";
    } else if (this.knownBotUserAgents.some((p) => p.test(userAgent))) {
      userAgentType = "bot";
    } else if (userAgent.includes("curl") || userAgent.includes("wget")) {
      userAgentType = "tool";
    }

    // Common headers
    const hasCommonHeaders = !!(
      request.headers.get("Accept") &&
      request.headers.get("Accept-Language") &&
      request.headers.get("Accept-Encoding")
    );

    // Protocol
    const usesHTTPS = url.protocol === "https:";

    // Behavioral signals
    const requestRate = session?.requestCount
      ? session.requestCount / ((Date.now() - session.firstSeen) / 1000)
      : 0;

    const burstiness = burstResult?.severity === "none" ? 0.7 : 0.1;
    const endpointDiversity = session?.endpoints?.size || 0;
    const sequentialPatterns = false; // TODO: Detect /page/1, /page/2 patterns

    // Content signals
    const hasWAFViolations = wafResult?.blocked || false;
    const query = url.search.toLowerCase();
    const hasSQLPatterns = /select|union|drop|insert|delete|update/.test(query);
    const hasXSSPatterns = /<script|javascript:|onerror=/.test(query);
    const hasPathTraversal = /\.\.\/|\.\.\\/.test(url.pathname + url.search);

    // Session signals
    const sessionAge = session ? Date.now() - session.firstSeen : 0;
    const sessionRequestCount = session?.requestCount || 0;
    const sessionBlockedRatio = session?.blockedCount
      ? session.blockedCount / session.requestCount
      : 0;
    const sessionReputation = session?.reputation || 50;

    // Geographic/network signals
    const country = request.headers.get("CF-IPCountry") || undefined;
    const asn = request.headers.get("CF-ASN") || undefined;
    const knownVPN = false; // TODO: Maintain VPN IP list
    const knownDatacenter = asn ? this.knownDatacenterASNs.has(asn) : false;

    return {
      hasValidUserAgent,
      userAgentType,
      hasCommonHeaders,
      usesHTTPS,
      requestRate,
      burstiness,
      endpointDiversity,
      sequentialPatterns,
      hasWAFViolations,
      hasSQLPatterns,
      hasXSSPatterns,
      hasPathTraversal,
      sessionAge,
      sessionRequestCount,
      sessionBlockedRatio,
      sessionReputation,
      country,
      asn,
      knownVPN,
      knownDatacenter,
    };
  }

  /**
   * Calculate traffic score based on signals
   * Returns -100 (definitely malicious) to 100 (definitely legitimate)
   */
  calculateScore(signals: TrafficSignals): number {
    let score = 0;

    // Positive signals (legitimate traffic)
    if (signals.userAgentType === "browser") score += 20;
    if (signals.hasValidUserAgent) score += 10;
    if (signals.hasCommonHeaders) score += 15;
    if (signals.usesHTTPS) score += 5;
    if (signals.burstiness > 0.5) score += 10; // Human-like variance
    if (signals.endpointDiversity >= 3) score += 15;
    if (signals.sessionAge > 300000) score += 10; // >5 minutes
    if (signals.sessionReputation >= 70) score += 15;

    // Negative signals (suspicious/malicious)
    if (signals.hasWAFViolations) score -= 50;
    if (signals.hasSQLPatterns) score -= 40;
    if (signals.hasXSSPatterns) score -= 40;
    if (signals.hasPathTraversal) score -= 40;
    if (signals.userAgentType === "bot") score -= 20;
    if (signals.userAgentType === "tool") score -= 30;
    if (!signals.hasValidUserAgent) score -= 25;
    if (signals.requestRate > 10) score -= 30; // >10 req/s
    if (signals.burstiness < 0.2) score -= 20; // Bot-like consistency
    if (signals.sessionBlockedRatio > 0.5) score -= 35;
    if (signals.sequentialPatterns) score -= 15; // Scraping pattern
    if (signals.knownDatacenter) score -= 10;
    if (signals.knownVPN) score -= 15;

    return Math.max(-100, Math.min(100, score));
  }

  /**
   * Classify traffic based on signals
   */
  classify(
    request: Request,
    session?: any,
    wafResult?: any,
    burstResult?: any
  ): ClassificationResult {
    const signals = this.extractSignals(
      request,
      session,
      wafResult,
      burstResult
    );
    const score = this.calculateScore(signals);

    // Determine classification
    let trafficClass: TrafficClass;
    let confidence: number;
    const reasons: string[] = [];

    if (score >= 50) {
      trafficClass = "legitimate";
      confidence = score / 100;
      if (signals.userAgentType === "browser")
        reasons.push("Browser user agent");
      if (signals.hasCommonHeaders) reasons.push("Standard HTTP headers");
      if (signals.sessionAge > 300000) reasons.push("Established session");
      if (signals.endpointDiversity >= 3)
        reasons.push("Diverse browsing pattern");
    } else if (score <= -50) {
      trafficClass = "malicious";
      confidence = Math.abs(score) / 100;
      if (signals.hasWAFViolations) reasons.push("WAF rule violation");
      if (signals.hasSQLPatterns) reasons.push("SQL injection pattern");
      if (signals.hasXSSPatterns) reasons.push("XSS attack pattern");
      if (signals.hasPathTraversal) reasons.push("Path traversal attempt");
      if (signals.requestRate > 10) reasons.push("Excessive request rate");
    } else if (score >= -50 && score < 0) {
      trafficClass = "suspicious";
      confidence = 0.5 + (Math.abs(score) / 100) * 0.5;
      if (signals.userAgentType === "bot") reasons.push("Bot user agent");
      if (signals.userAgentType === "tool") reasons.push("Automation tool");
      if (!signals.hasCommonHeaders) reasons.push("Missing standard headers");
      if (signals.knownDatacenter) reasons.push("Datacenter origin");
      if (signals.sessionBlockedRatio > 0.3) reasons.push("High block ratio");
    } else {
      trafficClass = "unknown";
      confidence = 0.3;
      reasons.push("Insufficient signals for classification");
    }

    return {
      class: trafficClass,
      confidence,
      signals,
      reasons,
      score,
    };
  }

  /**
   * Get or create reputation entry
   */
  getReputation(id: string): TrafficReputation {
    let reputation = this.reputations.get(id);

    if (!reputation) {
      reputation = {
        id,
        class: "unknown",
        score: 0,
        confidence: 0,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        requestCount: 0,
        blockedCount: 0,
        wafViolations: 0,
        history: [],
      };
      this.reputations.set(id, reputation);
    }

    return reputation;
  }

  /**
   * Update reputation based on classification
   */
  updateReputation(
    id: string,
    classification: ClassificationResult,
    blocked: boolean = false,
    wafViolation: boolean = false
  ): void {
    const reputation = this.getReputation(id);

    reputation.lastSeen = Date.now();
    reputation.requestCount++;

    if (blocked) {
      reputation.blockedCount++;
      reputation.history.push({
        timestamp: Date.now(),
        event: "block",
      });
    }

    if (wafViolation) {
      reputation.wafViolations++;
      reputation.history.push({
        timestamp: Date.now(),
        event: "waf-violation",
      });
    }

    // Update classification and score
    reputation.class = classification.class;
    reputation.confidence = classification.confidence;

    // Weighted average of old and new scores
    const weight = 0.7; // Weight towards new information
    reputation.score =
      reputation.score * (1 - weight) + classification.score * weight;

    // Add to history
    reputation.history.push({
      timestamp: Date.now(),
      event: "request",
      detail: classification.class,
    });

    // Keep history to last 100 events
    if (reputation.history.length > 100) {
      reputation.history = reputation.history.slice(-100);
    }
  }

  /**
   * Get all reputations
   */
  getAllReputations(): TrafficReputation[] {
    return Array.from(this.reputations.values());
  }

  /**
   * Clear old reputations (>1 hour inactive)
   */
  cleanupReputations(): void {
    const cutoff = Date.now() - 3600000; // 1 hour

    for (const [id, rep] of this.reputations.entries()) {
      if (rep.lastSeen < cutoff) {
        this.reputations.delete(id);
      }
    }
  }
}

/**
 * Create a traffic classifier instance
 */
export function createTrafficClassifier(): TrafficClassifier {
  return new TrafficClassifier();
}
