/**
 * Geolocation Blocking Module
 * Handles country-based access control and threat assessment
 * 
 * Note: Country blocklist should be configured by the user based on their
 * specific security requirements and threat landscape.
 */

import type { Env } from "../types";

/**
 * Country information
 */
export interface CountryInfo {
  code: string;        // ISO 3166-1 alpha-2 country code
  name?: string;       // Country name
  riskLevel?: 'low' | 'medium' | 'high' | 'critical';
  reason?: string;     // Reason for blocking/flagging
}

/**
 * Geolocation check result
 */
export interface GeolocationResult {
  allowed: boolean;
  country?: string;
  countryName?: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  reason?: string;
  action: 'allow' | 'challenge' | 'block';
}

/**
 * Geolocation blocking configuration
 */
export interface GeolocationConfig {
  // Enabled/disabled
  enabled: boolean;
  
  // Countries to block (ISO 3166-1 alpha-2 codes)
  blockedCountries: string[];
  
  // Countries to challenge (require additional verification)
  challengedCountries: string[];
  
  // Countries to always allow (bypass other checks)
  allowedCountries: string[];
  
  // Default action for unknown countries
  defaultAction: 'allow' | 'challenge' | 'block';
  
  // Log blocked requests
  logBlocked: boolean;
}

/**
 * Default geolocation configuration
 * 
 * FAKE TEST COUNTRIES (for load testing):
 * - ZZ: "Fakeland" - Simulates blocked high-threat country
 * - XX: "Testonia" - Simulates blocked country  
 * - YY: "Malwaristan" - Simulates blocked country
 * - QQ: "Suspectia" - Simulates challenged country (requires verification)
 * - WW: "Botlandia" - Simulates challenged country
 * 
 * These fake country codes allow testing geolocation blocking without
 * affecting real country traffic.
 */
export const DEFAULT_GEOLOCATION_CONFIG: GeolocationConfig = {
  enabled: true,
  // Blocked countries: Fake test countries for simulating high-threat regions
  blockedCountries: ['ZZ', 'XX', 'YY'], // Fakeland, Testonia, Malwaristan
  // Challenged countries: Fake test countries requiring verification
  challengedCountries: ['QQ', 'WW'], // Suspectia, Botlandia
  allowedCountries: [], // Empty = allow all non-blocked countries
  defaultAction: 'allow',
  logBlocked: true,
};

/**
 * Country name mapping (partial list - extend as needed)
 */
export const COUNTRY_NAMES: Record<string, string> = {
  // Real Countries - North America
  'US': 'United States',
  'CA': 'Canada',
  'MX': 'Mexico',
  
  // Real Countries - Europe
  'GB': 'United Kingdom',
  'DE': 'Germany',
  'FR': 'France',
  'IT': 'Italy',
  'ES': 'Spain',
  'NL': 'Netherlands',
  'SE': 'Sweden',
  'NO': 'Norway',
  'DK': 'Denmark',
  'FI': 'Finland',
  'PL': 'Poland',
  'CH': 'Switzerland',
  'AT': 'Austria',
  'BE': 'Belgium',
  'IE': 'Ireland',
  'PT': 'Portugal',
  'GR': 'Greece',
  'CZ': 'Czech Republic',
  'RO': 'Romania',
  'HU': 'Hungary',
  
  // Real Countries - Asia Pacific
  'JP': 'Japan',
  'KR': 'South Korea',
  'CN': 'China',
  'IN': 'India',
  'AU': 'Australia',
  'NZ': 'New Zealand',
  'SG': 'Singapore',
  'HK': 'Hong Kong',
  'TW': 'Taiwan',
  
  // Real Countries - Other
  'BR': 'Brazil',
  'RU': 'Russia',
  'AR': 'Argentina',
  'CL': 'Chile',
  'CO': 'Colombia',
  'ZA': 'South Africa',
  'AE': 'United Arab Emirates',
  'SA': 'Saudi Arabia',
  'IL': 'Israel',
  'EG': 'Egypt',
  'TR': 'Turkey',
  'UA': 'Ukraine',
  'TH': 'Thailand',
  'VN': 'Vietnam',
  'MY': 'Malaysia',
  'ID': 'Indonesia',
  'PH': 'Philippines',
  'PK': 'Pakistan',
  'BD': 'Bangladesh',
  'NG': 'Nigeria',
  'KE': 'Kenya',
  'IR': 'Iran',
  'KP': 'North Korea',
  
  // ================================================================
  // FAKE TEST COUNTRIES (for load testing simulation)
  // These are NOT real ISO country codes - used only for testing
  // ================================================================
  'ZZ': 'Fakeland (TEST - Blocked)',
  'XX': 'Testonia (TEST - Blocked)',
  'YY': 'Malwaristan (TEST - Blocked)',
  'QQ': 'Suspectia (TEST - Challenged)',
  'WW': 'Botlandia (TEST - Challenged)',
};

/**
 * Geolocation Blocker
 */
export class GeolocationBlocker {
  private config: GeolocationConfig;
  private blockedCountries: Set<string>;
  private challengedCountries: Set<string>;
  private allowedCountries: Set<string>;
  private blockLog: Array<{
    timestamp: number;
    country: string;
    ip: string;
    action: 'block' | 'challenge';
  }> = [];

  constructor(config?: Partial<GeolocationConfig>) {
    this.config = { ...DEFAULT_GEOLOCATION_CONFIG, ...config };
    
    // Normalize country codes to uppercase
    this.blockedCountries = new Set(
      this.config.blockedCountries.map(c => c.toUpperCase())
    );
    this.challengedCountries = new Set(
      this.config.challengedCountries.map(c => c.toUpperCase())
    );
    this.allowedCountries = new Set(
      this.config.allowedCountries.map(c => c.toUpperCase())
    );
  }

  /**
   * Extract country from request using Cloudflare headers
   */
  getCountryFromRequest(request: Request): string | undefined {
    // Cloudflare provides country in CF-IPCountry header
    const country = request.headers.get('CF-IPCountry');
    return country?.toUpperCase() || undefined;
  }

  /**
   * Get country name from code
   */
  getCountryName(code: string): string {
    return COUNTRY_NAMES[code.toUpperCase()] || code;
  }

  /**
   * Check if a country should be blocked
   */
  isBlockedCountry(country: string): boolean {
    if (!this.config.enabled) return false;
    return this.blockedCountries.has(country.toUpperCase());
  }

  /**
   * Check if a country should be challenged
   */
  isChallengedCountry(country: string): boolean {
    if (!this.config.enabled) return false;
    return this.challengedCountries.has(country.toUpperCase());
  }

  /**
   * Check if a country is explicitly allowed
   */
  isAllowedCountry(country: string): boolean {
    if (!this.config.enabled) return true;
    if (this.allowedCountries.size === 0) return true;
    return this.allowedCountries.has(country.toUpperCase());
  }

  /**
   * Check geolocation for a request
   */
  check(request: Request): GeolocationResult {
    if (!this.config.enabled) {
      return {
        allowed: true,
        riskLevel: 'unknown',
        action: 'allow',
      };
    }

    const country = this.getCountryFromRequest(request);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    if (!country) {
      return {
        allowed: this.config.defaultAction === 'allow',
        riskLevel: 'unknown',
        reason: 'Country could not be determined',
        action: this.config.defaultAction,
      };
    }

    const countryUpper = country.toUpperCase();
    const countryName = this.getCountryName(countryUpper);

    // Check allowlist first
    if (this.allowedCountries.size > 0 && this.allowedCountries.has(countryUpper)) {
      return {
        allowed: true,
        country: countryUpper,
        countryName,
        riskLevel: 'low',
        action: 'allow',
      };
    }

    // Check blocklist
    if (this.blockedCountries.has(countryUpper)) {
      if (this.config.logBlocked) {
        this.blockLog.push({
          timestamp: Date.now(),
          country: countryUpper,
          ip,
          action: 'block',
        });
      }

      return {
        allowed: false,
        country: countryUpper,
        countryName,
        riskLevel: 'critical',
        reason: `Country ${countryName} (${countryUpper}) is blocked`,
        action: 'block',
      };
    }

    // Check challenge list
    if (this.challengedCountries.has(countryUpper)) {
      if (this.config.logBlocked) {
        this.blockLog.push({
          timestamp: Date.now(),
          country: countryUpper,
          ip,
          action: 'challenge',
        });
      }

      return {
        allowed: true, // Allow but with challenge
        country: countryUpper,
        countryName,
        riskLevel: 'high',
        reason: `Country ${countryName} (${countryUpper}) requires verification`,
        action: 'challenge',
      };
    }

    // Default action for countries not in any list
    return {
      allowed: this.config.defaultAction === 'allow',
      country: countryUpper,
      countryName,
      riskLevel: 'low',
      action: this.config.defaultAction,
    };
  }

  /**
   * Add a country to the blocklist
   */
  blockCountry(country: string, reason?: string): void {
    const countryUpper = country.toUpperCase();
    this.blockedCountries.add(countryUpper);
    this.config.blockedCountries.push(countryUpper);
    
    // Remove from other lists
    this.challengedCountries.delete(countryUpper);
    this.allowedCountries.delete(countryUpper);
  }

  /**
   * Add a country to the challenge list
   */
  challengeCountry(country: string, reason?: string): void {
    const countryUpper = country.toUpperCase();
    this.challengedCountries.add(countryUpper);
    this.config.challengedCountries.push(countryUpper);
    
    // Remove from blocklist
    this.blockedCountries.delete(countryUpper);
  }

  /**
   * Add a country to the allowlist
   */
  allowCountry(country: string): void {
    const countryUpper = country.toUpperCase();
    this.allowedCountries.add(countryUpper);
    this.config.allowedCountries.push(countryUpper);
    
    // Remove from other lists
    this.blockedCountries.delete(countryUpper);
    this.challengedCountries.delete(countryUpper);
  }

  /**
   * Remove a country from blocklist
   */
  unblockCountry(country: string): void {
    const countryUpper = country.toUpperCase();
    this.blockedCountries.delete(countryUpper);
    this.config.blockedCountries = this.config.blockedCountries.filter(
      c => c.toUpperCase() !== countryUpper
    );
  }

  /**
   * Get block log
   */
  getBlockLog(): Array<{
    timestamp: number;
    country: string;
    ip: string;
    action: 'block' | 'challenge';
  }> {
    return [...this.blockLog];
  }

  /**
   * Clear block log
   */
  clearBlockLog(): void {
    this.blockLog = [];
  }

  /**
   * Get current configuration
   */
  getConfig(): GeolocationConfig {
    return { ...this.config };
  }

  /**
   * Get blocked countries list
   */
  getBlockedCountries(): string[] {
    return Array.from(this.blockedCountries);
  }

  /**
   * Get challenged countries list
   */
  getChallengedCountries(): string[] {
    return Array.from(this.challengedCountries);
  }

  /**
   * Get allowed countries list
   */
  getAllowedCountries(): string[] {
    return Array.from(this.allowedCountries);
  }

  /**
   * Enable/disable geolocation blocking
   */
  setEnabled(enabled: boolean): void {
    this.config.enabled = enabled;
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<GeolocationConfig>): void {
    this.config = { ...this.config, ...config };
    
    // Update sets
    if (config.blockedCountries) {
      this.blockedCountries = new Set(config.blockedCountries.map(c => c.toUpperCase()));
    }
    if (config.challengedCountries) {
      this.challengedCountries = new Set(config.challengedCountries.map(c => c.toUpperCase()));
    }
    if (config.allowedCountries) {
      this.allowedCountries = new Set(config.allowedCountries.map(c => c.toUpperCase()));
    }
  }
}

/**
 * Create a geolocation blocker
 */
export function createGeolocationBlocker(
  config?: Partial<GeolocationConfig>
): GeolocationBlocker {
  return new GeolocationBlocker(config);
}

/**
 * Quick check if request should be blocked based on geolocation
 */
export function isGeolocationBlocked(
  request: Request,
  blockedCountries: string[]
): boolean {
  const country = request.headers.get('CF-IPCountry');
  if (!country) return false;
  
  return blockedCountries.some(
    c => c.toUpperCase() === country.toUpperCase()
  );
}

/**
 * Get country from request
 */
export function getCountryFromRequest(request: Request): string | undefined {
  const country = request.headers.get('CF-IPCountry');
  return country?.toUpperCase() || undefined;
}

