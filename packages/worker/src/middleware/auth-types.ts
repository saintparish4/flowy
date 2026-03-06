/**
 * Request-scoped auth context set by auth middleware
 * Only the key hash is stored -- raw API key never in context or logs
 */

export interface AuthContext {
  /** SHA-256 hex digest of the API key (if authenticated via API key) */
  apiKeyHash: string;
  /** Optional JWT subject / identity when authenticated via Bearer token */
  jwtSub?: string;
}
