import { getSecretWithSession, hasSecretWithSession } from "./vault.ts";

/**
 * Get a secret from the eVault. No password prompt — uses cached session.
 */
export function get(key: string): string | undefined {
  return getSecretWithSession(key);
}

/**
 * Check if a secret exists in the eVault.
 */
export function has(key: string): boolean {
  return hasSecretWithSession(key);
}

export default { get, has };
