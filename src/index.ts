import { getSecretWithSession, hasSecretWithSession } from "./vault.ts";

/**
 * Get a secret from the EnvSave.
 * Tries vault session first, then falls back to process.env[key].
 * On Vercel, set the opaque key as the env var name: ev_7a3f...=<real value>
 */
export function get(key: string): string | undefined {
  try {
    const value = getSecretWithSession(key);
    if (value !== undefined) return value;
  } catch {
    // No vault session — fall through to env fallback
  }

  return process.env[key];
}

/**
 * Check if a secret exists in the EnvSave or as an environment variable.
 */
export function has(key: string): boolean {
  if (hasSecretWithSession(key)) return true;
  return process.env[key] !== undefined;
}

export default { get, has };
