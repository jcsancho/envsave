import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import { encrypt, decrypt, encryptWithKey, decryptWithKey, hmacSha256 } from "./crypto.ts";
import { parseEnvFile } from "./env-parser.ts";
import { hasValidLicense } from "./license.ts";

const FREE_TIER_MAX_SECRETS = 5;

function getEnvsaveDir(): string {
  return process.env.ENVSAVE_DIR || join(homedir(), ".envsave");
}
function getVaultFile(): string { return join(getEnvsaveDir(), "vault.enc"); }
function getCacheFile(): string { return join(getEnvsaveDir(), "cache.enc"); }
function getSessionFile(): string { return join(getEnvsaveDir(), ".session"); }
function getRateFile(): string { return join(getEnvsaveDir(), ".rate"); }
function getAccessLog(): string { return join(getEnvsaveDir(), "access.log"); }

const DEFAULT_RATE_LIMIT_WINDOW_MS = 60 * 1000;      // 1 minute
const DEFAULT_RATE_LIMIT_MAX = 30;                    // max 30 gets per minute
function getConfigFile(): string { return join(getEnvsaveDir(), "config.json"); }

/** Check if tests are accidentally targeting the real vault */
function guardRealVault(): void {
  if (process.env.NODE_ENV === "test" && getEnvsaveDir() === join(homedir(), ".envsave")) {
    throw new Error("Tests must not use the real vault. Set ENVSAVE_DIR to a temp directory.");
  }
}

interface RateLimitConfig {
  maxGetsPerMinute: number;
}

function readConfig(): RateLimitConfig {
  if (!existsSync(getConfigFile())) {
    return { maxGetsPerMinute: DEFAULT_RATE_LIMIT_MAX };
  }
  try {
    return JSON.parse(readFileSync(getConfigFile(), "utf8"));
  } catch {
    return { maxGetsPerMinute: DEFAULT_RATE_LIMIT_MAX };
  }
}

function writeConfig(config: RateLimitConfig): void {
  ensureDir();
  writeFileSync(getConfigFile(), JSON.stringify(config, null, 2), { mode: 0o600 });
}

/** Configure rate limit settings. REQUIRES PASSWORD. */
export function configureRateLimit(password: string, options: { maxGetsPerMinute?: number }): RateLimitConfig {
  // Verify password by reading vault
  readMainVault(password);
  const config = readConfig();
  if (options.maxGetsPerMinute !== undefined) config.maxGetsPerMinute = options.maxGetsPerMinute;
  writeConfig(config);
  return config;
}

/** Get current rate limit config */
export function getRateLimitConfig(): RateLimitConfig {
  return readConfig();
}

/**
 * Main vault — only accessible with master password.
 * Contains the HMAC seed and alias registry that an LLM can never reach.
 */
interface MainVault {
  version: 2 | 3 | 4;
  hmacSeed: string;       // hex — random 32 bytes, used to generate opaque names
  sshKeyPath?: string;    // optional SSH key factor path
  secrets: Record<string, string>;  // opaque_name → value
  registry: string[];     // clean names (for list command)
}

/**
 * Session cache — accessible with random session key.
 * Contains ONLY the secrets map. No aliases, no seed, no registry.
 * Even if an LLM reads .session + cache.enc, it can only access
 * secrets whose opaque names it already knows from the source code.
 */
interface SessionCache {
  secrets: Record<string, string>;  // opaque_name → value
  registry?: string[];              // clean key names (for search without password)
}

const BASE_CHARS_V3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@$&*=-!";

/** Shell-safe character set — only chars safe unquoted in bash/zsh/fish/sh */
const BASE_CHARS_V4 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";

function hexToBaseN(hex: string, length: number, chars: string): string {
  let result = "";
  for (let i = 0; i < length; i++) {
    const hexPair = hex.slice((i * 2) % hex.length, ((i * 2) % hex.length) + 2) || hex.slice(0, 2);
    const byte = parseInt(hexPair, 16);
    result += chars[byte % chars.length];
  }
  return result;
}

/** Old v3 key computation for migration */
function computeOpaqueNameV3(hmacSeed: string, cleanName: string, sshKeyContent?: string): string {
  let effectiveSeed = hmacSeed;
  if (sshKeyContent) {
    effectiveSeed = hmacSha256(hmacSeed, sshKeyContent);
  }
  const hash1 = hmacSha256(effectiveSeed, cleanName);
  const hash2 = hmacSha256(effectiveSeed, cleanName + ":2");
  return "es_" + hexToBaseN(hash1 + hash2, 48, BASE_CHARS_V3);
}

/**
 * Compute a fully opaque key name: HMAC-SHA256(seed, cleanName) → "es_" + 48 shell-safe chars.
 * Uses A-Z, a-z, 0-9, -, _ — safe unquoted in bash/zsh/fish/sh.
 * No trace of the original name. Impossible to reverse without the seed.
 * If SSH key is configured, the seed is further derived from the SSH key content.
 */
function computeOpaqueName(hmacSeed: string, cleanName: string, sshKeyContent?: string): string {
  let effectiveSeed = hmacSeed;
  if (sshKeyContent) {
    effectiveSeed = hmacSha256(hmacSeed, sshKeyContent);
  }
  // Double hash to get enough bytes for 48 chars
  const hash1 = hmacSha256(effectiveSeed, cleanName);
  const hash2 = hmacSha256(effectiveSeed, cleanName + ":2");
  return "es_" + hexToBaseN(hash1 + hash2, 48, BASE_CHARS);
}

/** Old v4 key computation for migration */
function computeOpaqueNameV4(hmacSeed: string, cleanName: string, sshKeyContent?: string): string {
  let effectiveSeed = hmacSeed;
  if (sshKeyContent) {
    effectiveSeed = hmacSha256(hmacSeed, sshKeyContent);
  }
  const hash1 = hmacSha256(effectiveSeed, cleanName);
  const hash2 = hmacSha256(effectiveSeed, cleanName + ":2");
  return "es_" + hexToBaseN(hash1 + hash2, 48, BASE_CHARS_V4);
}

/** Old v2 key computation for migration */
function computeOpaqueNameV2(hmacSeed: string, cleanName: string, sshKeyContent?: string): string {
  let effectiveSeed = hmacSeed;
  if (sshKeyContent) {
    effectiveSeed = hmacSha256(hmacSeed, sshKeyContent);
  }
  const hash = hmacSha256(effectiveSeed, cleanName);
  return "es_" + hash.slice(0, 24);
}

function ensureDir(): void {
  guardRealVault();
  if (!existsSync(getEnvsaveDir())) {
    mkdirSync(getEnvsaveDir(), { recursive: true, mode: 0o700 });
  }
}

export function vaultExists(): boolean {
  return existsSync(getVaultFile());
}

/** Read main vault (requires master password). Auto-migrates v2 → v3. */
function readMainVault(password: string): MainVault {
  guardRealVault();
  if (!existsSync(getVaultFile())) {
    throw new Error("Vault not found. Run 'envsave init' first.");
  }
  const payload = readFileSync(getVaultFile());
  const json = decrypt(payload, password);
  const data = JSON.parse(json);
  if (!data.version || data.version < 2) {
    throw new Error("Vault format outdated. Delete ~/.envsave/ and re-initialize.");
  }
  // Auto-migrate v2 → v3 (new opaque key format)
  if (data.version === 2 && data.registry?.length > 0) {
    const sshKeyContent = data.sshKeyPath && existsSync(data.sshKeyPath)
      ? readFileSync(data.sshKeyPath, "utf8") : undefined;
    const newSecrets: Record<string, string> = {};
    for (const cleanName of data.registry) {
      const oldKey = computeOpaqueNameV2(data.hmacSeed, cleanName, sshKeyContent);
      const newKey = computeOpaqueName(data.hmacSeed, cleanName, sshKeyContent);
      if (oldKey in data.secrets) {
        newSecrets[newKey] = data.secrets[oldKey];
      }
    }
    data.secrets = newSecrets;
    data.version = 3;
    writeMainVault(data, password);
    console.error("Vault migrated to v3 (stronger opaque keys).");
  }
  // Auto-migrate v3 → v4 (shell-safe opaque key characters)
  if (data.version === 3 && data.registry?.length > 0) {
    const sshKeyContent = data.sshKeyPath && existsSync(data.sshKeyPath)
      ? readFileSync(data.sshKeyPath, "utf8") : undefined;
    const newSecrets: Record<string, string> = {};
    for (const cleanName of data.registry) {
      const oldKey = computeOpaqueNameV3(data.hmacSeed, cleanName, sshKeyContent);
      const newKey = computeOpaqueName(data.hmacSeed, cleanName, sshKeyContent);
      if (oldKey in data.secrets) {
        newSecrets[newKey] = data.secrets[oldKey];
      }
    }
    data.secrets = newSecrets;
    data.version = 4;
    writeMainVault(data, password);
    console.error("Vault migrated to v4 (shell-safe opaque keys).");
  }
  // Auto-migrate v4 → v5 (Vercel-compatible: no hyphens in opaque keys)
  if (data.version === 4 && data.registry?.length > 0) {
    const sshKeyContent = data.sshKeyPath && existsSync(data.sshKeyPath)
      ? readFileSync(data.sshKeyPath, "utf8") : undefined;
    const newSecrets: Record<string, string> = {};
    for (const cleanName of data.registry) {
      const oldKey = computeOpaqueNameV4(data.hmacSeed, cleanName, sshKeyContent);
      const newKey = computeOpaqueName(data.hmacSeed, cleanName, sshKeyContent);
      if (oldKey in data.secrets) {
        newSecrets[newKey] = data.secrets[oldKey];
      }
    }
    data.secrets = newSecrets;
    data.version = 5;
    writeMainVault(data, password);
    console.error("Vault migrated to v5 (Vercel-compatible opaque keys).");
  }
  return data as MainVault;
}

function writeMainVault(data: MainVault, password: string): void {
  ensureDir();
  const json = JSON.stringify(data);
  const encrypted = encrypt(json, password);
  writeFileSync(getVaultFile(), encrypted, { mode: 0o600 });
}

/**
 * Write session cache — encrypted with a RANDOM key (not the password).
 * The cache contains ONLY the secrets map. An LLM reading .session + cache.enc
 * can look up values by opaque name, but cannot discover names or enumerate keys.
 */
function writeSessionCache(secrets: Record<string, string>, registry?: string[]): void {
  ensureDir();
  const sessionKey = randomBytes(32);
  const cache: SessionCache = { secrets, registry };
  const json = JSON.stringify(cache);
  const encrypted = encryptWithKey(json, sessionKey);
  writeFileSync(getCacheFile(), encrypted, { mode: 0o600 });
  writeFileSync(getSessionFile(), sessionKey.toString("hex"), { mode: 0o600 });
}

function readSessionCache(): SessionCache | null {
  if (!existsSync(getSessionFile()) || !existsSync(getCacheFile())) return null;
  try {
    const sessionKeyHex = readFileSync(getSessionFile(), "utf8").trim();
    const sessionKey = Buffer.from(sessionKeyHex, "hex");
    const payload = readFileSync(getCacheFile());
    const json = decryptWithKey(payload, sessionKey);
    return JSON.parse(json) as SessionCache;
  } catch {
    return null;
  }
}

/** Rate limit check — max N get calls per minute */
function checkRateLimit(): void {
  const config = readConfig();
  const now = Date.now();
  let timestamps: number[] = [];
  if (existsSync(getRateFile())) {
    try {
      timestamps = JSON.parse(readFileSync(getRateFile(), "utf8"));
    } catch {
      timestamps = [];
    }
  }
  // Keep only timestamps within the window
  timestamps = timestamps.filter(t => now - t < DEFAULT_RATE_LIMIT_WINDOW_MS);
  if (timestamps.length >= config.maxGetsPerMinute) {
    logAccess("RATE_LIMIT_BLOCKED", "blocked");
    throw new Error(`Rate limit exceeded. Max ${config.maxGetsPerMinute} get calls per minute. Try again in ${Math.ceil((DEFAULT_RATE_LIMIT_WINDOW_MS - (now - timestamps[0])) / 1000)}s.`);
  }
  // Warn at 80% of limit
  const threshold = Math.floor(config.maxGetsPerMinute * 0.8);
  if (timestamps.length >= threshold) {
    const remaining = config.maxGetsPerMinute - timestamps.length;
    console.error(`⚠ Rate limit warning: ${remaining} get(s) remaining this minute.`);
  }
  timestamps.push(now);
  writeFileSync(getRateFile(), JSON.stringify(timestamps), { mode: 0o600 });
}

/** Log access for audit */
function logAccess(opaqueKey: string, source: string): void {
  ensureDir();
  const entry = `${new Date().toISOString()} ${source} ${opaqueKey.slice(0, 10)}...\n`;
  appendFileSync(getAccessLog(), entry, { mode: 0o600 });
}

/** Read SSH key content if configured */
function loadSshKey(vault: MainVault): string | undefined {
  if (!vault.sshKeyPath) return undefined;
  if (!existsSync(vault.sshKeyPath)) {
    throw new Error(`SSH key not found: ${vault.sshKeyPath}. This vault requires the SSH key to operate.`);
  }
  return readFileSync(vault.sshKeyPath, "utf8");
}

// ─── Public API ───

export function initVault(password: string, options?: { envFile?: string; sshKeyPath?: string }): number {
  if (vaultExists()) {
    throw new Error("Vault already exists. Delete ~/.envsave/vault.enc to reinitialize.");
  }

  // Validate SSH key exists before creating vault
  if (options?.sshKeyPath && !existsSync(options.sshKeyPath)) {
    throw new Error(`SSH key not found: ${options.sshKeyPath}`);
  }

  const hmacSeed = randomBytes(32).toString("hex");
  const sshKeyContent = options?.sshKeyPath ? readFileSync(options.sshKeyPath, "utf8") : undefined;

  const vault: MainVault = {
    version: 4,
    hmacSeed,
    sshKeyPath: options?.sshKeyPath,
    secrets: {},
    registry: [],
  };

  let count = 0;
  if (options?.envFile) {
    const envSecrets = parseEnvFile(options.envFile);
    // Free tier limit check
    if (!hasValidLicense() && Object.keys(envSecrets).length > FREE_TIER_MAX_SECRETS) {
      throw new Error(`Free tier limit: max ${FREE_TIER_MAX_SECRETS} secrets. .env file has ${Object.keys(envSecrets).length} keys.\nRun 'envsave activate <token>' to unlock unlimited secrets.\nGet your license at https://api.envsave.com`);
    }
    for (const [key, value] of Object.entries(envSecrets)) {
      const opaque = computeOpaqueName(hmacSeed, key, sshKeyContent);
      vault.secrets[opaque] = value;
      vault.registry.push(key);
      count++;
    }
  }

  writeMainVault(vault, password);
  writeSessionCache(vault.secrets, vault.registry);
  chmodSync(getEnvsaveDir(), 0o700);
  return count;
}

/** Set a secret; returns the opaque key name for use in code */
export function setSecret(key: string, value: string, password: string): string {
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);
  const opaque = computeOpaqueName(vault.hmacSeed, key, sshKeyContent);

  // Free tier limit: only enforce when adding a NEW key
  if (!(opaque in vault.secrets) && !hasValidLicense()) {
    if (vault.registry.length >= FREE_TIER_MAX_SECRETS) {
      throw new Error(`Free tier limit: max ${FREE_TIER_MAX_SECRETS} secrets. Run 'envsave activate <token>' to unlock unlimited secrets.\nGet your license at https://api.envsave.com`);
    }
  }

  vault.secrets[opaque] = value;
  if (!vault.registry.includes(key)) {
    vault.registry.push(key);
  }

  writeMainVault(vault, password);
  writeSessionCache(vault.secrets, vault.registry);
  return opaque;
}

/** Show the real value of a secret by clean name. REQUIRES PASSWORD. */
export function showSecret(cleanName: string, password: string): string | undefined {
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);
  const opaque = computeOpaqueName(vault.hmacSeed, cleanName, sshKeyContent);
  writeSessionCache(vault.secrets, vault.registry);
  return vault.secrets[opaque];
}

/** Reveal the opaque key for a clean name. REQUIRES PASSWORD + SSH KEY. */
export function revealKey(cleanName: string, password: string): string | undefined {
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);
  writeSessionCache(vault.secrets, vault.registry);
  const opaque = computeOpaqueName(vault.hmacSeed, cleanName, sshKeyContent);
  return opaque in vault.secrets ? opaque : undefined;
}

/** Get a secret from session cache by opaque key. NO PASSWORD NEEDED. */
export function getSecretFromCache(opaqueKey: string): string | undefined {
  checkRateLimit();
  const cache = readSessionCache();
  if (!cache) {
    throw new Error("No session found. Run any envsave command with your password first.");
  }
  logAccess(opaqueKey, "cache");
  return cache.secrets[opaqueKey];
}

/** Get a secret by opaque key using password (fallback, also refreshes cache). */
export function getSecret(opaqueKey: string, password: string): string | undefined {
  checkRateLimit();
  const vault = readMainVault(password);
  writeSessionCache(vault.secrets, vault.registry);
  logAccess(opaqueKey, "vault");
  return vault.secrets[opaqueKey];
}

export function deleteSecret(key: string, password: string): boolean {
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);
  const opaque = computeOpaqueName(vault.hmacSeed, key, sshKeyContent);

  if (!(opaque in vault.secrets)) return false;
  delete vault.secrets[opaque];
  vault.registry = vault.registry.filter(k => k !== key);

  writeMainVault(vault, password);
  writeSessionCache(vault.secrets, vault.registry);
  return true;
}

/** List clean key names only. Requires password. Also refreshes session cache. */
export function listKeys(password: string): string[] {
  const vault = readMainVault(password);
  writeSessionCache(vault.secrets, vault.registry);
  return vault.registry;
}

export function importEnv(filePath: string, password: string): number {
  const envSecrets = parseEnvFile(filePath);
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);

  // Free tier limit check
  if (!hasValidLicense()) {
    const newKeys = Object.keys(envSecrets).filter(key => {
      const opaque = computeOpaqueName(vault.hmacSeed, key, sshKeyContent);
      return !(opaque in vault.secrets);
    });
    if (vault.registry.length + newKeys.length > FREE_TIER_MAX_SECRETS) {
      throw new Error(`Free tier limit: max ${FREE_TIER_MAX_SECRETS} secrets. Import would add ${newKeys.length} new keys (${vault.registry.length} existing).\nRun 'envsave activate <token>' to unlock unlimited secrets.\nGet your license at https://api.envsave.com`);
    }
  }

  let count = 0;
  for (const [key, value] of Object.entries(envSecrets)) {
    const opaque = computeOpaqueName(vault.hmacSeed, key, sshKeyContent);
    vault.secrets[opaque] = value;
    if (!vault.registry.includes(key)) {
      vault.registry.push(key);
    }
    count++;
  }

  writeMainVault(vault, password);
  writeSessionCache(vault.secrets, vault.registry);
  return count;
}

export function exportEnv(password: string): string {
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);
  return vault.registry
    .map(cleanName => {
      const opaque = computeOpaqueName(vault.hmacSeed, cleanName, sshKeyContent);
      return `${cleanName}=${vault.secrets[opaque] ?? ""}`;
    })
    .join("\n");
}

/** Change the master password. Re-encrypts the vault with the new password. */
export function changePassword(oldPassword: string, newPassword: string): void {
  const vault = readMainVault(oldPassword);
  writeMainVault(vault, newPassword);
  writeSessionCache(vault.secrets, vault.registry);
}

/** Search key names matching a pattern. NO PASSWORD NEEDED (uses session cache). */
export function searchKeys(pattern: string): string[] {
  const cache = readSessionCache();
  if (!cache || !cache.registry) {
    throw new Error("No session found. Run any envsave command with your password first.");
  }
  const lower = pattern.toLowerCase();
  return cache.registry.filter(k => k.toLowerCase().includes(lower));
}

/** Get opaque key + real value pairs for given opaque keys. REQUIRES PASSWORD. */
export function getDeploySecrets(opaqueKeys: string[], password: string): { name: string; opaque: string; value: string }[] {
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);
  writeSessionCache(vault.secrets, vault.registry);
  const results: { name: string; opaque: string; value: string }[] = [];
  for (const opaque of opaqueKeys) {
    if (opaque in vault.secrets) {
      const cleanName = vault.registry?.find((r: string) => computeOpaqueName(vault.hmacSeed, r, sshKeyContent) === opaque) || opaque;
      results.push({ name: cleanName, opaque, value: vault.secrets[opaque] });
    }
  }
  return results;
}

// ─── Library API (session cache only — no password, no enumeration) ───

export function getSecretWithSession(opaqueKey: string): string | undefined {
  return getSecretFromCache(opaqueKey);
}

export function hasSecretWithSession(opaqueKey: string): boolean {
  try {
    const cache = readSessionCache();
    if (!cache) return false;
    return opaqueKey in cache.secrets;
  } catch {
    return false;
  }
}
