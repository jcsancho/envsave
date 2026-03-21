import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, appendFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import { encrypt, decrypt, encryptWithKey, decryptWithKey, hmacSha256 } from "./crypto.ts";
import { parseEnvFile } from "./env-parser.ts";
import { hasValidLicense } from "./license.ts";

const FREE_TIER_MAX_SECRETS = 10;

const ENVSAVE_DIR = join(homedir(), ".envsave");
const VAULT_FILE = join(ENVSAVE_DIR, "vault.enc");    // Main vault (password-encrypted)
const CACHE_FILE = join(ENVSAVE_DIR, "cache.enc");    // Session cache (random-key-encrypted)
const SESSION_FILE = join(ENVSAVE_DIR, ".session");    // Random session key (NOT the password)
const RATE_FILE = join(ENVSAVE_DIR, ".rate");           // Rate limiting state
const ACCESS_LOG = join(ENVSAVE_DIR, "access.log");    // Access audit log

const DEFAULT_SESSION_TTL_MS = 4 * 60 * 60 * 1000;  // 4 hours
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60 * 1000;      // 1 minute
const DEFAULT_RATE_LIMIT_MAX = 30;                    // max 30 gets per minute
const CONFIG_FILE = join(ENVSAVE_DIR, "config.json");

interface RateLimitConfig {
  maxGetsPerMinute: number;
  sessionTtlHours: number;
}

function readConfig(): RateLimitConfig {
  if (!existsSync(CONFIG_FILE)) {
    return { maxGetsPerMinute: DEFAULT_RATE_LIMIT_MAX, sessionTtlHours: DEFAULT_SESSION_TTL_MS / 3600000 };
  }
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, "utf8"));
  } catch {
    return { maxGetsPerMinute: DEFAULT_RATE_LIMIT_MAX, sessionTtlHours: DEFAULT_SESSION_TTL_MS / 3600000 };
  }
}

function writeConfig(config: RateLimitConfig): void {
  ensureDir();
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
}

/** Configure rate limit settings. REQUIRES PASSWORD. */
export function configureRateLimit(password: string, options: { maxGetsPerMinute?: number; sessionTtlHours?: number }): RateLimitConfig {
  // Verify password by reading vault
  readMainVault(password);
  const config = readConfig();
  if (options.maxGetsPerMinute !== undefined) config.maxGetsPerMinute = options.maxGetsPerMinute;
  if (options.sessionTtlHours !== undefined) config.sessionTtlHours = options.sessionTtlHours;
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
  version: 2 | 3;
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

const BASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@$&*=-!";

/** Convert hex string to base69 string (A-Z, a-z, 0-9, @$&*=-!) of given length */
function hexToBase69(hex: string, length: number): string {
  let result = "";
  for (let i = 0; i < length; i++) {
    const hexPair = hex.slice((i * 2) % hex.length, ((i * 2) % hex.length) + 2) || hex.slice(0, 2);
    const byte = parseInt(hexPair, 16);
    result += BASE_CHARS[byte % BASE_CHARS.length];
  }
  return result;
}

/**
 * Compute a fully opaque key name: HMAC-SHA256(seed, cleanName) → "es_" + 48 base62 chars.
 * Uses A-Z, a-z, 0-9 for higher entropy density.
 * No trace of the original name. Impossible to reverse without the seed.
 * If SSH key is configured, the seed is further derived from the SSH key content.
 */
function computeOpaqueName(hmacSeed: string, cleanName: string, sshKeyContent?: string): string {
  let effectiveSeed = hmacSeed;
  if (sshKeyContent) {
    effectiveSeed = hmacSha256(hmacSeed, sshKeyContent);
  }
  // Double hash to get enough bytes for 48 base62 chars
  const hash1 = hmacSha256(effectiveSeed, cleanName);
  const hash2 = hmacSha256(effectiveSeed, cleanName + ":2");
  return "es_" + hexToBase69(hash1 + hash2, 48);
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
  if (!existsSync(ENVSAVE_DIR)) {
    mkdirSync(ENVSAVE_DIR, { recursive: true, mode: 0o700 });
  }
}

export function vaultExists(): boolean {
  return existsSync(VAULT_FILE);
}

/** Read main vault (requires master password). Auto-migrates v2 → v3. */
function readMainVault(password: string): MainVault {
  if (!existsSync(VAULT_FILE)) {
    throw new Error("Vault not found. Run 'envsave init' first.");
  }
  const payload = readFileSync(VAULT_FILE);
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
  return data as MainVault;
}

function writeMainVault(data: MainVault, password: string): void {
  ensureDir();
  const json = JSON.stringify(data);
  const encrypted = encrypt(json, password);
  writeFileSync(VAULT_FILE, encrypted, { mode: 0o600 });
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
  writeFileSync(CACHE_FILE, encrypted, { mode: 0o600 });
  writeFileSync(SESSION_FILE, sessionKey.toString("hex"), { mode: 0o600 });
}

function readSessionCache(): SessionCache | null {
  if (!existsSync(SESSION_FILE) || !existsSync(CACHE_FILE)) return null;
  try {
    // Check session expiry
    const sessionStat = statSync(SESSION_FILE);
    const age = Date.now() - sessionStat.mtimeMs;
    const config = readConfig();
    if (age > config.sessionTtlHours * 3600000) {
      return null; // expired
    }
    const sessionKeyHex = readFileSync(SESSION_FILE, "utf8").trim();
    const sessionKey = Buffer.from(sessionKeyHex, "hex");
    const payload = readFileSync(CACHE_FILE);
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
  if (existsSync(RATE_FILE)) {
    try {
      timestamps = JSON.parse(readFileSync(RATE_FILE, "utf8"));
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
  writeFileSync(RATE_FILE, JSON.stringify(timestamps), { mode: 0o600 });
}

/** Log access for audit */
function logAccess(opaqueKey: string, source: string): void {
  ensureDir();
  const entry = `${new Date().toISOString()} ${source} ${opaqueKey.slice(0, 10)}...\n`;
  appendFileSync(ACCESS_LOG, entry, { mode: 0o600 });
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
    version: 3,
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
      throw new Error(`Free tier limit: max ${FREE_TIER_MAX_SECRETS} secrets. .env file has ${Object.keys(envSecrets).length} keys.\nRun 'envsave activate <token>' to unlock unlimited secrets.\nGet your license at https://envsave.example.com`);
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
  chmodSync(ENVSAVE_DIR, 0o700);
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
      throw new Error(`Free tier limit: max ${FREE_TIER_MAX_SECRETS} secrets. Run 'envsave activate <token>' to unlock unlimited secrets.\nGet your license at https://envsave.example.com`);
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
      throw new Error(`Free tier limit: max ${FREE_TIER_MAX_SECRETS} secrets. Import would add ${newKeys.length} new keys (${vault.registry.length} existing).\nRun 'envsave activate <token>' to unlock unlimited secrets.\nGet your license at https://envsave.example.com`);
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

/** Get opaque key + real value pairs for given clean names. REQUIRES PASSWORD. */
export function getDeploySecrets(cleanNames: string[], password: string): { name: string; opaque: string; value: string }[] {
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);
  writeSessionCache(vault.secrets, vault.registry);
  const results: { name: string; opaque: string; value: string }[] = [];
  for (const name of cleanNames) {
    const opaque = computeOpaqueName(vault.hmacSeed, name, sshKeyContent);
    if (opaque in vault.secrets) {
      results.push({ name, opaque, value: vault.secrets[opaque] });
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
