import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import { encrypt, decrypt, encryptWithKey, decryptWithKey, hmacSha256 } from "./crypto.ts";
import { parseEnvFile } from "./env-parser.ts";

const ENVSAVE_DIR = join(homedir(), ".envsave");
const VAULT_FILE = join(ENVSAVE_DIR, "vault.enc");    // Main vault (password-encrypted)
const CACHE_FILE = join(ENVSAVE_DIR, "cache.enc");    // Session cache (random-key-encrypted)
const SESSION_FILE = join(ENVSAVE_DIR, ".session");    // Random session key (NOT the password)

/**
 * Main vault — only accessible with master password.
 * Contains the HMAC seed and alias registry that an LLM can never reach.
 */
interface MainVault {
  version: 2;
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
}

/**
 * Compute a fully opaque key name: HMAC-SHA256(seed, cleanName) → "es_" + 24 hex chars.
 * No trace of the original name. Impossible to reverse without the seed.
 * If SSH key is configured, the seed is further derived from the SSH key content.
 */
function computeOpaqueName(hmacSeed: string, cleanName: string, sshKeyContent?: string): string {
  let effectiveSeed = hmacSeed;
  if (sshKeyContent) {
    // Mix SSH key file content into the seed — adds "something you have" factor
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

/** Read main vault (requires master password) */
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
function writeSessionCache(secrets: Record<string, string>): void {
  ensureDir();
  const sessionKey = randomBytes(32);
  const cache: SessionCache = { secrets };
  const json = JSON.stringify(cache);
  const encrypted = encryptWithKey(json, sessionKey);
  writeFileSync(CACHE_FILE, encrypted, { mode: 0o600 });
  writeFileSync(SESSION_FILE, sessionKey.toString("hex"), { mode: 0o600 });
}

function readSessionCache(): SessionCache | null {
  if (!existsSync(SESSION_FILE) || !existsSync(CACHE_FILE)) return null;
  try {
    const sessionKeyHex = readFileSync(SESSION_FILE, "utf8").trim();
    const sessionKey = Buffer.from(sessionKeyHex, "hex");
    const payload = readFileSync(CACHE_FILE);
    const json = decryptWithKey(payload, sessionKey);
    return JSON.parse(json) as SessionCache;
  } catch {
    return null;
  }
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
    version: 2,
    hmacSeed,
    sshKeyPath: options?.sshKeyPath,
    secrets: {},
    registry: [],
  };

  let count = 0;
  if (options?.envFile) {
    const envSecrets = parseEnvFile(options.envFile);
    for (const [key, value] of Object.entries(envSecrets)) {
      const opaque = computeOpaqueName(hmacSeed, key, sshKeyContent);
      vault.secrets[opaque] = value;
      vault.registry.push(key);
      count++;
    }
  }

  writeMainVault(vault, password);
  writeSessionCache(vault.secrets);
  chmodSync(ENVSAVE_DIR, 0o700);
  return count;
}

/** Set a secret; returns the opaque key name for use in code */
export function setSecret(key: string, value: string, password: string): string {
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);
  const opaque = computeOpaqueName(vault.hmacSeed, key, sshKeyContent);

  vault.secrets[opaque] = value;
  if (!vault.registry.includes(key)) {
    vault.registry.push(key);
  }

  writeMainVault(vault, password);
  writeSessionCache(vault.secrets);
  return opaque;
}

/** Reveal the opaque key for a clean name. REQUIRES PASSWORD + SSH KEY. */
export function revealKey(cleanName: string, password: string): string | undefined {
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);
  const opaque = computeOpaqueName(vault.hmacSeed, cleanName, sshKeyContent);
  return opaque in vault.secrets ? opaque : undefined;
}

/** Get a secret from session cache by opaque key. NO PASSWORD NEEDED. */
export function getSecretFromCache(opaqueKey: string): string | undefined {
  const cache = readSessionCache();
  if (!cache) {
    throw new Error("No session found. Run any envsave command with your password first.");
  }
  return cache.secrets[opaqueKey];
}

/** Get a secret by opaque key using password (fallback, also refreshes cache). */
export function getSecret(opaqueKey: string, password: string): string | undefined {
  const vault = readMainVault(password);
  writeSessionCache(vault.secrets);
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
  writeSessionCache(vault.secrets);
  return true;
}

/** List clean key names only. Requires password. No opaque names revealed. */
export function listKeys(password: string): string[] {
  const vault = readMainVault(password);
  return vault.registry;
}

export function importEnv(filePath: string, password: string): number {
  const envSecrets = parseEnvFile(filePath);
  const vault = readMainVault(password);
  const sshKeyContent = loadSshKey(vault);

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
  writeSessionCache(vault.secrets);
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
