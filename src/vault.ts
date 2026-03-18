import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import { encrypt, decrypt } from "./crypto.ts";
import { parseEnvFile } from "./env-parser.ts";

const EVAULT_DIR = join(homedir(), ".evault");
const VAULT_FILE = join(EVAULT_DIR, "vault.enc");
const SESSION_FILE = join(EVAULT_DIR, ".session");

const SUFFIX_LENGTH = 12;
const SUFFIX_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";

interface VaultData {
  // Obfuscated key → value (e.g. "OPENAI_API_KEY_a7Bx#9mK2pQ1" → "sk-...")
  secrets: Record<string, string>;
  // Clean name → obfuscated key (for user reference only)
  aliases: Record<string, string>;
}

/** Generate a random 12-char suffix from letters, digits, and special chars */
function generateSuffix(): string {
  const bytes = randomBytes(SUFFIX_LENGTH);
  let suffix = "";
  for (let i = 0; i < SUFFIX_LENGTH; i++) {
    suffix += SUFFIX_CHARS[bytes[i]! % SUFFIX_CHARS.length];
  }
  return suffix;
}

/** Build an obfuscated internal key: CLEAN_NAME_<random12> */
function obfuscateKey(cleanName: string): string {
  return `${cleanName}_${generateSuffix()}`;
}

function ensureDir(): void {
  if (!existsSync(EVAULT_DIR)) {
    mkdirSync(EVAULT_DIR, { recursive: true, mode: 0o700 });
  }
}

export function vaultExists(): boolean {
  return existsSync(VAULT_FILE);
}

function readVault(password: string): VaultData {
  if (!existsSync(VAULT_FILE)) {
    throw new Error("Vault not found. Run 'evault init' first.");
  }
  const payload = readFileSync(VAULT_FILE);
  const json = decrypt(payload, password);
  const data = JSON.parse(json) as Partial<VaultData>;
  return {
    secrets: data.secrets ?? {},
    aliases: data.aliases ?? {},
  };
}

function writeVault(data: VaultData, password: string): void {
  ensureDir();
  const json = JSON.stringify(data);
  const encrypted = encrypt(json, password);
  writeFileSync(VAULT_FILE, encrypted, { mode: 0o600 });
}

// Session key management
export function saveSessionKey(password: string): void {
  ensureDir();
  writeFileSync(SESSION_FILE, password, { mode: 0o600 });
}

export function getSessionPassword(): string | null {
  if (!existsSync(SESSION_FILE)) return null;
  try {
    return readFileSync(SESSION_FILE, "utf8");
  } catch {
    return null;
  }
}

/** Init vault; returns list of [cleanName, obfuscatedKey] for imported keys */
export function initVault(password: string, envFile?: string): Array<[string, string]> {
  if (vaultExists()) {
    throw new Error("Vault already exists. Delete ~/.evault/vault.enc to reinitialize.");
  }

  const data: VaultData = { secrets: {}, aliases: {} };
  const imported: Array<[string, string]> = [];

  if (envFile) {
    const envSecrets = parseEnvFile(envFile);
    for (const [key, value] of Object.entries(envSecrets)) {
      const obfuscated = obfuscateKey(key);
      data.secrets[obfuscated] = value;
      data.aliases[key] = obfuscated;
      imported.push([key, obfuscated]);
    }
  }

  writeVault(data, password);
  saveSessionKey(password);
  chmodSync(EVAULT_DIR, 0o700);
  return imported;
}

/** Set a secret; returns the obfuscated key the user should use in code */
export function setSecret(key: string, value: string, password: string): string {
  const data = readVault(password);

  // If alias exists, reuse the same obfuscated key; otherwise generate new
  const obfuscated = data.aliases[key] ?? obfuscateKey(key);
  data.secrets[obfuscated] = value;
  data.aliases[key] = obfuscated;

  writeVault(data, password);
  saveSessionKey(password);
  return obfuscated;
}

/**
 * Get a secret by its OBFUSCATED key (the one with the random suffix).
 * This is what users put in their code — LLMs can't guess this.
 */
export function getSecret(obfuscatedKey: string, password: string): string | undefined {
  const data = readVault(password);
  return data.secrets[obfuscatedKey];
}

export function deleteSecret(key: string, password: string): boolean {
  const data = readVault(password);
  const obfuscated = data.aliases[key];
  if (!obfuscated) return false;
  delete data.secrets[obfuscated];
  delete data.aliases[key];
  writeVault(data, password);
  return true;
}

/** List all keys — returns [cleanName, obfuscatedKey] pairs */
export function listKeys(password: string): Array<[string, string]> {
  const data = readVault(password);
  return Object.entries(data.aliases);
}

/** Import from .env; returns [cleanName, obfuscatedKey] pairs */
export function importEnv(filePath: string, password: string): Array<[string, string]> {
  const envSecrets = parseEnvFile(filePath);
  const data = readVault(password);

  const imported: Array<[string, string]> = [];
  for (const [key, value] of Object.entries(envSecrets)) {
    const obfuscated = data.aliases[key] ?? obfuscateKey(key);
    data.secrets[obfuscated] = value;
    data.aliases[key] = obfuscated;
    imported.push([key, obfuscated]);
  }

  writeVault(data, password);
  return imported;
}

export function exportEnv(password: string): string {
  const data = readVault(password);
  return Object.entries(data.aliases)
    .map(([cleanName, obfuscated]) => `${cleanName}=${data.secrets[obfuscated] ?? ""}`)
    .join("\n");
}

/**
 * Library get() — uses the OBFUSCATED key (with random suffix).
 * Users must use the exact key shown by `evault set` or `evault list`.
 */
export function getSecretWithSession(obfuscatedKey: string): string | undefined {
  const password = getSessionPassword();
  if (!password) {
    throw new Error("No session found. Run 'evault init' or any evault command with your password first.");
  }
  return getSecret(obfuscatedKey, password);
}

export function hasSecretWithSession(obfuscatedKey: string): boolean {
  const password = getSessionPassword();
  if (!password) return false;
  try {
    const data = readVault(password);
    return obfuscatedKey in data.secrets;
  } catch {
    return false;
  }
}
