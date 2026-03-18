import { createCipheriv, createDecipheriv, createHmac, randomBytes, pbkdf2Sync } from "node:crypto";

const PBKDF2_ITERATIONS = 100_000;
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const KEY_LENGTH = 32; // AES-256
const AUTH_TAG_LENGTH = 16;

export function deriveKey(password: string, salt: Buffer): Buffer {
  return pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha512");
}

// Password-based encryption (uses PBKDF2 to derive key)
// Format: salt (32) | iv (12) | encrypted (variable) | authTag (16)
export function encrypt(data: string, password: string): Buffer {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(password, salt);

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, encrypted, authTag]);
}

export function decrypt(payload: Buffer, password: string): string {
  const salt = payload.subarray(0, SALT_LENGTH);
  const iv = payload.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const authTag = payload.subarray(payload.length - AUTH_TAG_LENGTH);
  const encrypted = payload.subarray(SALT_LENGTH + IV_LENGTH, payload.length - AUTH_TAG_LENGTH);

  const key = deriveKey(password, salt);

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  return decipher.update(encrypted) + decipher.final("utf8");
}

// Direct-key encryption (for session cache — key is already high-entropy)
// Format: iv (12) | encrypted (variable) | authTag (16)
export function encryptWithKey(data: string, key: Buffer): Buffer {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, encrypted, authTag]);
}

export function decryptWithKey(payload: Buffer, key: Buffer): string {
  const iv = payload.subarray(0, IV_LENGTH);
  const authTag = payload.subarray(payload.length - AUTH_TAG_LENGTH);
  const encrypted = payload.subarray(IV_LENGTH, payload.length - AUTH_TAG_LENGTH);

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  return decipher.update(encrypted) + decipher.final("utf8");
}

// HMAC-SHA256 for opaque key name generation
export function hmacSha256(seedHex: string, data: string): string {
  return createHmac("sha256", Buffer.from(seedHex, "hex"))
    .update(data)
    .digest("hex");
}
