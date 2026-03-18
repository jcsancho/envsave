import { createCipheriv, createDecipheriv, randomBytes, pbkdf2Sync } from "node:crypto";

const PBKDF2_ITERATIONS = 100_000;
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const KEY_LENGTH = 32; // AES-256
const AUTH_TAG_LENGTH = 16;

export interface EncryptedPayload {
  salt: Buffer;
  iv: Buffer;
  encrypted: Buffer;
  authTag: Buffer;
}

export function deriveKey(password: string, salt: Buffer): Buffer {
  return pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha512");
}

export function encrypt(data: string, password: string): Buffer {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(password, salt);

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Binary format: salt (32) | iv (12) | encrypted (variable) | authTag (16)
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

export function deriveKeyHex(password: string, salt: Buffer): string {
  return deriveKey(password, salt).toString("hex");
}
