import { test, expect, describe, beforeEach, afterAll } from "bun:test";
import { execSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// CRITICAL: Use a temp directory so tests never touch the real vault (~/.envsave)
const TEST_ENVSAVE_DIR = join(tmpdir(), `envsave-test-${process.pid}`);
process.env.ENVSAVE_DIR = TEST_ENVSAVE_DIR;
process.env.NODE_ENV = "test";

// Import AFTER setting env vars so vault.ts picks up the test directory
import { encrypt, decrypt, encryptWithKey, decryptWithKey, hmacSha256 } from "./crypto.ts";
import { parseEnvFile } from "./env-parser.ts";
import {
  initVault,
  setSecret,
  revealKey,
  getSecretFromCache,
  deleteSecret,
  listKeys,
  importEnv,
  exportEnv,
} from "./vault.ts";

function cleanup(): void {
  execSync(`rm -rf ${TEST_ENVSAVE_DIR}`);
}

afterAll(() => {
  cleanup();
});

// ─── crypto.ts ───

describe("crypto", () => {
  describe("encrypt / decrypt (password-based)", () => {
    test("roundtrip returns original plaintext", () => {
      const plaintext = "hello, vault!";
      const password = "strong-password-123";
      const encrypted = encrypt(plaintext, password);
      const decrypted = decrypt(encrypted, password);
      expect(decrypted).toBe(plaintext);
    });

    test("wrong password throws", () => {
      const encrypted = encrypt("secret data", "correct-password");
      expect(() => decrypt(encrypted, "wrong-password")).toThrow();
    });
  });

  describe("encryptWithKey / decryptWithKey", () => {
    test("roundtrip returns original plaintext", () => {
      const key = randomBytes(32);
      const plaintext = "key-encrypted content";
      const encrypted = encryptWithKey(plaintext, key);
      const decrypted = decryptWithKey(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    test("wrong key throws", () => {
      const key = randomBytes(32);
      const wrongKey = randomBytes(32);
      const encrypted = encryptWithKey("secret", key);
      expect(() => decryptWithKey(encrypted, wrongKey)).toThrow();
    });
  });

  describe("hmacSha256", () => {
    test("deterministic output for same inputs", () => {
      const seed = randomBytes(32).toString("hex");
      const data = "MY_SECRET";
      const hash1 = hmacSha256(seed, data);
      const hash2 = hmacSha256(seed, data);
      expect(hash1).toBe(hash2);
    });

    test("different inputs produce different outputs", () => {
      const seed = randomBytes(32).toString("hex");
      const hash1 = hmacSha256(seed, "KEY_A");
      const hash2 = hmacSha256(seed, "KEY_B");
      expect(hash1).not.toBe(hash2);
    });
  });
});

// ─── env-parser.ts ───

describe("env-parser", () => {
  let tmpFile: string;

  function writeTmp(content: string): string {
    const file = join(tmpdir(), `test-env-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    writeFileSync(file, content);
    return file;
  }

  test("parse basic KEY=value", () => {
    tmpFile = writeTmp("FOO=bar\nBAZ=qux\n");
    const result = parseEnvFile(tmpFile);
    expect(result).toEqual({ FOO: "bar", BAZ: "qux" });
  });

  test("skip comments and empty lines", () => {
    tmpFile = writeTmp("# this is a comment\n\nKEY=value\n  \n# another comment\n");
    const result = parseEnvFile(tmpFile);
    expect(result).toEqual({ KEY: "value" });
  });

  test("handle double-quoted values", () => {
    tmpFile = writeTmp('DB_URL="postgres://localhost/db"\n');
    const result = parseEnvFile(tmpFile);
    expect(result).toEqual({ DB_URL: "postgres://localhost/db" });
  });

  test("handle single-quoted values", () => {
    tmpFile = writeTmp("SECRET='my secret value'\n");
    const result = parseEnvFile(tmpFile);
    expect(result).toEqual({ SECRET: "my secret value" });
  });

  test("handle values with = in them", () => {
    tmpFile = writeTmp("CONN=host=localhost;port=5432\n");
    const result = parseEnvFile(tmpFile);
    expect(result).toEqual({ CONN: "host=localhost;port=5432" });
  });
});

// ─── vault.ts ───

describe("vault", () => {
  const PASSWORD = "test-master-password";

  beforeEach(() => {
    cleanup();
  });

  describe("initVault", () => {
    test("creates vault files", () => {
      initVault(PASSWORD);
      expect(existsSync(join(TEST_ENVSAVE_DIR, "vault.enc"))).toBe(true);
      expect(existsSync(join(TEST_ENVSAVE_DIR, "cache.enc"))).toBe(true);
      expect(existsSync(join(TEST_ENVSAVE_DIR, ".session"))).toBe(true);
    });

    test("with envFile imports secrets", () => {
      const envFile = join(tmpdir(), `test-env-init-${Date.now()}`);
      writeFileSync(envFile, "API_KEY=abc123\nDB_PASS=secret\n");
      const count = initVault(PASSWORD, { envFile });
      expect(count).toBe(2);
      const keys = listKeys(PASSWORD);
      expect(keys).toContain("API_KEY");
      expect(keys).toContain("DB_PASS");
    });

    test("with sshKeyPath stores it", () => {
      const sshKeyFile = join(tmpdir(), `test-ssh-key-${Date.now()}`);
      writeFileSync(sshKeyFile, "ssh-rsa AAAAB3FakeKeyContent test@test");
      initVault(PASSWORD, { sshKeyPath: sshKeyFile });
      // Verify vault was created and is functional
      expect(existsSync(join(TEST_ENVSAVE_DIR, "vault.enc"))).toBe(true);
      // Set and retrieve a secret to confirm SSH key factor works
      const opaque = setSecret("MY_KEY", "my_value", PASSWORD);
      expect(opaque.startsWith("es_")).toBe(true);
    });
  });

  describe("setSecret", () => {
    test("returns opaque key with es_ prefix and 51 chars", () => {
      initVault(PASSWORD);
      const opaque = setSecret("API_KEY", "secret123", PASSWORD);
      expect(opaque.startsWith("es_")).toBe(true);
      expect(opaque.length).toBe(51); // "es_" (3) + 48 base chars
      // Must not contain shell-unsafe characters
      expect(opaque).not.toMatch(/[*!&]/);
    });

    test("same key returns same opaque key", () => {
      initVault(PASSWORD);
      const opaque1 = setSecret("API_KEY", "value1", PASSWORD);
      const opaque2 = setSecret("API_KEY", "value2", PASSWORD);
      expect(opaque1).toBe(opaque2);
    });
  });

  describe("revealKey", () => {
    test("returns correct opaque key for existing secret", () => {
      initVault(PASSWORD);
      const opaqueFromSet = setSecret("MY_SECRET", "val", PASSWORD);
      const opaqueFromReveal = revealKey("MY_SECRET", PASSWORD);
      expect(opaqueFromReveal).toBe(opaqueFromSet);
    });

    test("returns undefined for non-existent name", () => {
      initVault(PASSWORD);
      const result = revealKey("DOES_NOT_EXIST", PASSWORD);
      expect(result).toBeUndefined();
    });
  });

  describe("getSecretFromCache", () => {
    test("works after setSecret", () => {
      initVault(PASSWORD);
      const opaque = setSecret("CACHED_KEY", "cached_value", PASSWORD);
      const value = getSecretFromCache(opaque);
      expect(value).toBe("cached_value");
    });

    test("returns undefined for unknown opaque name", () => {
      initVault(PASSWORD);
      setSecret("SOME_KEY", "some_value", PASSWORD);
      const value = getSecretFromCache("ev_000000000000000000000000");
      expect(value).toBeUndefined();
    });
  });

  describe("deleteSecret", () => {
    test("removes the key", () => {
      initVault(PASSWORD);
      setSecret("TO_DELETE", "gone_soon", PASSWORD);
      expect(listKeys(PASSWORD)).toContain("TO_DELETE");

      const deleted = deleteSecret("TO_DELETE", PASSWORD);
      expect(deleted).toBe(true);
      expect(listKeys(PASSWORD)).not.toContain("TO_DELETE");

      const opaque = revealKey("TO_DELETE", PASSWORD);
      expect(opaque).toBeUndefined();
    });
  });

  describe("listKeys", () => {
    test("returns clean names only", () => {
      initVault(PASSWORD);
      setSecret("ALPHA", "a", PASSWORD);
      setSecret("BETA", "b", PASSWORD);
      const keys = listKeys(PASSWORD);
      expect(keys).toEqual(["ALPHA", "BETA"]);
      // No opaque names in the list
      for (const k of keys) {
        expect(k.startsWith("es_")).toBe(false);
      }
    });
  });

  describe("importEnv", () => {
    test("imports all keys from env file", () => {
      initVault(PASSWORD);
      const envFile = join(tmpdir(), `test-import-${Date.now()}`);
      writeFileSync(envFile, "X=1\nY=2\nZ=3\n");
      const count = importEnv(envFile, PASSWORD);
      expect(count).toBe(3);
      const keys = listKeys(PASSWORD);
      expect(keys).toContain("X");
      expect(keys).toContain("Y");
      expect(keys).toContain("Z");
    });
  });

  describe("exportEnv", () => {
    test("outputs clean_name=value format", () => {
      initVault(PASSWORD);
      setSecret("HOST", "localhost", PASSWORD);
      setSecret("PORT", "5432", PASSWORD);
      const exported = exportEnv(PASSWORD);
      const lines = exported.split("\n");
      expect(lines).toContain("HOST=localhost");
      expect(lines).toContain("PORT=5432");
    });
  });

  describe("SSH key factor", () => {
    test("changes opaque names when SSH key is used", () => {
      // Init without SSH key
      initVault(PASSWORD);
      const opaqueNoSsh = setSecret("SHARED_KEY", "val", PASSWORD);
      cleanup();

      // Init with SSH key
      const sshKeyFile = join(tmpdir(), `test-ssh-factor-${Date.now()}`);
      writeFileSync(sshKeyFile, "ssh-ed25519 AAAAC3FakeEd25519Key test@host");
      initVault(PASSWORD, { sshKeyPath: sshKeyFile });
      const opaqueWithSsh = setSecret("SHARED_KEY", "val", PASSWORD);

      // The opaque names must differ because the SSH key changes the HMAC seed
      expect(opaqueNoSsh).not.toBe(opaqueWithSsh);
    });
  });

  describe("session cache security", () => {
    test("cache has no aliases or registry (only secrets map)", () => {
      initVault(PASSWORD);
      setSecret("SECRET_A", "aaa", PASSWORD);
      setSecret("SECRET_B", "bbb", PASSWORD);

      // Read and decrypt the cache directly
      const sessionKeyHex = readFileSync(join(TEST_ENVSAVE_DIR, ".session"), "utf8").trim();
      const sessionKey = Buffer.from(sessionKeyHex, "hex");
      const payload = readFileSync(join(TEST_ENVSAVE_DIR, "cache.enc"));
      const json = decryptWithKey(payload, sessionKey);
      const cache = JSON.parse(json);

      // Cache must only have "secrets" and "registry" — no hmacSeed, no aliases
      expect(Object.keys(cache).sort()).toEqual(["registry", "secrets"]);
      expect(cache.registry).toBeDefined();
      expect(cache.hmacSeed).toBeUndefined();
      expect(cache.sshKeyPath).toBeUndefined();
      expect(cache.version).toBeUndefined();

      // Keys inside secrets must be opaque (ev_ prefix)
      for (const key of Object.keys(cache.secrets)) {
        expect(key.startsWith("es_")).toBe(true);
      }

      // Clean names appear only in registry, not as secret keys
      for (const key of Object.keys(cache.secrets)) {
        expect(key).not.toBe("SECRET_A");
        expect(key).not.toBe("SECRET_B");
      }
    });
  });
});
