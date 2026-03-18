#!/usr/bin/env node

import { createInterface } from "node:readline";
import { existsSync } from "node:fs";
import {
  initVault,
  setSecret,
  getSecret,
  getSecretFromCache,
  deleteSecret,
  listKeys,
  importEnv,
  exportEnv,
  revealKey,
  vaultExists,
} from "./vault.ts";
import { activateLicense, checkLicense } from "./license.ts";

const args = process.argv.slice(2);
const command = args[0];

function usage(): void {
  console.log(`
eVault — Local Secret Vault for LLM-Safe Environments

Usage:
  evault activate <token>              Activate license
  evault init [--env <f>] [--ssh-key <f>]  Initialize vault
  evault set <key> <value>             Add/update a secret (outputs opaque key)
  evault get <opaque_key>              Retrieve a value (no password needed)
  evault reveal <key>                  Show opaque key name (password required)
  evault delete <key>                  Remove a secret (password required)
  evault list                          List clean key names (password required)
  evault import <file>                 Import from .env file (password required)
  evault export                        Export as .env format (password required)
  evault help                          Show this help

Security model:
  1. evault set OPENAI_API_KEY sk-...     → outputs: ev_7a3f2b1e9c8d4f6b2a1c3d5f
  2. evault reveal OPENAI_API_KEY         → password required to see opaque key
  3. evault.get("ev_7a3f2b1e9c8d4f6b2a1c3d5f")  → returns value (no password)

  Key names are HMAC-SHA256 hashes — fully opaque, no trace of original name.
  Session cache stores secrets only — no aliases, no seed, no enumeration.
  Optional --ssh-key adds hardware-level "something you have" factor.
`);
}

async function promptPassword(prompt = "Master password: "): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true,
    });

    process.stderr.write(prompt);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    if (stdin.isTTY && stdin.setRawMode) {
      stdin.setRawMode(true);
    }

    let password = "";
    const onData = (ch: Buffer) => {
      const c = ch.toString();
      if (c === "\n" || c === "\r" || c === "\u0004") {
        if (stdin.isTTY && stdin.setRawMode) {
          stdin.setRawMode(wasRaw ?? false);
        }
        stdin.removeListener("data", onData);
        process.stderr.write("\n");
        rl.close();
        resolve(password);
      } else if (c === "\u0003") {
        process.exit(1);
      } else if (c === "\u007F" || c === "\b") {
        password = password.slice(0, -1);
      } else {
        password += c;
      }
    };

    stdin.on("data", onData);
  });
}

async function requirePassword(): Promise<string> {
  const password = await promptPassword();
  if (!password) {
    console.error("Password cannot be empty.");
    process.exit(1);
  }
  return password;
}

function requireLicense(): void {
  if (!checkLicense()) {
    console.error("No valid license found. Run 'evault activate <token>' first.");
    console.error("Get your license at https://evault.example.com");
    process.exit(1);
  }
}

function getFlag(name: string): string | undefined {
  const idx = args.indexOf(name);
  return idx !== -1 ? args[idx + 1] : undefined;
}

async function main(): Promise<void> {
  if (!command || command === "help" || command === "--help" || command === "-h") {
    usage();
    return;
  }

  switch (command) {
    case "activate": {
      const token = args[1];
      if (!token) {
        console.error("Usage: evault activate <token>");
        process.exit(1);
      }
      const ok = await activateLicense(token);
      if (ok) {
        console.log("License activated successfully!");
      } else {
        process.exit(1);
      }
      break;
    }

    case "init": {
      requireLicense();
      if (vaultExists()) {
        console.error("Vault already exists. Delete ~/.evault/vault.enc to reinitialize.");
        process.exit(1);
      }

      const password = await promptPassword("Set master password: ");
      if (!password) {
        console.error("Password cannot be empty.");
        process.exit(1);
      }
      const confirm = await promptPassword("Confirm password: ");
      if (password !== confirm) {
        console.error("Passwords do not match.");
        process.exit(1);
      }

      const envFile = getFlag("--env");
      const sshKeyPath = getFlag("--ssh-key");

      if (envFile && !existsSync(envFile)) {
        console.error(`File not found: ${envFile}`);
        process.exit(1);
      }
      if (sshKeyPath && !existsSync(sshKeyPath)) {
        console.error(`SSH key not found: ${sshKeyPath}`);
        process.exit(1);
      }

      const count = initVault(password, { envFile, sshKeyPath });
      console.log("Vault initialized successfully!");
      if (sshKeyPath) {
        console.log(`SSH key factor enabled: ${sshKeyPath}`);
      }
      if (count > 0) {
        console.log(`Imported ${count} secrets.`);
        console.log(`\nUse 'evault reveal <KEY>' to get the opaque key for each secret.`);
      }
      break;
    }

    case "set": {
      requireLicense();
      const key = args[1];
      const value = args[2];
      if (!key || value === undefined) {
        console.error("Usage: evault set <key> <value>");
        process.exit(1);
      }
      const password = await requirePassword();
      const opaque = setSecret(key, value, password);
      console.log(opaque);
      break;
    }

    case "reveal": {
      requireLicense();
      const key = args[1];
      if (!key) {
        console.error("Usage: evault reveal <key>");
        process.exit(1);
      }
      const password = await requirePassword();
      const opaque = revealKey(key, password);
      if (opaque) {
        console.log(opaque);
      } else {
        console.error(`Secret '${key}' not found.`);
        process.exit(1);
      }
      break;
    }

    case "get": {
      requireLicense();
      const key = args[1];
      if (!key) {
        console.error("Usage: evault get <opaque_key>");
        process.exit(1);
      }
      // Try session cache first (no password prompt)
      try {
        const value = getSecretFromCache(key);
        if (value !== undefined) {
          process.stdout.write(value);
          break;
        }
      } catch {
        // No cache, fall through to password prompt
      }
      const password = await requirePassword();
      const val = getSecret(key, password);
      if (val !== undefined) {
        process.stdout.write(val);
      } else {
        console.error(`Secret not found. Use 'evault reveal <name>' to get the opaque key.`);
        process.exit(1);
      }
      break;
    }

    case "delete": {
      requireLicense();
      const key = args[1];
      if (!key) {
        console.error("Usage: evault delete <key>");
        process.exit(1);
      }
      const password = await requirePassword();
      const deleted = deleteSecret(key, password);
      if (deleted) {
        console.log(`Secret '${key}' deleted.`);
      } else {
        console.error(`Secret '${key}' not found.`);
        process.exit(1);
      }
      break;
    }

    case "list": {
      requireLicense();
      const password = await requirePassword();
      const keys = listKeys(password);
      if (keys.length === 0) {
        console.log("No secrets stored.");
      } else {
        for (const k of keys) {
          console.log(k);
        }
        console.log(`\n${keys.length} secret(s). Use 'evault reveal <KEY>' to get the opaque key.`);
      }
      break;
    }

    case "import": {
      requireLicense();
      const file = args[1];
      if (!file) {
        console.error("Usage: evault import <file>");
        process.exit(1);
      }
      if (!existsSync(file)) {
        console.error(`File not found: ${file}`);
        process.exit(1);
      }
      const password = await requirePassword();
      const count = importEnv(file, password);
      console.log(`Imported ${count} secrets.`);
      console.log(`\nUse 'evault reveal <KEY>' to get the opaque key for each secret.`);
      break;
    }

    case "export": {
      requireLicense();
      const password = await requirePassword();
      const output = exportEnv(password);
      console.log(output);
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      usage();
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
