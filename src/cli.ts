#!/usr/bin/env node

import { createInterface } from "node:readline";
import { existsSync } from "node:fs";
import {
  initVault,
  setSecret,
  getSecret,
  deleteSecret,
  listKeys,
  importEnv,
  exportEnv,
  vaultExists,
  getSessionPassword,
  saveSessionKey,
} from "./vault.ts";
import { activateLicense, checkLicense } from "./license.ts";

const args = process.argv.slice(2);
const command = args[0];

function usage(): void {
  console.log(`
eVault — Local Secret Vault for LLM-Safe Environments

Usage:
  evault activate <token>    Activate license
  evault init [--env <file>] Initialize vault (optionally import .env)
  evault set <key> <value>   Add/update a secret (prints obfuscated key)
  evault get <obfuscated>    Retrieve a secret using its obfuscated key
  evault delete <key>        Remove a secret by clean name
  evault list                List all keys (clean name → obfuscated key)
  evault import <file>       Import from .env file (prints obfuscated keys)
  evault export              Export all secrets as .env format
  evault help                Show this help

The obfuscated key (with random suffix) is what you use in your code:
  const apiKey = evault.get("OPENAI_API_KEY_a7Bx#9mK2pQ1");
This makes it impossible for LLMs to guess your secret names.
`);
}

async function promptPassword(prompt = "Master password: "): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true,
    });

    // Hide input
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
        // Ctrl+C
        process.exit(1);
      } else if (c === "\u007F" || c === "\b") {
        // Backspace
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

      const envFlag = args.indexOf("--env");
      const envFile = envFlag !== -1 ? args[envFlag + 1] : undefined;

      if (envFile && !existsSync(envFile)) {
        console.error(`File not found: ${envFile}`);
        process.exit(1);
      }

      const imported = initVault(password, envFile);
      console.log("Vault initialized successfully!");
      if (imported.length > 0) {
        console.log(`\nImported ${imported.length} secrets. Use these obfuscated keys in your code:\n`);
        for (const [clean, obfuscated] of imported) {
          console.log(`  ${clean} → ${obfuscated}`);
        }
        console.log(`\nExample: evault.get("${imported[0]![1]}")`);
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
      const obfuscated = setSecret(key, value, password);
      console.log(`Secret stored. Use this key in your code:\n`);
      console.log(`  ${obfuscated}`);
      console.log(`\nExample: evault.get("${obfuscated}")`);
      break;
    }

    case "get": {
      requireLicense();
      const key = args[1];
      if (!key) {
        console.error("Usage: evault get <obfuscated_key>");
        process.exit(1);
      }
      // Try session password first (no prompt)
      const sessionPw = getSessionPassword();
      if (sessionPw) {
        try {
          const value = getSecret(key, sessionPw);
          if (value !== undefined) {
            process.stdout.write(value);
          } else {
            console.error(`Secret '${key}' not found. Use the full obfuscated key from 'evault list'.`);
            process.exit(1);
          }
          break;
        } catch {
          // Session key invalid, fall through to prompt
        }
      }
      const password = await requirePassword();
      const val = getSecret(key, password);
      if (val !== undefined) {
        saveSessionKey(password);
        process.stdout.write(val);
      } else {
        console.error(`Secret '${key}' not found. Use the full obfuscated key from 'evault list'.`);
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
        console.log("Clean Name → Obfuscated Key (use the right side in your code)\n");
        for (const [clean, obfuscated] of keys) {
          console.log(`  ${clean} → ${obfuscated}`);
        }
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
      const imported = importEnv(file, password);
      console.log(`Imported ${imported.length} secrets. Use these obfuscated keys in your code:\n`);
      for (const [clean, obfuscated] of imported) {
        console.log(`  ${clean} → ${obfuscated}`);
      }
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
