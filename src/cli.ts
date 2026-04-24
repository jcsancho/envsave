#!/usr/bin/env node

import { createInterface } from "node:readline";
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  initVault,
  setSecret,
  getSecret,
  getSecretFromCache,
  showSecret,
  deleteSecret,
  listKeys,
  searchKeys,
  importEnv,
  exportEnv,
  revealKey,
  revealKeysByPattern,
  vaultExists,
  configureRateLimit,
  getRateLimitConfig,
  getDeploySecrets,
} from "./vault.ts";
import { activateLicense, checkLicense, getLicenseToken } from "./license.ts";
import pkg from "../package.json" with { type: "json" };

const args = process.argv.slice(2);
const command = args[0];

function checkEnvFiles(): void {
  const cwd = process.cwd();
  const envPatterns = [".env", ".env.local", ".env.development", ".env.production", ".env.staging", ".env.test"];
  const found: string[] = [];
  try {
    const files = readdirSync(cwd);
    for (const f of files) {
      if (f === ".env" || f.startsWith(".env.")) {
        found.push(f);
      }
    }
  } catch {}
  if (found.length > 0) {
    const RED = "\x1b[31m";
    const BOLD = "\x1b[1m";
    const RESET = "\x1b[0m";
    console.error(`\n${RED}${BOLD}⚠  Warning: Found .env files in current directory:${RESET}`);
    for (const f of found) {
      console.error(`${RED}   • ${f}${RESET}`);
    }
    console.error(`${RED}   Consider importing them into EnvSave: envsave import <file>${RESET}`);
  }
}

function usage(): void {
  console.log(`
EnvSave — Local Secret Vault for LLM-Safe Environments

Usage:
  envsave activate <token> [--offline]   Activate license (--offline skips server)
  envsave init [--env <f>] [--ssh-key <f>]  Initialize vault
  envsave set <key> <value>             Add/update a secret (outputs opaque key)
  envsave get <opaque_key>              Retrieve a value (no password needed)
  envsave show <key>                    Show real value by key name (password required)
  envsave reveal <keyword> [keyword2]... Show opaque key(s) for any name matching keyword (password required)
  envsave delete <key>                  Remove a secret (password required)
  envsave search <keyword>              Search keys matching keyword (no password)
  envsave scan [dir]                    Scan project for env variable usage
  envsave passwd                        Change master password
  envsave config                        Show rate limit config
  envsave config --max-gets <n>         Set max gets per minute (password required)
  envsave list                          List clean key names (password required)
  envsave import <file>                 Import from .env file (password required)
  envsave export                        Export as .env format (password required)
  envsave backup                        Upload encrypted vault to server
  envsave restore                       Download vault backup from server
  envsave sync                          Sync vault with server (pull if cloud newer)
  envsave vercel <KEY|es_key>...        Push secrets to Vercel (accepts names or opaque keys)
  envsave help                          Show this help

Security model:
  1. envsave set OPENAI_API_KEY sk-...     → outputs: es_7a3f2b1e9c8d4f6b2a1c3d5f
  2. envsave reveal OPENAI_API_KEY         → password required to see opaque key
  3. envsave.get("es_7a3f2b1e9c8d4f6b2a1c3d5f")  → returns value (no password)

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
      terminal: false,
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

async function requireLicense(): Promise<void> {
  if (!(await checkLicense())) {
    console.error("No valid license found. Run 'envsave activate <token>' first.");
    console.error("Get your license at https://api.envsave.com");
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
    checkEnvFiles();
    return;
  }

  if (command === "--version" || command === "-v" || command === "version") {
    console.log(pkg.version);
    return;
  }

  switch (command) {
    case "activate": {
      const token = args[1];
      if (!token) {
        console.error("Usage: envsave activate <token> [--offline]");
        process.exit(1);
      }
      const offline = args.includes("--offline");
      const ok = await activateLicense(token, offline);
      if (ok) {
        console.log("License activated successfully!");
      } else {
        process.exit(1);
      }
      break;
    }

    case "init": {
      if (vaultExists()) {
        console.error("Vault already exists. Delete ~/.envsave/vault.enc to reinitialize.");
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
        console.log(`\nUse 'envsave reveal <KEY>' to get the opaque key for each secret.`);
      }
      break;
    }

    case "set": {
      const key = args[1];
      const value = args[2];
      if (!key || value === undefined) {
        console.error("Usage: envsave set <key> <value>");
        process.exit(1);
      }
      const password = await requirePassword();
      const { opaque, updated } = setSecret(key, value, password);
      console.log(`\n  ${updated ? "Updated" : "Added"}: ${key} → ${opaque}\n`);
      console.log(`  Use this in your code to access ${key}:`);
      console.log(`    envsave.get("${opaque}")\n`);
      break;
    }

    case "reveal": {
      const patterns = args.slice(1);
      if (patterns.length === 0) {
        console.error("Usage: envsave reveal <keyword> [keyword2]...");
        process.exit(1);
      }
      const password = await requirePassword();
      const results = revealKeysByPattern(patterns, password);
      let totalMatches = 0;
      let notFoundPatterns = 0;
      for (const { pattern, matches } of results) {
        if (matches.length === 0) {
          console.error(`No keys matching '${pattern}'.`);
          notFoundPatterns++;
          continue;
        }
        for (const { name, opaque } of matches) {
          console.log(`\n  ${name} → ${opaque}`);
          console.log(`    envsave.get("${opaque}")`);
          totalMatches++;
        }
      }
      if (totalMatches > 0) console.log();
      if (notFoundPatterns === patterns.length) process.exit(1);
      break;
    }

    case "show": {
      const key = args[1];
      if (!key) {
        console.error("Usage: envsave show <key>");
        process.exit(1);
      }
      const password = await requirePassword();
      const val = showSecret(key, password);
      if (val !== undefined) {
        console.log(`\n  ${key} = ${val}\n`);
      } else {
        console.error(`Secret '${key}' not found.`);
        process.exit(1);
      }
      break;
    }

    case "get": {
      const key = args[1];
      if (!key) {
        console.error("Usage: envsave get <opaque_key>");
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
        console.error(`Secret not found. Use 'envsave reveal <name>' to get the opaque key.`);
        process.exit(1);
      }
      break;
    }

    case "delete": {
      const key = args[1];
      if (!key) {
        console.error("Usage: envsave delete <key>");
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

    case "config": {
      const maxGets = getFlag("--max-gets");
      if (!maxGets) {
        // Just show current config
        const config = getRateLimitConfig();
        console.log(`Rate limit config:`);
        console.log(`  Max gets per minute: ${config.maxGetsPerMinute}`);
        break;
      }
      const password = await requirePassword();
      const options: { maxGetsPerMinute?: number } = {
        maxGetsPerMinute: parseInt(maxGets, 10),
      };
      if (options.maxGetsPerMinute !== undefined && (isNaN(options.maxGetsPerMinute) || options.maxGetsPerMinute < 1)) {
        console.error("--max-gets must be a positive number.");
        process.exit(1);
      }
      const config = configureRateLimit(password, options);
      console.log(`Config updated:`);
      console.log(`  Max gets per minute: ${config.maxGetsPerMinute}`);
      break;
    }

    case "passwd": {
      const oldPassword = await promptPassword("Current password: ");
      if (!oldPassword) {
        console.error("Password cannot be empty.");
        process.exit(1);
      }
      // Verify old password works
      try {
        listKeys(oldPassword);
      } catch {
        console.error("Incorrect current password.");
        process.exit(1);
      }
      const newPassword = await promptPassword("New password: ");
      if (!newPassword) {
        console.error("Password cannot be empty.");
        process.exit(1);
      }
      const confirmNew = await promptPassword("Confirm new password: ");
      if (newPassword !== confirmNew) {
        console.error("Passwords do not match.");
        process.exit(1);
      }
      const { changePassword } = await import("./vault.ts");
      changePassword(oldPassword, newPassword);
      console.log("Password changed successfully!");
      break;
    }

    case "search": {
      const keyword = args[1];
      if (!keyword) {
        console.error("Usage: envsave search <keyword>");
        process.exit(1);
      }
      let matches: string[];
      try {
        matches = searchKeys(keyword);
      } catch {
        // No session — prompt for password to create one
        const password = await requirePassword();
        listKeys(password); // refreshes session cache with registry
        matches = searchKeys(keyword);
      }
      if (matches.length === 0) {
        console.log(`No keys matching "${keyword}".`);
      } else {
        for (const k of matches) {
          console.log(k);
        }
        console.log(`\n${matches.length} key(s) matching "${keyword}".`);
      }
      break;
    }

    case "scan": {
      const scanDir = args.slice(1).find(a => !a.startsWith("--")) || process.cwd();
      const { scanProject } = await import("./scanner.ts");
      const results = scanProject(scanDir);
      if (results.length === 0) {
        console.log("No env variable usage found.");
      } else {
        // Build reverse map: opaque key → clean name (requires password + vault)
        let opaqueToName: Record<string, string> = {};
        const hasOpaqueKeys = results.some(r => r.match.startsWith("es_"));
        if (hasOpaqueKeys && vaultExists()) {
          try {
            const password = await requirePassword();
            const keys = listKeys(password);
            for (const k of keys) {
              const opaque = revealKey(k, password);
              if (opaque) opaqueToName[opaque] = k;
            }
          } catch (err: any) {
            if (err.message?.includes("unable to authenticate data") || err.message?.includes("Unsupported state")) {
              console.error("Incorrect password — skipping key resolution.");
            }
          }
        }

        const grouped: Record<string, { file: string; line: number; match: string }[]> = {};
        for (const r of results) {
          if (!grouped[r.type]) grouped[r.type] = [];
          grouped[r.type].push(r);
        }
        for (const [type, entries] of Object.entries(grouped)) {
          console.log(`\n\x1b[1m${type}\x1b[0m`);
          for (const e of entries) {
            const name = opaqueToName[e.match];
            const display = name ? `${e.match} → ${name}` : e.match;
            console.log(`  ${e.file}:${e.line}  ${display}`);
          }
        }
        const uniqueVars = new Set(results.map(r => r.match));
        console.log(`\n${results.length} reference(s), ${uniqueVars.size} unique variable(s) found.`);
      }
      break;
    }

    case "list": {
      const password = await requirePassword();
      const keys = listKeys(password);
      if (keys.length === 0) {
        console.log("No secrets stored.");
      } else {
        for (const k of keys) {
          console.log(k);
        }
        console.log(`\n${keys.length} secret(s). Use 'envsave reveal <KEY>' to get the opaque key.`);
      }
      break;
    }

    case "import": {
      const file = args[1];
      if (!file) {
        console.error("Usage: envsave import <file>");
        process.exit(1);
      }
      if (!existsSync(file)) {
        console.error(`File not found: ${file}`);
        process.exit(1);
      }
      const password = await requirePassword();
      const count = importEnv(file, password);
      console.log(`Imported ${count} secrets.`);
      console.log(`\nUse 'envsave reveal <KEY>' to get the opaque key for each secret.`);
      break;
    }

    case "export": {
      const password = await requirePassword();
      const output = exportEnv(password);
      console.log(output);
      break;
    }

    case "backup": {
      await requireLicense();
      const token = getLicenseToken();
      if (!token) {
        console.error("No license token found. Run 'envsave activate <token>' first.");
        process.exit(1);
      }

      const envsaveDir = join(homedir(), ".envsave");
      const vaultFile = join(envsaveDir, "vault.enc");
      if (!existsSync(vaultFile)) {
        console.error("No vault found. Run 'envsave init' first.");
        process.exit(1);
      }

      const vaultData = readFileSync(vaultFile);
      const checksum = createHash("sha256").update(vaultData).digest("hex");
      const apiBase = (process.env.ENVSAVE_LICENSE_API || "https://api.envsave.com/api/license/validate").replace("/api/license/validate", "");

      console.log(`Uploading encrypted vault (${vaultData.byteLength} bytes)...`);

      const resp = await fetch(`${apiBase}/api/vault/backup`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/octet-stream",
        },
        body: vaultData,
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({})) as Record<string, string>;
        console.error(`Backup failed: ${err.error || resp.statusText}`);
        process.exit(1);
      }

      const result = await resp.json() as { checksum: string; size: number };
      if (result.checksum !== checksum) {
        console.error("Checksum mismatch! Backup may be corrupted.");
        process.exit(1);
      }

      console.log(`Vault backed up successfully!`);
      console.log(`  Size: ${result.size} bytes`);
      console.log(`  Checksum: ${checksum.slice(0, 16)}...`);
      break;
    }

    case "restore": {
      await requireLicense();
      const token = getLicenseToken();
      if (!token) {
        console.error("No license token found. Run 'envsave activate <token>' first.");
        process.exit(1);
      }

      const envsaveDir = join(homedir(), ".envsave");
      const vaultFile = join(envsaveDir, "vault.enc");
      const apiBase = (process.env.ENVSAVE_LICENSE_API || "https://api.envsave.com/api/license/validate").replace("/api/license/validate", "");

      // Check if there's an existing vault and warn
      if (existsSync(vaultFile)) {
        const rl = createInterface({ input: process.stdin, output: process.stderr });
        const answer = await new Promise<string>((resolve) => {
          rl.question("Local vault exists. Overwrite with backup? (y/N) ", resolve);
        });
        rl.close();
        if (answer.toLowerCase() !== "y") {
          console.log("Restore cancelled.");
          break;
        }
      }

      console.log("Downloading vault backup...");

      const resp = await fetch(`${apiBase}/api/vault/download`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` },
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({})) as Record<string, string>;
        console.error(`Restore failed: ${err.error || resp.statusText}`);
        process.exit(1);
      }

      const vaultData = Buffer.from(await resp.arrayBuffer());
      const serverChecksum = resp.headers.get("x-checksum") || "";
      const localChecksum = createHash("sha256").update(vaultData).digest("hex");

      if (serverChecksum && localChecksum !== serverChecksum) {
        console.error("Checksum mismatch! Download may be corrupted.");
        process.exit(1);
      }

      if (!existsSync(envsaveDir)) {
        mkdirSync(envsaveDir, { recursive: true, mode: 0o700 });
      }
      writeFileSync(vaultFile, vaultData, { mode: 0o600 });

      const backupDate = resp.headers.get("x-backup-date") || "unknown";
      console.log(`Vault restored successfully!`);
      console.log(`  Size: ${vaultData.byteLength} bytes`);
      console.log(`  Backup date: ${backupDate}`);
      console.log(`\nUse 'envsave list' to verify your secrets.`);
      break;
    }

    case "sync": {
      await requireLicense();
      const token = getLicenseToken();
      if (!token) {
        console.error("No license token found. Run 'envsave activate <token>' first.");
        process.exit(1);
      }

      const envsaveDir = join(homedir(), ".envsave");
      const vaultFile = join(envsaveDir, "vault.enc");
      const apiBase = (process.env.ENVSAVE_LICENSE_API || "https://api.envsave.com/api/license/validate").replace("/api/license/validate", "");

      // Get cloud status
      const statusResp = await fetch(`${apiBase}/api/vault/status`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` },
      });

      if (!statusResp.ok) {
        console.error("Failed to check cloud status.");
        process.exit(1);
      }

      const cloudStatus = await statusResp.json() as { hasBackup: boolean; checksum?: string; size?: number; updatedAt?: string };
      const hasLocal = existsSync(vaultFile);

      // Compute local checksum if vault exists
      let localChecksum = "";
      let localSize = 0;
      if (hasLocal) {
        const localData = readFileSync(vaultFile);
        localChecksum = createHash("sha256").update(localData).digest("hex");
        localSize = localData.byteLength;
      }

      // Already in sync
      if (cloudStatus.hasBackup && hasLocal && cloudStatus.checksum === localChecksum) {
        console.log("Already in sync.");
        console.log(`  Checksum: ${localChecksum.slice(0, 16)}...`);
        break;
      }

      // No cloud backup, local exists → push
      if (!cloudStatus.hasBackup && hasLocal) {
        console.log("No cloud backup found. Uploading local vault...");
        const localData = readFileSync(vaultFile);
        const resp = await fetch(`${apiBase}/api/vault/backup`, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/octet-stream",
          },
          body: localData,
        });
        if (!resp.ok) {
          console.error("Upload failed.");
          process.exit(1);
        }
        console.log(`Pushed local vault to cloud (${localSize} bytes).`);
        break;
      }

      // Cloud backup exists, no local → pull
      if (cloudStatus.hasBackup && !hasLocal) {
        console.log("No local vault found. Downloading from cloud...");
        const resp = await fetch(`${apiBase}/api/vault/download`, {
          method: "POST",
          headers: { "Authorization": `Bearer ${token}` },
        });
        if (!resp.ok) {
          console.error("Download failed.");
          process.exit(1);
        }
        const vaultData = Buffer.from(await resp.arrayBuffer());
        if (!existsSync(envsaveDir)) {
          mkdirSync(envsaveDir, { recursive: true, mode: 0o700 });
        }
        writeFileSync(vaultFile, vaultData, { mode: 0o600 });
        console.log(`Pulled vault from cloud (${vaultData.byteLength} bytes).`);
        break;
      }

      // Both exist but different → compare dates, let user choose
      if (cloudStatus.hasBackup && hasLocal && cloudStatus.checksum !== localChecksum) {
        const localMtime = statSync(vaultFile).mtimeMs;
        const cloudDate = cloudStatus.updatedAt ? new Date(cloudStatus.updatedAt).getTime() : 0;

        console.log("Local and cloud vaults differ:");
        console.log(`  Local:  ${localSize} bytes, modified ${new Date(localMtime).toISOString()}`);
        console.log(`  Cloud:  ${cloudStatus.size} bytes, modified ${cloudStatus.updatedAt || "unknown"}`);

        const rl = createInterface({ input: process.stdin, output: process.stderr });
        const answer = await new Promise<string>((resolve) => {
          rl.question("Pull from cloud (p), push local to cloud (l), or cancel (c)? [p/l/c] ", resolve);
        });
        rl.close();

        if (answer.toLowerCase() === "p") {
          const resp = await fetch(`${apiBase}/api/vault/download`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${token}` },
          });
          if (!resp.ok) {
            console.error("Download failed.");
            process.exit(1);
          }
          const vaultData = Buffer.from(await resp.arrayBuffer());
          writeFileSync(vaultFile, vaultData, { mode: 0o600 });
          console.log(`Pulled vault from cloud (${vaultData.byteLength} bytes).`);
        } else if (answer.toLowerCase() === "l") {
          const localData = readFileSync(vaultFile);
          const resp = await fetch(`${apiBase}/api/vault/backup`, {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${token}`,
              "Content-Type": "application/octet-stream",
            },
            body: localData,
          });
          if (!resp.ok) {
            console.error("Upload failed.");
            process.exit(1);
          }
          console.log(`Pushed local vault to cloud (${localData.byteLength} bytes).`);
        } else {
          console.log("Sync cancelled.");
        }
        break;
      }

      // Neither exists
      if (!cloudStatus.hasBackup && !hasLocal) {
        console.log("No vault found locally or in cloud. Run 'envsave init' first.");
      }
      break;
    }

    case "vercel": {

      // Check if project is linked to Vercel
      const vercelDir = join(process.cwd(), ".vercel");
      const vercelProjectJson = join(vercelDir, "project.json");
      if (!existsSync(vercelProjectJson)) {
        console.error("This project is not linked to Vercel.");
        console.error("Run 'vercel link' first to connect this directory to a Vercel project.");
        process.exit(1);
      }

      let projectName = "unknown";
      try {
        const proj = JSON.parse(readFileSync(vercelProjectJson, "utf8"));
        projectName = proj.projectId || "unknown";
      } catch {}

      const envArg = getFlag("--env");
      const environments = envArg ? envArg.split(",") : ["production", "preview", "development"];

      const keyArgs = args.slice(1).filter(a => !a.startsWith("--"));
      // Remove --env's value from keys list
      if (envArg) {
        const envIdx = keyArgs.indexOf(envArg);
        if (envIdx !== -1) keyArgs.splice(envIdx, 1);
      }

      if (keyArgs.length === 0) {
        console.error("Usage: envsave vercel <KEY|es_key> [KEY|es_key2]... [--env production,preview]");
        process.exit(1);
      }

      const password = await requirePassword();
      const keysToPush = keyArgs;

      const secrets = getDeploySecrets(keysToPush, password);
      const notFound = keysToPush.filter(k => !secrets.find(s => s.opaque === k || s.name === k));

      if (notFound.length > 0) {
        console.error(`Secrets not found: ${notFound.join(", ")}`);
        if (secrets.length === 0) process.exit(1);
      }

      console.log(`\nPushing ${secrets.length} secret(s) to Vercel (${environments.join(", ")})...\n`);

      let success = 0;
      let failed = 0;

      for (const secret of secrets) {
        for (const env of environments) {
          // Check if env var already exists — try to remove first, ignore errors
          spawnSync("vercel", ["env", "rm", secret.opaque, env, "-y"], {
            stdio: "ignore",
          });

          // Add the env var — pipe value via stdin to avoid shell escaping issues
          const proc = spawnSync("vercel", ["env", "add", secret.opaque, env], {
            input: Buffer.from(secret.value),
            stdio: ["pipe", "pipe", "pipe"],
          });

          if (proc.status === 0) {
            console.log(`  \x1b[32m✓\x1b[0m ${secret.name} → ${secret.opaque} [${env}]`);
            success++;
          } else {
            const errMsg = proc.stderr.toString().trim();
            console.error(`  \x1b[31m✗\x1b[0m ${secret.name} → ${secret.opaque} [${env}]: ${errMsg}`);
            failed++;
          }
        }
      }

      console.log(`\nDone: ${success} pushed, ${failed} failed.`);
      if (failed > 0) process.exit(1);
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      usage();
      process.exit(1);
  }

  // Alert about .env files in current directory (skip for 'get' to keep output clean)
  if (command !== "get") {
    checkEnvFiles();
  }
}

main().catch((err) => {
  if (err.message?.includes("unable to authenticate data") || err.message?.includes("Unsupported state")) {
    console.error("Incorrect password.");
  } else {
    console.error("Error:", err.message);
  }
  process.exit(1);
});
