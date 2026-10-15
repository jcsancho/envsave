#!/usr/bin/env node

import { createInterface } from "node:readline";
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import {
  initVault,
  setSecret,
  getSecret,
  getSecretFromCache,
  showSecret,
  deleteSecrets,
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
  renameSecret,
} from "./vault.ts";
import { activateLicense, checkLicense, getLicenseToken } from "./license.ts";
import { disableTouchId, enableTouchId, getPasswordWithTouchId, touchIdEnabled, touchIdSupported, updateTouchIdPassword } from "./touchid.ts";
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
  envsave set <key> [value]             Add/update a secret (omit value to be prompted — safe for !, $, spaces)
  envsave get <opaque_key>              Retrieve a value (no password needed)
  envsave show <key>                    Show real value by key name (password required)
  envsave reveal <keyword> [keyword2]... Show opaque key(s) for any name matching keyword (password required)
  envsave delete <name|pattern> [...]   Remove secrets; a partial name lists matches and asks to confirm (password required)
  envsave rename <old> <new>            Rename a secret (creates new opaque key, deletes old) (password required)
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
  envsave vercel <KEY|es_key>...        Push secrets to Vercel under both clean name + opaque id
  envsave install-skill [--agent <name>] [--local|--global]
                                        Install the EnvSave skill for an agent platform.
                                        Supported: claude (default). Coming soon: codex, others.
  envsave touchid [enable|disable|status]
                                        Unlock with Touch ID instead of typing the password (macOS)
  envsave update                        Update envsave to the latest version
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
    // Iterate per character: a paste arrives as a single chunk that may
    // include the trailing Enter.
    const onData = (chunk: Buffer) => {
      for (const c of chunk.toString()) {
        if (c === "\n" || c === "\r" || c === "\u0004") {
          if (stdin.isTTY && stdin.setRawMode) {
            stdin.setRawMode(wasRaw ?? false);
          }
          stdin.removeListener("data", onData);
          process.stderr.write("\n");
          rl.close();
          resolve(password);
          return;
        } else if (c === "\u0003") {
          process.exit(1);
        } else if (c === "\u007F" || c === "\b") {
          password = password.slice(0, -1);
        } else {
          password += c;
        }
      }
    };

    stdin.on("data", onData);
  });
}

async function requirePassword(): Promise<string> {
  // Touch ID first (if enabled); the dialog names the command so an
  // unexpected request from an agent is easy to spot and cancel.
  const fromTouchId = getPasswordWithTouchId(`run "envsave ${args.join(" ").slice(0, 80)}"`);
  if (fromTouchId) return fromTouchId;
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
    case "touchid": {
      const sub = args[1] ?? "status";
      if (!touchIdSupported()) {
        console.error("Touch ID unlock is only available on macOS.");
        process.exit(1);
      }
      if (sub === "status") {
        console.log(touchIdEnabled() ? "Touch ID unlock is enabled." : "Touch ID unlock is disabled. Run 'envsave touchid enable'.");
      } else if (sub === "enable") {
        const password = await promptPassword();
        try {
          listKeys(password);
        } catch {
          console.error("Incorrect password.");
          process.exit(1);
        }
        try {
          enableTouchId(password);
        } catch (e) {
          console.error((e as Error).message);
          process.exit(1);
        }
        console.log("Touch ID unlock enabled. Commands that need your password will ask for Touch ID instead.");
      } else if (sub === "disable") {
        disableTouchId();
        console.log("Touch ID unlock disabled. Your password was removed from the Keychain.");
      } else {
        console.error("Usage: envsave touchid [enable|disable|status]");
        process.exit(1);
      }
      break;
    }

    case "update": {
      const res = await fetch(`https://registry.npmjs.org/${pkg.name}/latest`).catch(() => null);
      if (!res?.ok) {
        console.error("Could not reach the npm registry to check for updates.");
        process.exit(1);
      }
      const latest = ((await res.json()) as { version: string }).version;
      if (latest === pkg.version) {
        console.log(`envsave ${pkg.version} is already the latest version.`);
        break;
      }
      console.log(`Updating envsave ${pkg.version} → ${latest}...`);

      // Update every global install so neither one shadows the other on PATH.
      const spec = `${pkg.name}@${latest}`;
      const installers: [string, string[]][] = [];
      const npmCheck = spawnSync("npm", ["ls", "-g", pkg.name], { stdio: "ignore", shell: process.platform === "win32" });
      if (npmCheck.status === 0) installers.push(["npm", ["install", "-g", "--prefer-online", spec]]);
      if (existsSync(join(homedir(), ".bun", "install", "global", "node_modules", pkg.name))) {
        installers.push(["bun", ["add", "-g", "--no-cache", spec]]);
      }
      if (installers.length === 0) {
        installers.push(process.argv[1]?.includes(".bun") ? ["bun", ["add", "-g", "--no-cache", spec]] : ["npm", ["install", "-g", "--prefer-online", spec]]);
      }

      let failed = false;
      for (const [cmd, cmdArgs] of installers) {
        console.log(`$ ${cmd} ${cmdArgs.join(" ")}`);
        const r = spawnSync(cmd, cmdArgs, { stdio: "inherit", shell: process.platform === "win32" });
        if (r.status !== 0) failed = true;
      }
      if (failed) {
        console.error("Update failed. Try running the command above manually.");
        process.exit(1);
      }
      console.log(`envsave updated to ${latest}.`);
      break;
    }

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
      let value = args[2];
      if (!key) {
        console.error("Usage: envsave set <key> [value]");
        process.exit(1);
      }
      // Omitting the value prompts for it (hidden input), so characters the
      // shell would mangle — like `!` (history expansion), `$`, or spaces —
      // are stored verbatim and the secret never lands in shell history.
      if (value === undefined) {
        value = await promptPassword(`Value for ${key}: `);
        if (!value) {
          console.error("Error: value cannot be empty.");
          process.exit(1);
        }
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
      const names = args.slice(1);
      if (names.length === 0) {
        console.error("Usage: envsave delete <name|pattern> [name2 ...]");
        process.exit(1);
      }
      const password = await requirePassword();
      const registry = listKeys(password);

      // Exact names are deleted directly; anything else is a case-insensitive
      // substring pattern whose matches are listed and need confirmation.
      const toDelete = new Set<string>();
      const matched = new Set<string>();
      const unmatched: string[] = [];
      for (const name of names) {
        if (registry.includes(name)) {
          toDelete.add(name);
          continue;
        }
        const lower = name.toLowerCase();
        const matches = registry.filter(k => k.toLowerCase().includes(lower));
        if (matches.length === 0) unmatched.push(name);
        for (const m of matches) matched.add(m);
      }

      for (const name of unmatched) console.error(`Secret '${name}' not found.`);

      const toConfirm = [...matched].filter(k => !toDelete.has(k));
      if (toConfirm.length > 0) {
        console.log(`Matching secrets (${toConfirm.length}):`);
        for (const k of toConfirm) console.log(`  ${k}`);
        const rl = createInterface({ input: process.stdin, output: process.stderr });
        const answer = await new Promise<string>((resolve) => {
          rl.question(`Delete ${toConfirm.length === 1 ? "it" : `all ${toConfirm.length}`}? (y/N) `, resolve);
        });
        rl.close();
        if (answer.trim().toLowerCase() === "y") {
          for (const k of toConfirm) toDelete.add(k);
        } else {
          console.log("Matching secrets not deleted.");
        }
      }

      if (toDelete.size > 0) {
        const { deleted } = deleteSecrets([...toDelete], password);
        for (const name of deleted) console.log(`Secret '${name}' deleted.`);
      }
      if (unmatched.length > 0) process.exit(1);
      break;
    }

    case "rename": {
      const oldName = args[1];
      const newName = args[2];
      if (!oldName || !newName) {
        console.error("Usage: envsave rename <old> <new>");
        process.exit(1);
      }
      const password = await requirePassword();
      const { oldOpaque, newOpaque } = renameSecret(oldName, newName, password);
      console.log(`\n  Renamed: ${oldName} → ${newName}`);
      console.log(`\n  Replace in your code:`);
      console.log(`    OLD (deleted):  ${oldOpaque}`);
      console.log(`    NEW (created):  ${newOpaque}`);
      console.log(`\n  Or replace the full call:`);
      console.log(`    envsave.get("${oldOpaque}")`);
      console.log(`    envsave.get("${newOpaque}")\n`);
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
      updateTouchIdPassword(newPassword);
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

      // Check if project is linked to Vercel.
      // Accept both link formats:
      //   - .vercel/project.json (legacy, single-project link)
      //   - .vercel/repo.json    (current, git-repo link with one or more projects)
      const vercelDir = join(process.cwd(), ".vercel");
      const vercelProjectJson = join(vercelDir, "project.json");
      const vercelRepoJson = join(vercelDir, "repo.json");
      if (!existsSync(vercelProjectJson) && !existsSync(vercelRepoJson)) {
        console.error("This project is not linked to Vercel.");
        console.error("Run 'vercel link' first to connect this directory to a Vercel project.");
        process.exit(1);
      }

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

      const pushVar = (varName: string, value: string, env: string): boolean => {
        spawnSync("vercel", ["env", "rm", varName, env, "-y"], {
          stdio: "ignore",
        });
        const proc = spawnSync("vercel", ["env", "add", varName, env], {
          input: Buffer.from(value),
          stdio: ["pipe", "pipe", "pipe"],
        });
        if (proc.status === 0) return true;
        const errMsg = proc.stderr.toString().trim();
        console.error(`  \x1b[31m✗\x1b[0m ${varName} [${env}]: ${errMsg}`);
        return false;
      };

      for (const secret of secrets) {
        // Always push under both the opaque id AND the clean name, so the same
        // secret works for build-time code (envsave.get("es_...")) and for
        // runtime serverless functions reading process.env.CLEAN_NAME.
        // If the key was added via opaque id only (no registry entry), name
        // falls back to opaque — skip the duplicate push in that case.
        const varNames = secret.name !== secret.opaque
          ? [secret.opaque, secret.name]
          : [secret.opaque];

        for (const env of environments) {
          for (const varName of varNames) {
            if (pushVar(varName, secret.value, env)) {
              console.log(`  \x1b[32m✓\x1b[0m ${varName} [${env}]`);
              success++;
            } else {
              failed++;
            }
          }
        }
      }

      console.log(`\nDone: ${success} pushed, ${failed} failed.`);
      if (failed > 0) process.exit(1);
      break;
    }

    case "install-skill": {
      const SUPPORTED_AGENTS = ["claude"] as const;
      type Agent = typeof SUPPORTED_AGENTS[number];

      const agent = (getFlag("--agent") ?? "claude").toLowerCase();
      if (!SUPPORTED_AGENTS.includes(agent as Agent)) {
        console.error(`Agent '${agent}' is not yet supported.`);
        console.error(`Supported today: ${SUPPORTED_AGENTS.join(", ")}. Coming soon: codex, others.`);
        process.exit(1);
      }

      // Resolve packaged SKILL.md. When run from the npm bundle it sits next to
      // dist/cli.js; when run from src/ during dev it lives under .claude/skills/.
      const cliDir = dirname(fileURLToPath(import.meta.url));
      const candidates = [
        join(cliDir, "SKILL.md"),                                    // dist/SKILL.md (shipped)
        join(cliDir, "..", ".claude", "skills", "envsave", "SKILL.md"), // dev (from src/)
      ];
      const skillSource = candidates.find(p => existsSync(p));
      if (!skillSource) {
        console.error("Skill source SKILL.md not found in the package.");
        process.exit(1);
      }

      let scope: "local" | "global" | undefined;
      if (args.includes("--local")) scope = "local";
      else if (args.includes("--global")) scope = "global";

      if (!scope) {
        const rl = createInterface({ input: process.stdin, output: process.stderr });
        const answer = await new Promise<string>((resolve) => {
          rl.question(
            `Install EnvSave skill for ${agent} — (l)ocally in this project or (g)lobally for your user? [l/g] `,
            resolve,
          );
        });
        rl.close();
        const a = answer.trim().toLowerCase();
        if (a === "l" || a === "local") scope = "local";
        else if (a === "g" || a === "global") scope = "global";
        else {
          console.error("Cancelled — answer must be 'l' or 'g'.");
          process.exit(1);
        }
      }

      // Per-agent install paths. Today only Claude is wired up.
      const agentDir: Record<Agent, string> = {
        claude: ".claude",
      };
      const subdir = agentDir[agent as Agent];
      const targetDir = scope === "local"
        ? join(process.cwd(), subdir, "skills", "envsave")
        : join(homedir(), subdir, "skills", "envsave");
      const targetFile = join(targetDir, "SKILL.md");

      if (existsSync(targetFile)) {
        const rl = createInterface({ input: process.stdin, output: process.stderr });
        const answer = await new Promise<string>((resolve) => {
          rl.question(`Skill already exists at ${targetFile}. Overwrite? (y/N) `, resolve);
        });
        rl.close();
        if (answer.trim().toLowerCase() !== "y") {
          console.log("Install cancelled.");
          break;
        }
      }

      mkdirSync(targetDir, { recursive: true });
      writeFileSync(targetFile, readFileSync(skillSource));
      console.log(`\n  ✓ Installed EnvSave skill for ${agent} (${scope})`);
      console.log(`    ${targetFile}\n`);
      console.log(`  Restart your agent (or open the project) and invoke /envsave to use it.\n`);
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
