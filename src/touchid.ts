// Touch ID unlock (macOS). The master password lives in the login Keychain,
// readable only by a small Swift helper that first asks for Touch ID (or the
// Mac login password). Agents can't approve the prompt, so the password still
// gates reads — the user just stops typing it.
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

function getEnvsaveDir(): string {
  return process.env.ENVSAVE_DIR || join(homedir(), ".envsave");
}
function getHelperPath(): string { return join(getEnvsaveDir(), "bin", "envsave-touchid"); }
function getMarkerFile(): string { return join(getEnvsaveDir(), "touchid"); }
// One Keychain entry per vault directory.
function getAccount(): string { return getEnvsaveDir(); }

function findHelperSource(): string | undefined {
  const here = dirname(fileURLToPath(import.meta.url));
  // dist/cli.js and src/cli.ts both sit one level below native/
  const candidate = join(here, "..", "native", "touchid.swift");
  return existsSync(candidate) ? candidate : undefined;
}

export function touchIdSupported(): boolean {
  return process.platform === "darwin";
}

/** Compile the helper if missing or if its source changed (e.g. after an update). */
export function ensureHelper(): void {
  const source = findHelperSource();
  if (!source) throw new Error("Touch ID helper source not found in the envsave package.");
  const helper = getHelperPath();
  const hashFile = `${helper}.sha256`;
  const hash = createHash("sha256").update(readFileSync(source)).digest("hex");
  if (existsSync(helper) && existsSync(hashFile) && readFileSync(hashFile, "utf8").trim() === hash) return;

  mkdirSync(dirname(helper), { recursive: true, mode: 0o700 });
  const r = spawnSync("swiftc", ["-O", source, "-o", helper], { stdio: ["ignore", "ignore", "pipe"], cwd: dirname(helper) });
  if (r.error || r.status !== 0) {
    throw new Error(
      "Could not compile the Touch ID helper. Install the Xcode command line tools with 'xcode-select --install'.\n" +
        (r.stderr?.toString() ?? ""),
    );
  }
  writeFileSync(hashFile, hash, { mode: 0o600 });
}

export function touchIdEnabled(): boolean {
  return touchIdSupported() && existsSync(getMarkerFile()) && existsSync(getHelperPath());
}

export function enableTouchId(password: string): void {
  ensureHelper();
  const r = spawnSync(getHelperPath(), ["store", getAccount()], { input: password, stdio: ["pipe", "ignore", "pipe"] });
  if (r.status !== 0) throw new Error(`Could not save the password to the Keychain. ${r.stderr?.toString() ?? ""}`);
  writeFileSync(getMarkerFile(), "enabled\n", { mode: 0o600 });
}

export function disableTouchId(): void {
  if (existsSync(getHelperPath())) spawnSync(getHelperPath(), ["delete", getAccount()], { stdio: "ignore" });
  if (existsSync(getMarkerFile())) unlinkSync(getMarkerFile());
}

/** Update the stored password after `envsave passwd`. No-op if Touch ID is off. */
export function updateTouchIdPassword(password: string): void {
  if (touchIdEnabled()) enableTouchId(password);
}

/**
 * Ask for Touch ID and return the stored password, or undefined if Touch ID is
 * off, cancelled, unavailable (e.g. over SSH), or nothing is stored.
 */
export function getPasswordWithTouchId(reason: string): string | undefined {
  if (!touchIdEnabled()) return undefined;
  try {
    ensureHelper();
  } catch {
    return undefined;
  }
  const r = spawnSync(getHelperPath(), ["get", getAccount(), reason], { stdio: ["ignore", "pipe", "ignore"] });
  if (r.status !== 0) return undefined;
  const password = r.stdout.toString();
  return password || undefined;
}
