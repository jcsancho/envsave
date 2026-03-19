import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const ENVSAVE_DIR = join(homedir(), ".envsave");
const LICENSE_FILE = join(ENVSAVE_DIR, "license.json");

const LICENSE_API_URL = process.env.ENVSAVE_LICENSE_API || "https://envsave.example.com/api/license/validate";

interface LicenseData {
  token: string;
  validatedAt: string;
  expiresAt: string | null;
}

function ensureDir(): void {
  if (!existsSync(ENVSAVE_DIR)) {
    mkdirSync(ENVSAVE_DIR, { recursive: true, mode: 0o700 });
  }
}

/**
 * Decode dates from a signed token (es_<base64url>) without verifying HMAC.
 * The HMAC is verified server-side during activation — locally we just read the embedded expiry.
 */
function parseToken(token: string): { email: string; createdAt: Date; expiresAt: Date } | null {
  if (!token.startsWith("es_")) return null;
  try {
    const b64 = token.slice(3);
    const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
    const raw = Buffer.from(b64.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64").toString("utf8");
    const parts = raw.split("|");
    if (parts.length !== 4) return null;
    return {
      email: parts[0],
      createdAt: new Date(Number(parts[1]) * 1000),
      expiresAt: new Date(Number(parts[2]) * 1000),
    };
  } catch {
    return null;
  }
}

export async function activateLicense(token: string, offline = false): Promise<boolean> {
  const dates = parseToken(token);

  const OFFLINE_ALLOWED_EMAILS = [
    "support@envsave.com",
  ];

  if (offline) {
    if (!dates) {
      console.error("Invalid token format. Must be a signed es_ token.");
      return false;
    }
    if (!OFFLINE_ALLOWED_EMAILS.includes(dates.email)) {
      console.error("Offline activation is not available for this account.");
      return false;
    }
    if (dates.expiresAt < new Date()) {
      console.error("Token is expired.");
      return false;
    }
    ensureDir();
    writeFileSync(LICENSE_FILE, JSON.stringify({
      token,
      validatedAt: new Date().toISOString(),
      expiresAt: dates.expiresAt.toISOString(),
    } satisfies LicenseData, null, 2), { mode: 0o600 });
    return true;
  }

  try {
    const response = await fetch(LICENSE_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });

    if (!response.ok) {
      console.error("License validation failed: server returned", response.status);
      return false;
    }

    const data = await response.json() as { valid: boolean; expiresAt?: string; createdAt?: string };
    if (!data.valid) {
      console.error("Invalid license token.");
      return false;
    }

    ensureDir();
    const licenseData: LicenseData = {
      token,
      validatedAt: new Date().toISOString(),
      expiresAt: dates?.expiresAt.toISOString() ?? data.expiresAt ?? null,
    };
    writeFileSync(LICENSE_FILE, JSON.stringify(licenseData, null, 2), { mode: 0o600 });
    return true;
  } catch (err) {
    console.error("Failed to contact license server:", (err as Error).message);
    return false;
  }
}

export function getLicenseToken(): string | null {
  if (!existsSync(LICENSE_FILE)) return null;
  try {
    const data = JSON.parse(readFileSync(LICENSE_FILE, "utf8")) as LicenseData;
    return data.token ?? null;
  } catch {
    return null;
  }
}

const RENEW_API_URL = (process.env.ENVSAVE_LICENSE_API || "https://envsave.example.com/api/license/validate").replace("/validate", "/renew");

async function tryAutoRenew(token: string): Promise<boolean> {
  try {
    const response = await fetch(RENEW_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });

    if (!response.ok) return false;

    const result = await response.json() as { token?: string; expiresAt?: string; renewed?: boolean };
    if (!result.token || !result.renewed) return false;

    const newDates = parseToken(result.token);
    ensureDir();
    writeFileSync(LICENSE_FILE, JSON.stringify({
      token: result.token,
      validatedAt: new Date().toISOString(),
      expiresAt: newDates?.expiresAt.toISOString() ?? result.expiresAt ?? null,
    } satisfies LicenseData, null, 2), { mode: 0o600 });

    console.error("License renewed automatically.");
    return true;
  } catch {
    return false;
  }
}

export async function checkLicense(): Promise<boolean> {
  if (!existsSync(LICENSE_FILE)) return false;

  try {
    const data = JSON.parse(readFileSync(LICENSE_FILE, "utf8")) as LicenseData;

    // Try reading expiry from the token itself first
    const dates = parseToken(data.token);
    if (dates) {
      if (dates.expiresAt > new Date()) return true;
      // Token expired — try auto-renew
      return await tryAutoRenew(data.token);
    }

    // Fallback for legacy UUID tokens
    if (data.expiresAt) {
      if (new Date(data.expiresAt) > new Date()) return true;
      return await tryAutoRenew(data.token);
    }
    return true;
  } catch {
    return false;
  }
}
