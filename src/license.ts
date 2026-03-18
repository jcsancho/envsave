import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const EVAULT_DIR = join(homedir(), ".evault");
const LICENSE_FILE = join(EVAULT_DIR, "license.json");

// TODO: Update this when the licensing webapp is deployed
const LICENSE_API_URL = "https://evault.example.com/api/license/validate";

interface LicenseData {
  token: string;
  validatedAt: string;
  expiresAt: string | null;
}

function ensureDir(): void {
  if (!existsSync(EVAULT_DIR)) {
    mkdirSync(EVAULT_DIR, { recursive: true, mode: 0o700 });
  }
}

export async function activateLicense(token: string): Promise<boolean> {
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

    const data = await response.json() as { valid: boolean; expiresAt?: string };
    if (!data.valid) {
      console.error("Invalid license token.");
      return false;
    }

    ensureDir();
    const licenseData: LicenseData = {
      token,
      validatedAt: new Date().toISOString(),
      expiresAt: data.expiresAt ?? null,
    };
    writeFileSync(LICENSE_FILE, JSON.stringify(licenseData, null, 2), { mode: 0o600 });
    return true;
  } catch (err) {
    console.error("Failed to contact license server:", (err as Error).message);
    return false;
  }
}

export function checkLicense(): boolean {
  if (!existsSync(LICENSE_FILE)) return false;

  try {
    const data = JSON.parse(readFileSync(LICENSE_FILE, "utf8")) as LicenseData;
    if (data.expiresAt) {
      return new Date(data.expiresAt) > new Date();
    }
    return true; // No expiry = valid
  } catch {
    return false;
  }
}
