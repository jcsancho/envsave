import { supabase } from "../supabase.ts";
import { createHash, createHmac, randomBytes } from "node:crypto";

const TOKEN_SECRET = process.env.ENVSAVE_TOKEN_SECRET || randomBytes(32).toString("hex");
const MAX_VAULT_SIZE = 1024 * 1024; // 1MB max
const DEFAULT_EXPIRY_DAYS = 365;

// --- Signed token helpers ---

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64url(s: string): Buffer {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

function signPayload(payload: string): string {
  return createHmac("sha256", TOKEN_SECRET).update(payload).digest("hex").slice(0, 16);
}

function generateSignedToken(email: string, createdAt: Date, expiresAt: Date): string {
  const payload = `${email}|${Math.floor(createdAt.getTime() / 1000)}|${Math.floor(expiresAt.getTime() / 1000)}`;
  const sig = signPayload(payload);
  return "es_" + base64url(Buffer.from(`${payload}|${sig}`));
}

function parseSignedToken(token: string): { email: string; createdAt: Date; expiresAt: Date } | null {
  if (!token.startsWith("es_")) return null;
  try {
    const raw = fromBase64url(token.slice(3)).toString("utf8");
    const parts = raw.split("|");
    if (parts.length !== 4) return null;
    const [email, createdStr, expiresStr, sig] = parts;
    const payload = `${email}|${createdStr}|${expiresStr}`;
    if (signPayload(payload) !== sig) return null;
    return {
      email,
      createdAt: new Date(Number(createdStr) * 1000),
      expiresAt: new Date(Number(expiresStr) * 1000),
    };
  } catch {
    return null;
  }
}

// --- Auth helper: validate Bearer token against Supabase ---

interface EnvsaveUser {
  id: string;
  clerk_id: string;
  email: string;
  token: string;
}

async function authenticateToken(token: string | undefined): Promise<EnvsaveUser | null> {
  if (!token) return null;
  const { data } = await supabase
    .from("users")
    .select("*")
    .eq("token", token)
    .single();
  return data ?? null;
}

// --- Vault backup/download/status (Supabase storage) ---

export async function handleVaultBackup(req: Request): Promise<Response> {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  const user = await authenticateToken(token);
  if (!user) {
    return Response.json({ error: "Invalid or missing license token" }, { status: 401 });
  }

  const body = await req.arrayBuffer();
  if (body.byteLength === 0) {
    return Response.json({ error: "Empty vault data" }, { status: 400 });
  }
  if (body.byteLength > MAX_VAULT_SIZE) {
    return Response.json({ error: "Vault too large (max 1MB)" }, { status: 413 });
  }

  const vaultBuffer = Buffer.from(body);
  const checksum = createHash("sha256").update(vaultBuffer).digest("hex");
  const now = new Date().toISOString();

  // Store vault as base64 in Supabase (JSONB-compatible)
  const vaultBase64 = vaultBuffer.toString("base64");

  const { data: existing } = await supabase
    .from("vault_backups")
    .select("id")
    .eq("user_id", user.id)
    .single();

  if (existing) {
    await supabase
      .from("vault_backups")
      .update({
        vault_data: vaultBase64,
        size: vaultBuffer.byteLength,
        checksum,
        updated_at: now,
      })
      .eq("user_id", user.id);
  } else {
    await supabase
      .from("vault_backups")
      .insert({
        user_id: user.id,
        vault_data: vaultBase64,
        size: vaultBuffer.byteLength,
        checksum,
        created_at: now,
        updated_at: now,
      });
  }

  return Response.json({
    ok: true,
    size: vaultBuffer.byteLength,
    checksum,
    updatedAt: now,
  });
}

export async function handleVaultDownload(token: string | undefined): Promise<Response> {
  const user = await authenticateToken(token);
  if (!user) {
    return Response.json({ error: "Invalid or missing license token" }, { status: 401 });
  }

  const { data: backup } = await supabase
    .from("vault_backups")
    .select("*")
    .eq("user_id", user.id)
    .single();

  if (!backup) {
    return Response.json({ error: "No backup found" }, { status: 404 });
  }

  const vaultBuffer = Buffer.from(backup.vault_data, "base64");

  return new Response(vaultBuffer, {
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Checksum": backup.checksum,
      "X-Backup-Date": backup.updated_at,
      "X-Vault-Size": String(backup.size),
    },
  });
}

export async function handleVaultStatus(token: string | undefined): Promise<Response> {
  const user = await authenticateToken(token);
  if (!user) {
    return Response.json({ error: "Invalid or missing license token" }, { status: 401 });
  }

  const { data: backup } = await supabase
    .from("vault_backups")
    .select("size, checksum, updated_at")
    .eq("user_id", user.id)
    .single();

  if (!backup) {
    return Response.json({ hasBackup: false });
  }

  return Response.json({
    hasBackup: true,
    size: backup.size,
    checksum: backup.checksum,
    updatedAt: backup.updated_at,
  });
}

// --- License management (Clerk-backed) ---

/**
 * Called after Clerk auth — creates or returns user's envsave token.
 * The Clerk session token is verified server-side before calling this.
 */
export async function handleProvisionToken(clerkId: string, email: string): Promise<Response> {
  // Check if user already has a token
  const { data: existing } = await supabase
    .from("users")
    .select("*")
    .eq("clerk_id", clerkId)
    .single();

  if (existing) {
    const parsed = parseSignedToken(existing.token);
    return Response.json({
      token: existing.token,
      email: existing.email,
      createdAt: parsed?.createdAt.toISOString() ?? existing.created_at,
      expiresAt: parsed?.expiresAt.toISOString() ?? existing.expires_at,
    });
  }

  // Create new token
  const now = new Date();
  const expires = new Date(now.getTime() + DEFAULT_EXPIRY_DAYS * 86400000);
  const token = generateSignedToken(email, now, expires);

  await supabase.from("users").insert({
    clerk_id: clerkId,
    email,
    token,
    created_at: now.toISOString(),
    expires_at: expires.toISOString(),
  });

  return Response.json({
    token,
    email,
    createdAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    isNew: true,
  }, { status: 201 });
}

/**
 * Regenerate the user's envsave token (requires Clerk auth).
 */
export async function handleRegenerateToken(clerkId: string, email: string): Promise<Response> {
  const now = new Date();
  const expires = new Date(now.getTime() + DEFAULT_EXPIRY_DAYS * 86400000);
  const newToken = generateSignedToken(email, now, expires);

  const { data, error } = await supabase
    .from("users")
    .update({
      token: newToken,
      created_at: now.toISOString(),
      expires_at: expires.toISOString(),
    })
    .eq("clerk_id", clerkId)
    .select()
    .single();

  if (error || !data) {
    return Response.json({ error: "User not found" }, { status: 404 });
  }

  return Response.json({
    token: newToken,
    email,
    expiresAt: expires.toISOString(),
    regenerated: true,
  });
}

/**
 * Auto-renew an expired CLI token (called from CLI, not browser).
 * Uses the old token to authenticate + find the user.
 */
export async function handleRenewToken(body: { token?: string }): Promise<Response> {
  const { token } = body;
  if (!token) {
    return Response.json({ error: "Token is required" }, { status: 400 });
  }

  const parsed = parseSignedToken(token);
  if (!parsed) {
    return Response.json({ error: "Invalid token signature" }, { status: 401 });
  }

  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("email", parsed.email)
    .single();

  if (!user) {
    return Response.json({ error: "User not found" }, { status: 404 });
  }

  if (user.token !== token) {
    return Response.json({ error: "Token revoked or already renewed" }, { status: 403 });
  }

  const now = new Date();
  const expires = new Date(now.getTime() + DEFAULT_EXPIRY_DAYS * 86400000);
  const newToken = generateSignedToken(parsed.email, now, expires);

  await supabase
    .from("users")
    .update({
      token: newToken,
      created_at: now.toISOString(),
      expires_at: expires.toISOString(),
    })
    .eq("clerk_id", user.clerk_id);

  return Response.json({
    token: newToken,
    email: parsed.email,
    expiresAt: expires.toISOString(),
    renewed: true,
  });
}

/**
 * Validate a CLI token (called from CLI).
 */
export async function handleValidateToken(body: { token?: string }): Promise<Response> {
  const { token } = body;
  if (!token) {
    return Response.json({ error: "Token is required" }, { status: 400 });
  }

  const parsed = parseSignedToken(token);
  if (!parsed) {
    return Response.json({ valid: false, error: "Invalid token" }, { status: 401 });
  }

  if (parsed.expiresAt < new Date()) {
    return Response.json({ valid: false, error: "Token expired" }, { status: 403 });
  }

  const { data: user } = await supabase
    .from("users")
    .select("id")
    .eq("token", token)
    .single();

  if (!user) {
    return Response.json({ valid: false, error: "Token revoked" }, { status: 404 });
  }

  return Response.json({
    valid: true,
    email: parsed.email,
    expiresAt: parsed.expiresAt.toISOString(),
    createdAt: parsed.createdAt.toISOString(),
  });
}
