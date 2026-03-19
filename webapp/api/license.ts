import db from "../db.ts";
import { createHmac, randomBytes } from "node:crypto";

const TOKEN_SECRET = process.env.ENVSAVE_TOKEN_SECRET || randomBytes(32).toString("hex");
const DEFAULT_EXPIRY_DAYS = 365;

interface User {
  id: number;
  email: string;
  token: string;
  created_at: string;
  expires_at: string | null;
}

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

/**
 * Generate a signed token: es_<base64url(email|createdEpoch|expiresEpoch|hmac)>
 * Dates are encoded as unix timestamps — opaque to the user but self-contained.
 */
function generateSignedToken(email: string, createdAt: Date, expiresAt: Date): string {
  const payload = `${email}|${Math.floor(createdAt.getTime() / 1000)}|${Math.floor(expiresAt.getTime() / 1000)}`;
  const sig = signPayload(payload);
  return "es_" + base64url(Buffer.from(`${payload}|${sig}`));
}

/**
 * Parse and verify a signed token. Returns null if invalid/tampered.
 */
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

// --- API handlers ---

export function handleRegister(body: { email?: string; expiryDays?: number }): Response {
  const { email, expiryDays } = body;

  if (!email || !email.includes("@")) {
    return Response.json({ error: "Valid email is required" }, { status: 400 });
  }

  // Check if email already exists
  const existing = db.query<User, [string]>("SELECT * FROM users WHERE email = ?").get(email);
  if (existing) {
    return Response.json({
      error: "Email already registered",
      token: existing.token,
    }, { status: 409 });
  }

  const now = new Date();
  const days = expiryDays ?? DEFAULT_EXPIRY_DAYS;
  const expires = new Date(now.getTime() + days * 86400000);
  const token = generateSignedToken(email, now, expires);

  db.run(
    "INSERT INTO users (email, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
    [email, token, now.toISOString(), expires.toISOString()],
  );

  return Response.json({ token, email, expiresAt: expires.toISOString() }, { status: 201 });
}

export function handleValidate(body: { token?: string }): Response {
  const { token } = body;

  if (!token) {
    return Response.json({ error: "Token is required" }, { status: 400 });
  }

  // First verify the token signature and extract embedded dates
  const parsed = parseSignedToken(token);
  if (!parsed) {
    return Response.json({ valid: false, error: "Invalid token" }, { status: 401 });
  }

  // Check expiry from the token itself (no DB needed for this check)
  if (parsed.expiresAt < new Date()) {
    return Response.json({ valid: false, error: "Token expired" }, { status: 403 });
  }

  // Verify token exists in DB (ensures it hasn't been revoked)
  const user = db.query<User, [string]>("SELECT * FROM users WHERE token = ?").get(token);
  if (!user) {
    return Response.json({ valid: false, error: "Token revoked or not found" }, { status: 404 });
  }

  return Response.json({
    valid: true,
    email: parsed.email,
    expiresAt: parsed.expiresAt.toISOString(),
    createdAt: parsed.createdAt.toISOString(),
  });
}

export function handleDashboard(body: { email?: string; token?: string }): Response {
  const { email, token } = body;

  if (!email || !token) {
    return Response.json({ error: "Email and token are required" }, { status: 400 });
  }

  const user = db.query<User, [string]>("SELECT * FROM users WHERE email = ?").get(email);

  if (!user || user.token !== token) {
    return Response.json({ error: "Invalid email or token" }, { status: 403 });
  }

  const parsed = parseSignedToken(token);

  return Response.json({
    email: user.email,
    token: user.token,
    createdAt: parsed?.createdAt.toISOString() ?? user.created_at,
    expiresAt: parsed?.expiresAt.toISOString() ?? user.expires_at,
  });
}

/**
 * Auto-renew an expired token. Accepts the old (expired) token,
 * verifies the user still exists in DB (subscription valid), and issues a new token.
 * Does NOT require the token to be non-expired — that's the whole point.
 */
export function handleRenew(body: { token?: string }): Response {
  const { token } = body;

  if (!token) {
    return Response.json({ error: "Token is required" }, { status: 400 });
  }

  // Parse token — we verify HMAC signature but allow expired tokens
  const parsed = parseSignedToken(token);
  if (!parsed) {
    return Response.json({ error: "Invalid token signature" }, { status: 401 });
  }

  // Find user by email — if user exists, their subscription is valid
  const user = db.query<User, [string]>("SELECT * FROM users WHERE email = ?").get(parsed.email);
  if (!user) {
    return Response.json({ error: "User not found or subscription cancelled" }, { status: 404 });
  }

  // Verify the token matches what's in DB (prevents use of old revoked tokens)
  if (user.token !== token) {
    return Response.json({ error: "Token has been revoked or already renewed" }, { status: 403 });
  }

  // Issue a new token with fresh expiry
  const now = new Date();
  const expires = new Date(now.getTime() + DEFAULT_EXPIRY_DAYS * 86400000);
  const newToken = generateSignedToken(parsed.email, now, expires);

  db.run(
    "UPDATE users SET token = ?, created_at = ?, expires_at = ? WHERE email = ?",
    [newToken, now.toISOString(), expires.toISOString(), parsed.email],
  );

  return Response.json({
    token: newToken,
    email: parsed.email,
    expiresAt: expires.toISOString(),
    renewed: true,
  });
}

export function handleRegenerate(body: { email?: string; token?: string; expiryDays?: number }): Response {
  const { email, token, expiryDays } = body;

  if (!email || !token) {
    return Response.json({ error: "Email and current token are required" }, { status: 400 });
  }

  const user = db.query<User, [string]>("SELECT * FROM users WHERE email = ?").get(email);

  if (!user || user.token !== token) {
    return Response.json({ error: "Invalid email or token" }, { status: 403 });
  }

  const now = new Date();
  const days = expiryDays ?? DEFAULT_EXPIRY_DAYS;
  const expires = new Date(now.getTime() + days * 86400000);
  const newToken = generateSignedToken(email, now, expires);

  db.run(
    "UPDATE users SET token = ?, created_at = ?, expires_at = ? WHERE email = ?",
    [newToken, now.toISOString(), expires.toISOString(), email],
  );

  return Response.json({ token: newToken, email, expiresAt: expires.toISOString() });
}
