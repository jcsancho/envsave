import db from "../db.ts";
import { randomUUID } from "node:crypto";

interface User {
  id: number;
  email: string;
  token: string;
  created_at: string;
  expires_at: string | null;
}

export function handleRegister(body: { email?: string }): Response {
  const { email } = body;

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

  const token = randomUUID();
  db.run("INSERT INTO users (email, token) VALUES (?, ?)", [email, token]);

  return Response.json({ token, email }, { status: 201 });
}

export function handleValidate(body: { token?: string }): Response {
  const { token } = body;

  if (!token) {
    return Response.json({ error: "Token is required" }, { status: 400 });
  }

  const user = db.query<User, [string]>("SELECT * FROM users WHERE token = ?").get(token);

  if (!user) {
    return Response.json({ valid: false, error: "Invalid token" }, { status: 404 });
  }

  // Check expiry
  if (user.expires_at && new Date(user.expires_at) < new Date()) {
    return Response.json({ valid: false, error: "Token expired" }, { status: 403 });
  }

  return Response.json({
    valid: true,
    email: user.email,
    expiresAt: user.expires_at,
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

  return Response.json({
    email: user.email,
    token: user.token,
    createdAt: user.created_at,
    expiresAt: user.expires_at,
  });
}

export function handleRegenerate(body: { email?: string; token?: string }): Response {
  const { email, token } = body;

  if (!email || !token) {
    return Response.json({ error: "Email and current token are required" }, { status: 400 });
  }

  const user = db.query<User, [string]>("SELECT * FROM users WHERE email = ?").get(email);

  if (!user || user.token !== token) {
    return Response.json({ error: "Invalid email or token" }, { status: 403 });
  }

  const newToken = randomUUID();
  db.run("UPDATE users SET token = ? WHERE email = ?", [newToken, email]);

  return Response.json({ token: newToken, email });
}
