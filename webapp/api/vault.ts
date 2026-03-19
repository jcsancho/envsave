import db from "../db.ts";
import { createHash } from "node:crypto";

interface User {
  id: number;
  email: string;
  token: string;
}

interface VaultBackup {
  id: number;
  user_id: number;
  vault_data: Buffer;
  size: number;
  checksum: string;
  created_at: string;
  updated_at: string;
}

const MAX_VAULT_SIZE = 1024 * 1024; // 1MB max

function authenticateToken(token: string | undefined): User | null {
  if (!token) return null;
  return db.query<User, [string]>("SELECT * FROM users WHERE token = ?").get(token) ?? null;
}

export async function handleVaultBackup(req: Request): Promise<Response> {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  const user = authenticateToken(token);
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

  const vaultData = Buffer.from(body);
  const checksum = createHash("sha256").update(vaultData).digest("hex");
  const now = new Date().toISOString();

  const existing = db.query<VaultBackup, [number]>(
    "SELECT id FROM vault_backups WHERE user_id = ?"
  ).get(user.id);

  if (existing) {
    db.run(
      "UPDATE vault_backups SET vault_data = ?, size = ?, checksum = ?, updated_at = ? WHERE user_id = ?",
      [vaultData, vaultData.byteLength, checksum, now, user.id]
    );
  } else {
    db.run(
      "INSERT INTO vault_backups (user_id, vault_data, size, checksum, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
      [user.id, vaultData, vaultData.byteLength, checksum, now, now]
    );
  }

  return Response.json({
    ok: true,
    size: vaultData.byteLength,
    checksum,
    updatedAt: now,
  });
}

export function handleVaultDownload(token: string | undefined): Response {
  const user = authenticateToken(token);
  if (!user) {
    return Response.json({ error: "Invalid or missing license token" }, { status: 401 });
  }

  const backup = db.query<VaultBackup, [number]>(
    "SELECT * FROM vault_backups WHERE user_id = ?"
  ).get(user.id);

  if (!backup) {
    return Response.json({ error: "No backup found" }, { status: 404 });
  }

  return new Response(backup.vault_data, {
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Checksum": backup.checksum,
      "X-Backup-Date": backup.updated_at,
      "X-Vault-Size": String(backup.size),
    },
  });
}

export function handleVaultStatus(token: string | undefined): Response {
  const user = authenticateToken(token);
  if (!user) {
    return Response.json({ error: "Invalid or missing license token" }, { status: 401 });
  }

  const backup = db.query<Pick<VaultBackup, "size" | "checksum" | "updated_at">, [number]>(
    "SELECT size, checksum, updated_at FROM vault_backups WHERE user_id = ?"
  ).get(user.id);

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
