import { verifyClerkSession, getClerkUserEmail, CLERK_PUBLISHABLE_KEY } from "./auth.ts";
import {
  handleVaultBackup,
  handleVaultDownload,
  handleVaultStatus,
  handleProvisionToken,
  handleRegenerateToken,
  handleRenewToken,
  handleValidateToken,
} from "./api/vault.ts";

const PORT = Number(process.env.ENVSAVE_PORT) || 3900;

async function parseJson(req: Request): Promise<Record<string, unknown>> {
  try {
    return (await req.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

// Inject Clerk publishable key into HTML pages
function injectClerkKey(html: string): string {
  return html.replace("__CLERK_PUBLISHABLE_KEY__", CLERK_PUBLISHABLE_KEY);
}

// Read HTML files
const indexHtml = await Bun.file(import.meta.dir + "/pages/index.html").text();
const dashboardHtml = await Bun.file(import.meta.dir + "/pages/dashboard.html").text();
const docsHtml = await Bun.file(import.meta.dir + "/pages/docs.html").text();

Bun.serve({
  port: PORT,
  routes: {
    // Pages
    "/": () => new Response(injectClerkKey(indexHtml), {
      headers: { "Content-Type": "text/html" },
    }),
    "/docs": () => new Response(docsHtml, {
      headers: { "Content-Type": "text/html" },
    }),
    "/dashboard": () => new Response(injectClerkKey(dashboardHtml), {
      headers: { "Content-Type": "text/html" },
    }),

    // Clerk-authenticated API: provision/regenerate token
    "/api/token/provision": {
      POST: async (req) => {
        const clerkId = await verifyClerkSession(req);
        if (!clerkId) {
          return Response.json({ error: "Unauthorized" }, { status: 401 });
        }
        const email = await getClerkUserEmail(clerkId);
        if (!email) {
          return Response.json({ error: "Could not resolve email" }, { status: 400 });
        }
        return handleProvisionToken(clerkId, email);
      },
    },
    "/api/token/regenerate": {
      POST: async (req) => {
        const clerkId = await verifyClerkSession(req);
        if (!clerkId) {
          return Response.json({ error: "Unauthorized" }, { status: 401 });
        }
        const email = await getClerkUserEmail(clerkId);
        if (!email) {
          return Response.json({ error: "Could not resolve email" }, { status: 400 });
        }
        return handleRegenerateToken(clerkId, email);
      },
    },

    // CLI-facing APIs (Bearer token auth)
    "/api/license/validate": {
      POST: async (req) => {
        const body = await parseJson(req);
        return handleValidateToken(body as { token?: string });
      },
    },
    "/api/license/renew": {
      POST: async (req) => {
        const body = await parseJson(req);
        return handleRenewToken(body as { token?: string });
      },
    },
    "/api/vault/backup": {
      POST: async (req) => handleVaultBackup(req),
    },
    "/api/vault/download": {
      POST: (req) => {
        const token = req.headers.get("authorization")?.replace("Bearer ", "");
        return handleVaultDownload(token);
      },
    },
    "/api/vault/status": {
      POST: (req) => {
        const token = req.headers.get("authorization")?.replace("Bearer ", "");
        return handleVaultStatus(token);
      },
    },
  },
});

console.log(`EnvSave running on http://localhost:${PORT}`);
