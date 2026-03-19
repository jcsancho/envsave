import { handleRegister, handleValidate, handleDashboard, handleRegenerate, handleRenew } from "./api/license.ts";
import { handleVaultBackup, handleVaultDownload, handleVaultStatus } from "./api/vault.ts";
import indexPage from "./pages/index.html";
import signupPage from "./pages/signup.html";
import dashboardPage from "./pages/dashboard.html";

const PORT = Number(process.env.ENVSAVE_PORT) || 3900;

async function parseJson(req: Request): Promise<Record<string, unknown>> {
  try {
    return await req.json() as Record<string, unknown>;
  } catch {
    return {};
  }
}

Bun.serve({
  port: PORT,
  routes: {
    "/": indexPage,
    "/signup": signupPage,
    "/dashboard": dashboardPage,

    "/api/license/register": {
      POST: async (req) => {
        const body = await parseJson(req);
        return handleRegister(body as { email?: string });
      },
    },
    "/api/license/validate": {
      POST: async (req) => {
        const body = await parseJson(req);
        return handleValidate(body as { token?: string });
      },
    },
    "/api/license/dashboard": {
      POST: async (req) => {
        const body = await parseJson(req);
        return handleDashboard(body as { email?: string });
      },
    },
    "/api/license/regenerate": {
      POST: async (req) => {
        const body = await parseJson(req);
        return handleRegenerate(body as { email?: string });
      },
    },
    "/api/license/renew": {
      POST: async (req) => {
        const body = await parseJson(req);
        return handleRenew(body as { token?: string });
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

console.log(`EnvSave License Server running on http://localhost:${PORT}`);
