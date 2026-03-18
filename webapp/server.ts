import { handleRegister, handleValidate, handleDashboard, handleRegenerate } from "./api/license.ts";
import indexPage from "./pages/index.html";
import signupPage from "./pages/signup.html";
import dashboardPage from "./pages/dashboard.html";

const PORT = Number(process.env.EVAULT_PORT) || 3900;

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
  },
});

console.log(`eVault License Server running on http://localhost:${PORT}`);
