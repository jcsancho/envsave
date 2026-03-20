import { createClerkClient, verifyToken } from "@clerk/backend";

const CLERK_SECRET_KEY = process.env.CLERK_SECRET_KEY!;
const CLERK_PUBLISHABLE_KEY = process.env.CLERK_PUBLISHABLE_KEY!;

if (!CLERK_SECRET_KEY || !CLERK_PUBLISHABLE_KEY) {
  console.error("Missing CLERK_SECRET_KEY or CLERK_PUBLISHABLE_KEY env vars");
  process.exit(1);
}

export const clerk = createClerkClient({ secretKey: CLERK_SECRET_KEY });

export { CLERK_PUBLISHABLE_KEY };

/**
 * Verify a Clerk session token from the Authorization header.
 * Returns the Clerk user ID if valid, null otherwise.
 */
export async function verifyClerkSession(req: Request): Promise<string | null> {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;

  const token = authHeader.slice(7);
  try {
    const payload = await verifyToken(token, {
      secretKey: CLERK_SECRET_KEY,
    });
    return payload.sub; // Clerk user ID
  } catch {
    return null;
  }
}

/**
 * Get the Clerk user's email from their user ID.
 */
export async function getClerkUserEmail(userId: string): Promise<string | null> {
  try {
    const user = await clerk.users.getUser(userId);
    return user.emailAddresses[0]?.emailAddress ?? null;
  } catch {
    return null;
  }
}
