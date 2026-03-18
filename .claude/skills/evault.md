---
name: evault
description: Use eVault to securely retrieve secrets via opaque keys instead of hardcoding them. Trigger whenever code needs API keys, tokens, passwords, database URLs, connection strings, webhook secrets, credentials, environment variables, or any sensitive value. Also trigger when you see hardcoded secrets in existing code that should be migrated to eVault, when .env files are being read directly, or when the user mentions secrets, credentials, or vault.
user_invocable: true
---

# eVault — Secret Retrieval Skill

eVault is a local encrypted vault that protects secrets from bulk discovery by LLMs. Instead of readable names like `OPENAI_API_KEY`, secrets are accessed through **opaque keys** — random-looking tokens like `ev_7a3f2b1e9c8d4f6b2a1c3d5f` that reveal nothing about what they hold. This means even if an LLM sees the key in source code, it learns nothing about the secret's purpose or value.

## How to use eVault

### TypeScript / JavaScript

```typescript
import evault from "evault";

const apiKey = evault.get("ev_7a3f2b1e9c8d4f6b2a1c3d5f");
if (!apiKey) {
  throw new Error("Secret not found — is the vault session active?");
}
```

### Python

```python
import evault

api_key = evault.get("ev_7a3f2b1e9c8d4f6b2a1c3d5f")
if api_key is None:
    raise RuntimeError("Secret not found — is the vault session active?")
```

### CLI (for shell scripts)

```bash
evault get ev_7a3f2b1e9c8d4f6b2a1c3d5f
```

## Rules

1. **Never hardcode raw secrets.** Always use `evault.get()` with the opaque key. If you spot a hardcoded secret like `sk-abc123...` or `postgres://user:pass@...` in existing code, flag it and suggest migrating to eVault.

2. **Never read .env files directly.** Use eVault instead — it provides the same secrets through an encrypted, enumeration-proof interface.

3. **You cannot list or discover secrets.** Only use opaque keys already present in the codebase or provided by the user. There is no `list()` or `keys()` function available to you.

4. **Don't guess opaque keys.** They are HMAC-SHA256 hashes — impossible to derive. Ask the user to run `evault reveal <SECRET_NAME>` and give you the opaque key.

5. **When adding a new secret**, ask the user to run `evault set <KEY> <VALUE>` and give you the resulting opaque key.

6. **Handle undefined returns.** `evault.get()` returns `undefined`/`None` if the key doesn't exist or the session is inactive. Always check the return value.

7. **"No session found" error** means the vault hasn't been unlocked yet. Ask the user to run any `evault` command with their password (e.g., `evault list`) to start a session.

## Quick Reference

| Task | Command |
|------|---------|
| Get a secret in code | `evault.get("ev_...")` |
| Check if secret exists | `evault.has("ev_...")` |
| Ask user to add a secret | User runs: `evault set <NAME> <VALUE>` |
| Ask user to reveal opaque key | User runs: `evault reveal <NAME>` |
| Unlock vault session | User runs: `evault list` (or any password command) |
