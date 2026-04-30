---
name: envsave
description: Use EnvSave to securely retrieve secrets via opaque keys instead of hardcoding them. Trigger whenever code needs API keys, tokens, passwords, database URLs, connection strings, webhook secrets, credentials, environment variables, or any sensitive value. Also trigger when you see hardcoded secrets in existing code that should be migrated to EnvSave, when .env files are being read directly, or when the user mentions secrets, credentials, or vault.
user_invocable: true
---

# EnvSave Migration & Usage Skill

When this skill is triggered, follow the instructions below. Everything you need to know is in this file. Do not research, explore, or investigate envsave — just execute the steps.

## Installation

EnvSave is installed from **npm** (not from a local path on the user's machine). The npm package is scoped: `@envsave/cli`.

```bash
# Global CLI (the `envsave` binary)
npm install -g @envsave/cli

# As a library in a project
npm install @envsave/cli
# or: bun add @envsave/cli

# Python
pip install envsave
```

If the user's project doesn't yet depend on envsave, add `@envsave/cli` to their dependencies before emitting `import` statements. Never tell the user to link from a local checkout — always use the npm package.

**Installing this skill in your agent:**

```bash
envsave install-skill              # interactive — asks local or global
envsave install-skill --local      # → ./.claude/skills/envsave/SKILL.md (this project only)
envsave install-skill --global     # → ~/.claude/skills/envsave/SKILL.md (all your projects)
envsave install-skill --agent claude --global   # explicit agent
```

`--agent` defaults to `claude`. Codex and other agentic platforms are planned but not yet supported.

**Upgrading from the old unscoped package:** if `npm install -g @envsave/cli` fails with `EEXIST` on `bin/envsave`, the user has the old unscoped `envsave` package installed globally (pre-rename). Fix it with:

```bash
npm uninstall -g envsave
npm install -g @envsave/cli
```

## If user asks to migrate / invokes `/envsave`:

Execute these steps in order. Start with Step 1 immediately.

### Step 1 — Grep the project NOW

Use the Grep tool (not Bash, not Agent, not Explore) to search the current project directory. Run ALL of these searches in parallel in a single response:

- `process\.env` in `*.{ts,js,tsx,jsx,mjs,cjs}`
- `os\.environ|os\.getenv|environ\.get` in `*.py`
- `dotenv|load_dotenv|from dotenv|python-dotenv` in all source files
- `sk-[a-zA-Z0-9]{20,}|pk_[a-zA-Z0-9]{20,}|ghp_|gho_|xoxb-|xoxp-|postgres://|mongodb://|redis://|mysql://|amqp://` in all files
- `readFileSync.*\.env|Bun\.file.*\.env|open.*\.env` in all files
- Glob for `.env*` files in project root

Skip `node_modules/`, `.git/`, `dist/`, `build/`, `__pycache__/`, `.venv/`, `bun.lockb`.

### Step 2 — Show findings table

| File:Line | Env Var | Current Code | Replacement |
|-----------|---------|-------------|-------------|
| src/api.ts:12 | OPENAI_API_KEY | `process.env.OPENAI_API_KEY` | `envsave.get("es_???")` |
| lib/db.py:5 | DATABASE_URL | `os.getenv("DATABASE_URL")` | `envsave.get("es_???")` |

Also list `dotenv`/`load_dotenv` imports to remove and `.env` files found.

### Step 3 — Summary + copy-paste command

List unique env var names, then output ONE single `envsave reveal` command with all keys (supports multiple args, one password prompt).

**IMPORTANT: The command MUST be on a single line with no line breaks.** If the list of keys is long, still keep it on one line. Never wrap or split the command across multiple lines — line breaks will break copy-paste in the terminal.

```
## Env Vars to Migrate

| # | Env Var Name | Files |
|---|-------------|-------|
| 1 | OPENAI_API_KEY | 3 |
| 2 | DATABASE_URL | 1 |

## Run this to get all opaque keys (single password prompt):

envsave reveal OPENAI_API_KEY DATABASE_URL
```

Tell user: run the command, paste back the output, and I'll do all code replacements.

### Step 4 — Replace code (only after user provides keys)

Wait for opaque keys. Then:
1. Replace `process.env.XXX` / `os.getenv("XXX")` with `envsave.get("es_actual_key")`
2. Add `import envsave from "@envsave/cli"` (TS/JS) or `import envsave` (Python) if missing
3. Remove `dotenv`/`load_dotenv` imports and `.config()` calls
4. List all `.env*` files found (`.env`, `.env.local`, `.env.production`, etc.) and **tell the user they must delete them** — these files contain real secrets in plain text and are no longer needed after migration to envsave. Add them to `.gitignore` if not already there.

**IMPORTANT: Always use `envsave.get("es_...")` directly — the full module call. Never create wrapper functions like `envsave_get()`, `get_secret()`, `_get_env()`, or similar. The call should always be `envsave.get("es_...")` exactly.**

---

## If user needs a secret in new code:

Use `envsave.get("es_???")` as placeholder and ask user to provide the opaque key.

**TypeScript/JavaScript:**
```typescript
import envsave from "@envsave/cli";
const apiKey = envsave.get("es_7a3f2b1e9c8d4f6b2a1c3d5f");
```

**Python:**
```python
import envsave
api_key = envsave.get("es_7a3f2b1e9c8d4f6b2a1c3d5f")
```

**Shell:**
```bash
envsave get es_7a3f2b1e9c8d4f6b2a1c3d5f
```

## Vercel / Cloud Deployment

On Vercel there is no envsave vault. When `envsave.get("es_xxx")` can't find the vault, it falls back to `process.env["es_xxx"]`. So you need to set Vercel env vars where:

- **Name** = the opaque key (e.g. `es_7a3f2b1e9c8d4f6b`)
- **Value** = the real secret (e.g. `sk-proj-abc123...`)

This way the code `envsave.get("es_7a3f2b1e9c8d4f6b")` resolves via `process.env.es_7a3f2b1e9c8d4f6b` on Vercel, returning the real API key — without any vault needed.

**To push secrets to Vercel**, use the built-in `envsave vercel` command. The project must be linked to Vercel first (`vercel link`).

```bash
# Push specific secrets
envsave vercel OPENAI_API_KEY STRIPE_KEY

# Target specific environments (default: production,preview,development)
envsave vercel OPENAI_API_KEY --env production,preview
```

The command automatically:
- Checks the project is linked to Vercel (`.vercel/project.json`)
- Resolves each clean key name to its opaque key
- Sets the opaque key as the Vercel env var name, real secret as the value
- Removes existing vars before adding (handles updates)
- Pipes values via stdin — no shell escaping issues, no trailing newlines

**CRITICAL: Never write real secret values to any local file.** No `.env.local`, no `.env.production`, no temp files.

---

## Rules

1. Never hardcode raw secrets. Use `envsave.get()` with opaque key.
2. Never read .env files directly. Use EnvSave instead.
3. You cannot list or discover secrets. Ask the user for opaque keys.
4. Don't guess opaque keys. Ask user to run `envsave reveal <NAME>`.
5. Handle undefined returns — `envsave.get()` returns `undefined`/`None` if key doesn't exist.
6. **Never write real secret values to any local file** (no `.env.local`, `.env.production`, etc.). For cloud deployments (Vercel, etc.), pipe from `envsave get` directly to the platform CLI.

## Quick Reference

| Task | User Command |
|------|-------------|
| Add a secret | `envsave set <NAME> <VALUE>` |
| Get opaque key | `envsave reveal <NAME>` |
| Rename a secret | `envsave rename <OLD_NAME> <NEW_NAME>` (creates new opaque key, deletes old — output prints OLD → NEW for code search-and-replace) |
| Unlock vault | `envsave list` |
| Push to Vercel | `envsave vercel KEY1 KEY2` |
| Install this skill | `envsave install-skill [--agent <name>] [--local\|--global]` (claude only today) |
