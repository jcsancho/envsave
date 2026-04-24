# EnvSave

A local encrypted vault for secrets (API keys, tokens, passwords) designed to be safe for use with LLM agents. Secrets are accessed via opaque keys (`es_...`) — agents can read values but can't discover or enumerate other secrets.

## The problem EnvSave solves

API keys, access tokens, database URLs, webhook secrets — **these must never be visible to AI assistants or coding agents you run on your codebase.** If an LLM can read a real secret, so can anyone watching the LLM:

- **Exfiltration.** An agent with tool access (shell, file read, HTTP) can quietly send keys to an external endpoint, log them into a transcript cached by a third party, or commit them to a public repo. You won't notice until the bill arrives.
- **Abuse by strangers.** A leaked OpenAI / Anthropic / Stripe / AWS key is an open tab on your credit card. Attackers scrape keys out of GitHub, npm tarballs, Discord pastes, and LLM transcripts within minutes of exposure.
- **Prompt injection.** A malicious webpage, PR description, or document pulled into the agent's context can instruct it to read `.env`, list environment variables, or print secrets as "debug output." If the secret is in your code or your environment, a compromised agent will surface it.
- **Context-window leakage.** Once a key is in the LLM's context it can be logged, embedded, cached, and potentially used to train future models — you've lost control of it.
- **Painful rotation.** Rotating a leaked production key means downtime, redeploys, and hunting down every place it was pasted.

**EnvSave is how you stop giving LLMs your real secrets.** Instead of exposing `sk-proj-...` or reading `.env` in your code, you hand the LLM an *opaque key* — a deterministic HMAC hash like `es_7a3f2b1e9c8d4f6b2a1c3d5f` — that only resolves to the real value through the encrypted vault on your machine. The agent can read your code, your `.env`, even the session cache, and still learn nothing: opaque keys can't be reversed, enumerated, or brute-forced without the master password.

```ts
// ❌ Bad — the LLM sees the real key in your code
const openai = new OpenAI({ apiKey: "sk-proj-abc123..." });

// ❌ Also bad — .env still contains the plaintext key, and agents read .env
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ✅ EnvSave — the agent only ever sees "es_7a3f...", useless outside your vault
import { get } from "@envsave/cli";
const openai = new OpenAI({ apiKey: get("es_7a3f2b1e9c8d4f6b2a1c3d5f") });
```

This is the single problem this project is built around. Everything else — the CLI, the license server, the Python bridge, the cloud backup — exists to make opaque-key-based secrets practical to use day to day.

## Pricing

Local personal use is **free and unlimited** — store as many secrets as you want with no license. A license is only required to sync your vault to the cloud; activate one with `envsave activate <token>` — get yours at https://envsave.com.

## Installation

```bash
# Global CLI (binary will be available as `envsave`)
npm install -g @envsave/cli

# Or use it as a library
npm install @envsave/cli
```

Python users:

```bash
pip install envsave
```

## Activation

### Online (production)

Requires the license server running at `https://api.envsave.com`.

```bash
# 1. Register on the webapp to get a token
# 2. Activate
envsave activate <token>
```

The CLI calls `/api/license/validate` to verify the token's HMAC signature, expiry, and DB status.

### Offline (dev/testing)

Skips server validation. Only allowed for a small set of whitelisted emails maintained in `src/license.ts`.

```bash
envsave activate <token> --offline
```

This parses the signed token locally, checks the embedded email is in the allowed list, verifies expiry, and writes `~/.envsave/license.json`.

## Setup

```bash
# Initialize vault (creates ~/.envsave/vault.enc)
envsave init

# Optional: initialize with an existing .env file
envsave init --env .env

# Optional: add SSH key as second factor
envsave init --ssh-key ~/.ssh/id_ed25519
```

You'll be prompted to set and confirm a master password.

## Storing Secrets

```bash
envsave set OPENAI_API_KEY sk-abc123
#  Output:
#    OPENAI_API_KEY → es_7a3f2b1e9c8d4f6b
#    Use this in your code to access OPENAI_API_KEY:
#      envsave.get("es_7a3f2b1e9c8d4f6b")
```

The opaque key (`es_...`) is an HMAC-SHA256 hash — no trace of the original key name.

## Retrieving Secrets

### CLI

```bash
# By opaque key (tries session cache first, then prompts for password)
envsave get es_7a3f2b1e9c8d4f6b
```

### Node.js / Bun

```ts
import { get, has } from "@envsave/cli";

const apiKey = get("es_7a3f2b1e9c8d4f6b");

if (has("es_7a3f2b1e9c8d4f6b")) {
  // secret exists
}
```

### Python

```python
from envsave import get

api_key = get("es_7a3f2b1e9c8d4f6b")
```

## Other Commands

```bash
# Show opaque key for a named secret (requires password)
envsave reveal OPENAI_API_KEY

# Reveal multiple keys at once
envsave reveal OPENAI_API_KEY DATABASE_URL STRIPE_KEY

# List all stored key names (requires password)
envsave list

# Delete a secret (requires password)
envsave delete OPENAI_API_KEY

# Bulk import from .env file (requires password)
envsave import .env

# Export all secrets as .env format (requires password)
envsave export
```

## Cloud Backup & Sync

The encrypted vault can be backed up to the EnvSave cloud server for disaster recovery or syncing across machines. The server only stores the encrypted bytes — it never sees plaintext secrets.

```bash
# Upload encrypted vault to cloud
envsave backup

# Download vault backup from cloud (prompts before overwriting)
envsave restore

# Smart sync — auto-detects which direction to sync
envsave sync
```

### Sync behavior

| Scenario | Action |
|---|---|
| Both match (same checksum) | "Already in sync" |
| Local only, no cloud backup | Auto-pushes to cloud |
| Cloud only, no local vault | Auto-pulls from cloud |
| Both exist but differ | Asks: pull (p), push (l), or cancel (c) |
| Neither exists | Tells user to run `envsave init` |

### Setting up on a new machine or remote server

```bash
# 1. Install envsave
bun install @envsave/cli

# 2. Activate with same license token
envsave activate <token>

# 3. Pull vault from cloud
envsave sync
# or: envsave restore

# 4. Verify
envsave list
```

## Security Model

1. Vault is encrypted with AES-256-GCM + PBKDF2 key derivation
2. Stored at `~/.envsave/vault.enc` (binary: salt + iv + encrypted data + auth tag)
3. Key names are HMAC-SHA256 hashes — fully opaque, no trace of original name
4. Session cache stores decrypted secrets in memory — no password needed for repeated reads
5. Optional SSH key adds a "something you have" hardware factor
6. LLM agents only see opaque keys — they can read values but can't discover or enumerate secrets

## License Tokens

Tokens are self-contained signed strings: `es_<base64url(email|created_ts|expires_ts|hmac)>`

- Dates are embedded inside the token (opaque to users)
- HMAC signature prevents tampering (verified server-side)
- Server also checks DB for revocation support
- Offline mode reads expiry from the token directly without server call

### Auto-Renewal

When a license token expires, the CLI automatically contacts the server to renew it — no user action needed. The renewal succeeds if the user's subscription is still active (user exists in DB and hasn't been revoked). The new token is saved locally and the command proceeds normally.

## File Locations

| File | Purpose |
|------|---------|
| `~/.envsave/vault.enc` | Encrypted vault |
| `~/.envsave/license.json` | Activated license |
| `~/.envsave/session.json` | Session cache (decrypted secrets) |
