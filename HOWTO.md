# EnvSave — How To Use

## What is EnvSave?

A local encrypted vault for secrets (API keys, tokens, passwords) designed to be safe for use with LLM agents. Secrets are accessed via opaque keys (`es_...`) — agents can read values but can't discover or enumerate other secrets.

## Installation

```bash
# From source (local dev)
bun run build
bun link

# Then available globally as:
envsave
```

## Activation

### Online (production)

Requires the license server running at `https://envsave.example.com`.

```bash
# 1. Register on the webapp to get a token
# 2. Activate
envsave activate <token>
```

The CLI calls `/api/license/validate` to verify the token's HMAC signature, expiry, and DB status.

### Offline (dev/testing)

Skips server validation. Only allowed for whitelisted emails (hardcoded in `src/license.ts`).

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
import { get, has } from "envsave";

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
bun install envsave

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
