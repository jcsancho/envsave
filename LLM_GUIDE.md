# eVault — LLM Integration Guide

eVault is a local secret vault designed for LLM-safe environments. It lets AI agents and LLMs access secrets **without exposing secret names or allowing bulk discovery**.

## How It Works

The human operator stores secrets with readable names (e.g., `OPENAI_API_KEY`). eVault generates an **opaque key** — a random-looking token like `ev_7a3f2b1e9c8d4f6b2a1c3d5f` — that maps to the secret value. The LLM only ever sees and uses these opaque keys.

### Security Model

- **Opaque keys**: Secret names are HMAC-SHA256 hashes — fully opaque, no trace of the original name
- **No enumeration**: The session cache contains only `opaque_key → value` pairs. An LLM cannot list, discover, or guess key names
- **Session isolation**: The session cache is encrypted with a random key (not the master password). It only contains secrets, not metadata
- **Need-to-know**: An LLM can only retrieve a secret if it already knows the exact opaque key

### Data Flow

```
Human (once):
  evault set OPENAI_API_KEY sk-abc123...
  → outputs: ev_7a3f2b1e9c8d4f6b2a1c3d5f

LLM (at runtime):
  evault.get("ev_7a3f2b1e9c8d4f6b2a1c3d5f")
  → returns: sk-abc123...
```

## Setup (Human Operator)

```bash
# 1. Install
bun install evault

# 2. Activate license
evault activate <token>

# 3. Initialize vault (optionally import from .env)
evault init
evault init --env .env
evault init --env .env --ssh-key ~/.ssh/id_ed25519

# 4. Add secrets
evault set OPENAI_API_KEY sk-abc123...
# → ev_7a3f2b1e9c8d4f6b2a1c3d5f   (give this to the LLM)

evault set DATABASE_URL postgres://user:pass@host/db
# → ev_1b2c3d4e5f6a7b8c9d0e1f2a   (give this to the LLM)

# 5. Reveal an opaque key later (requires password)
evault reveal OPENAI_API_KEY
# → ev_7a3f2b1e9c8d4f6b2a1c3d5f
```

## Usage in Code (LLM / Agent)

### TypeScript / JavaScript

```typescript
import evault from "evault";

// Retrieve a secret by its opaque key (no password needed)
const apiKey = evault.get("ev_7a3f2b1e9c8d4f6b2a1c3d5f");

// Check if a secret exists
if (evault.has("ev_7a3f2b1e9c8d4f6b2a1c3d5f")) {
  // use the secret
}
```

### Python

```python
import evault

# Retrieve a secret by its opaque key (no password needed)
api_key = evault.get("ev_7a3f2b1e9c8d4f6b2a1c3d5f")

# Check if a secret exists
if evault.has("ev_7a3f2b1e9c8d4f6b2a1c3d5f"):
    # use the secret
```

**Python requirement**: `pip install cryptography`

### CLI (for scripts)

```bash
# Get a secret value (tries session cache first, no password needed)
evault get ev_7a3f2b1e9c8d4f6b2a1c3d5f
```

## API Reference

| Function | Auth Required | Description |
|----------|--------------|-------------|
| `get(opaqueKey)` | None (session) | Returns the secret value, or `undefined`/`None` |
| `has(opaqueKey)` | None (session) | Returns `true`/`false` |

That's the entire LLM-facing API. Two functions, no password, no enumeration.

## Important Notes for LLMs

1. **You cannot list secrets.** There is no `list()` or `keys()` function available to you. You can only access secrets whose opaque keys are explicitly provided in your source code or configuration.

2. **Opaque keys are meaningless.** `ev_7a3f2b1e9c8d4f6b2a1c3d5f` reveals nothing about what secret it holds. Don't try to guess or derive opaque keys — they are HMAC-SHA256 hashes.

3. **Session must be active.** A human must have run at least one password-authenticated `evault` command in the current session for the cache to exist. If `get()` throws a "No session found" error, ask the user to run `evault list` or any command to unlock the vault.

4. **Secrets are local.** The vault lives at `~/.evault/vault.enc` on the local machine. It is not synced to any cloud service.

## CLI Reference (Human Operator)

| Command | Description |
|---------|-------------|
| `evault activate <token>` | Activate license |
| `evault init [--env <file>] [--ssh-key <file>]` | Create vault |
| `evault set <key> <value>` | Store secret (outputs opaque key) |
| `evault get <opaque_key>` | Retrieve value |
| `evault reveal <key>` | Show opaque key for a name (password required) |
| `evault delete <key>` | Remove secret (password required) |
| `evault list` | List secret names (password required) |
| `evault import <file>` | Import from .env file (password required) |
| `evault export` | Export as .env format (password required) |

## Encryption Details

- **Vault**: AES-256-GCM with PBKDF2 key derivation (100,000 iterations, SHA-512)
- **Session cache**: AES-256-GCM with a random 256-bit key
- **Opaque keys**: HMAC-SHA256 with a random seed (optionally mixed with SSH key content)
- **File format**: `salt(32B) | iv(12B) | ciphertext | authTag(16B)`
