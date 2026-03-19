# EnvSave — LLM Integration Guide

EnvSave is a local secret vault designed for LLM-safe environments. It lets AI agents and LLMs access secrets **without exposing secret names or allowing bulk discovery**.

## How It Works

The human operator stores secrets with readable names (e.g., `OPENAI_API_KEY`). EnvSave generates an **opaque key** — a random-looking token like `es_7a3f2b1e9c8d4f6b2a1c3d5f` — that maps to the secret value. The LLM only ever sees and uses these opaque keys.

### Security Model

- **Opaque keys**: Secret names are HMAC-SHA256 hashes — fully opaque, no trace of the original name
- **No enumeration**: The session cache contains only `opaque_key → value` pairs. An LLM cannot list, discover, or guess key names
- **Session isolation**: The session cache is encrypted with a random key (not the master password). It only contains secrets, not metadata
- **Need-to-know**: An LLM can only retrieve a secret if it already knows the exact opaque key

### Data Flow

```
Human (once):
  envsave set OPENAI_API_KEY sk-abc123...
  → outputs: es_7a3f2b1e9c8d4f6b2a1c3d5f

LLM (at runtime):
  envsave.get("es_7a3f2b1e9c8d4f6b2a1c3d5f")
  → returns: sk-abc123...
```

## Setup (Human Operator)

```bash
# 1. Install
bun install envsave

# 2. Activate license
envsave activate <token>

# 3. Initialize vault (optionally import from .env)
envsave init
envsave init --env .env
envsave init --env .env --ssh-key ~/.ssh/id_ed25519

# 4. Add secrets
envsave set OPENAI_API_KEY sk-abc123...
# → es_7a3f2b1e9c8d4f6b2a1c3d5f   (give this to the LLM)

envsave set DATABASE_URL postgres://user:pass@host/db
# → es_1b2c3d4e5f6a7b8c9d0e1f2a   (give this to the LLM)

# 5. Reveal an opaque key later (requires password)
envsave reveal OPENAI_API_KEY
# → es_7a3f2b1e9c8d4f6b2a1c3d5f
```

## Usage in Code (LLM / Agent)

### TypeScript / JavaScript

```typescript
import envsave from "envsave";

// Same code works everywhere:
// - Local: reads from encrypted vault
// - Vercel/cloud: reads from process.env.es_7a3f2b1e9c8d4f6b2a1c3d5f
const apiKey = envsave.get("es_7a3f2b1e9c8d4f6b2a1c3d5f");
```

### Python

```python
import envsave

# Same code works everywhere:
# - Local: reads from encrypted vault
# - Vercel/cloud: reads from os.environ["es_7a3f2b1e9c8d4f6b2a1c3d5f"]
api_key = envsave.get("es_7a3f2b1e9c8d4f6b2a1c3d5f")
```

**Python requirement**: `pip install cryptography`

### CLI (for scripts)

```bash
# Get a secret value (tries session cache first, no password needed)
envsave get es_7a3f2b1e9c8d4f6b2a1c3d5f
```

## API Reference

| Function | Description |
|----------|-------------|
| `get(opaqueKey)` | Returns the secret from vault, or falls back to `process.env[opaqueKey]` |
| `has(opaqueKey)` | Returns `true`/`false` — checks vault first, then env var |

Two functions, no password, no enumeration. Works locally via vault, works in the cloud via env vars.

## Cloud Deployment (Vercel, etc.)

On Vercel or any cloud platform, set the **opaque key as the environment variable name**:

```
es_7a3f2b1e9c8d4f6b2a1c3d5f = sk-abc123...
```

Your code doesn't change — `envsave.get("es_7a3f2b1e9c8d4f6b2a1c3d5f")` returns the value from the env var. The LLM sees the opaque key in the code but has no idea what the secret is for.

## Important Notes for LLMs

1. **You cannot list secrets.** There is no `list()` or `keys()` function available to you. You can only access secrets whose opaque keys are explicitly provided in your source code or configuration.

2. **Opaque keys are meaningless.** `es_7a3f2b1e9c8d4f6b2a1c3d5f` reveals nothing about what secret it holds. Don't try to guess or derive opaque keys — they are HMAC-SHA256 hashes.

3. **Session must be active.** A human must have run at least one password-authenticated `envsave` command in the current session for the cache to exist. If `get()` throws a "No session found" error, ask the user to run `envsave list` or any command to unlock the vault.

4. **Secrets can be synced.** The vault lives at `~/.envsave/vault.enc` on the local machine. It can be backed up and synced to the cloud using `envsave backup`, `envsave restore`, or `envsave sync`. The server only stores the encrypted vault — it never sees plaintext secrets.

## CLI Reference (Human Operator)

| Command | Description |
|---------|-------------|
| `envsave activate <token>` | Activate license |
| `envsave init [--env <file>] [--ssh-key <file>]` | Create vault |
| `envsave set <key> <value>` | Store secret (outputs opaque key) |
| `envsave get <opaque_key>` | Retrieve value |
| `envsave reveal <key> [key2]...` | Show opaque key(s) for name(s) (password required) |
| `envsave delete <key>` | Remove secret (password required) |
| `envsave list` | List secret names (password required) |
| `envsave import <file>` | Import from .env file (password required) |
| `envsave export` | Export as .env format (password required) |
| `envsave backup` | Upload encrypted vault to cloud server |
| `envsave restore` | Download vault backup from cloud server |
| `envsave sync` | Sync vault with cloud (auto-detects direction) |

## Encryption Details

- **Vault**: AES-256-GCM with PBKDF2 key derivation (100,000 iterations, SHA-512)
- **Session cache**: AES-256-GCM with a random 256-bit key
- **Opaque keys**: HMAC-SHA256 with a random seed (optionally mixed with SSH key content)
- **File format**: `salt(32B) | iv(12B) | ciphertext | authTag(16B)`
