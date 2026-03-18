"""
eVault Python Bridge — reads the session cache (NOT the main vault).

The session cache contains only the secrets map (opaque_key → value).
No aliases, no HMAC seed, no registry — an LLM reading this file
can only access secrets whose opaque key it already knows.

Usage:
    import evault
    api_key = evault.get("ev_7a3f2b1e9c8d4f6b2a1c3d5f")

Requirements:
    pip install cryptography
"""

import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

EVAULT_DIR = Path.home() / ".evault"
CACHE_FILE = EVAULT_DIR / "cache.enc"
SESSION_FILE = EVAULT_DIR / ".session"

IV_LENGTH = 12


def _decrypt_cache() -> dict:
    """Decrypt session cache using random session key (NOT the master password)."""
    if not SESSION_FILE.exists() or not CACHE_FILE.exists():
        raise RuntimeError("No session found. Run any evault command with your password first.")

    session_key_hex = SESSION_FILE.read_text().strip()
    session_key = bytes.fromhex(session_key_hex)

    payload = CACHE_FILE.read_bytes()
    iv = payload[:IV_LENGTH]
    encrypted_with_tag = payload[IV_LENGTH:]

    aesgcm = AESGCM(session_key)
    decrypted = aesgcm.decrypt(iv, encrypted_with_tag, None)
    return json.loads(decrypted.decode("utf-8"))


# Cache for repeated calls
_cache: dict | None = None


def _get_cache() -> dict:
    global _cache
    if _cache is None:
        _cache = _decrypt_cache()
    return _cache


def get(key: str) -> str | None:
    """Get a secret by its opaque key (e.g. 'ev_7a3f2b1e9c8d4f6b2a1c3d5f')."""
    cache = _get_cache()
    return cache.get("secrets", {}).get(key)


def has(key: str) -> bool:
    """Check if an opaque key exists in the session cache."""
    cache = _get_cache()
    return key in cache.get("secrets", {})


def clear_cache():
    """Clear the in-memory cache."""
    global _cache
    _cache = None
