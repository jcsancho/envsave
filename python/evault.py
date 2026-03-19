"""
EnvSave Python Bridge — reads the session cache (NOT the main vault).

The session cache contains only the secrets map (opaque_key → value).
No aliases, no HMAC seed, no registry — an LLM reading this file
can only access secrets whose opaque key it already knows.

Usage:
    import envsave
    api_key = envsave.get("es_7a3f2b1e9c8d4f6b2a1c3d5f")

Requirements:
    pip install cryptography
"""

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVSAVE_DIR = Path.home() / ".envsave"
CACHE_FILE = ENVSAVE_DIR / "cache.enc"
SESSION_FILE = ENVSAVE_DIR / ".session"

IV_LENGTH = 12


def _decrypt_cache() -> dict:
    """Decrypt session cache using random session key (NOT the master password)."""
    if not SESSION_FILE.exists() or not CACHE_FILE.exists():
        raise RuntimeError("No session found. Run any envsave command with your password first.")

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
    """Get a secret by its opaque key. Falls back to os.environ[key] if vault is unavailable."""
    try:
        cache = _get_cache()
        value = cache.get("secrets", {}).get(key)
        if value is not None:
            return value
    except RuntimeError:
        pass

    return os.environ.get(key)


def has(key: str) -> bool:
    """Check if an opaque key exists in the session cache or as an environment variable."""
    try:
        cache = _get_cache()
        if key in cache.get("secrets", {}):
            return True
    except RuntimeError:
        pass

    return key in os.environ


def clear_cache():
    """Clear the in-memory cache."""
    global _cache
    _cache = None
