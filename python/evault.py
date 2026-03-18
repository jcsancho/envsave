"""
eVault Python Bridge — reads the same ~/.evault/vault.enc file as the Node.js CLI.

Usage:
    import evault
    api_key = evault.get("OPENAI_API_KEY")

Requirements:
    pip install cryptography
"""

import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

EVAULT_DIR = Path.home() / ".evault"
VAULT_FILE = EVAULT_DIR / "vault.enc"
SESSION_FILE = EVAULT_DIR / ".session"

PBKDF2_ITERATIONS = 100_000
SALT_LENGTH = 32
IV_LENGTH = 12
KEY_LENGTH = 32
AUTH_TAG_LENGTH = 16


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password.encode(), salt, PBKDF2_ITERATIONS, dklen=KEY_LENGTH)


def _decrypt_vault(password: str) -> dict:
    if not VAULT_FILE.exists():
        raise FileNotFoundError("Vault not found. Run 'evault init' first.")

    payload = VAULT_FILE.read_bytes()

    salt = payload[:SALT_LENGTH]
    iv = payload[SALT_LENGTH : SALT_LENGTH + IV_LENGTH]
    # AES-GCM: ciphertext + auth_tag are handled together by cryptography lib
    encrypted_with_tag = payload[SALT_LENGTH + IV_LENGTH :]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    decrypted = aesgcm.decrypt(iv, encrypted_with_tag, None)
    return json.loads(decrypted.decode("utf-8"))


def _get_session_password() -> str | None:
    if not SESSION_FILE.exists():
        return None
    try:
        return SESSION_FILE.read_text()
    except Exception:
        return None


def _load_vault() -> dict:
    password = _get_session_password()
    if password is None:
        raise RuntimeError("No session found. Run 'evault init' or any evault command with your password first.")
    return _decrypt_vault(password)


# Cache for repeated calls
_cache: dict | None = None


def _get_vault() -> dict:
    global _cache
    if _cache is None:
        _cache = _load_vault()
    return _cache


def get(key: str) -> str | None:
    """Get a secret by its obfuscated key (e.g. 'OPENAI_API_KEY_a7Bx#9mK2pQ1')."""
    vault = _get_vault()
    return vault.get("secrets", {}).get(key)


def has(key: str) -> bool:
    """Check if an obfuscated key exists in the eVault."""
    vault = _get_vault()
    return key in vault.get("secrets", {})


def clear_cache():
    """Clear the in-memory vault cache."""
    global _cache
    _cache = None
