"""Session tokens: opaque, random, shown once. Only the hash is stored (like an agent's key,
see agent_keys.py): a stolen database dump cannot be used to impersonate a logged-in user."""

import secrets
from hashlib import sha256

TOKEN_BYTES = 32  # 256 bits of randomness: nothing to brute-force


def generate_session_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_session_token(token: str) -> str:
    return sha256(token.encode()).hexdigest()
