"""TOTP primitives (PyOTP/RFC 6238), encrypted secrets and hashed recovery codes."""

import hmac
import re
import secrets
from datetime import datetime
from hashlib import sha256
from uuid import UUID

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr

from sentinel_core.db.models import User


class MFAUnavailable(Exception):
    """The encryption key is missing or cannot decrypt this account's secret."""


class SecretBox:
    def __init__(self, key: SecretStr | None) -> None:
        self._fernet = Fernet(key.get_secret_value().encode()) if key else None

    @property
    def available(self) -> bool:
        return self._fernet is not None

    def encrypt(self, secret: str, user_id: UUID) -> str:
        if self._fernet is None:
            raise MFAUnavailable
        return self._fernet.encrypt(f"{user_id}:{secret}".encode()).decode()

    def decrypt(self, ciphertext: str, user_id: UUID) -> str:
        if self._fernet is None:
            raise MFAUnavailable
        try:
            plaintext = self._fernet.decrypt(ciphertext.encode()).decode()
        except (InvalidToken, UnicodeError):
            raise MFAUnavailable from None
        prefix = f"{user_id}:"
        if not plaintext.startswith(prefix):
            raise MFAUnavailable
        return plaintext.removeprefix(prefix)


def match_counter(secret: str, code: str, now: datetime, last_counter: int | None) -> int | None:
    if not re.fullmatch(r"[0-9]{6}", code):
        return None
    current = int(now.timestamp()) // 30
    otp = pyotp.TOTP(secret)
    # Accept one step of clock skew, but never an already accepted (or older) step.
    for counter in (current, current - 1, current + 1):
        if counter >= 0 and (last_counter is None or counter > last_counter):
            if hmac.compare_digest(otp.at(counter * 30), code):
                return counter
    return None


def recovery_hash(code: str) -> str:
    return sha256(code.replace("-", "").strip().lower().encode()).hexdigest()


def new_recovery_codes() -> tuple[list[str], list[str]]:
    raw = [secrets.token_hex(16) for _ in range(10)]
    displayed = ["-".join(code[i : i + 8] for i in range(0, 32, 8)) for code in raw]
    return displayed, [recovery_hash(code) for code in raw]


def consume_factor(user: User, code: str, box: SecretBox, now: datetime) -> bool:
    """Caller MUST hold the user's row lock and commit this with the privileged operation."""
    if user.totp_secret is None:
        return False
    normalized = code.strip().lower().replace("-", "")
    if re.fullmatch(r"[0-9a-f]{32}", normalized):
        candidate = recovery_hash(normalized)
        existing = user.recovery_code_hashes or []
        match = next((value for value in existing if hmac.compare_digest(candidate, value)), None)
        if match is None:
            return False
        user.recovery_code_hashes = [value for value in existing if value != match]
        return True
    secret = box.decrypt(user.totp_secret, user.id)
    counter = match_counter(secret, code.strip(), now, user.totp_last_counter)
    if counter is None:
        return False
    user.totp_last_counter = counter
    return True
