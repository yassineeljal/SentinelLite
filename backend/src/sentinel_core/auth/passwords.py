"""Password hashing (Argon2id, via `argon2-cffi`): the library's own tuned defaults, no custom
cost parameters to get subtly wrong.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_PASSWORD_LENGTH = 12
# Hashing cost scales with input size: an unbounded password lets a client make every attempt
# (its own and everyone else's, since the server does the work) expensive. Far beyond any real
# passphrase or passphrase manager's output.
MAX_PASSWORD_LENGTH = 1024

_hasher = PasswordHasher()


class WeakPassword(ValueError):
    """The password is too short or too long to hash."""


def hash_password(password: str) -> str:
    if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        raise WeakPassword(
            f"a password must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters"
        )
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """False for a wrong password AND for a hash that is not valid Argon2 (never raises)."""
    try:
        return _hasher.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
