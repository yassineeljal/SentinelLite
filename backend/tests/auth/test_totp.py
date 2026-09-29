"""RFC 6238 vectors, replay window, secret binding and recovery material."""

from datetime import UTC, datetime
from uuid import uuid4

import pyotp
import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from sentinel_core.auth.totp import (
    MFAUnavailable,
    SecretBox,
    match_counter,
    new_recovery_codes,
    recovery_hash,
)

SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # noqa: S105 — RFC public test vector


@pytest.mark.parametrize(
    ("timestamp", "code"),
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ],
)
def test_rfc_6238_sha1_vectors_with_six_digits(timestamp: int, code: str) -> None:
    now = datetime.fromtimestamp(timestamp, UTC)
    assert match_counter(SECRET, code, now, None) == timestamp // 30


def test_clock_skew_is_bounded_and_previously_consumed_steps_are_rejected() -> None:
    now = datetime.fromtimestamp(1234567890, UTC)
    current = int(now.timestamp()) // 30
    otp = pyotp.TOTP(SECRET)
    for delta in (-1, 0, 1):
        code = otp.at((current + delta) * 30)
        assert match_counter(SECRET, code, now, None) == current + delta
        assert match_counter(SECRET, code, now, current + delta) is None
        assert match_counter(SECRET, code, now, current + 2) is None
    for delta in (-2, 2):
        assert match_counter(SECRET, otp.at((current + delta) * 30), now, None) is None
    for malformed in ("", "abcdef", "1234567", "\uff11\uff12\uff13\uff14\uff15\uff16"):
        assert match_counter(SECRET, malformed, now, None) is None


def test_encryption_is_bound_to_the_account_and_never_falls_back_to_plaintext() -> None:
    key = SecretStr(Fernet.generate_key().decode())
    box = SecretBox(key)
    user_id = uuid4()
    encrypted = box.encrypt(SECRET, user_id)
    assert SECRET not in encrypted
    assert box.decrypt(encrypted, user_id) == SECRET
    with pytest.raises(MFAUnavailable):
        box.decrypt(encrypted, uuid4())
    with pytest.raises(MFAUnavailable):
        box.decrypt("invalid" + encrypted[7:], user_id)
    with pytest.raises(MFAUnavailable):
        SecretBox(None).decrypt(encrypted, user_id)
    with pytest.raises(MFAUnavailable):
        SecretBox(SecretStr(Fernet.generate_key().decode())).decrypt(encrypted, user_id)


def test_recovery_codes_have_independent_high_entropy_hashes() -> None:
    codes, hashes = new_recovery_codes()
    assert len(set(codes)) == len(set(hashes)) == 10
    assert all(len(code.replace("-", "")) == 32 for code in codes)
    assert [recovery_hash(code) for code in codes] == hashes
    assert [recovery_hash(code.upper().replace("-", "")) for code in codes] == hashes
    assert not set(codes) & set(hashes)
