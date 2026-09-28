import pytest

from sentinel_core.auth.passwords import (
    MIN_PASSWORD_LENGTH,
    WeakPassword,
    hash_password,
    verify_password,
)


def test_a_password_hashes_and_verifies() -> None:
    hashed = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", hashed)


def test_the_wrong_password_does_not_verify() -> None:
    hashed = hash_password("correct horse battery staple")

    assert not verify_password("wrong password entirely", hashed)


def test_the_hash_never_contains_the_plaintext() -> None:
    passphrase = "correct horse battery staple"  # noqa: S105

    assert passphrase not in hash_password(passphrase)


def test_the_same_password_hashes_differently_each_time() -> None:
    # A fresh random salt per hash: two hashes of the same password never match byte for byte,
    # even though both verify the same password.
    a, b = (
        hash_password("correct horse battery staple"),
        hash_password("correct horse battery staple"),
    )

    assert a != b
    assert verify_password("correct horse battery staple", a)
    assert verify_password("correct horse battery staple", b)


def test_garbage_that_is_not_a_hash_never_verifies_and_never_raises() -> None:
    assert not verify_password("anything", "not-an-argon2-hash")
    assert not verify_password("anything", "")


@pytest.mark.parametrize("password", ["", "short", "1234567", "a" * (MIN_PASSWORD_LENGTH - 1)])
def test_a_password_below_the_minimum_length_is_refused(password: str) -> None:
    with pytest.raises(WeakPassword):
        hash_password(password)


def test_a_password_at_or_above_the_minimum_length_is_accepted() -> None:
    hash_password("a" * MIN_PASSWORD_LENGTH)  # must not raise


def test_an_extremely_long_password_is_refused_before_hashing() -> None:
    # Argon2 hashing cost scales with input size: an unbounded password would let a client make
    # every login attempt expensive. 1024 characters is far beyond any real passphrase.
    with pytest.raises(WeakPassword):
        hash_password("a" * 1025)
