"""core.passwords: scrypt hashes of EST passwords (ADR-0018)."""

import time

import pytest

from h42pki.core import passwords
from h42pki.core.passwords import (
    DEFAULT_PARAMETERS,
    USERNAME,
    InvalidPassword,
    ScryptParameters,
    check_password,
    generate_password,
    hash_password,
    verify_password,
)

FAST = ScryptParameters(n=2**10, r=8, p=1)


def test_real_parameters() -> None:
    """N = 2^15, r = 8, p = 3: OWASP equivalent of 2^17 / 8 / 1, 32 MiB per hash."""
    assert DEFAULT_PARAMETERS == ScryptParameters(n=2**15, r=8, p=3)
    assert 32 * 1024 * 1024 <= DEFAULT_PARAMETERS.memory < 33 * 1024 * 1024


def test_hash_with_the_real_parameters() -> None:
    stored = hash_password("correct horse", DEFAULT_PARAMETERS)

    assert stored.startswith("scrypt$32768$8$3$")
    assert verify_password("correct horse", stored)
    assert not verify_password("correct horsf", stored)


def test_format_salt_and_parameters_read_back() -> None:
    first, second = hash_password("same password", FAST), hash_password("same password", FAST)

    assert first != second  # random salt per hash
    assert first.split("$")[:4] == ["scrypt", "1024", "8", "1"]
    assert verify_password("same password", first) and verify_password("same password", second)
    assert "same password" not in first


@pytest.mark.parametrize(
    "stored",
    [None, "", "argon2$x", "scrypt$1000$8$1$AA==$AA==", "scrypt$1024$8$1$!!$AA==", "scrypt$1$2$3"],
)
def test_unknown_or_unreadable_hash_never_matches(stored: str | None) -> None:
    assert not verify_password("anything", stored)


def test_unknown_account_costs_like_a_wrong_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(passwords, "DEFAULT_PARAMETERS", ScryptParameters(n=2**14, r=8, p=1))
    stored = hash_password("the password")
    verify_password("warm-up", None)  # the dummy hash is computed once

    def duration(candidate: str | None) -> float:
        start = time.perf_counter()
        for _ in range(3):
            verify_password("wrong password", candidate)
        return time.perf_counter() - start

    unknown, wrong = duration(None), duration(stored)

    assert 0.5 < unknown / wrong < 2.0


def test_generated_passwords() -> None:
    generated = {generate_password() for _ in range(20)}

    assert len(generated) == 20
    assert all(len(value) == 24 and value.isalnum() for value in generated)
    check_password(next(iter(generated)))


@pytest.mark.parametrize("bad", ["short", "x" * 1025, "with\nnewline", "tab\tinside!"])
def test_bad_passwords(bad: str) -> None:
    with pytest.raises(InvalidPassword):
        check_password(bad)


@pytest.mark.parametrize("name", ["alice", "router-01", "dev.ice_2", "a" * 64])
def test_valid_usernames(name: str) -> None:
    assert USERNAME.fullmatch(name)


@pytest.mark.parametrize("name", ["", "a:b", "a b", "é", "a" * 65, "x/y"])
def test_invalid_usernames(name: str) -> None:
    assert not USERNAME.fullmatch(name)
