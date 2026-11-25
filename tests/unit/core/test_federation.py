from uuid import uuid4

import pytest

from h42pki.core.federation import (
    SubCaConstraints,
    constrain_sub_ca,
    effective_path_length,
    hash_secret,
    new_token,
    parse_token,
    secret_matches,
)
from h42pki.core.profiles import BUILTIN_PROFILES


def test_token_round_trip() -> None:
    token = new_token(uuid4())

    assert parse_token(token.reveal()) == token
    assert len(token.secret) == 43  # 32 bytes, base64url without padding
    assert new_token(token.invitation_id).secret != token.secret
    assert token.secret not in repr(token)


@pytest.mark.parametrize(
    "change",
    [
        lambda t: "",
        lambda t: t[:-1],
        lambda t: t + "A",
        lambda t: t.replace("h42fed_", "h42_"),
        lambda t: t.replace(".", ""),
        lambda t: t[:20],
        lambda t: "h42fed_not-a-uuid." + t.partition(".")[2],
        lambda t: t.partition(".")[0] + ".é" + "A" * 42,
        lambda t: t.partition(".")[0] + "." + "+" * 43,
    ],
)
def test_malformed_tokens(change) -> None:  # type: ignore[no-untyped-def]
    assert parse_token(change(new_token(uuid4()).reveal())) is None


def test_secret_matches() -> None:
    token = new_token(uuid4())
    stored = hash_secret(token.secret)

    assert token.secret not in stored
    assert secret_matches(token.secret, stored)
    assert not secret_matches(new_token(uuid4()).secret, stored)
    assert not secret_matches(token.secret, None)  # unknown invitation


@pytest.mark.parametrize(
    ("invited", "issuer", "expected"),
    [(None, None, None), (3, None, 3), (None, 2, 1), (0, 2, 0), (5, 2, 1), (1, 1, 0)],
)
def test_effective_path_length(
    invited: int | None, issuer: int | None, expected: int | None
) -> None:
    assert effective_path_length(invited, issuer) == expected


def test_constrained_profile() -> None:
    spec = BUILTIN_PROFILES["sub_ca"]

    free = constrain_sub_ca(spec, SubCaConstraints(None, None, auto_approve=True))
    tight = constrain_sub_ca(spec, SubCaConstraints(1, 30, auto_approve=False))

    assert free.basic_constraints.path_length is None and free.auto_approve
    assert (free.validity_days, free.max_validity_days) == (1825, 3650)
    assert tight.basic_constraints.path_length == 1 and not tight.auto_approve
    assert (tight.validity_days, tight.max_validity_days) == (30, 30)
    assert spec.basic_constraints.path_length == 0  # the built-in profile is untouched
    assert tight.key_usage == spec.key_usage
