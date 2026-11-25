"""Federation invitations: token format and checks, constraints on a subordinate CA. Pure.

The secret has 256 bits of entropy, so a plain SHA-256 is stored: a slow password hash (argon2)
only helps against guessable secrets (ADR-0015).
"""

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from uuid import UUID

from h42pki.core.extensions import BasicConstraints
from h42pki.core.profiles import ProfileSpec

_PREFIX = "h42fed_"
_SECRET_BYTES = 32
_SECRET = re.compile(r"[A-Za-z0-9_-]{43}")  # base64url of 32 bytes, no padding

DEFAULT_EXPIRES_IN_HOURS = 7 * 24
MAX_EXPIRES_IN_HOURS = 30 * 24


@dataclass(frozen=True, repr=False)
class InvitationToken:
    invitation_id: UUID
    secret: str

    def __repr__(self) -> str:
        return f"InvitationToken({self.invitation_id}, secret=**********)"

    def reveal(self) -> str:
        """Clear text: shown once, when the invitation is created. Never log it."""
        return f"{_PREFIX}{self.invitation_id}.{self.secret}"


def new_token(invitation_id: UUID) -> InvitationToken:
    secret = base64.urlsafe_b64encode(secrets.token_bytes(_SECRET_BYTES)).rstrip(b"=").decode()
    return InvitationToken(invitation_id, secret)


def parse_token(text: str) -> InvitationToken | None:
    """None for anything that is not a well-formed token."""
    if not text.startswith(_PREFIX):
        return None
    identifier, _, secret = text.removeprefix(_PREFIX).partition(".")
    if not _SECRET.fullmatch(secret):
        return None
    try:
        invitation_id = UUID(identifier)
    except ValueError:
        return None
    return InvitationToken(invitation_id, secret)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def secret_matches(secret: str, stored_hash: str | None) -> bool:
    """Constant time, with the same work when the invitation does not exist."""
    expected = stored_hash if stored_hash is not None else "0" * 64
    return hmac.compare_digest(hash_secret(secret), expected) and stored_hash is not None


@dataclass(frozen=True)
class SubCaConstraints:
    """What an invitation imposes on the CA certificate it gives right to."""

    path_length: int | None
    validity_days: int | None
    auto_approve: bool


def constrain_sub_ca(spec: ProfileSpec, constraints: SubCaConstraints) -> ProfileSpec:
    """``sub_ca`` profile as restricted by an invitation.

    The path length of the invitation replaces the one of the profile (0), which would forbid any
    intermediate CA; ``core.issuance`` then caps it strictly below the issuer. The validity can
    only get shorter. The approval is chosen by the invitation (ADR-0015).
    """
    days = constraints.validity_days
    return spec.model_copy(
        update={
            "basic_constraints": BasicConstraints(ca=True, path_length=constraints.path_length),
            "validity_days": spec.validity_days if days is None else days,
            "max_validity_days": (
                spec.max_validity_days if days is None else min(days, spec.max_validity_days)
            ),
            "auto_approve": constraints.auto_approve,
        }
    )


def effective_path_length(invited: int | None, issuer: int | None) -> int | None:
    """``min(invited, issuer - 1)``; None = unlimited. The issuer must not have pathLen 0."""
    ceiling = None if issuer is None else issuer - 1
    if invited is None or ceiling is None:
        return ceiling if invited is None else invited
    return min(invited, ceiling)
