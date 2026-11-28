"""ACME status transitions (RFC 8555 section 7.1.6), computed from the facts.

Order: pending → ready (every authorization valid) → processing (finalize) → valid | invalid;
pending or ready → invalid when an authorization fails or the order expires. Authorization:
pending → valid | invalid | expired (deactivated by the client). Challenge: pending → processing
→ valid | invalid. Statuses are plain strings here (``core`` does not import the models, whose
``StrEnum`` values are the same).
"""

from collections.abc import Iterable
from datetime import datetime

FAILED_AUTHORIZATIONS = frozenset({"invalid", "deactivated", "expired", "revoked"})


def authorization_status(
    current: str, challenge_statuses: Iterable[str], *, expires_at: datetime, now: datetime
) -> str:
    """Status of an authorization from its challenges (one valid challenge is enough)."""
    if current != "pending":
        return current
    statuses = list(challenge_statuses)
    if "valid" in statuses:
        return "valid"
    if statuses and all(status == "invalid" for status in statuses):
        return "invalid"
    if now >= expires_at:
        return "expired"
    return "pending"


def order_status(
    current: str, authorization_statuses: Iterable[str], *, expires_at: datetime, now: datetime
) -> str:
    """Status of an order before finalize, from its authorizations and its expiry.

    ``processing`` and later follow the certificate request, not the authorizations.
    """
    if current not in ("pending", "ready"):
        return current
    statuses = list(authorization_statuses)
    if any(status in FAILED_AUTHORIZATIONS for status in statuses) or now >= expires_at:
        return "invalid"
    if statuses and all(status == "valid" for status in statuses):
        return "ready"
    return "pending"


def order_status_of_request(request_status: str) -> str:
    """After finalize: the order follows its certificate request (approval of the profile)."""
    return {"pending": "processing", "issued": "valid"}.get(request_status, "invalid")
