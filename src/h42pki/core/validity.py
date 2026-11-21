"""Validity bounds and windows (single source of truth, also used by the API and the CLI)."""

from datetime import UTC, datetime, timedelta

from h42pki.core.errors import InvalidValidity

# Single source of truth, also used by the API request schema.
DEFAULT_CA_VALIDITY_DAYS = 3650
MIN_VALIDITY_DAYS = 1
MAX_VALIDITY_DAYS = 10950  # 30 years
# not_before is backdated to tolerate relying parties whose clock is slightly behind.
CLOCK_SKEW = timedelta(minutes=5)


def check_validity_days(validity_days: int) -> None:
    if not MIN_VALIDITY_DAYS <= validity_days <= MAX_VALIDITY_DAYS:
        raise InvalidValidity(
            f"validity_days must be between {MIN_VALIDITY_DAYS} and {MAX_VALIDITY_DAYS}"
        )


def validity_window(now: datetime, validity_days: int) -> tuple[datetime, datetime]:
    """``(not_before, not_after)`` for a certificate issued at ``now``.

    X.509 encodes times to the second, so ``now`` is truncated: the stored values then equal
    the certificate's, and ``not_after - not_before`` is exactly ``validity_days``.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")  # B17
    check_validity_days(validity_days)
    not_before = now.astimezone(UTC).replace(microsecond=0) - CLOCK_SKEW
    return not_before, not_before + timedelta(days=validity_days)
