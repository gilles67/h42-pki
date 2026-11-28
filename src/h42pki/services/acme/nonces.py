"""Replay-Nonce (RFC 8555 section 7.2): random, single use, short-lived."""

import secrets
from datetime import UTC, datetime, timedelta

from h42pki.core.acme.errors import AcmeError
from h42pki.models import AcmeNonce

NONCE_BYTES = 16


class NonceService:
    @staticmethod
    async def new(lifetime_minutes: int) -> str:
        value = secrets.token_urlsafe(NONCE_BYTES)
        await AcmeNonce.create(
            value=value, expires_at=datetime.now(UTC) + timedelta(minutes=lifetime_minutes)
        )
        return value

    @staticmethod
    async def consume(value: str) -> None:
        """Delete the nonce (single use); ``badNonce`` if unknown, already used or expired."""
        if len(value) > 64:
            raise AcmeError("badNonce", "unknown nonce")
        now = datetime.now(UTC)
        deleted = await AcmeNonce.filter(value=value, expires_at__gt=now).delete()
        if not deleted:
            raise AcmeError("badNonce", "the nonce is unknown, expired or already used")

    @staticmethod
    async def purge() -> int:
        """Delete expired nonces (the maintenance task)."""
        return await AcmeNonce.filter(expires_at__lte=datetime.now(UTC)).delete()
