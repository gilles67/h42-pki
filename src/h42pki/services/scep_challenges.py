"""SCEP challenges (ADR-0019): generated, single-use by default or reusable, any profile.

The challenge is returned once, at creation; only the SHA-256 of its secret is stored. A request
consumes one use when it is accepted (recorded), even if it is rejected afterwards; a retransmission
of the same transaction consumes nothing (``services/scep.py``).
"""

import builtins
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from tortoise.transactions import in_transaction

from h42pki.core.challenges import (
    ID_LENGTH,
    Challenge,
    hash_secret,
    new_challenge,
    parse_challenge,
    secret_matches,
)
from h42pki.errors import Conflict, InvalidRequest, NotFound
from h42pki.models import AuditLog, CredentialKind, CredentialStatus, EnrollmentCredential

MAX_EXPIRES_IN_HOURS = 24 * 365


@dataclass(frozen=True, repr=False)
class CreatedChallenge:
    credential: EnrollmentCredential
    challenge: Challenge

    def __repr__(self) -> str:
        return f"CreatedChallenge({self.credential.identifier})"


def is_usable(credential: EnrollmentCredential, now: datetime) -> bool:
    return (
        credential.status is CredentialStatus.ACTIVE
        and (credential.expires_at is None or credential.expires_at > now)
        and (credential.max_uses is None or credential.use_count < credential.max_uses)
    )


class ScepChallengeService:
    KIND = CredentialKind.SCEP_CHALLENGE

    async def list(self) -> builtins.list[EnrollmentCredential]:
        return await EnrollmentCredential.filter(kind=self.KIND).order_by("created_at")

    async def get(self, identifier: str) -> EnrollmentCredential:
        credential = (
            await EnrollmentCredential.get_or_none(kind=self.KIND, identifier=identifier.upper())
            if len(identifier) == ID_LENGTH
            else None
        )
        if credential is None:
            raise NotFound(f"no SCEP challenge {identifier!r}")
        return credential

    async def create(
        self,
        *,
        max_uses: int | None = 1,
        expires_in_hours: int | None = None,
        description: str | None = None,
        actor: str,
    ) -> CreatedChallenge:
        """``max_uses``: 1 by default, None for a reusable challenge (a fleet of devices)."""
        if max_uses is not None and max_uses < 1:
            raise InvalidRequest("max_uses is at least 1 (or null for a reusable challenge)")
        if expires_in_hours is not None and not 1 <= expires_in_hours <= MAX_EXPIRES_IN_HOURS:
            raise InvalidRequest(f"expires_in_hours is between 1 and {MAX_EXPIRES_IN_HOURS}")
        expires_at = (
            datetime.now(UTC) + timedelta(hours=expires_in_hours)
            if expires_in_hours is not None
            else None
        )
        challenge = new_challenge()
        while await EnrollmentCredential.exists(kind=self.KIND, identifier=challenge.identifier):
            challenge = new_challenge()  # pragma: no cover - 36^8 identifiers
        async with in_transaction():
            credential = await EnrollmentCredential.create(
                kind=self.KIND,
                identifier=challenge.identifier,
                secret_hash=hash_secret(challenge.secret),
                max_uses=max_uses,
                expires_at=expires_at,
                description=description,
                created_by=actor,
            )
            await self._audit(
                actor,
                "scep.challenge.create",
                credential,
                {
                    "max_uses": max_uses,
                    "expires_at": expires_at.isoformat() if expires_at is not None else None,
                },
            )
        return CreatedChallenge(credential, challenge)

    async def set_status(
        self, identifier: str, status: CredentialStatus, *, actor: str
    ) -> EnrollmentCredential:
        credential = await self.get(identifier)
        action = (
            "scep.challenge.enable"
            if status is CredentialStatus.ACTIVE
            else "scep.challenge.disable"
        )
        async with in_transaction():
            await EnrollmentCredential.filter(id=credential.id).update(status=status)
            await self._audit(actor, action, credential, {})
        return await self.get(identifier)

    async def delete(self, identifier: str, *, actor: str) -> None:
        credential = await self.get(identifier)
        async with in_transaction():
            await EnrollmentCredential.filter(id=credential.id).delete()
            await self._audit(actor, "scep.challenge.delete", credential, {})

    async def check(self, text: str | None) -> EnrollmentCredential | None:
        """The usable challenge matching ``text``, or None (same work whatever the reason)."""
        parsed = parse_challenge(text) if text is not None else None
        credential = (
            await EnrollmentCredential.get_or_none(kind=self.KIND, identifier=parsed.identifier)
            if parsed is not None
            else None
        )
        stored = credential.secret_hash if credential is not None else None
        matches = secret_matches(parsed.secret if parsed is not None else "", stored)
        if credential is None or not matches or not is_usable(credential, datetime.now(UTC)):
            return None
        return credential

    async def consume(self, credential: EnrollmentCredential, *, actor: str) -> None:
        """One use, inside the transaction that records the request; Conflict if exhausted."""
        updated = await EnrollmentCredential.filter(
            id=credential.id, use_count=credential.use_count
        ).update(use_count=credential.use_count + 1, last_used_at=datetime.now(UTC))
        if not updated:
            raise Conflict("the challenge was used concurrently")
        if credential.max_uses is not None and credential.use_count + 1 > credential.max_uses:
            raise Conflict("the challenge is exhausted")  # pragma: no cover - checked before
        await self._audit(
            actor, "scep.challenge.use", credential, {"use_count": credential.use_count + 1}
        )

    @staticmethod
    async def _audit(
        actor: str, action: str, credential: EnrollmentCredential, details: dict[str, object]
    ) -> None:
        await AuditLog.record(
            actor=actor,
            action=action,
            object_type="enrollment_credential",
            object_id=credential.id,
            details={"kind": credential.kind.value, "identifier": credential.identifier, **details},
        )
