"""CRL of the local CAs: generation, freshness, publication (ADR-0017).

Only this service signs a CRL, from a revocation or a scheduled check; the public endpoint serves
the last stored CRL and never signs (no key operation triggered by an anonymous request).
"""

import asyncio
import builtins
import logging
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tortoise.exceptions import IntegrityError
from tortoise.transactions import in_transaction

from h42pki.core.crl import RevokedEntry, build_crl, crl_due
from h42pki.errors import MissingPassphrase, NotFound
from h42pki.keystore import KEY_OPERATIONS_REQUIREMENT, KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    CertificateStatus,
    Crl,
    PrivateKey,
)
from h42pki.services.settings import SettingsService

log = logging.getLogger(__name__)

SYSTEM_ACTOR = "system"
# Local CAs whose CRL is kept fresh: the current one (active or revoked by its parent) and
# previous generations while they have certificates left (ARCHITECTURE section 8.3).
CURRENT_STATUSES = (AuthorityStatus.ACTIVE, AuthorityStatus.REVOKED)
PREVIOUS_STATUSES = (AuthorityStatus.ROLLING_OVER, AuthorityStatus.RETIRED)


class CrlService:
    def __init__(self, keystore: KeyStore | None = None) -> None:
        """``keystore`` is only needed to generate a CRL; reading needs none (B32)."""
        self._key_store = keystore

    @property
    def _keystore(self) -> KeyStore:
        if self._key_store is None:
            raise MissingPassphrase(KEY_OPERATIONS_REQUIREMENT)
        return self._key_store

    # --- reading --------------------------------------------------------------------------

    @staticmethod
    async def current(authority: Authority) -> Crl | None:
        """The latest CRL of ``authority`` (highest number), if any."""
        return await Crl.filter(authority_id=authority.id).order_by("-crl_number").first()

    @classmethod
    async def published(cls, name: str) -> Crl:
        """CRL served at ``/crl/{name}.crl``: a local CA with the CRL enabled; 404 otherwise."""
        authority = await Authority.get_or_none(name=name, kind=AuthorityKind.LOCAL)
        crl = await cls.current(authority) if authority is not None else None
        if authority is None or not authority.crl_enabled or crl is None:
            raise NotFound(f"no CRL published for {name!r}")
        return crl

    # --- generation -----------------------------------------------------------------------

    async def ensure_fresh(
        self,
        authority: Authority,
        *,
        force: bool = False,
        actor: str = SYSTEM_ACTOR,
        now: datetime | None = None,
    ) -> Crl | None:
        """Generate a CRL when needed; None when the CA has no CRL.

        Needed: forced (right after a revocation), none yet, ``crl.regenerate_before_hours``
        before nextUpdate, or a revocation that the latest CRL does not cover (a generation that
        failed after the revocation is caught up here).
        """
        if not authority.crl_enabled:
            return None
        now = now or datetime.now(UTC)
        latest = await self.current(authority)
        if not force and latest is not None:
            settings = (await SettingsService().effective()).crl
            due = crl_due(
                latest.next_update, now, regenerate_before_hours=settings.regenerate_before_hours
            )
            if not due and not await self._uncovered(authority, latest):
                return latest
        return await self.generate(authority, actor=actor, now=now)

    @staticmethod
    async def _uncovered(authority: Authority, crl: Crl) -> bool:
        return await Certificate.filter(
            issuer_id=authority.id,
            status=CertificateStatus.REVOKED,
            revoked_at__gte=crl.entries_as_of,
        ).exists()

    async def generate(
        self, authority: Authority, *, actor: str = SYSTEM_ACTOR, now: datetime | None = None
    ) -> Crl:
        """Sign a new CRL with the next number (one retry if another process took it)."""
        try:
            return await self._generate(authority, actor=actor, now=now)
        except IntegrityError:  # same number taken concurrently (CLI and server)
            return await self._generate(authority, actor=actor, now=now)

    async def _generate(self, authority: Authority, *, actor: str, now: datetime | None) -> Crl:
        if authority.private_key_id is None:  # pragma: no cover - local CAs have a key
            raise NotFound(f"the CA {authority.name!r} has no private key")
        settings = (await SettingsService().effective()).crl
        entries_as_of = datetime.now(UTC)
        now = now or entries_as_of
        record = await Certificate.get(authority_id=authority.id)
        issuer_cert = x509.load_der_x509_certificate(record.der)
        stored_key = await PrivateKey.get(id=authority.private_key_id)
        issuer_key = await self._keystore.load(stored_key.encrypted_key)
        revoked = await Certificate.filter(
            issuer_id=authority.id, status=CertificateStatus.REVOKED, not_after__gt=now
        )
        entries = [
            RevokedEntry(
                serial_hex=certificate.serial_hex,
                revoked_at=certificate.revoked_at or now,
                reason=certificate.revocation_reason,
                invalidity_date=certificate.invalidity_date,
                not_after=certificate.not_after,
            )
            for certificate in revoked
        ]
        latest = await self.current(authority)
        number = latest.crl_number + 1 if latest is not None else 1
        crl = await asyncio.to_thread(
            build_crl,
            issuer_cert,
            issuer_key,
            entries,
            crl_number=number,
            now=now,
            validity_hours=settings.validity_hours,
        )
        async with in_transaction():
            stored = await Crl.create(
                authority_id=authority.id,
                crl_number=number,
                this_update=crl.last_update_utc,
                next_update=crl.next_update_utc,
                entries_as_of=entries_as_of,
                entries=len(crl),
                der=crl.public_bytes(serialization.Encoding.DER),
            )
            await AuditLog.record(
                actor=actor,
                action="crl.generate",
                object_type="authority",
                object_id=authority.id,
                details={
                    "name": authority.name,
                    "crl_number": number,
                    "entries": len(crl),
                    "next_update": stored.next_update.isoformat(),
                },
            )
        log.info(
            "CRL %d of %s generated: %d entries, next update %s",
            number,
            authority.name,
            len(crl),
            stored.next_update.isoformat(),
        )
        return stored

    async def refresh_all(self, *, now: datetime | None = None) -> builtins.list[Crl]:
        """Scheduled check: keep the CRL of every local CA that needs one fresh."""
        now = now or datetime.now(UTC)
        refreshed: list[Crl] = []
        for authority in await self.authorities(now):
            crl = await self.ensure_fresh(authority, now=now)
            if crl is not None:
                refreshed.append(crl)
        return refreshed

    @staticmethod
    async def authorities(now: datetime) -> builtins.list[Authority]:
        """Local CAs with a CRL that must stay published."""
        candidates = await Authority.filter(
            kind=AuthorityKind.LOCAL,
            crl_enabled=True,
            status__in=[*CURRENT_STATUSES, *PREVIOUS_STATUSES],
        ).order_by("name")
        kept: list[Authority] = []
        for authority in candidates:
            if (
                authority.status in PREVIOUS_STATUSES
                and not await Certificate.filter(issuer_id=authority.id, not_after__gt=now).exists()
            ):
                continue  # a previous generation whose certificates all expired
            kept.append(authority)
        return kept
