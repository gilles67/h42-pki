"""Certificates: read access. Certificates are created by AuthorityService.init_root (the root
CA certificate) and by IssuanceService (everything signed by the CA), nowhere else (ADR-0010).
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from tortoise.expressions import Q
from tortoise.transactions import in_transaction

from h42pki.errors import Conflict, NotFound
from h42pki.models import (
    AuditLog,
    Certificate,
    CertificateStatus,
    Channel,
    KeyPurpose,
    PrivateKey,
)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
# A chain is short (root -> intermediates -> leaf); the bound only guards against bad data.
MAX_CHAIN_LENGTH = 16


def effective_status(certificate: Certificate, now: datetime) -> CertificateStatus:
    """Status as seen by clients: a valid certificate past its not_after is expired (B34).

    Nothing is written here: the expiry task writes it every hour; this covers the time in between.
    """
    if certificate.status is CertificateStatus.VALID and certificate.not_after <= now:
        return CertificateStatus.EXPIRED
    return certificate.status


@dataclass(frozen=True)
class CertificatePage:
    items: list[Certificate]
    total: int


class CertificateService:
    async def get(self, cert_id: UUID) -> Certificate:
        return await Certificate.get(id=cert_id).prefetch_related("profile", "issuer")

    @staticmethod
    async def delete_stored_key(cert_id: UUID, *, actor: str) -> None:
        """Delete the copy of a key generated for an EST client (serverkeygen, ADR-0018).

        404 without stored key; 409 for any other key (the CA key, the HTTPS server key). The
        key is never returned: deleting it is the only operation on it.
        """
        certificate = await Certificate.get(id=cert_id)
        if certificate.private_key_id is None:
            raise NotFound("no private key is stored for this certificate")
        key = await PrivateKey.get(id=certificate.private_key_id)
        if key.purpose is not KeyPurpose.SERVERKEYGEN:
            raise Conflict(
                f"this is a {key.purpose.value} key, managed by the CA: only a key generated for "
                "an EST client (serverkeygen) can be deleted"
            )
        async with in_transaction():
            await Certificate.filter(id=certificate.id).update(private_key_id=None)
            await PrivateKey.filter(id=key.id).delete()
            await AuditLog.record(
                actor=actor,
                action="private_key.delete",
                object_type="private_key",
                object_id=key.id,
                details={
                    "purpose": key.purpose.value,
                    "algorithm": key.algorithm.value,
                    "certificate_id": str(certificate.id),
                    "serial_hex": certificate.serial_hex,
                },
            )

    async def search(
        self,
        *,
        status: CertificateStatus | None = None,
        profile: str | None = None,
        channel: Channel | None = None,
        q: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
        now: datetime | None = None,
    ) -> CertificatePage:
        """Certificates, newest first; ``q`` is a case-insensitive substring of the subject DN.

        ``status`` filters on the effective status (see :func:`effective_status`).
        """
        now = now or datetime.now(UTC)
        query = Certificate.all()
        if status is CertificateStatus.VALID:
            query = query.filter(status=CertificateStatus.VALID, not_after__gt=now)
        elif status is CertificateStatus.EXPIRED:
            query = query.filter(
                Q(status=CertificateStatus.EXPIRED)
                | Q(status=CertificateStatus.VALID, not_after__lte=now)
            )
        elif status is not None:
            query = query.filter(status=status)
        if profile is not None:
            query = query.filter(profile__name=profile)
        if channel is not None:
            query = query.filter(channel=channel)
        if q:
            query = query.filter(subject_dn__icontains=q)
        total = await query.count()
        items = (
            await query.order_by("-created_at", "-id")
            .offset(offset)
            .limit(limit)
            .prefetch_related("profile", "issuer")
        )
        return CertificatePage(items=items, total=total)

    async def chain(self, certificate: Certificate) -> list[Certificate]:
        """``certificate`` followed by its issuers' certificates, up to the root included."""
        chain = [certificate]
        current = certificate
        while current.issuer_id is not None and len(chain) < MAX_CHAIN_LENGTH:
            issuer_certificate = await Certificate.get_or_none(authority_id=current.issuer_id)
            if issuer_certificate is None:  # issuer known without its certificate
                break
            chain.append(issuer_certificate)
            current = issuer_certificate
        return chain
