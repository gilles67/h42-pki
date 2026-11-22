"""Certificates: read access. Certificates are created by AuthorityService.init_root (the root
CA certificate) and by IssuanceService (everything signed by the CA), nowhere else (ADR-0010).
"""

from dataclasses import dataclass
from uuid import UUID

from h42pki.models import Certificate, CertificateStatus, Channel

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
# A chain is short (root -> intermediates -> leaf); the bound only guards against bad data.
MAX_CHAIN_LENGTH = 16


@dataclass(frozen=True)
class CertificatePage:
    items: list[Certificate]
    total: int


class CertificateService:
    async def get(self, cert_id: UUID) -> Certificate:
        return await Certificate.get(id=cert_id).prefetch_related("profile", "issuer")

    async def search(
        self,
        *,
        status: CertificateStatus | None = None,
        profile: str | None = None,
        channel: Channel | None = None,
        q: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> CertificatePage:
        """Certificates, newest first; ``q`` is a case-insensitive substring of the subject DN."""
        query = Certificate.all()
        if status is not None:
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
