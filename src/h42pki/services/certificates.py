"""Certificates: read access. Certificates are created by AuthorityService.init_root (the root
CA certificate) and by IssuanceService (everything signed by the CA), nowhere else (ADR-0010).
"""

from uuid import UUID

from h42pki.models import Certificate


class CertificateService:
    async def get(self, cert_id: UUID) -> Certificate:
        return await Certificate.get(id=cert_id).prefetch_related("profile")
