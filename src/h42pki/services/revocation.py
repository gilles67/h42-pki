"""Revocation of certificates issued by a local CA (ADR-0017).

Final: no suspension. The certificate is marked, audited, then the CRL of its issuer is generated
again at once (when enabled) and the OCSP cache of this process is told. The API, the CLI and the
federation (revocation of a child CA) all come here.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from cryptography import x509
from tortoise.transactions import in_transaction

from h42pki.core.crl import check_invalidity_date, revocation_reason
from h42pki.core.profiles import SERVICE_TLS_PROFILE
from h42pki.errors import Conflict, H42Error, MissingPassphrase
from h42pki.keystore import KEY_OPERATIONS_REQUIREMENT, KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    CertificateStatus,
)
from h42pki.services.crl import CrlService

log = logging.getLogger(__name__)

# Told about each revocation (issuer id, serial): the OCSP cache of this process.
RevocationListener = Callable[[UUID, str], None]


class RevocationService:
    def __init__(
        self, keystore: KeyStore | None = None, *, on_revoked: RevocationListener | None = None
    ) -> None:
        """``keystore`` is needed when the issuer publishes a CRL (it is signed at once)."""
        self._keystore = keystore
        self._on_revoked = on_revoked

    async def revoke(
        self,
        certificate_id: UUID,
        *,
        reason: x509.ReasonFlags | str,
        invalidity_date: datetime | None = None,
        actor: str,
    ) -> Certificate:
        """Revoke a certificate issued by a local CA; 409 when it cannot be, 422 bad input."""
        now = datetime.now(UTC)
        flag = reason if isinstance(reason, x509.ReasonFlags) else revocation_reason(reason)
        if isinstance(reason, x509.ReasonFlags):
            revocation_reason(reason.name)  # suspension refused whatever the caller
        check_invalidity_date(invalidity_date, now)
        certificate = await Certificate.get(id=certificate_id).prefetch_related(
            "issuer", "profile", "authority"
        )
        issuer = self._check_revocable(certificate)
        if issuer.crl_enabled and self._keystore is None:
            # Refused before anything changes: a revocation is never left out of the CRL.
            raise MissingPassphrase(
                f"the CRL of {issuer.name} must be signed: {KEY_OPERATIONS_REQUIREMENT}"
            )

        async with in_transaction():
            updated = (
                await Certificate.filter(id=certificate.id)
                .exclude(status=CertificateStatus.REVOKED)
                .update(
                    status=CertificateStatus.REVOKED,
                    revoked_at=now,
                    revocation_reason=flag,
                    invalidity_date=invalidity_date,
                )
            )
            if not updated:
                raise Conflict("the certificate is already revoked")
            child = certificate.authority
            if child is not None and child.kind is AuthorityKind.CHILD:
                await Authority.filter(id=child.id).update(status=AuthorityStatus.REVOKED)
            await AuditLog.record(
                actor=actor,
                action="certificate.revoke",
                object_type="certificate",
                object_id=certificate.id,
                details={
                    "serial_hex": certificate.serial_hex,
                    "subject_dn": certificate.subject_dn,
                    "issuer": issuer.name,
                    "reason": flag.name,
                    "invalidity_date": (
                        invalidity_date.isoformat() if invalidity_date is not None else None
                    ),
                    "child_ca": child.name if child is not None else None,
                },
            )

        if self._on_revoked is not None:
            self._on_revoked(issuer.id, certificate.serial_hex)
        await self._refresh_crl(issuer, actor=actor)
        return await Certificate.get(id=certificate.id).prefetch_related("issuer", "profile")

    @staticmethod
    def _check_revocable(certificate: Certificate) -> Authority:
        """The local CA that issued ``certificate``; 409 for what this CA may not revoke."""
        if certificate.status is CertificateStatus.REVOKED:
            raise Conflict("the certificate is already revoked")
        own = certificate.authority
        if own is not None and own.kind is AuthorityKind.LOCAL:
            raise Conflict(
                "this is the certificate of the local CA: only the CA that issued it can revoke it"
            )
        issuer = certificate.issuer
        if issuer is None or issuer.kind is not AuthorityKind.LOCAL:
            raise Conflict("this certificate was not issued by this CA")
        profile = certificate.profile
        if profile is not None and profile.name == SERVICE_TLS_PROFILE:
            raise Conflict(
                "this is the certificate of the built-in HTTPS server, managed by the CA itself"
            )
        return issuer

    async def _refresh_crl(self, issuer: Authority, *, actor: str) -> None:
        if not issuer.crl_enabled:
            return
        try:
            await CrlService(self._keystore).ensure_fresh(issuer, force=True, actor=actor)
        except H42Error as exc:
            # The revocation stands; the scheduled task catches up (uncovered revocation).
            log.warning(
                "CRL of %s not generated after a revocation (%s); the next scheduled check "
                "will try again",
                issuer.name,
                exc.detail,
            )
