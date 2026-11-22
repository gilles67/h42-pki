"""Certificate of the built-in HTTPS server, issued by the local CA for itself (ADR-0013)."""

import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from h42pki.core.profiles import SERVICE_TLS_PROFILE
from h42pki.core.service_tls import issue_reason
from h42pki.errors import ServiceUnavailable
from h42pki.keystore import KeyStore
from h42pki.models import Authority, Certificate, CertificateStatus
from h42pki.services.authority import AuthorityService
from h42pki.services.issuance import IssuanceService
from h42pki.services.publication import PublicationService
from h42pki.services.settings import SettingsService


@dataclass(frozen=True, repr=False)
class TlsMaterial:
    """What the HTTPS listener loads: chain (leaf first), encrypted key and its one-time password.

    The key is encrypted PKCS#8 PEM (CLAUDE.md section 6.2): the password lives in memory only.
    """

    chain_pem: bytes
    key_pem: bytes
    password: bytes
    anchors_pem: str  # local CA chain, trust anchors for client certificates
    serial_hex: str
    sha256_fingerprint: str
    not_after: datetime

    def __repr__(self) -> str:
        return f"TlsMaterial(serial={self.serial_hex}, not_after={self.not_after.isoformat()})"


@dataclass(frozen=True)
class EnsureResult:
    certificate: Certificate | None  # None: no active CA yet
    issued: bool
    reason: str | None


def _pem(der: bytes) -> bytes:
    return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)


class TlsServiceManager:
    """Keeps a valid ``service_tls`` certificate for ``names`` (hostname first)."""

    def __init__(self, keystore: KeyStore, names: Sequence[str]) -> None:
        if not names:
            raise ValueError("the server needs a hostname (H42_PKI_SERVER_HOSTNAME)")
        self._keystore = keystore
        self._names = list(names)

    @property
    def names(self) -> list[str]:
        return list(self._names)

    @staticmethod
    async def _authority() -> Authority | None:
        return await AuthorityService().find_local()

    async def current(self) -> Certificate | None:
        """Latest valid service_tls certificate issued by the active local CA."""
        authority = await self._authority()
        if authority is None:
            return None
        return (
            await Certificate.filter(
                issuer_id=authority.id,
                profile__name=SERVICE_TLS_PROFILE,
                status=CertificateStatus.VALID,
            )
            .order_by("-created_at")
            .first()
        )

    async def ensure(self, now: datetime | None = None) -> EnsureResult:
        """Issue a certificate when none is valid, the names changed or the renewal is due."""
        now = now or datetime.now(UTC)
        if await self._authority() is None:
            return EnsureResult(None, issued=False, reason=None)
        current = await self.current()
        settings = (await SettingsService().effective()).tls_service
        reason = issue_reason(
            x509.load_der_x509_certificate(current.der) if current is not None else None,
            self._names,
            renew_before_days=settings.renew_before_days,
            now=now,
        )
        if reason is None:
            return EnsureResult(current, issued=False, reason=None)
        request = await IssuanceService(self._keystore).issue_service_certificate(
            self._names, validity_days=settings.validity_days
        )
        certificate = await Certificate.get(id=request.certificate_id)
        return EnsureResult(certificate, issued=True, reason=reason)

    async def material(self, certificate: Certificate) -> TlsMaterial:
        """Chain and key of ``certificate`` for an ``SSLContext``."""
        await certificate.fetch_related("private_key")
        if certificate.private_key is None:  # pragma: no cover - set at issuance
            raise ServiceUnavailable("the HTTPS server certificate has no private key here")
        password = secrets.token_hex(32).encode("ascii")
        key_pem = await self._keystore.export_encrypted(
            certificate.private_key.encrypted_key, password
        )
        ca_chain = [_pem(record.der) for record in await PublicationService().chain()]
        return TlsMaterial(
            chain_pem=_pem(certificate.der) + b"".join(ca_chain),
            key_pem=key_pem,
            password=password,
            anchors_pem=b"".join(ca_chain).decode("ascii"),
            serial_hex=certificate.serial_hex,
            sha256_fingerprint=certificate.sha256_fingerprint,
            not_after=certificate.not_after,
        )
