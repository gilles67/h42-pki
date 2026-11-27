"""Client certificates checked by the application (B45, ADR-0018).

The HTTPS listener already verified a certificate presented in TLS, but against the whole chain of
the local CA (its parent and the root included) and ``server.client_trust_anchors``. A certificate
forwarded by a trusted proxy (``Client-Cert``) was not verified at all. Both are checked here:

- issued **directly** by a local CA (current, revoked by its parent, or a previous generation): in
  its validity period, known in the database and not revoked;
- or, unless ``local_only``, issued directly by an anchor of ``server.client_trust_anchors``: in its
  validity period (the revocation of an external CA is not checked).

An intermediate between an external anchor and the certificate is not followed. As OpenSSL does in
the TLS handshake (checked by a spike in phase 4), a certificate whose extended key usage leaves out
``clientAuth`` is refused: a ``tls_server`` certificate cannot authenticate a client.
"""

from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID

from h42pki.errors import Unauthorized
from h42pki.models import (
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    CertificateStatus,
)
from h42pki.services.settings import SettingsService

LOCAL_ISSUERS = (
    AuthorityStatus.ACTIVE,
    AuthorityStatus.REVOKED,
    AuthorityStatus.ROLLING_OVER,
    AuthorityStatus.RETIRED,
)


class ClientCertificateRefused(Unauthorized):
    """The client certificate cannot authenticate the request (the reason stays in the log)."""


@dataclass(frozen=True)
class VerifiedClient:
    certificate: x509.Certificate
    fingerprint: str  # SHA-256, hex
    record: Certificate | None  # the stored certificate, when a local CA issued it
    issuer: Authority | None  # that local CA


def _client_usage(certificate: x509.Certificate) -> bool:
    try:
        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return True  # no restriction
    return ExtendedKeyUsageOID.CLIENT_AUTH in usages or (
        ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in usages
    )


def _issued_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        certificate.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


async def verify_client_certificate(
    certificate: x509.Certificate, *, now: datetime, local_only: bool = False
) -> VerifiedClient:
    """The verified client, or ``ClientCertificateRefused`` with a short reason."""
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise ClientCertificateRefused("the client certificate is outside its validity period")
    if not _client_usage(certificate):
        raise ClientCertificateRefused("the certificate is not meant for client authentication")
    local = await Authority.filter(
        kind=AuthorityKind.LOCAL, status__in=LOCAL_ISSUERS
    ).prefetch_related("certificate")
    for authority in local:
        issuer = x509.load_der_x509_certificate(authority.certificate.der)
        if not _issued_by(certificate, issuer):
            continue
        record = await Certificate.get_or_none(
            issuer_id=authority.id, serial_hex=format(certificate.serial_number, "x")
        )
        if record is None or record.sha256_fingerprint != fingerprint:
            raise ClientCertificateRefused("the client certificate is unknown to this CA")
        if record.status is CertificateStatus.REVOKED:
            raise ClientCertificateRefused("the client certificate is revoked")
        return VerifiedClient(certificate, fingerprint, record, authority)
    if not local_only:
        anchors = (await SettingsService().effective()).server.client_trust_anchors
        for pem in anchors:
            anchor = x509.load_pem_x509_certificate(pem.encode("ascii"))
            if _issued_by(certificate, anchor):
                return VerifiedClient(certificate, fingerprint, None, None)
    raise ClientCertificateRefused(
        "the client certificate was not issued by this CA"
        + ("" if local_only else " nor by a trusted client anchor")
    )
