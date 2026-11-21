"""Tortoise models, one module per aggregate (registered as the "models" app)."""

from h42pki.models.audit import AuditLog
from h42pki.models.authority import Authority, AuthorityKind, AuthorityStatus
from h42pki.models.certificate import Certificate, CertificateStatus, new_serial_hex
from h42pki.models.private_key import KeyAlgorithm, KeyBackend, PrivateKey

__models__ = [PrivateKey, Authority, Certificate, AuditLog]

__all__ = [
    "AuditLog",
    "Authority",
    "AuthorityKind",
    "AuthorityStatus",
    "Certificate",
    "CertificateStatus",
    "KeyAlgorithm",
    "KeyBackend",
    "PrivateKey",
    "new_serial_hex",
]
