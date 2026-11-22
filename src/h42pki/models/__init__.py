"""Tortoise models, one module per aggregate (registered as the "models" app)."""

from h42pki.models.audit import AuditLog
from h42pki.models.authority import Authority, AuthorityKind, AuthorityStatus
from h42pki.models.certificate import Certificate, CertificateStatus
from h42pki.models.private_key import KeyBackend, PrivateKey
from h42pki.models.profile import Profile
from h42pki.models.request import CertificateRequest, Channel, RequestStatus
from h42pki.models.setting import Setting, SettingsRevision

__models__ = [
    PrivateKey,
    Authority,
    Profile,
    Certificate,
    CertificateRequest,
    AuditLog,
    Setting,
    SettingsRevision,
]

__all__ = [
    "AuditLog",
    "Authority",
    "AuthorityKind",
    "AuthorityStatus",
    "Certificate",
    "CertificateRequest",
    "CertificateStatus",
    "Channel",
    "KeyBackend",
    "PrivateKey",
    "Profile",
    "RequestStatus",
    "Setting",
    "SettingsRevision",
]
