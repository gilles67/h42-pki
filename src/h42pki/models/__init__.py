"""Tortoise models, one module per aggregate (registered as the "models" app)."""

from h42pki.models.audit import AuditLog
from h42pki.models.authority import Authority, AuthorityKind, AuthorityStatus
from h42pki.models.certificate import Certificate, CertificateStatus
from h42pki.models.crl import Crl
from h42pki.models.enrollment import CredentialKind, CredentialStatus, EnrollmentCredential
from h42pki.models.federation import FederationInvitation, InvitationStatus
from h42pki.models.private_key import KeyBackend, KeyPurpose, PrivateKey
from h42pki.models.profile import Profile
from h42pki.models.request import CertificateRequest, Channel, RequestStatus
from h42pki.models.scep import ScepNonce, ScepTransaction, ScepTransactionStatus
from h42pki.models.setting import Setting, SettingsRevision

__models__ = [
    PrivateKey,
    Authority,
    Profile,
    Certificate,
    CertificateRequest,
    Crl,
    FederationInvitation,
    EnrollmentCredential,
    ScepTransaction,
    ScepNonce,
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
    "CredentialKind",
    "CredentialStatus",
    "Crl",
    "EnrollmentCredential",
    "FederationInvitation",
    "InvitationStatus",
    "KeyBackend",
    "KeyPurpose",
    "PrivateKey",
    "Profile",
    "RequestStatus",
    "ScepNonce",
    "ScepTransaction",
    "ScepTransactionStatus",
    "Setting",
    "SettingsRevision",
]
