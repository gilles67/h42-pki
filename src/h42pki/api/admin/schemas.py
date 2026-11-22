"""Hand-written request and response schemas of the admin API (snake_case, ADR-0006).

Tortoise models are never returned directly, and no schema exposes ``encrypted_key``.
"""

from datetime import datetime
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, ConfigDict, Field

from h42pki.core.inspection import ca_issuers_url, subject_alternative_names
from h42pki.core.keys import KeyAlgorithm
from h42pki.core.profiles import ProfileSpec, SanType
from h42pki.core.validity import MAX_VALIDITY_DAYS, MIN_VALIDITY_DAYS
from h42pki.models import (
    Authority,
    AuthorityStatus,
    Certificate,
    CertificateRequest,
    CertificateStatus,
    Channel,
    KeyBackend,
    PrivateKey,
    Profile,
    RequestStatus,
)
from h42pki.services.profiles import spec_of

MAX_CSR_PEM_LENGTH = 65536


class Schema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PrivateKeyCreate(Schema):
    algorithm: KeyAlgorithm


class PrivateKeyOut(Schema):
    id: UUID
    algorithm: KeyAlgorithm
    backend: KeyBackend
    public_key_pem: str
    created_at: datetime

    @classmethod
    def from_model(cls, key: PrivateKey) -> "PrivateKeyOut":
        public_key = serialization.load_der_public_key(key.public_key_der)
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cls(
            id=key.id,
            algorithm=key.algorithm,
            backend=key.backend,
            public_key_pem=pem.decode("ascii"),
            created_at=key.created_at,
        )


class SanOut(Schema):
    type: SanType
    value: str


class CertificateOut(Schema):
    id: UUID
    serial_hex: str
    subject_dn: str
    status: CertificateStatus
    not_before: datetime
    not_after: datetime
    sha256_fingerprint: str
    profile: str | None  # None for the root CA certificate
    channel: Channel
    issuer: str | None  # name of the issuing CA; None for the root CA certificate
    issuer_id: UUID | None
    sans: list[SanOut] = Field(description="Subject alternative names, read from the DER.")
    ca_issuers_url: str | None = Field(
        description="AIA caIssuers URL, read from the DER; None when absent."
    )

    @classmethod
    def from_model(cls, cert: Certificate) -> "CertificateOut":
        """``cert.profile`` and ``cert.issuer`` must be prefetched."""
        parsed = x509.load_der_x509_certificate(cert.der)
        return cls(
            id=cert.id,
            serial_hex=cert.serial_hex,
            subject_dn=cert.subject_dn,
            status=cert.status,
            not_before=cert.not_before,
            not_after=cert.not_after,
            sha256_fingerprint=cert.sha256_fingerprint,
            profile=cert.profile.name if cert.profile is not None else None,
            channel=cert.channel,
            issuer=cert.issuer.name if cert.issuer is not None else None,
            issuer_id=cert.issuer_id,
            sans=[
                SanOut(type=san.type, value=san.value) for san in subject_alternative_names(parsed)
            ],
            ca_issuers_url=ca_issuers_url(parsed),
        )


class CertificateList(Schema):
    items: list[CertificateOut]
    total: int = Field(description="Number of certificates matching the filters.")
    limit: int
    offset: int


def certificate_pem(der: bytes) -> bytes:
    """Convert a DER certificate to PEM (PEM is produced at output time only)."""
    return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)


# --- authority ------------------------------------------------------------------------------


class AuthorityOut(Schema):
    name: str
    status: AuthorityStatus
    certificate_id: UUID
    subject_dn: str
    sha256_fingerprint: str
    not_before: datetime
    not_after: datetime
    path_length: int | None
    key_algorithm: KeyAlgorithm
    public_base_url: str | None

    @classmethod
    def from_model(cls, authority: Authority, certificate: Certificate) -> "AuthorityOut":
        """``authority.private_key`` must be prefetched."""
        assert authority.private_key is not None  # noqa: S101 - set by init_root
        return cls(
            name=authority.name,
            status=authority.status,
            certificate_id=certificate.id,
            subject_dn=certificate.subject_dn,
            sha256_fingerprint=certificate.sha256_fingerprint,
            not_before=certificate.not_before,
            not_after=certificate.not_after,
            path_length=authority.path_length,
            key_algorithm=authority.private_key.algorithm,
            public_base_url=authority.public_base_url,
        )


# --- profiles -------------------------------------------------------------------------------


class ProfileOut(ProfileSpec):
    builtin: bool

    @classmethod
    def from_model(cls, profile: Profile) -> "ProfileOut":
        return cls(**spec_of(profile).model_dump(), builtin=profile.builtin)


# --- certificate requests -------------------------------------------------------------------


class RequestCreate(Schema):
    csr_pem: str = Field(
        max_length=MAX_CSR_PEM_LENGTH,
        description="PKCS#10 certificate signing request, PEM encoded.",
        examples=["-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"],
    )
    profile: str = Field(description="Name of the profile, see GET /api/v1/profiles.")
    validity_days: int | None = Field(
        default=None,
        ge=MIN_VALIDITY_DAYS,
        le=MAX_VALIDITY_DAYS,
        description="Requested validity in days; the profile default when omitted, at most "
        "the profile maximum.",
    )


class RequestReject(Schema):
    reason: str = Field(min_length=1, max_length=1000)


class RequestOut(Schema):
    id: UUID
    profile: str
    status: RequestStatus
    subject_dn: str
    requested_validity_days: int | None
    requester: str
    channel: Channel
    certificate_id: UUID | None
    validity_truncated: bool | None = Field(
        description="True when not_after was shortened to the CA certificate's not_after."
    )
    ignored_extensions: list[str] = Field(
        description="Extensions present in the CSR and not copied (the profile decides)."
    )
    rejection_reason: str | None
    failure: str | None
    decided_by: str | None
    decided_at: datetime | None
    created_at: datetime

    @classmethod
    def from_model(cls, request: CertificateRequest) -> "RequestOut":
        """``request.profile`` must be prefetched."""
        metadata = request.metadata
        return cls(
            id=request.id,
            profile=request.profile.name,
            status=request.status,
            subject_dn=request.subject_dn,
            requested_validity_days=request.requested_validity_days,
            requester=request.requester,
            channel=request.channel,
            certificate_id=request.certificate_id,
            validity_truncated=metadata.get("validity_truncated"),
            ignored_extensions=metadata.get("ignored_extensions", []),
            rejection_reason=request.rejection_reason,
            failure=metadata.get("failure"),
            decided_by=request.decided_by,
            decided_at=request.decided_at,
            created_at=request.created_at,
        )
