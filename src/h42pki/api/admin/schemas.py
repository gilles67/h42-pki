"""Hand-written request and response schemas of the admin API (snake_case, ADR-0006).

Tortoise models are never returned directly, and no schema exposes ``encrypted_key``.
"""

from datetime import datetime
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, ConfigDict, Field

from h42pki.ca.pki_models import Extensions, Subject
from h42pki.models import Certificate, CertificateStatus, KeyAlgorithm, KeyBackend, PrivateKey


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


class CertificateCreate(Schema):
    private_key_id: UUID | None = None
    subject: Subject
    extensions: Extensions = Field(default_factory=Extensions)


class CertificateOut(Schema):
    id: UUID
    serial_hex: str
    subject: Subject
    subject_dn: str | None
    status: CertificateStatus
    not_before: datetime | None
    not_after: datetime | None
    sha256_fingerprint: str | None
    extensions: Extensions

    @classmethod
    def from_model(cls, cert: Certificate) -> "CertificateOut":
        return cls(
            id=cert.id,
            serial_hex=cert.serial_hex,
            subject=cert.subject,
            subject_dn=cert.subject_dn,
            status=cert.status,
            not_before=cert.not_before,
            not_after=cert.not_after,
            sha256_fingerprint=cert.sha256_fingerprint,
            extensions=cert.extensions,
        )


def certificate_pem(der: bytes) -> bytes:
    """Convert a DER certificate to PEM (PEM is produced at output time only)."""
    return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)
