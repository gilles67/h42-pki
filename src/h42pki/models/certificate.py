"""Certificates, stored in DER."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from cryptography.x509 import ReasonFlags
from tortoise import fields

from h42pki.core.serial import new_serial_hex
from h42pki.models.base import TimestampedModel
from h42pki.models.request import Channel

if TYPE_CHECKING:
    from h42pki.models.authority import Authority
    from h42pki.models.private_key import PrivateKey
    from h42pki.models.profile import Profile


class CertificateStatus(StrEnum):
    # A certificate is always stored already signed; `on_hold` comes with revocation (phase 3).
    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Certificate(TimestampedModel):
    # NULL issuer = the root CA certificate, issued by its own key (ADR-0010).
    issuer: fields.ForeignKeyNullableRelation[Authority] = fields.ForeignKeyField(
        "models.Authority",
        related_name="issued_certificates",
        null=True,
        on_delete=fields.RESTRICT,
    )
    # Set when this certificate is the certificate *of* a CA (Authority.certificate).
    authority: fields.OneToOneNullableRelation[Authority] = fields.OneToOneField(
        "models.Authority",
        related_name="certificate",
        null=True,
        on_delete=fields.SET_NULL,
    )
    # NULL for the root CA certificate, which no profile describes.
    profile: fields.ForeignKeyNullableRelation[Profile] = fields.ForeignKeyField(
        "models.Profile", related_name="certificates", null=True, on_delete=fields.RESTRICT
    )
    channel = fields.CharEnumField(Channel, default=Channel.API, max_length=16)
    serial_hex = fields.CharField(max_length=40, default=new_serial_hex)
    subject_dn = fields.TextField()  # RFC 4514 (core.names.rfc4514); the DER is the source
    private_key: fields.ForeignKeyNullableRelation[PrivateKey] = fields.ForeignKeyField(
        "models.PrivateKey",
        related_name="certificates",
        null=True,
        on_delete=fields.RESTRICT,
    )
    public_key_der = fields.BinaryField()
    der = fields.BinaryField()
    sha256_fingerprint = fields.CharField(max_length=64, unique=True)
    status = fields.CharEnumField(CertificateStatus, default=CertificateStatus.VALID, max_length=16)
    not_before = fields.DatetimeField()
    not_after = fields.DatetimeField()
    revoked_at = fields.DatetimeField(null=True)
    revocation_reason = fields.CharEnumField(ReasonFlags, max_length=32, null=True)
    invalidity_date = fields.DatetimeField(null=True)

    # Foreign key columns created by Tortoise, declared for type checkers.
    issuer_id: UUID | None
    authority_id: UUID | None
    profile_id: UUID | None
    private_key_id: UUID | None

    class Meta:
        table = "certificate"
        unique_together = (("issuer", "serial_hex"),)
