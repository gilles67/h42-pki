"""Certificates, stored in DER."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from cryptography.x509 import ReasonFlags
from tortoise import fields

from h42pki.ca.pki_models import Extensions
from h42pki.core.names import Subject
from h42pki.core.serial import new_serial_hex
from h42pki.models.base import TimestampedModel

if TYPE_CHECKING:
    from h42pki.models.authority import Authority
    from h42pki.models.private_key import PrivateKey


class CertificateStatus(StrEnum):
    # `pending` lasts until CertificateRequest exists; `on_hold` comes with revocation (phase 3).
    PENDING = "pending"
    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Certificate(TimestampedModel):
    # NULL issuer = self-signed certificate.
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
    serial_hex = fields.CharField(max_length=40, default=new_serial_hex)
    subject: fields.JSONField[Subject] = fields.JSONField(field_type=Subject)
    subject_dn = fields.TextField(null=True)  # RFC 4514, set when signed
    # Requested extensions, until profiles exist.
    extensions: fields.JSONField[Extensions] = fields.JSONField(field_type=Extensions)
    private_key: fields.ForeignKeyNullableRelation[PrivateKey] = fields.ForeignKeyField(
        "models.PrivateKey",
        related_name="certificates",
        null=True,
        on_delete=fields.RESTRICT,
    )
    public_key_der = fields.BinaryField(null=True)
    der = fields.BinaryField(null=True)  # NULL until signed
    sha256_fingerprint = fields.CharField(max_length=64, unique=True, null=True)
    status = fields.CharEnumField(
        CertificateStatus, default=CertificateStatus.PENDING, max_length=16
    )
    not_before = fields.DatetimeField(null=True)
    not_after = fields.DatetimeField(null=True)
    revoked_at = fields.DatetimeField(null=True)
    revocation_reason = fields.CharEnumField(ReasonFlags, max_length=32, null=True)
    invalidity_date = fields.DatetimeField(null=True)

    class Meta:
        table = "certificate"
        unique_together = (("issuer", "serial_hex"),)
