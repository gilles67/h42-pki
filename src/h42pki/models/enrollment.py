"""Enrollment credentials of the enrollment protocols (EST; SCEP and ACME later, ADR-0018)."""

from enum import StrEnum

from tortoise import fields

from h42pki.models.base import TimestampedModel


class CredentialKind(StrEnum):
    EST_BASIC = "est_basic"  # HTTP Basic account of EST


class CredentialStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class EnrollmentCredential(TimestampedModel):
    """A secret that lets a client enrol. No profile restriction: any enabled profile (ADR-0018)."""

    kind = fields.CharEnumField(CredentialKind, max_length=32)
    identifier = fields.CharField(max_length=64)  # the user name for est_basic
    secret_hash = fields.CharField(max_length=255)  # core.passwords format, never the secret
    status = fields.CharEnumField(CredentialStatus, default=CredentialStatus.ACTIVE, max_length=16)
    expires_at = fields.DatetimeField(null=True)
    description = fields.CharField(max_length=255, null=True)
    created_by = fields.CharField(max_length=128)
    last_used_at = fields.DatetimeField(null=True)

    class Meta:
        table = "enrollment_credential"
        unique_together = (("kind", "identifier"),)
        ordering = ["identifier"]

    def __repr__(self) -> str:  # never the hash
        return f"EnrollmentCredential({self.kind.value}:{self.identifier}, {self.status.value})"
