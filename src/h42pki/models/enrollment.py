"""Enrollment credentials of the enrollment protocols (EST; SCEP and ACME later, ADR-0018)."""

from enum import StrEnum

from tortoise import fields

from h42pki.models.base import TimestampedModel


class CredentialKind(StrEnum):
    EST_BASIC = "est_basic"  # HTTP Basic account of EST
    SCEP_CHALLENGE = "scep_challenge"  # challengePassword of SCEP, generated (ADR-0019)


class CredentialStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class EnrollmentCredential(TimestampedModel):
    """A secret that lets a client enrol. No profile restriction: any enabled profile (ADR-0018)."""

    kind = fields.CharEnumField(CredentialKind, max_length=32)
    identifier = fields.CharField(max_length=64)  # user name (EST), challenge id (SCEP)
    # core.passwords format (EST), sha256$<hex> (SCEP, core.challenges): never the secret.
    secret_hash = fields.CharField(max_length=255)
    status = fields.CharEnumField(CredentialStatus, default=CredentialStatus.ACTIVE, max_length=16)
    expires_at = fields.DatetimeField(null=True)
    # SCEP challenges: uses allowed (None = reusable, for a fleet) and made. Unused by EST.
    max_uses = fields.IntField(null=True)
    use_count = fields.IntField(default=0)
    description = fields.CharField(max_length=255, null=True)
    created_by = fields.CharField(max_length=128)
    last_used_at = fields.DatetimeField(null=True)

    class Meta:
        table = "enrollment_credential"
        unique_together = (("kind", "identifier"),)
        ordering = ["identifier"]

    def __repr__(self) -> str:  # never the hash
        return f"EnrollmentCredential({self.kind.value}:{self.identifier}, {self.status.value})"
