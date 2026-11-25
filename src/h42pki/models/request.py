"""Certificate requests (CSR + profile), decided automatically or manually."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from tortoise import fields

from h42pki.models.base import TimestampedModel

if TYPE_CHECKING:
    from h42pki.models.certificate import Certificate
    from h42pki.models.profile import Profile


class RequestStatus(StrEnum):
    PENDING = "pending"
    ISSUED = "issued"
    REJECTED = "rejected"
    FAILED = "failed"  # approved, but the issuance could not happen


class Channel(StrEnum):
    """How a certificate or a request reached the CA (EST, SCEP, ACME, federation later)."""

    CLI = "cli"
    API = "api"
    FEDERATION = "federation"  # child CA enrolled with an invitation (ADR-0015)
    SYSTEM = "system"  # issued by the CA for itself: built-in HTTPS server (ADR-0013)


class CertificateRequest(TimestampedModel):
    csr_der = fields.BinaryField()
    profile: fields.ForeignKeyRelation[Profile] = fields.ForeignKeyField(
        "models.Profile", related_name="requests", on_delete=fields.RESTRICT
    )
    status = fields.CharEnumField(RequestStatus, default=RequestStatus.PENDING, max_length=16)
    requested_validity_days = fields.IntField(null=True)
    requester = fields.CharField(max_length=128)
    channel = fields.CharEnumField(Channel, max_length=16)
    certificate: fields.OneToOneNullableRelation[Certificate] = fields.OneToOneField(
        "models.Certificate", related_name="request", null=True, on_delete=fields.RESTRICT
    )
    subject_dn = fields.TextField()  # as requested, for listings
    rejection_reason = fields.TextField(null=True)
    decided_by = fields.CharField(max_length=128, null=True)
    decided_at = fields.DatetimeField(null=True)
    # e.g. ignored_extensions (never copied, B2), validity_truncated, failure reason.
    metadata: fields.JSONField[dict[str, Any]] = fields.JSONField(default=dict)

    # Foreign key columns created by Tortoise, declared for type checkers.
    profile_id: UUID
    certificate_id: UUID | None

    class Meta:
        table = "certificate_request"
        ordering = ["created_at"]
