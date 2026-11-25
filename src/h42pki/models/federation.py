"""Single-use invitations given to future child CAs (ADR-0015)."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from tortoise import fields

from h42pki.models.base import TimestampedModel

if TYPE_CHECKING:
    from h42pki.models.request import CertificateRequest


class InvitationStatus(StrEnum):
    ACTIVE = "active"
    USED = "used"
    REVOKED = "revoked"
    EXPIRED = "expired"  # computed when read, never stored


class FederationInvitation(TimestampedModel):
    label = fields.CharField(max_length=128, null=True)
    secret_hash = fields.CharField(max_length=64)  # SHA-256, never returned
    path_length = fields.IntField(null=True)  # null: whatever the parent CA allows
    validity_days = fields.IntField(null=True)  # null: default of the sub_ca profile
    auto_approve = fields.BooleanField(default=False)
    expires_at = fields.DatetimeField()  # limit of the first use
    status = fields.CharEnumField(InvitationStatus, default=InvitationStatus.ACTIVE, max_length=16)
    created_by = fields.CharField(max_length=128)
    used_at = fields.DatetimeField(null=True)
    request: fields.OneToOneNullableRelation[CertificateRequest] = fields.OneToOneField(
        "models.CertificateRequest", related_name="invitation", null=True, on_delete=fields.RESTRICT
    )

    # Foreign key column created by Tortoise, declared for type checkers.
    request_id: UUID | None

    class Meta:
        table = "federation_invitation"
        ordering = ["-created_at"]
