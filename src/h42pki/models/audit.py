"""Audit trail. ``details`` must never contain a secret."""

from typing import Any
from uuid import UUID

from tortoise import fields

from h42pki.models.base import TimestampedModel


class AuditLog(TimestampedModel):
    timestamp = fields.DatetimeField(auto_now_add=True)
    actor = fields.CharField(max_length=128)
    action = fields.CharField(max_length=64)
    object_type = fields.CharField(max_length=64)
    object_id = fields.CharField(max_length=64)
    details: fields.JSONField[dict[str, Any]] = fields.JSONField(default=dict)

    class Meta:
        table = "audit_log"
        ordering = ["timestamp"]

    @classmethod
    async def record(
        cls,
        *,
        actor: str,
        action: str,
        object_type: str,
        object_id: UUID | str,
        details: dict[str, Any] | None = None,
    ) -> "AuditLog":
        return await cls.create(
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=str(object_id),
            details=details or {},
        )
