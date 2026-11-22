"""Certificate authorities known to this container (docs/ARCHITECTURE.md section 4.2)."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from tortoise import fields

from h42pki.models.base import TimestampedModel

if TYPE_CHECKING:
    from h42pki.models.certificate import Certificate
    from h42pki.models.private_key import PrivateKey


class AuthorityKind(StrEnum):
    LOCAL = "local"
    PARENT = "parent"
    CHILD = "child"


class AuthorityStatus(StrEnum):
    """Life cycle of a local CA (docs/ARCHITECTURE.md section 3)."""

    UNINITIALIZED = "uninitialized"
    PENDING_SIGNATURE = "pending_signature"
    ACTIVE = "active"
    ROLLING_OVER = "rolling_over"
    RETIRED = "retired"
    REVOKED = "revoked"


class Authority(TimestampedModel):
    """Not used by any route yet."""

    name = fields.CharField(max_length=128, unique=True)
    kind = fields.CharEnumField(AuthorityKind, max_length=16)
    status = fields.CharEnumField(
        AuthorityStatus, default=AuthorityStatus.UNINITIALIZED, max_length=32
    )
    private_key: fields.ForeignKeyNullableRelation[PrivateKey] = fields.ForeignKeyField(
        "models.PrivateKey",
        related_name="authorities",
        null=True,
        on_delete=fields.RESTRICT,
    )
    parent: fields.ForeignKeyNullableRelation[Authority] = fields.ForeignKeyField(
        "models.Authority",
        related_name="children",
        null=True,
        on_delete=fields.RESTRICT,
    )
    path_length = fields.IntField(null=True)
    public_base_url = fields.CharField(max_length=255, null=True)

    # The CA's own certificate: reverse side of Certificate.authority. A foreign key on this
    # table would form a cycle with Certificate.issuer, which Tortoise cannot create.
    certificate: fields.BackwardOneToOneRelation[Certificate]

    # Foreign key columns created by Tortoise, declared for type checkers.
    private_key_id: UUID | None
    parent_id: UUID | None

    class Meta:
        table = "authority"
