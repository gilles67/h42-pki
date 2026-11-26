"""Certificate authorities known to this container (docs/ARCHITECTURE.md section 4.2)."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from tortoise import fields

from h42pki.core.publication import validate_authority_name
from h42pki.models.base import TimestampedModel

if TYPE_CHECKING:
    from h42pki.models.certificate import Certificate
    from h42pki.models.crl import Crl
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
    """A CA: the local one, its ancestors (``parent``) or the CAs it signed (``child``)."""

    name = fields.CharField(max_length=64, unique=True)
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
    # Direct parent (kind=parent): where this CA enrolled, and what it pinned (ADR-0015).
    federation_url = fields.CharField(max_length=255, null=True)
    pinned_fingerprint = fields.CharField(max_length=64, null=True)
    # Local CA in pending_signature: identifier of the enrolment on the parent (not a foreign
    # key), and the CSR, kept so that a lost answer can be asked again with the same request.
    pending_enrollment_id = fields.UUIDField(null=True)
    pending_csr_der = fields.BinaryField(null=True)
    # Revocation services of a local CA (ADR-0017): chosen by `h42pki authority init`, never
    # changed afterwards. They decide the CDP and AIA OCSP URLs written in issued certificates.
    crl_enabled = fields.BooleanField(default=False)
    ocsp_enabled = fields.BooleanField(default=False)
    # Local subordinate CA: last check of its own status with the OCSP of its parent.
    parent_check_at = fields.DatetimeField(null=True)
    parent_check_result = fields.CharField(max_length=32, null=True)

    crls: fields.ReverseRelation[Crl]

    # The CA's own certificate: reverse side of Certificate.authority. A foreign key on this
    # table would form a cycle with Certificate.issuer, which Tortoise cannot create.
    certificate: fields.BackwardOneToOneRelation[Certificate]

    # Foreign key columns created by Tortoise, declared for type checkers.
    private_key_id: UUID | None
    parent_id: UUID | None

    class Meta:
        table = "authority"

    async def save(self, *args: Any, **kwargs: Any) -> None:
        """Every creation goes through here: the name enters public URLs (B37).

        Not a field validator, which Tortoise could also run on query filters: a lookup of an
        invalid name must stay a plain "not found".
        """
        validate_authority_name(self.name)
        await super().save(*args, **kwargs)
