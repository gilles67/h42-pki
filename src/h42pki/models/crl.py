"""Certificate revocation lists of the local CAs (one full CRL at a time, no delta, ADR-0017)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from tortoise import fields

from h42pki.models.base import TimestampedModel

if TYPE_CHECKING:
    from h42pki.models.authority import Authority


class Crl(TimestampedModel):
    """A signed CRL, stored in DER. The current one is the highest number; older ones are kept."""

    authority: fields.ForeignKeyRelation[Authority] = fields.ForeignKeyField(
        "models.Authority", related_name="crls", on_delete=fields.RESTRICT
    )
    crl_number = fields.IntField()  # monotonic per CA, never reused
    this_update = fields.DatetimeField()
    next_update = fields.DatetimeField()
    # When the revoked certificates were read: a revocation after it is not in this CRL.
    entries_as_of = fields.DatetimeField()
    entries = fields.IntField()
    der = fields.BinaryField()

    authority_id: UUID

    class Meta:
        table = "crl"
        unique_together = (("authority", "crl_number"),)
        ordering = ["-crl_number"]
