"""SCEP transactions and nonces (RFC 8894, ADR-0019)."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from tortoise import fields

from h42pki.models.base import TimestampedModel

if TYPE_CHECKING:
    from h42pki.models.authority import Authority
    from h42pki.models.certificate import Certificate
    from h42pki.models.request import CertificateRequest


class ScepTransactionStatus(StrEnum):
    PENDING = "pending"
    ISSUED = "issued"
    FAILED = "failed"


class ScepTransaction(TimestampedModel):
    """A PKCSReq or RenewalReq: a retransmission of its transactionID gets the same answer."""

    authority: fields.ForeignKeyRelation[Authority] = fields.ForeignKeyField(
        "models.Authority", related_name="scep_transactions", on_delete=fields.RESTRICT
    )
    transaction_id = fields.CharField(max_length=128)
    message_type = fields.IntField()
    sender_nonce = fields.CharField(max_length=64)  # hex of the first request
    signer_cert_der = fields.BinaryField()
    status = fields.CharEnumField(ScepTransactionStatus, max_length=16)
    request: fields.ForeignKeyNullableRelation[CertificateRequest] = fields.ForeignKeyField(
        "models.CertificateRequest", related_name="scep_transactions", null=True,
        on_delete=fields.SET_NULL,
    )  # fmt: skip
    certificate: fields.ForeignKeyNullableRelation[Certificate] = fields.ForeignKeyField(
        "models.Certificate", related_name="scep_transactions", null=True,
        on_delete=fields.SET_NULL,
    )  # fmt: skip
    fail_info = fields.IntField(null=True)

    authority_id: UUID
    request_id: UUID | None
    certificate_id: UUID | None

    class Meta:
        table = "scep_transaction"
        unique_together = (("authority", "transaction_id"),)


class ScepNonce(TimestampedModel):
    """A senderNonce seen: the same one on another transaction is a replay."""

    authority: fields.ForeignKeyRelation[Authority] = fields.ForeignKeyField(
        "models.Authority", related_name="scep_nonces", on_delete=fields.RESTRICT
    )
    nonce = fields.CharField(max_length=64)  # hex
    transaction_id = fields.CharField(max_length=128)

    authority_id: UUID

    class Meta:
        table = "scep_nonce"
        unique_together = (("authority", "nonce"),)
