"""ACME accounts, orders, authorizations, challenges and nonces (RFC 8555, ADR-0020).

Foreign keys point "up" only (B27): challenge → authorization → order → account, and an order
points to the request and the certificate it produced.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from tortoise import fields

from h42pki.models.base import TimestampedModel

if TYPE_CHECKING:
    from h42pki.models.certificate import Certificate
    from h42pki.models.profile import Profile
    from h42pki.models.request import CertificateRequest


class AccountStatus(StrEnum):
    VALID = "valid"
    DEACTIVATED = "deactivated"
    REVOKED = "revoked"


class OrderStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class AuthorizationStatus(StrEnum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ChallengeStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class IdentifierType(StrEnum):
    DNS = "dns"
    IP = "ip"


class ChallengeType(StrEnum):
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"


class AcmeNonce(TimestampedModel):
    """A Replay-Nonce handed out: used once (deleted when consumed), purged when expired."""

    value = fields.CharField(max_length=64, unique=True)
    expires_at = fields.DatetimeField()

    class Meta:
        table = "acme_nonce"


class AcmeAccount(TimestampedModel):
    jwk: fields.JSONField[dict[str, Any]] = (
        fields.JSONField()
    )  # public JWK, members of RFC 7638 only
    jwk_thumbprint = fields.CharField(max_length=64, unique=True)
    status = fields.CharEnumField(AccountStatus, default=AccountStatus.VALID, max_length=16)
    contact: fields.JSONField[list[str]] = fields.JSONField(default=list)  # ["mailto:..."]
    tos_agreed_at = fields.DatetimeField(null=True)

    class Meta:
        table = "acme_account"


class AcmeOrder(TimestampedModel):
    account: fields.ForeignKeyRelation[AcmeAccount] = fields.ForeignKeyField(
        "models.AcmeAccount", related_name="orders", on_delete=fields.CASCADE
    )
    profile: fields.ForeignKeyRelation[Profile] = fields.ForeignKeyField(
        "models.Profile", related_name="acme_orders", on_delete=fields.RESTRICT
    )
    status = fields.CharEnumField(OrderStatus, default=OrderStatus.PENDING, max_length=16)
    expires_at = fields.DatetimeField()
    identifiers: fields.JSONField[list[dict[str, str]]] = (
        fields.JSONField()
    )  # [{"type": "dns", "value": "..."}], as ordered
    error: fields.JSONField[dict[str, Any] | None] = fields.JSONField(null=True)  # problem
    request: fields.ForeignKeyNullableRelation[CertificateRequest] = fields.ForeignKeyField(
        "models.CertificateRequest", related_name="acme_orders", null=True,
        on_delete=fields.SET_NULL,
    )  # fmt: skip
    certificate: fields.ForeignKeyNullableRelation[Certificate] = fields.ForeignKeyField(
        "models.Certificate", related_name="acme_orders", null=True, on_delete=fields.SET_NULL
    )

    account_id: UUID
    profile_id: UUID
    request_id: UUID | None
    certificate_id: UUID | None

    class Meta:
        table = "acme_order"


class AcmeAuthorization(TimestampedModel):
    order: fields.ForeignKeyRelation[AcmeOrder] = fields.ForeignKeyField(
        "models.AcmeOrder", related_name="authorizations", on_delete=fields.CASCADE
    )
    identifier_type = fields.CharEnumField(IdentifierType, max_length=8)
    identifier_value = fields.CharField(max_length=255)  # without "*." for a wildcard
    wildcard = fields.BooleanField(default=False)
    status = fields.CharEnumField(
        AuthorizationStatus, default=AuthorizationStatus.PENDING, max_length=16
    )
    expires_at = fields.DatetimeField()

    order_id: UUID

    class Meta:
        table = "acme_authorization"


class AcmeChallenge(TimestampedModel):
    authorization: fields.ForeignKeyRelation[AcmeAuthorization] = fields.ForeignKeyField(
        "models.AcmeAuthorization", related_name="challenges", on_delete=fields.CASCADE
    )
    type = fields.CharEnumField(ChallengeType, max_length=16)
    token = fields.CharField(max_length=64, unique=True)
    status = fields.CharEnumField(ChallengeStatus, default=ChallengeStatus.PENDING, max_length=16)
    validated_at = fields.DatetimeField(null=True)
    error: fields.JSONField[dict[str, Any] | None] = fields.JSONField(null=True)
    attempts = fields.IntField(default=0)  # validation attempts made
    next_attempt_at = fields.DatetimeField(null=True)  # while processing

    authorization_id: UUID

    class Meta:
        table = "acme_challenge"
