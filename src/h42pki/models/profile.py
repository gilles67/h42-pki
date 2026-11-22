"""Certificate profiles, written from the built-in definitions at start-up (ADR-0009)."""

from typing import Any

from tortoise import fields

from h42pki.core.extensions import BasicConstraints, KeyUsage
from h42pki.core.profiles import ProfileKind, SanPolicy, SubjectPolicy
from h42pki.models.base import TimestampedModel


class Profile(TimestampedModel):
    name = fields.CharField(max_length=64, unique=True)
    kind = fields.CharEnumField(ProfileKind, max_length=32)
    description = fields.TextField()
    builtin = fields.BooleanField(default=True)
    auto_approve = fields.BooleanField(default=False)
    validity_days = fields.IntField()
    max_validity_days = fields.IntField()
    basic_constraints: fields.JSONField[BasicConstraints] = fields.JSONField(
        field_type=BasicConstraints
    )
    key_usage: fields.JSONField[KeyUsage] = fields.JSONField(field_type=KeyUsage)
    extended_key_usage: fields.JSONField[list[str]] = fields.JSONField(default=list)
    allowed_key_algorithms: fields.JSONField[list[str]] = fields.JSONField(default=list)
    subject_policy: fields.JSONField[SubjectPolicy] = fields.JSONField(field_type=SubjectPolicy)
    san_policy: fields.JSONField[SanPolicy] = fields.JSONField(field_type=SanPolicy)
    ocsp_no_check = fields.BooleanField(default=False)
    include_aia = fields.BooleanField(default=True)
    internal = fields.BooleanField(default=False)  # service_tls (ADR-0013)

    class Meta:
        table = "profile"
        ordering = ["name"]

    def spec_values(self) -> dict[str, Any]:
        """Field values in the shape of :class:`h42pki.core.profiles.ProfileSpec`."""
        return {
            "name": self.name,
            "kind": self.kind,
            "description": self.description,
            "auto_approve": self.auto_approve,
            "validity_days": self.validity_days,
            "max_validity_days": self.max_validity_days,
            "basic_constraints": self.basic_constraints,
            "key_usage": self.key_usage,
            "extended_key_usage": self.extended_key_usage,
            "allowed_key_algorithms": self.allowed_key_algorithms,
            "subject_policy": self.subject_policy,
            "san_policy": self.san_policy,
            "ocsp_no_check": self.ocsp_no_check,
            "include_aia": self.include_aia,
            "internal": self.internal,
        }
