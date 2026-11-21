"""Common base of the Tortoise models."""

from tortoise import fields
from tortoise.models import Model


class TimestampedModel(Model):
    """UUID primary key and UTC-aware creation / update timestamps."""

    id = fields.UUIDField(primary_key=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        abstract = True
