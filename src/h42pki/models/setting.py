"""Runtime settings modified on this instance (ADR-0011); defaults stay in the code."""

from tortoise import fields
from tortoise.models import Model

from h42pki.models.base import TimestampedModel


class Setting(TimestampedModel):
    """One modified setting. ``value`` is JSON text (validated by ``RuntimeSettings``)."""

    key = fields.CharField(max_length=128, unique=True)  # section.name
    # JSON text rather than JSONField: a setting may be a bare string, number or null.
    value = fields.TextField()
    updated_by = fields.CharField(max_length=128)

    class Meta:
        table = "setting"
        ordering = ["key"]


class SettingsRevision(Model):
    """Single row, incremented with every write: the server polls it to reload its settings.

    A counter rather than ``max(Setting.updated_at)``: an ``unset`` deletes its row and would
    otherwise go unnoticed.
    """

    id = fields.IntField(primary_key=True)
    revision = fields.IntField(default=0)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        table = "settings_revision"
