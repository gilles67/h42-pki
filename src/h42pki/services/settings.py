"""Runtime settings in the database (ADR-0011): effective values, writes, reload by the server.

Writes come from the CLI, in another process than the server. Services therefore read the
effective settings from the database each time (:meth:`SettingsService.effective`, no cache), and
the server polls a revision counter (:class:`SettingsWatcher`) to react to changes that need an
action of its own (log level, listener restart).
"""

import asyncio
import inspect
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from tortoise.expressions import F
from tortoise.transactions import in_transaction

from h42pki.core.errors import InvalidSetting
from h42pki.core.settings_schema import (
    SETTINGS,
    ApplyLevel,
    Listener,
    RuntimeSettings,
    build_settings,
    setting_info,
    value_of,
)
from h42pki.models import AuditLog, Setting, SettingsRevision

log = logging.getLogger(__name__)

# How often the server checks whether the settings changed (written by the CLI).
SETTINGS_POLL_SECONDS = 5.0
_REVISION_ID = 1


@dataclass(frozen=True)
class SettingView:
    key: str
    value: Any
    default: Any
    origin: str  # "default" or "database"
    apply: ApplyLevel
    listeners: tuple[Listener, ...]
    description: str
    updated_at: datetime | None
    updated_by: str | None


@dataclass(frozen=True)
class SettingChange:
    key: str
    previous: Any
    new: Any
    changed: bool
    apply: ApplyLevel
    listeners: tuple[Listener, ...]


def _decode(row: Setting) -> Any:
    return json.loads(row.value)


class SettingsService:
    async def _rows(self) -> dict[str, Setting]:
        return {row.key: row for row in await Setting.all()}

    async def effective(self) -> RuntimeSettings:
        """Code defaults plus stored values; a stored value that no longer validates is skipped.

        Without migrations (ADR-0007) a schema change may leave an obsolete row behind: it is
        ignored with a warning rather than making the whole instance unusable.
        """
        rows = await self._rows()
        values = {key: _decode(row) for key, row in rows.items() if key in SETTINGS}
        try:
            return build_settings(values)
        except InvalidSetting:
            pass
        kept: dict[str, Any] = {}
        for key, value in values.items():
            try:
                build_settings({**kept, key: value})
            except InvalidSetting as exc:
                log.warning("stored setting %s ignored: %s", key, exc.detail)
            else:
                kept[key] = value
        return build_settings(kept)

    async def describe(self) -> list[SettingView]:
        rows = await self._rows()
        effective = await self.effective()
        return [self._view(info.key, effective, rows.get(info.key)) for info in SETTINGS.values()]

    async def get(self, key: str) -> SettingView:
        setting_info(key)
        return self._view(key, await self.effective(), await Setting.get_or_none(key=key))

    async def revision(self) -> int:
        row = await SettingsRevision.get_or_none(id=_REVISION_ID)
        return row.revision if row is not None else 0

    async def set(self, key: str, value: Any, *, actor: str) -> SettingChange:
        """Store one value after validating all settings together; audited."""
        info = setting_info(key)
        async with in_transaction():
            rows = await self._rows()
            values = {k: _decode(row) for k, row in rows.items() if k in SETTINGS}
            previous = value_of(build_settings(values), key)
            new = value_of(build_settings({**values, key: value}), key)  # normalized
            encoded = json.dumps(new, separators=(",", ":"))
            row = rows.get(key)
            if row is None:
                await Setting.create(key=key, value=encoded, updated_by=actor)
            else:
                row.value = encoded
                row.updated_by = actor
                await row.save()
            await self._bump()
            await self._audit(actor, "config.set", key, previous, new, origin_was=row is not None)
        return SettingChange(key, previous, new, previous != new, info.apply, info.listeners)

    async def unset(self, key: str, *, actor: str) -> SettingChange:
        """Go back to the code default; refused if the other stored values then conflict."""
        info = setting_info(key)
        async with in_transaction():
            rows = await self._rows()
            row = rows.get(key)
            values = {k: _decode(r) for k, r in rows.items() if k in SETTINGS}
            previous = value_of(build_settings(values), key)
            if row is None:
                return SettingChange(key, previous, previous, False, info.apply, info.listeners)
            remaining = {k: v for k, v in values.items() if k != key}
            new = value_of(build_settings(remaining), key)
            await row.delete()
            await self._bump()
            await self._audit(actor, "config.unset", key, previous, new, origin_was=True)
        return SettingChange(key, previous, new, previous != new, info.apply, info.listeners)

    # --- internals ------------------------------------------------------------------------

    @staticmethod
    def _view(key: str, effective: RuntimeSettings, row: Setting | None) -> SettingView:
        info = setting_info(key)
        return SettingView(
            key=key,
            value=value_of(effective, key),
            default=info.default,
            origin="database" if row is not None else "default",
            apply=info.apply,
            listeners=info.listeners,
            description=info.description,
            updated_at=row.updated_at if row is not None else None,
            updated_by=row.updated_by if row is not None else None,
        )

    @staticmethod
    async def _bump() -> None:
        updated = await SettingsRevision.filter(id=_REVISION_ID).update(revision=F("revision") + 1)
        if not updated:
            await SettingsRevision.create(id=_REVISION_ID, revision=1)

    @staticmethod
    async def _audit(
        actor: str, action: str, key: str, previous: Any, new: Any, *, origin_was: bool
    ) -> None:
        # Settings of phase 1.1 hold no secret; secret settings will be masked here (ADR-0011).
        await AuditLog.record(
            actor=actor,
            action=action,
            object_type="setting",
            object_id=key,
            details={
                "key": key,
                "previous": previous,
                "new": new,
                "previous_origin": "database" if origin_was else "default",
            },
        )


type SettingsListener = Callable[[RuntimeSettings, RuntimeSettings], Awaitable[None] | None]


class SettingsWatcher:
    """Keeps a snapshot of the settings in the server, reloaded when the revision changes."""

    def __init__(
        self, service: SettingsService | None = None, *, interval: float | None = None
    ) -> None:
        self._service = service or SettingsService()
        self._interval = interval
        self._listeners: list[SettingsListener] = []
        self.revision = -1
        self.current = RuntimeSettings()

    @property
    def interval(self) -> float:
        # Read at each cycle so that tests can shorten SETTINGS_POLL_SECONDS.
        return self._interval if self._interval is not None else SETTINGS_POLL_SECONDS

    def subscribe(self, listener: SettingsListener) -> None:
        """``listener(previous, current)`` is called after each reload that changed something."""
        self._listeners.append(listener)

    async def load(self) -> RuntimeSettings:
        self.revision = await self._service.revision()
        self.current = await self._service.effective()
        return self.current

    async def poll(self) -> bool:
        """Reload if the revision changed; True if the effective settings changed."""
        revision = await self._service.revision()
        if revision == self.revision:
            return False
        previous = self.current
        await self.load()
        if self.current == previous:
            return False
        log.info("settings reloaded (revision %d)", self.revision)
        for listener in self._listeners:
            result = listener(previous, self.current)
            if inspect.isawaitable(result):
                await result
        return True

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.interval)
            except TimeoutError:
                try:
                    await self.poll()
                except Exception:  # keep watching: a transient database error must not stop it
                    log.exception("cannot reload the settings")
