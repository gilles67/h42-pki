"""Runtime settings in the database: service, audit, revision, reload by the server."""

import asyncio
import json

import pytest
from httpx import AsyncClient

from h42pki.core.errors import InvalidSetting, UnknownSetting
from h42pki.core.settings_schema import ApplyLevel, RuntimeSettings
from h42pki.models import AuditLog, Setting, SettingsRevision
from h42pki.services import settings as settings_module
from h42pki.services.settings import SettingsService, SettingsWatcher

pytestmark = pytest.mark.usefixtures("client")  # database of the test application


async def test_effective_settings_are_the_defaults_without_rows() -> None:
    service = SettingsService()

    assert await service.effective() == RuntimeSettings()
    assert await service.revision() == 0
    view = await service.get("tls_service.validity_days")
    assert (view.value, view.default, view.origin) == (47, 47, "default")
    assert view.apply is ApplyLevel.HOT


async def test_set_stores_audits_and_bumps_the_revision() -> None:
    service = SettingsService()

    change = await service.set("tls_service.validity_days", 30, actor="cli")

    assert (change.previous, change.new, change.changed) == (47, 30, True)
    assert change.apply is ApplyLevel.HOT
    assert (await service.effective()).tls_service.validity_days == 30
    assert await service.revision() == 1
    row = await Setting.get(key="tls_service.validity_days")
    assert (json.loads(row.value), row.updated_by) == (30, "cli")
    view = await service.get("tls_service.validity_days")
    assert (view.value, view.origin, view.updated_by) == (30, "database", "cli")
    entry = await AuditLog.get(action="config.set")
    assert (entry.actor, entry.object_type, entry.object_id) == (
        "cli",
        "setting",
        "tls_service.validity_days",
    )
    assert entry.details == {
        "key": "tls_service.validity_days",
        "previous": 47,
        "new": 30,
        "previous_origin": "default",
    }


async def test_set_twice_updates_the_row() -> None:
    service = SettingsService()
    await service.set("logging.level", "debug", actor="cli")

    change = await service.set("logging.level", "warning", actor="cli")

    assert (change.previous, change.new) == ("debug", "warning")
    assert await Setting.filter(key="logging.level").count() == 1
    assert await service.revision() == 2


async def test_set_stores_the_normalized_value() -> None:
    service = SettingsService()

    change = await service.set(
        "issuance.disabled_profiles", ["device", "device", "tls_client"], actor="cli"
    )

    assert change.new == ["device", "tls_client"]
    row = await Setting.get(key="issuance.disabled_profiles")
    assert json.loads(row.value) == ["device", "tls_client"]


async def test_invalid_set_changes_nothing() -> None:
    service = SettingsService()

    with pytest.raises(InvalidSetting, match="less than or equal to 200"):
        await service.set("tls_service.validity_days", 365, actor="cli")
    with pytest.raises(UnknownSetting):
        await service.set("tls_service.nope", 1, actor="cli")

    assert await Setting.all().count() == 0
    assert await AuditLog.filter(action="config.set").count() == 0
    assert await service.revision() == 0


async def test_cross_field_rule_uses_the_stored_values() -> None:
    service = SettingsService()
    await service.set("tls_service.validity_days", 90, actor="cli")
    await service.set("tls_service.renew_before_days", 60, actor="cli")

    # Going back to 47 days would leave renew_before_days (60) above the validity.
    with pytest.raises(InvalidSetting, match="lower than tls_service.validity_days"):
        await service.unset("tls_service.validity_days", actor="cli")

    assert (await service.effective()).tls_service.validity_days == 90


async def test_unset_goes_back_to_the_default() -> None:
    service = SettingsService()
    await service.set("server.tls_min_version", "tls1.3", actor="cli")

    change = await service.unset("server.tls_min_version", actor="cli")

    assert (change.previous, change.new, change.changed) == ("tls1.3", "tls1.2", True)
    assert change.apply is ApplyLevel.LISTENER
    assert change.listeners == ("https",)
    assert await Setting.filter(key="server.tls_min_version").count() == 0
    assert await service.revision() == 2
    entry = await AuditLog.get(action="config.unset")
    assert entry.details["previous"] == "tls1.3"
    assert entry.details["new"] == "tls1.2"


async def test_unset_without_row_is_a_no_op() -> None:
    service = SettingsService()

    change = await service.unset("logging.level", actor="cli")

    assert not change.changed
    assert await service.revision() == 0
    assert await AuditLog.filter(action="config.unset").count() == 0


async def test_obsolete_stored_value_is_skipped(caplog: pytest.LogCaptureFixture) -> None:
    """No migration before the release (ADR-0007): a row that no longer validates is ignored."""
    await Setting.create(key="tls_service.validity_days", value="999", updated_by="cli")
    await Setting.create(key="logging.level", value='"debug"', updated_by="cli")
    await Setting.create(key="removed.setting", value="1", updated_by="cli")

    settings = await SettingsService().effective()

    assert settings.tls_service.validity_days == 47
    assert settings.logging.level == "debug"
    assert "tls_service.validity_days ignored" in caplog.text


async def test_describe_lists_every_setting() -> None:
    service = SettingsService()
    await service.set("logging.level", "debug", actor="cli")

    views = {view.key: view for view in await service.describe()}

    assert len(views) == 16
    assert views["logging.level"].origin == "database"
    assert views["logging.format"].origin == "default"


async def test_watcher_reloads_a_write_made_by_another_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The CLI writes from another process: the server sees it at the next poll."""
    monkeypatch.setattr(settings_module, "SETTINGS_POLL_SECONDS", 0.05)
    watcher = SettingsWatcher()
    await watcher.load()
    changes: list[tuple[str, str]] = []
    watcher.subscribe(lambda old, new: changes.append((old.logging.level, new.logging.level)))
    stop = asyncio.Event()
    task = asyncio.create_task(watcher.run(stop))
    try:
        # Direct database writes, as another process would do them (no in-process signal).
        await Setting.create(key="logging.level", value='"debug"', updated_by="cli")
        await SettingsRevision.create(id=1, revision=1)
        for _ in range(100):
            if changes:
                break
            await asyncio.sleep(0.02)
    finally:
        stop.set()
        await task

    assert changes == [("info", "debug")]
    assert watcher.current.logging.level == "debug"
    assert watcher.revision == 1


async def test_watcher_ignores_an_unchanged_revision() -> None:
    watcher = SettingsWatcher()
    await watcher.load()
    calls: list[object] = []

    async def listener(old: RuntimeSettings, new: RuntimeSettings) -> None:
        calls.append(new)

    watcher.subscribe(listener)

    assert not await watcher.poll()
    await SettingsService().set("logging.level", "error", actor="cli")
    assert await watcher.poll()
    assert not await watcher.poll()
    assert len(calls) == 1


async def test_watcher_keeps_running_after_a_database_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    service = SettingsService()
    failures = 0

    async def broken() -> int:
        nonlocal failures
        failures += 1
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(service, "revision", broken)
    watcher = SettingsWatcher(service, interval=0.01)
    stop = asyncio.Event()
    task = asyncio.create_task(watcher.run(stop))
    for _ in range(100):
        if failures >= 2:
            break
        await asyncio.sleep(0.01)
    stop.set()
    await task

    assert failures >= 2
    assert "cannot reload the settings" in caplog.text


async def test_client_fixture_database(client: AsyncClient) -> None:
    """Sanity check: the settings tables exist in the test database."""
    assert await Setting.all().count() == 0
