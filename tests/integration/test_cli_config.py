"""`h42pki config …` on a temporary SQLite database (no passphrase, no hostname needed)."""

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import Result
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.cli._runtime import run
from h42pki.config import ENV_PREFIX, Settings, get_settings
from h42pki.models import AuditLog
from tests.cli_helpers import plain

runner = CliRunner()


@pytest.fixture(autouse=True)
def cli_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    database = tmp_path / "data" / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    # Neither H42_PKI_CA_PASSPHRASE nor H42_PKI_SERVER_HOSTNAME: config needs no key.
    get_settings.cache_clear()


def invoke(*args: str) -> Result:
    result = runner.invoke(app, list(args))
    assert "Traceback" not in plain(result)
    return result


def audit_entries(action: str) -> list[dict[str, Any]]:
    async def operation(settings: Settings) -> list[dict[str, Any]]:
        return [
            {"actor": entry.actor, "object_id": entry.object_id, **entry.details}
            for entry in await AuditLog.filter(action=action)
        ]

    return run(operation)


def test_show_lists_every_setting() -> None:
    result = invoke("config", "show")

    assert result.exit_code == 0, result.output
    lines = plain(result, "stdout").splitlines()
    assert lines[0].split() == ["KEY", "VALUE", "DEFAULT", "ORIGIN", "LEVEL"]
    assert len(lines) == 1 + 13
    row = next(line for line in lines if line.startswith("server.tls_min_version"))
    assert row.split() == [
        "server.tls_min_version",
        '"tls1.2"',
        '"tls1.2"',
        "default",
        "listener",
        "(https)",
    ]


def test_show_marks_stored_values() -> None:
    invoke("config", "set", "tls_service.validity_days", "30")

    result = invoke("config", "show")

    row = next(line for line in plain(result, "stdout").splitlines() if "validity_days" in line)
    assert row.split() == ["tls_service.validity_days", "30", "47", "database", "hot"]


def test_get_prints_the_json_value() -> None:
    result = invoke("config", "get", "issuance.disabled_profiles")

    assert result.exit_code == 0, result.output
    assert json.loads(plain(result, "stdout")) == []
    assert "default [], origin default, level hot" in plain(result, "stderr")


def test_set_hot_setting() -> None:
    result = invoke("config", "set", "issuance.disabled_profiles", '["device"]')

    assert result.exit_code == 0, result.output
    assert 'issuance.disabled_profiles = ["device"] (was [])' in plain(result, "stdout")
    assert "applied hot" in plain(result, "stdout")
    assert json.loads(plain(invoke("config", "get", "issuance.disabled_profiles"), "stdout")) == [
        "device"
    ]
    get = invoke("config", "get", "issuance.disabled_profiles")
    assert "origin database" in plain(get, "stderr")
    assert "set by cli" in plain(get, "stderr")


def test_set_listener_setting_with_plain_text() -> None:
    result = invoke("config", "set", "server.tls_min_version", "tls1.3")

    assert result.exit_code == 0, result.output
    assert 'server.tls_min_version = "tls1.3" (was "tls1.2")' in plain(result, "stdout")
    assert "the HTTPS listener will restart" in plain(result, "stdout")


def test_set_listener_setting_of_both_listeners() -> None:
    result = invoke("config", "set", "server.keep_alive_timeout", "30")

    assert "the HTTP and HTTPS listeners will restart" in plain(result, "stdout")


def test_set_process_setting() -> None:
    result = invoke("config", "set", "logging.format", "json")

    assert result.exit_code == 0, result.output
    assert "takes effect at the next restart of the container" in plain(result, "stdout")


def test_set_same_value_reports_nothing_to_apply() -> None:
    result = invoke("config", "set", "logging.level", "info")

    assert "nothing to apply" in plain(result, "stdout")


def test_set_is_audited() -> None:
    invoke("config", "set", "tls_service.validity_days", "30")

    assert audit_entries("config.set") == [
        {
            "actor": "cli",
            "object_id": "tls_service.validity_days",
            "key": "tls_service.validity_days",
            "previous": 47,
            "new": 30,
            "previous_origin": "default",
        }
    ]


def test_unset() -> None:
    invoke("config", "set", "logging.level", "debug")

    result = invoke("config", "unset", "logging.level")

    assert result.exit_code == 0, result.output
    assert 'logging.level = "info" (default; was "debug")' in plain(result, "stdout")
    assert "applied hot" in plain(result, "stdout")
    assert [entry["previous"] for entry in audit_entries("config.unset")] == ["debug"]


def test_unset_of_a_default_value() -> None:
    result = invoke("config", "unset", "logging.level")

    assert result.exit_code == 0
    assert "nothing to apply" in plain(result, "stdout")
    assert audit_entries("config.unset") == []


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("get", "server.nope"), "unknown setting 'server.nope'"),
        (("set", "nope", "1"), "unknown setting 'nope'"),
        (("unset", "nope"), "unknown setting 'nope'"),
        (("set", "tls_service.validity_days", "365"), "less than or equal to 200"),
        (("set", "issuance.disabled_profiles", '["nope"]'), "unknown profile 'nope'"),
        (("set", "server.tls_min_version", "tls1.0"), "tls_min_version"),
    ],
)
def test_errors_are_readable(args: tuple[str, ...], message: str) -> None:
    result = invoke("config", *args)

    assert result.exit_code == 1
    assert message in plain(result, "stderr")
    assert audit_entries("config.set") == []
