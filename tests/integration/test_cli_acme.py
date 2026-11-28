"""`h42pki acme account list|show|deactivate` (ADR-0020)."""

import asyncio
from pathlib import Path

import pytest
from click.testing import Result
from tortoise import Tortoise
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.config import ENV_PREFIX, get_settings
from h42pki.db import ensure_sqlite_directory, tortoise_config
from h42pki.models import AccountStatus, AcmeAccount
from tests.cli_helpers import plain

runner = CliRunner()


@pytest.fixture
def account_id(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
    """A CLI database holding one ACME account."""
    database = tmp_path / "data" / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    get_settings.cache_clear()

    async def create() -> str:
        settings = get_settings()
        ensure_sqlite_directory(settings.database_url)
        await Tortoise.init(config=tortoise_config(settings))
        await Tortoise.generate_schemas()
        account = await AcmeAccount.create(
            jwk={"kty": "EC"}, jwk_thumbprint="thumb", contact=["mailto:a@example.test"]
        )
        await Tortoise.close_connections()
        return str(account.id)

    return asyncio.run(create())


def invoke(*args: str) -> Result:
    result = runner.invoke(app, list(args))
    assert "Traceback" not in plain(result)
    return result


def test_cli_accounts(account_id: str) -> None:
    listing = invoke("acme", "account", "list")
    shown = invoke("acme", "account", "show", account_id)
    deactivated = invoke("acme", "account", "deactivate", account_id)
    again = invoke("acme", "account", "show", account_id)
    missing = invoke("acme", "account", "show", "00000000-0000-0000-0000-000000000000")

    assert account_id in plain(listing) and "mailto:a@example.test" in plain(listing)
    assert "EC (thumbprint thumb)" in plain(shown) and "valid" in plain(shown)
    assert AccountStatus.DEACTIVATED.value in plain(deactivated)
    assert "deactivated" in plain(again)
    assert missing.exit_code == 1
