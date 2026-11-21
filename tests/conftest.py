"""Shared fixtures.

The legacy ``h42pki.ca.pki`` module reads the passphrase through ``get_settings()``, so the
``settings`` fixture configures the test environment through ``H42_PKI_*`` variables and
returns the cached settings: the app and the legacy code then see the same values.
"""

import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from h42pki.config import ENV_PREFIX, Settings, get_settings
from h42pki.main import create_app

TEST_PASSPHRASE = "test-only-passphrase"  # noqa: S105 - not a real secret


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Drop any H42_PKI_* variable from the developer environment and the settings cache."""
    for name in list(os.environ):
        if name.upper().startswith(ENV_PREFIX):
            monkeypatch.delenv(name)
    monkeypatch.setenv(f"{ENV_PREFIX}SECRETS_DIR", str(tmp_path / "no-secrets"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", "sqlite://:memory:")
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", TEST_PASSPHRASE)
    get_settings.cache_clear()
    return get_settings()


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[AsyncClient]:
    app = create_app(settings)
    async with (
        LifespanManager(app) as manager,
        AsyncClient(transport=ASGITransport(app=manager.app), base_url="http://testserver") as ac,
    ):
        yield ac
