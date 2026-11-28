"""ACME lab mode (acme.insecure_skip_validation) is refused in production (ADR-0020)."""

import pytest

from h42pki.config import ENV_PREFIX, get_settings
from h42pki.errors import LabModeInProduction
from h42pki.models import Setting
from h42pki.services.settings import SettingsService, check_lab_mode

pytestmark = pytest.mark.usefixtures("client")

KEY = "acme.insecure_skip_validation"


async def test_lab_mode_accepted_outside_production() -> None:
    change = await SettingsService().set(KEY, True, actor="cli")

    assert change.changed and (await SettingsService().effective()).acme.insecure_skip_validation
    await check_lab_mode()  # no error


async def test_lab_mode_refused_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "production")
    get_settings.cache_clear()

    with pytest.raises(LabModeInProduction, match="refused when H42_PKI_ENVIRONMENT is production"):
        await SettingsService().set(KEY, True, actor="cli")
    await SettingsService().set(KEY, False, actor="cli")  # false is fine

    assert await Setting.get_or_none(key=KEY) is not None


async def test_start_refused_with_lab_mode_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    await SettingsService().set(KEY, True, actor="cli")  # written in test, then production
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "production")
    get_settings.cache_clear()

    with pytest.raises(LabModeInProduction):
        await check_lab_mode()
