import warnings
from pathlib import Path

import pytest

from h42pki.config import ENV_PREFIX, Settings, get_settings

PASSPHRASE = "unit-test-passphrase"  # noqa: S105 - not a real secret


def test_reads_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", PASSPHRASE)
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "dev")
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", "sqlite://:memory:")

    settings = get_settings()

    assert settings.ca_passphrase.get_secret_value() == PASSPHRASE
    assert settings.environment == "dev"
    assert settings.database_url == "sqlite://:memory:"


def test_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", PASSPHRASE)

    settings = get_settings()

    assert settings.environment == "production"
    assert settings.database_url == "sqlite://data/h42pki.sqlite3"


def test_reads_secrets_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "h42_pki_ca_passphrase").write_text(PASSPHRASE + "\n", encoding="utf-8")
    monkeypatch.setenv(f"{ENV_PREFIX}SECRETS_DIR", str(tmp_path))

    assert get_settings().ca_passphrase.get_secret_value() == PASSPHRASE


def test_reads_file_variable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret = tmp_path / "passphrase.txt"
    secret.write_text(PASSPHRASE + "\n", encoding="utf-8")
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE_FILE", str(secret))

    assert get_settings().ca_passphrase.get_secret_value() == PASSPHRASE


def test_environment_variable_wins_over_secret_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "h42_pki_ca_passphrase").write_text("from-file", encoding="utf-8")
    monkeypatch.setenv(f"{ENV_PREFIX}SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", PASSPHRASE)

    assert get_settings().ca_passphrase.get_secret_value() == PASSPHRASE


def test_missing_secrets_dir_is_ignored(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}SECRETS_DIR", str(tmp_path / "does-not-exist"))
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", PASSPHRASE)

    with warnings.catch_warnings():
        warnings.simplefilter("error")  # pydantic-settings warns on a missing secrets_dir
        settings = get_settings()

    assert settings.ca_passphrase.get_secret_value() == PASSPHRASE


def test_passphrase_is_required() -> None:
    with pytest.raises(ValueError, match="ca_passphrase"):
        Settings()  # type: ignore[call-arg]


def test_passphrase_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", PASSPHRASE)

    settings = get_settings()

    assert PASSPHRASE not in repr(settings)
    assert PASSPHRASE not in str(settings)
    assert PASSPHRASE not in settings.model_dump_json()
