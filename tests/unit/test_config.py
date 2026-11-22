import os
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
    os.chmod(secret, 0o600)  # private file: no B4 warning on POSIX
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


def test_passphrase_is_optional_in_settings() -> None:  # B32
    assert Settings().ca_passphrase is None


def test_regression_B32_server_refuses_to_start_without_passphrase() -> None:
    from h42pki.main import create_app

    with pytest.raises(RuntimeError, match="H42_PKI_CA_PASSPHRASE .* is required"):
        create_app(Settings(environment="dev"))


def test_keystore_requires_the_passphrase() -> None:
    from h42pki.errors import MissingPassphrase
    from h42pki.keystore import get_keystore

    with pytest.raises(MissingPassphrase, match="H42_PKI_CA_PASSPHRASE"):
        get_keystore(Settings())
    assert MissingPassphrase.status_code == 503


def test_passphrase_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", PASSPHRASE)

    settings = get_settings()

    assert PASSPHRASE not in repr(settings)
    assert PASSPHRASE not in str(settings)
    assert PASSPHRASE not in settings.model_dump_json()


posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")


def _secret_file(directory: Path, name: str, mode: int) -> Path:
    path = directory / name
    path.write_text(PASSPHRASE, encoding="utf-8")
    os.chmod(path, mode)
    return path


@posix_only
def test_regression_B4_writable_file_rejected_in_production(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = _secret_file(tmp_path, "passphrase", 0o620)
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE_FILE", str(secret))

    with pytest.raises(ValueError, match="writable by group or others") as excinfo:
        get_settings()
    assert PASSPHRASE not in str(excinfo.value)


@posix_only
def test_regression_B4_writable_secrets_dir_file_rejected_in_production(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _secret_file(tmp_path, "h42_pki_ca_passphrase", 0o666)
    monkeypatch.setenv(f"{ENV_PREFIX}SECRETS_DIR", str(tmp_path))

    with pytest.raises(ValueError, match="writable by group or others") as excinfo:
        get_settings()
    assert PASSPHRASE not in str(excinfo.value)


@posix_only
def test_regression_B4_writable_file_warns_outside_production(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = _secret_file(tmp_path, "passphrase", 0o602)
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE_FILE", str(secret))
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "dev")

    with pytest.warns(UserWarning, match="writable by group or others") as record:
        settings = get_settings()

    assert settings.ca_passphrase.get_secret_value() == PASSPHRASE
    assert all(PASSPHRASE not in str(w.message) for w in record)


@posix_only
def test_regression_B4_world_readable_file_variable_warns(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = _secret_file(tmp_path, "passphrase", 0o644)
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE_FILE", str(secret))

    with pytest.warns(UserWarning, match="readable by others"):
        settings = get_settings()  # production: readable is only a warning

    assert settings.ca_passphrase.get_secret_value() == PASSPHRASE


@posix_only
def test_regression_B4_docker_secret_0444_accepted_silently(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _secret_file(tmp_path, "h42_pki_ca_passphrase", 0o444)
    monkeypatch.setenv(f"{ENV_PREFIX}SECRETS_DIR", str(tmp_path))

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        settings = get_settings()

    assert settings.ca_passphrase.get_secret_value() == PASSPHRASE


@posix_only
def test_regression_B4_private_file_accepted_silently(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = _secret_file(tmp_path, "passphrase", 0o600)
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE_FILE", str(secret))

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        settings = get_settings()

    assert settings.ca_passphrase.get_secret_value() == PASSPHRASE
