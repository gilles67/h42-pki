"""`h42pki authority …` and `h42pki profile …` on a temporary SQLite database."""

import json
from datetime import timedelta
from pathlib import Path

import pytest
from click.testing import Result
from cryptography import x509
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.config import ENV_PREFIX, get_settings
from tests.conftest import TEST_PASSPHRASE

runner = CliRunner()
INIT = ["authority", "init", "--name", "home42-root", "--common-name", "Home42 Root CA"]


@pytest.fixture(autouse=True)
def cli_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    database = tmp_path / "data" / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", TEST_PASSPHRASE)
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    get_settings.cache_clear()
    return database


def invoke(*args: str) -> Result:
    result = runner.invoke(app, list(args))
    assert "Traceback" not in result.output
    return result


def exported(*extra: str) -> x509.Certificate:
    result = invoke("authority", "export", "--format", "der", *extra)
    assert result.exit_code == 0, result.output
    return x509.load_der_x509_certificate(result.stdout_bytes)


def validity(cert: x509.Certificate) -> timedelta:
    return cert.not_valid_after_utc - cert.not_valid_before_utc


def test_init_with_defaults(cli_environment: Path) -> None:
    result = invoke(*INIT)

    assert result.exit_code == 0, result.output
    assert "Root CA created." in result.output
    assert "CN=Home42 Root CA" in result.output
    assert cli_environment.exists()  # the data directory is created
    cert = exported()
    cert.verify_directly_issued_by(cert)
    assert validity(cert) == timedelta(days=3650)
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca and basic.path_length is None


def test_init_with_options() -> None:
    result = invoke(
        *INIT,
        "--organization",
        "Home42",
        "--country",
        "FR",
        "--key-algorithm",
        "ed25519",
        "--validity-days",
        "365",
        "--path-length",
        "1",
        "--public-base-url",
        "http://pki.home42.test",
    )

    assert result.exit_code == 0, result.output
    cert = exported()
    assert validity(cert) == timedelta(days=365)
    assert cert.signature_hash_algorithm is None  # Ed25519
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 1
    status = invoke("authority", "status")
    assert "http://pki.home42.test" in status.output
    assert "Path length      1" in status.output


@pytest.mark.parametrize("days", ["0", "10951", "abc"])
def test_init_rejects_invalid_validity_before_doing_anything(days: str) -> None:
    result = invoke(*INIT, "--validity-days", days)

    assert result.exit_code == 2
    assert "--validity-days" in result.output
    assert invoke("authority", "status").exit_code == 1  # nothing was created


def test_init_rejects_invalid_subject() -> None:
    result = invoke(*INIT, "--country", "france")

    assert result.exit_code == 2
    assert "invalid subject: country_name" in result.output


def test_second_init_is_refused() -> None:
    assert invoke(*INIT).exit_code == 0

    result = invoke("authority", "init", "--name", "other", "--common-name", "Other")

    assert result.exit_code == 1
    assert "error: a local certificate authority already exists" in result.output


def test_status() -> None:
    assert invoke("authority", "status").exit_code == 1
    invoke(*INIT)

    result = invoke("authority", "status")

    assert result.exit_code == 0
    for label in ("Name", "Status", "Subject", "SHA-256", "Not before", "Not after"):
        assert label in result.output
    assert "home42-root" in result.output and "active" in result.output


def test_export(tmp_path: Path) -> None:
    invoke(*INIT)

    pem = invoke("authority", "export")
    assert pem.exit_code == 0
    from_pem = x509.load_pem_x509_certificate(pem.stdout_bytes)
    target = tmp_path / "root.crt"
    assert invoke("authority", "export", "--format", "der", "--output", str(target)).exit_code == 0
    assert x509.load_der_x509_certificate(target.read_bytes()) == from_pem == exported()


def test_export_without_authority() -> None:
    result = invoke("authority", "export")

    assert result.exit_code == 1
    assert "h42pki authority init" in result.output


def test_profile_list() -> None:
    result = invoke("profile", "list")

    assert result.exit_code == 0
    lines = result.output.splitlines()
    assert lines[0].split()[:3] == ["NAME", "KIND", "APPROVAL"]
    tls_server = next(line for line in lines if line.startswith("tls_server"))
    assert "auto" in tls_server and "90 (max 200)" in tls_server and "server_auth" in tls_server
    assert len(lines) == 6


def test_profile_show() -> None:
    result = invoke("profile", "show", "sub_ca")

    assert result.exit_code == 0
    profile = json.loads(result.stdout)
    assert profile["basic_constraints"] == {"ca": True, "path_length": 0}
    assert profile["auto_approve"] is False


def test_profile_show_unknown() -> None:
    result = invoke("profile", "show", "code_signing")

    assert result.exit_code == 1
    assert "profile 'code_signing' does not exist" in result.output


@pytest.fixture
def no_passphrase(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(f"{ENV_PREFIX}CA_PASSPHRASE")
    get_settings.cache_clear()


def test_regression_B32_read_only_commands_need_no_passphrase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert invoke(*INIT).exit_code == 0  # with the passphrase
    monkeypatch.delenv(f"{ENV_PREFIX}CA_PASSPHRASE")
    get_settings.cache_clear()

    for command in (
        ["profile", "list"],
        ["profile", "show", "tls_server"],
        ["authority", "status"],
        ["authority", "export"],
    ):
        result = invoke(*command)
        assert result.exit_code == 0, (command, result.output)


@pytest.mark.usefixtures("no_passphrase")
def test_init_without_passphrase_is_a_readable_error() -> None:
    result = invoke(*INIT)

    assert result.exit_code == 1
    assert "error: H42_PKI_CA_PASSPHRASE" in result.output
    assert "required for operations on private keys" in result.output
    assert invoke("authority", "status").exit_code == 1  # nothing was created


@pytest.mark.usefixtures("no_passphrase")
def test_serve_without_passphrase_is_refused() -> None:
    result = invoke("serve")

    assert result.exit_code == 2
    assert "cannot start the server: H42_PKI_CA_PASSPHRASE" in result.output


def test_invalid_configuration_is_a_readable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "staging")
    get_settings.cache_clear()

    result = invoke("profile", "list")

    assert result.exit_code == 2
    assert "invalid configuration: environment:" in result.output


def test_authority_update_public_base_url() -> None:
    invoke(*INIT)

    result = invoke("authority", "update", "--public-base-url", "http://pki.home42.test/")

    assert result.exit_code == 0, result.output
    assert "Public base URL set to http://pki.home42.test" in result.output
    assert "Certificates already issued are unchanged" in result.output
    assert "http://pki.home42.test" in invoke("authority", "status").output

    removed = invoke("authority", "update", "--public-base-url", "")
    assert removed.exit_code == 0
    assert "Public base URL removed" in removed.output
    assert "Public base URL  -" in invoke("authority", "status").output


def test_https_public_base_url_warns() -> None:
    result = invoke(*INIT, "--public-base-url", "https://pki.home42.test")

    assert result.exit_code == 0, result.output
    assert "warning: an https public base URL may cause validation loops" in result.output


@pytest.mark.parametrize("command", ["init", "update"])
def test_invalid_public_base_url_fails_before_anything(command: str) -> None:
    if command == "update":
        invoke(*INIT)
        args = ["authority", "update", "--public-base-url", "ftp://pki.home42.test"]
    else:
        args = [*INIT, "--public-base-url", "ftp://pki.home42.test"]

    result = invoke(*args)

    assert result.exit_code == 2
    assert "must use http or https" in result.output


def test_update_without_authority() -> None:
    result = invoke("authority", "update", "--public-base-url", "http://pki.home42.test")

    assert result.exit_code == 1
    assert "h42pki authority init" in result.output


def test_invalid_authority_name() -> None:
    result = invoke("authority", "init", "--name", "Home42 Root", "--common-name", "Root")

    assert result.exit_code == 1
    assert "invalid CA name" in result.output
