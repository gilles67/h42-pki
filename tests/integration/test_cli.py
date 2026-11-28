"""`h42pki authority …` and `h42pki profile …` on a temporary SQLite database."""

import json
from datetime import timedelta
from pathlib import Path

import pytest
from click.testing import Result
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.cli._runtime import run
from h42pki.config import ENV_PREFIX, Settings, get_settings
from h42pki.keystore import get_keystore
from h42pki.services import IssuanceService
from tests.cli_helpers import plain
from tests.conftest import TEST_PASSPHRASE
from tests.x509_helpers import csr_pem, make_csr, name

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
    assert "Traceback" not in plain(result)
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
    assert "Root CA created." in plain(result)
    assert "CN=Home42 Root CA" in plain(result)
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
    assert "http://pki.home42.test" in plain(status)
    assert "Path length      1" in plain(status)


@pytest.mark.parametrize("days", ["0", "10951", "abc"])
def test_init_rejects_invalid_validity_before_doing_anything(days: str) -> None:
    result = invoke(*INIT, "--validity-days", days)

    assert result.exit_code == 2
    assert "--validity-days" in plain(result)
    assert invoke("authority", "status").exit_code == 1  # nothing was created


def test_init_rejects_invalid_subject() -> None:
    result = invoke(*INIT, "--country", "france")

    assert result.exit_code == 2
    assert "invalid subject: country_name" in plain(result)


def test_second_init_is_refused() -> None:
    assert invoke(*INIT).exit_code == 0

    result = invoke("authority", "init", "--name", "other", "--common-name", "Other")

    assert result.exit_code == 1
    assert "error: a local certificate authority already exists" in plain(result)


def test_status() -> None:
    assert invoke("authority", "status").exit_code == 1
    invoke(*INIT)

    result = invoke("authority", "status")

    assert result.exit_code == 0
    for label in ("Name", "Status", "Subject", "SHA-256", "Not before", "Not after"):
        assert label in plain(result)
    assert "home42-root" in plain(result) and "active" in plain(result)


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
    assert "h42pki authority init" in plain(result)


def test_profile_list() -> None:
    result = invoke("profile", "list")

    assert result.exit_code == 0
    lines = plain(result).splitlines()
    assert lines[0].split()[:4] == ["NAME", "KIND", "ENABLED", "APPROVAL"]
    tls_server = next(line for line in lines if line.startswith("tls_server"))
    assert tls_server.split()[2:4] == ["yes", "auto"]
    assert "90 (max 200)" in tls_server and "server_auth" in tls_server
    assert len(lines) == 8
    service_tls = next(line for line in lines if line.startswith("service_tls"))
    assert service_tls.split()[2] == "internal"
    scep_ra = next(line for line in lines if line.startswith("scep_ra"))
    assert scep_ra.split()[2] == "internal"


def test_profile_disable_and_enable() -> None:
    result = invoke("profile", "disable", "device")

    assert result.exit_code == 0, result.output
    assert "profile device disabled (issuance.disabled_profiles = ['device'])" in plain(
        result, "stdout"
    )
    assert "applied hot" in plain(result, "stdout")
    listing = plain(invoke("profile", "list"), "stdout").splitlines()
    device = next(line for line in listing if line.startswith("device"))
    assert device.split()[2] == "no"
    assert "already disabled" in plain(invoke("profile", "disable", "device"), "stdout")
    assert json.loads(plain(invoke("config", "get", "issuance.disabled_profiles"), "stdout")) == [
        "device"
    ]

    result = invoke("profile", "enable", "device")

    assert result.exit_code == 0, result.output
    assert "profile device enabled (issuance.disabled_profiles = [])" in plain(result, "stdout")
    assert "already enabled" in plain(invoke("profile", "enable", "device"), "stdout")


def test_profile_disable_unknown() -> None:
    result = invoke("profile", "disable", "code_signing")

    assert result.exit_code == 1
    assert "profile 'code_signing' does not exist" in plain(result, "stderr")


def test_profile_show() -> None:
    result = invoke("profile", "show", "sub_ca")

    assert result.exit_code == 0
    profile = json.loads(plain(result, "stdout"))
    assert profile["basic_constraints"] == {"ca": True, "path_length": 0}
    assert profile["auto_approve"] is False


def test_profile_show_unknown() -> None:
    result = invoke("profile", "show", "code_signing")

    assert result.exit_code == 1
    assert "profile 'code_signing' does not exist" in plain(result)


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
    assert "error: H42_PKI_CA_PASSPHRASE" in plain(result)
    assert "required for operations on private keys" in plain(result)
    assert invoke("authority", "status").exit_code == 1  # nothing was created


@pytest.mark.usefixtures("no_passphrase")
def test_serve_without_passphrase_is_refused() -> None:
    result = invoke("serve")

    assert result.exit_code == 2
    assert "cannot start the server: H42_PKI_CA_PASSPHRASE" in plain(result)


def test_invalid_configuration_is_a_readable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "staging")
    get_settings.cache_clear()

    result = invoke("profile", "list")

    assert result.exit_code == 2
    assert "invalid configuration: environment:" in plain(result)


def test_authority_update_public_base_url() -> None:
    invoke(*INIT)

    result = invoke("authority", "update", "--public-base-url", "http://pki.home42.test/")

    assert result.exit_code == 0, result.output
    assert "Public base URL set to http://pki.home42.test" in plain(result)
    assert "Certificates already issued are unchanged" in plain(result)
    assert "http://pki.home42.test" in plain(invoke("authority", "status"))

    removed = invoke("authority", "update", "--public-base-url", "")
    assert removed.exit_code == 0
    assert "Public base URL removed" in plain(removed)
    assert "Public base URL  -" in plain(invoke("authority", "status"))


def test_https_public_base_url_warns() -> None:
    result = invoke(*INIT, "--public-base-url", "https://pki.home42.test")

    assert result.exit_code == 0, result.output
    assert "warning: an https public base URL may cause validation loops" in plain(result)


@pytest.mark.parametrize("command", ["init", "update"])
def test_invalid_public_base_url_fails_before_anything(command: str) -> None:
    if command == "update":
        invoke(*INIT)
        args = ["authority", "update", "--public-base-url", "ftp://pki.home42.test"]
    else:
        args = [*INIT, "--public-base-url", "ftp://pki.home42.test"]

    result = invoke(*args)

    assert result.exit_code == 2
    assert "must use http or https" in plain(result)


def test_update_without_authority() -> None:
    result = invoke("authority", "update", "--public-base-url", "http://pki.home42.test")

    assert result.exit_code == 1
    assert "h42pki authority init" in plain(result)


def test_invalid_authority_name() -> None:
    result = invoke("authority", "init", "--name", "Home42 Root", "--common-name", "Root")

    assert result.exit_code == 1
    assert "invalid CA name" in plain(result)


def _issue_in_cli_database(profile: str, csr: str) -> str:
    """Submit a request against the CLI database (there is no submit command)."""

    async def operation(settings: Settings) -> str:
        request = await IssuanceService(get_keystore(settings)).submit(
            csr=csr, profile_name=profile, validity_days=None, actor="cli"
        )
        return str(request.certificate_id)

    return run(operation)


def _server_csr(host: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return csr_pem(make_csr(key, name(CN=host), sans=[f"dns:{host}"]))


def test_certificate_list(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke(*INIT)
    for host in ("a.example.test", "b.example.test"):
        _issue_in_cli_database("tls_server", _server_csr(host))
    monkeypatch.delenv(f"{ENV_PREFIX}CA_PASSPHRASE")  # B32: read-only, no passphrase
    get_settings.cache_clear()

    everything = invoke("certificate", "list")
    servers = invoke("certificate", "list", "--profile", "tls_server", "--limit", "1")

    assert everything.exit_code == 0, everything.output
    lines = plain(everything, "stdout").splitlines()
    assert lines[0].split() == ["ID", "SERIAL", "SUBJECT", "PROFILE", "STATUS", "NOT", "AFTER"]
    assert [line.split()[2] for line in lines[1:]] == [
        "CN=b.example.test",
        "CN=a.example.test",
        "CN=Home42",  # root subject "CN=Home42 Root CA"
    ]
    assert "(root)" in lines[-1] and "valid" in lines[1]
    assert "3 of 3 certificate(s)" in plain(everything)
    assert plain(servers, "stdout").count("tls_server") == 1
    assert "1 of 2 certificate(s)" in plain(servers)


def test_certificate_list_rejects_invalid_options() -> None:
    assert invoke("certificate", "list", "--limit", "501").exit_code == 2
    assert invoke("certificate", "list", "--status", "pending").exit_code == 2


def test_certificate_export(tmp_path: Path) -> None:
    invoke(*INIT)
    certificate_id = _issue_in_cli_database("tls_server", _server_csr("www.example.test"))

    pem = invoke("certificate", "export", certificate_id)
    chain = invoke("certificate", "export", certificate_id, "--chain")
    target = tmp_path / "leaf.crt"
    der = invoke(
        "certificate", "export", certificate_id, "--format", "der", "--output", str(target)
    )

    assert pem.exit_code == chain.exit_code == der.exit_code == 0
    leaf = x509.load_pem_x509_certificate(pem.stdout_bytes)
    assert x509.load_der_x509_certificate(target.read_bytes()) == leaf
    leaf_again, root = x509.load_pem_x509_certificates(chain.stdout_bytes)
    assert leaf_again == leaf
    leaf.verify_directly_issued_by(root)
    assert root == exported()


def test_certificate_export_errors() -> None:
    invoke(*INIT)

    unknown = invoke("certificate", "export", "00000000-0000-0000-0000-000000000000")
    chain_der = invoke(
        "certificate", "export", "00000000-0000-0000-0000-000000000000", "--chain",
        "--format", "der",
    )  # fmt: skip
    bad_id = invoke("certificate", "export", "not-a-uuid")

    assert unknown.exit_code == 1 and "does not exist" in plain(unknown)
    assert chain_der.exit_code == 2 and "--chain is only available in PEM" in plain(chain_der)
    assert bad_id.exit_code == 2
