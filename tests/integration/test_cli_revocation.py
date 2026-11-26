"""`h42pki certificate revoke` and `h42pki crl …` on a temporary SQLite database."""

import pytest
from cryptography import x509

from h42pki.config import ENV_PREFIX, get_settings
from tests.cli_helpers import plain
from tests.integration.test_cli import (
    INIT,
    _issue_in_cli_database,
    _server_csr,
    cli_environment,  # noqa: F401 - autouse fixture of the CLI tests
    invoke,
)


def test_revoke_and_crl(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke(*INIT, "--crl")
    certificate_id = _issue_in_cli_database("tls_server", _server_csr("a.example.test"))

    revoked = invoke(
        "certificate", "revoke", certificate_id, "--reason", "key_compromise",
        "--invalidity-date", "2026-11-01",
    )  # fmt: skip
    again = invoke("certificate", "revoke", certificate_id, "--reason", "superseded")
    shown = invoke("crl", "show")
    der = invoke("crl", "show", "--der")
    listing = invoke("certificate", "list", "--status", "revoked")

    assert revoked.exit_code == 0, revoked.output
    assert "revoked (key_compromise)" in plain(revoked)
    assert again.exit_code == 1 and "already revoked" in plain(again)
    assert shown.exit_code == 0, shown.output
    lines = plain(shown).splitlines()
    # CRL 1 at `authority init --crl`, CRL 2 after the revocation.
    assert ["CRL", "number", "2"] in [line.split() for line in lines]
    assert ["Entries", "1"] in [line.split() for line in lines]
    crl = x509.load_der_x509_crl(der.stdout_bytes)
    [entry] = list(crl)
    invalidity = entry.extensions.get_extension_for_class(x509.InvalidityDate).value
    assert invalidity.invalidity_date_utc.isoformat() == "2026-11-01T00:00:00+00:00"
    assert plain(listing, "stdout").splitlines()[1].split()[0] == certificate_id


def test_revoke_refuses_suspension() -> None:
    invoke(*INIT)
    certificate_id = _issue_in_cli_database("tls_server", _server_csr("a.example.test"))

    result = invoke("certificate", "revoke", certificate_id, "--reason", "certificate_hold")

    assert result.exit_code == 2


def test_revoke_needs_the_passphrase_only_with_a_crl(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke(*INIT, "--crl")
    certificate_id = _issue_in_cli_database("tls_server", _server_csr("a.example.test"))
    monkeypatch.delenv(f"{ENV_PREFIX}CA_PASSPHRASE")
    get_settings.cache_clear()

    result = invoke("certificate", "revoke", certificate_id, "--reason", "superseded")

    assert result.exit_code == 1 and "H42_PKI_CA_PASSPHRASE" in plain(result)
    assert "valid" in plain(invoke("certificate", "list"), "stdout").splitlines()[1]


def test_revoke_without_crl_needs_no_passphrase(monkeypatch: pytest.MonkeyPatch) -> None:
    invoke(*INIT)
    certificate_id = _issue_in_cli_database("tls_server", _server_csr("a.example.test"))
    monkeypatch.delenv(f"{ENV_PREFIX}CA_PASSPHRASE")
    get_settings.cache_clear()

    result = invoke("certificate", "revoke", certificate_id, "--reason", "superseded")

    assert result.exit_code == 0, result.output


def test_crl_generate_increments_the_number() -> None:
    invoke(*INIT, "--crl")

    first = invoke("crl", "generate")
    second = invoke("crl", "generate")

    assert first.exit_code == 0, first.output
    assert "CRL 2 generated." in plain(first) and "CRL 3 generated." in plain(second)


def test_init_publishes_the_first_crl() -> None:
    invoke(*INIT, "--crl")

    shown = invoke("crl", "show")

    assert shown.exit_code == 0, shown.output
    assert ["Entries", "0"] in [line.split() for line in plain(shown).splitlines()]


def test_crl_commands_without_crl() -> None:
    invoke(*INIT)

    for command in (("crl", "show"), ("crl", "generate")):
        result = invoke(*command)
        assert result.exit_code == 1 and "without a CRL" in plain(result)
