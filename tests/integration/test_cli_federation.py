"""`h42pki federation …` and `h42pki request …` on a temporary SQLite database."""

from pathlib import Path
from uuid import uuid4

import pytest
from click.testing import Result
from cryptography.hazmat.primitives.asymmetric import ec
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.cli._runtime import run
from h42pki.config import ENV_PREFIX, Settings, get_settings
from h42pki.core.federation import parse_token
from h42pki.keystore import get_keystore
from h42pki.models import AuditLog
from h42pki.services.federation import FederationService
from tests.cli_helpers import plain
from tests.conftest import TEST_PASSPHRASE
from tests.x509_helpers import csr_pem, make_csr, name

runner = CliRunner()


@pytest.fixture(autouse=True)
def cli_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    database = tmp_path / "data" / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", TEST_PASSPHRASE)
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    get_settings.cache_clear()


def invoke(*args: str) -> Result:
    result = runner.invoke(app, list(args))
    assert "Traceback" not in plain(result)
    return result


@pytest.fixture
def root() -> None:
    result = invoke(
        "authority", "init", "--name", "root", "--common-name", "Root", "--path-length", "2"
    )
    assert result.exit_code == 0, plain(result)


@pytest.fixture
def no_passphrase(root: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(f"{ENV_PREFIX}CA_PASSPHRASE")
    get_settings.cache_clear()


def enrol(token: str, ca_name: str = "child") -> str:
    """Enrol a child CA as its container would; returns the request ID."""
    csr = csr_pem(make_csr(ec.generate_private_key(ec.SECP256R1()), name(CN="Child CA")))

    async def operation(settings: Settings) -> str:
        enrolment = await FederationService(get_keystore(settings)).enroll(
            token, csr=csr, name=ca_name, public_base_url=None
        )
        return str(enrolment.request.id)

    return run(operation)


def token_of(result: Result) -> str:
    assert result.exit_code == 0, plain(result)
    return plain(result, "stdout").strip()


def test_invite(no_passphrase: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}SERVER_HOSTNAME", "root.pki.test")
    get_settings.cache_clear()

    result = invoke("federation", "invite", "--label", "intermediate", "--path-length", "1")

    token = token_of(result)
    assert parse_token(token) is not None  # the token alone on stdout
    details = plain(result, "stderr")
    assert token not in details
    assert "Child path length   1" in details
    assert "waits for `h42pki request approve`" in details
    assert "--parent-url https://root.pki.test:8443 --token -" in details
    listing = plain(invoke("federation", "invitations"))
    assert "intermediate" in listing and "manual" in listing and "active" in listing
    assert token.partition(".")[2] not in listing


def test_token_is_never_audited(root: None) -> None:
    secret = token_of(invoke("federation", "invite", "--auto-approve")).partition(".")[2]

    async def details(settings: Settings) -> str:
        return str([entry.details for entry in await AuditLog.all()])

    assert secret not in run(details)


def test_invite_errors() -> None:
    result = invoke("federation", "invite")
    assert result.exit_code == 1
    assert "h42pki authority init" in plain(result)


def test_unlimited_path_length_is_shown() -> None:
    invoke("authority", "init", "--name", "root", "--common-name", "Root")
    result = invoke("federation", "invite")
    assert "Child path length   unlimited" in plain(result, "stderr")


def test_invite_under_path_length_zero() -> None:
    invoke("authority", "init", "--name", "root", "--common-name", "Root", "--path-length", "0")
    result = invoke("federation", "invite")
    assert result.exit_code == 1 and "pathLen 0" in plain(result)


def test_revoke_invitation(no_passphrase: None) -> None:
    token = parse_token(token_of(invoke("federation", "invite")))
    assert token is not None

    result = invoke("federation", "revoke-invitation", str(token.invitation_id))

    assert result.exit_code == 0 and "Invitation revoked." in plain(result)
    assert "revoked" in plain(invoke("federation", "invitations"))
    again = invoke("federation", "revoke-invitation", str(token.invitation_id))
    assert again.exit_code == 1 and "already revoked" in plain(again)
    unknown = invoke("federation", "revoke-invitation", str(uuid4()))
    assert unknown.exit_code == 1 and "not found" in plain(unknown)


def test_request_approve(root: None) -> None:
    request_id = enrol(token_of(invoke("federation", "invite")))

    pending = plain(invoke("request", "list", "--status", "pending"))
    shown = plain(invoke("request", "show", request_id))
    approved = invoke("request", "approve", request_id)

    assert request_id in pending and "federation" in pending
    assert "Child CA" in shown and "child" in shown and "Invitation" in shown
    assert approved.exit_code == 0, plain(approved)
    assert "certificate issued" in plain(approved) and "by cli" in plain(approved)
    assert request_id not in plain(invoke("request", "list", "--status", "pending"))
    assert request_id in plain(invoke("request", "list"))
    children = plain(invoke("federation", "children"))
    assert "child" in children and "CN=Child CA" in children
    again = invoke("request", "approve", request_id)
    assert again.exit_code == 1 and "already been decided" in plain(again)


def test_request_reject(root: None) -> None:
    request_id = enrol(token_of(invoke("federation", "invite")))

    missing = invoke("request", "reject", request_id)
    result = invoke("request", "reject", request_id, "--reason", "not planned")

    assert missing.exit_code == 2 and "--reason" in plain(missing)
    assert result.exit_code == 0, plain(result)
    assert "rejected" in plain(result) and "not planned" in plain(result)


def test_only_approval_needs_the_passphrase(no_passphrase: None) -> None:
    for command in (("request", "list"), ("federation", "children")):
        assert invoke(*command).exit_code == 0
    unknown = invoke("request", "show", str(uuid4()))
    assert unknown.exit_code == 1 and "not found" in plain(unknown)
    approve = invoke("request", "approve", str(uuid4()))
    assert approve.exit_code == 1 and "H42_PKI_CA_PASSPHRASE" in plain(approve)


def test_revoke_child(root: None) -> None:
    enrol(token_of(invoke("federation", "invite", "--auto-approve")))

    bad = invoke("federation", "revoke-child", "child", "--reason", "certificate_hold")
    result = invoke("federation", "revoke-child", "child", "--reason", "key_compromise")

    assert bad.exit_code == 2
    assert result.exit_code == 0, plain(result)
    assert "revoked (key_compromise)" in plain(result) and "check-parent" in plain(result)
    assert "revoked" in plain(invoke("federation", "children"))
    unknown = invoke("federation", "revoke-child", "nobody", "--reason", "superseded")
    assert unknown.exit_code == 1 and "no child CA named 'nobody'" in plain(unknown)
