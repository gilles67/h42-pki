"""EST accounts: admin API and CLI (ADR-0018). Passwords never come back, except a generated one."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import time_machine
from click.testing import Result
from httpx import AsyncClient
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.config import ENV_PREFIX, get_settings
from h42pki.models import AuditLog, EnrollmentCredential
from h42pki.services.est_accounts import EstAccountService
from tests.cli_helpers import plain

API = "/api/v1/est/accounts"
PASSWORD = "a chosen password"  # noqa: S105 - test value


async def audit_text() -> str:
    return " ".join(str(entry.details) for entry in await AuditLog.all())


# --- API --------------------------------------------------------------------------------------


async def test_create_with_a_chosen_password(client: AsyncClient) -> None:
    response = await client.post(
        API, json={"username": "router-01", "password": PASSWORD, "description": "lab router"}
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["password"] is None  # chosen: never echoed
    account = body["account"]
    assert (account["username"], account["status"], account["description"]) == (
        "router-01",
        "active",
        "lab router",
    )
    assert set(account) == {
        "username", "status", "expires_at", "description", "created_by", "created_at",
        "last_used_at",
    }  # fmt: skip
    assert await EstAccountService().authenticate("router-01", PASSWORD) is not None
    stored = await EnrollmentCredential.get(identifier="router-01")
    assert PASSWORD not in stored.secret_hash and PASSWORD not in repr(stored)
    entry = await AuditLog.get(action="est.account.create")
    assert entry.details["password"] == "chosen"  # noqa: S105 - how it was set, not the value
    assert PASSWORD not in await audit_text()


async def test_create_with_a_generated_password_shown_once(client: AsyncClient) -> None:
    created = (await client.post(API, json={"username": "alice"})).json()
    generated = created["password"]

    shown = (await client.get(f"{API}/alice")).json()
    listed = (await client.get(API)).json()

    assert len(generated) == 24
    assert "password" not in shown and generated not in str(listed)
    assert await EstAccountService().authenticate("alice", generated) is not None
    assert generated not in await audit_text()


@pytest.mark.parametrize(
    "body",
    [
        {"username": "a:b"},
        {"username": "x" * 65},
        {"username": "alice", "password": "short"},
        {"username": "alice", "expires_at": "2020-01-01T00:00:00Z"},
        {"username": "alice", "expires_at": "2030-01-01T00:00:00"},  # no time zone
        {"username": "alice", "role": "admin"},
    ],
)
async def test_invalid_creations(client: AsyncClient, body: dict[str, object]) -> None:
    response = await client.post(API, json=body)

    assert response.status_code == 422
    assert "short" not in response.text or body.get("password") != "short"


async def test_duplicate_and_unknown(client: AsyncClient) -> None:
    await client.post(API, json={"username": "alice", "password": PASSWORD})

    again = await client.post(API, json={"username": "alice", "password": PASSWORD})
    unknown = await client.get(f"{API}/bob")

    assert again.status_code == 409
    assert unknown.status_code == 404


async def test_disable_enable_password_delete(client: AsyncClient) -> None:
    await client.post(API, json={"username": "alice", "password": PASSWORD})
    service = EstAccountService()

    disabled = (await client.post(f"{API}/alice/disable")).json()
    refused = await service.authenticate("alice", PASSWORD)
    enabled = (await client.post(f"{API}/alice/enable")).json()
    changed = (await client.post(f"{API}/alice/password", json={})).json()
    chosen = (await client.post(f"{API}/alice/password", json={"password": "another one!"})).json()
    deleted = await client.delete(f"{API}/alice")

    assert disabled["status"] == "disabled" and refused is None
    assert enabled["status"] == "active"
    assert len(changed["password"]) == 24 and chosen["password"] is None
    assert deleted.status_code == 204
    assert (await client.get(f"{API}/alice")).status_code == 404
    actions = [entry.action for entry in await AuditLog.filter(action__startswith="est.")]
    assert actions == [
        "est.account.create",
        "est.account.disable",
        "est.account.enable",
        "est.account.password",
        "est.account.password",
        "est.account.delete",
    ]


async def test_authentication(client: AsyncClient) -> None:
    expires = datetime.now(UTC) + timedelta(days=1)
    await client.post(
        API, json={"username": "alice", "password": PASSWORD, "expires_at": expires.isoformat()}
    )
    service = EstAccountService()

    good = await service.authenticate("alice", PASSWORD)
    wrong = await service.authenticate("alice", PASSWORD + "!")
    unknown = await service.authenticate("bob", PASSWORD)
    malformed = await service.authenticate("a:b", PASSWORD)
    with time_machine.travel(expires + timedelta(seconds=1), tick=False):
        expired = await service.authenticate("alice", PASSWORD)

    assert good is not None and good.last_used_at is not None
    assert (wrong, unknown, malformed, expired) == (None, None, None, None)
    shown = (await client.get(f"{API}/alice")).json()
    assert shown["last_used_at"] is not None


# --- CLI --------------------------------------------------------------------------------------

runner = CliRunner()


@pytest.fixture
def cli_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    database = tmp_path / "data" / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    get_settings.cache_clear()


def invoke(*args: str, stdin: str | None = None) -> Result:
    result = runner.invoke(app, list(args), input=stdin)
    assert "Traceback" not in plain(result)
    return result


@pytest.mark.usefixtures("cli_environment")
def test_cli_account_life_cycle() -> None:
    chosen = invoke("est", "account", "create", "alice", "--password", "-", stdin=PASSWORD + "\n")
    generated = invoke("est", "account", "create", "bob", "--description", "lab")
    listing = invoke("est", "account", "list")
    shown = invoke("est", "account", "show", "bob")
    disabled = invoke("est", "account", "disable", "alice")
    enabled = invoke("est", "account", "enable", "alice")
    reset = invoke("est", "account", "reset-password", "alice")
    deleted = invoke("est", "account", "delete", "bob")
    missing = invoke("est", "account", "show", "bob")

    assert chosen.exit_code == 0, chosen.output
    assert PASSWORD not in plain(chosen)
    password = plain(generated, "stdout").strip()
    assert len(password) == 24 and password.isalnum()  # alone on stdout: easy to capture
    assert "shown this one time" in plain(generated, "stderr")
    assert "alice" in plain(listing) and "bob" in plain(listing)
    assert password not in plain(listing) + plain(shown)
    assert "lab" in plain(shown)
    assert "disabled" in plain(disabled) and "active" in plain(enabled)
    assert len(plain(reset, "stdout").strip()) == 24
    assert deleted.exit_code == 0 and missing.exit_code == 1


@pytest.mark.usefixtures("cli_environment")
def test_cli_refuses_bad_input() -> None:
    short = invoke("est", "account", "create", "alice", "--password", "-", stdin="short\n")
    bad_name = invoke("est", "account", "create", "a:b")
    argument = invoke("est", "account", "create", "alice", "--password", PASSWORD)

    assert short.exit_code == 1 and "8 to 1024" in plain(short)
    assert bad_name.exit_code == 1
    assert argument.exit_code == 2 and "standard input" in plain(argument)
    assert PASSWORD not in plain(argument)
