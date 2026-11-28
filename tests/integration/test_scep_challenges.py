"""SCEP challenges: API, CLI and service (ADR-0019). Shown once, never stored nor audited."""

from datetime import timedelta
from pathlib import Path

import pytest
import time_machine
from click.testing import Result
from httpx import AsyncClient
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.config import ENV_PREFIX, get_settings
from h42pki.errors import Conflict
from h42pki.models import AuditLog, EnrollmentCredential
from h42pki.services.scep_challenges import ScepChallengeService
from tests.cli_helpers import plain

API = "/api/v1/scep/challenges"


async def audit_text() -> str:
    return " ".join(str(entry.details) for entry in await AuditLog.all())


async def test_single_use_by_default(client: AsyncClient) -> None:
    created = (await client.post(API, json={})).json()
    text = created["challenge"]
    service = ScepChallengeService()

    found = await service.check(text)
    assert found is not None
    await service.consume(found, actor="scep:test")
    spent = await service.check(text)

    assert created["details"]["max_uses"] == 1 and created["details"]["usable"] is True
    assert spent is None
    shown = (await client.get(f"{API}/{created['details']['id']}")).json()
    assert (shown["use_count"], shown["usable"]) == (1, False)
    assert "challenge" not in shown
    stored = await EnrollmentCredential.get(identifier=created["details"]["id"])
    assert text.split("-")[1] not in stored.secret_hash
    assert text.split("-")[1] not in await audit_text()


async def test_reusable_and_limited(client: AsyncClient) -> None:
    reusable = (await client.post(API, json={"max_uses": None})).json()["challenge"]
    twice = (await client.post(API, json={"max_uses": 2})).json()["challenge"]
    service = ScepChallengeService()

    for _ in range(5):
        found = await service.check(reusable)
        assert found is not None
        await service.consume(found, actor="scep:test")
    for _ in range(2):
        found = await service.check(twice)
        assert found is not None
        await service.consume(found, actor="scep:test")

    assert await service.check(reusable) is not None
    assert await service.check(twice) is None


async def test_expiry_and_disabling(client: AsyncClient) -> None:
    created = (await client.post(API, json={"expires_in_hours": 2})).json()
    identifier, text = created["details"]["id"], created["challenge"]
    service = ScepChallengeService()

    with time_machine.travel(timedelta(hours=2, seconds=1)):
        assert await service.check(text) is None
    disabled = (await client.post(f"{API}/{identifier}/disable")).json()
    refused = await service.check(text)
    enabled = (await client.post(f"{API}/{identifier}/enable")).json()
    accepted = await service.check(text)
    deleted = await client.delete(f"{API}/{identifier}")

    assert disabled["status"] == "disabled" and refused is None
    assert enabled["status"] == "active" and accepted is not None
    assert deleted.status_code == 204
    assert (await client.get(f"{API}/{identifier}")).status_code == 404
    actions = [e.action for e in await AuditLog.filter(action__startswith="scep.challenge")]
    assert actions == [
        "scep.challenge.create",
        "scep.challenge.disable",
        "scep.challenge.enable",
        "scep.challenge.delete",
    ]


@pytest.mark.parametrize("text", ["", "garbage", "ABCDEFGH-" + "A" * 32, None])
async def test_unknown_challenges(client: AsyncClient, text: str | None) -> None:
    await client.post(API, json={})

    assert await ScepChallengeService().check(text) is None


async def test_wrong_secret_of_a_known_id(client: AsyncClient) -> None:
    created = (await client.post(API, json={})).json()

    forged = created["details"]["id"] + "-" + "A" * 32

    assert await ScepChallengeService().check(forged) is None


async def test_concurrent_use_is_refused(client: AsyncClient) -> None:
    text = (await client.post(API, json={})).json()["challenge"]
    service = ScepChallengeService()
    first, second = await service.check(text), await service.check(text)
    assert first is not None and second is not None

    await service.consume(first, actor="scep:test")
    with pytest.raises(Conflict):
        await service.consume(second, actor="scep:test")


@pytest.mark.parametrize(
    "body", [{"max_uses": 0}, {"expires_in_hours": 0}, {"description": "x" * 300}, {"x": 1}]
)
async def test_invalid_creations(client: AsyncClient, body: dict[str, object]) -> None:
    assert (await client.post(API, json=body)).status_code == 422


# --- CLI --------------------------------------------------------------------------------------

runner = CliRunner()


@pytest.fixture
def cli_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    database = tmp_path / "data" / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    get_settings.cache_clear()


def invoke(*args: str) -> Result:
    result = runner.invoke(app, list(args))
    assert "Traceback" not in plain(result)
    return result


@pytest.mark.usefixtures("cli_environment")
def test_cli_life_cycle() -> None:
    single = invoke("scep", "challenge", "create", "--description", "router")
    fleet = invoke("scep", "challenge", "create", "--reusable", "--expires-in-hours", "24")
    three = invoke("scep", "challenge", "create", "--max-uses", "3")
    both = invoke("scep", "challenge", "create", "--reusable", "--max-uses", "3")
    text = plain(single, "stdout").strip()
    identifier = text.split("-")[0]
    listing = invoke("scep", "challenge", "list")
    shown = invoke("scep", "challenge", "show", identifier)
    disabled = invoke("scep", "challenge", "disable", identifier)
    deleted = invoke("scep", "challenge", "delete", identifier)

    assert single.exit_code == 0 and len(text) == 41
    assert "shown this one time" in plain(single, "stderr")
    assert len(plain(fleet, "stdout").strip()) == 41 and "unlimited" in plain(fleet, "stderr")
    assert "0/3" in plain(three, "stderr")
    assert both.exit_code == 2
    assert identifier in plain(listing) and text.split("-")[1] not in plain(listing)
    assert "0/1" in plain(shown) and "router" in plain(shown)
    assert "disabled" in plain(disabled)
    assert deleted.exit_code == 0
    assert invoke("scep", "challenge", "show", identifier).exit_code == 1
