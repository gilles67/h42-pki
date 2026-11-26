"""Revocation statuses in GET /health (ADR-0017): CRL, OCSP, check with the parent."""

from datetime import UTC, datetime, timedelta

import time_machine
from httpx import AsyncClient

from h42pki.keystore import KeyStore
from h42pki.models import Authority, AuthorityStatus
from h42pki.services.crl import CrlService
from tests.conftest import RootFactory


async def test_without_a_ca(client: AsyncClient) -> None:
    body = (await client.get("/health")).json()

    assert (body["crl"], body["ocsp"], body["parent_check"]) == (None, None, None)


async def test_without_revocation(client: AsyncClient, make_root: RootFactory) -> None:
    await make_root()

    body = (await client.get("/health")).json()

    assert body["crl"]["enabled"] is False and body["ocsp"] == "disabled"
    assert body["warnings"] == [] and body["status"] == "ok"


async def test_crl_and_ocsp(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    authority = await make_root(crl=True, ocsp=True)
    waiting = (await client.get("/health")).json()
    crl = await CrlService(keystore).ensure_fresh(authority)
    assert crl is not None

    body = (await client.get("/health")).json()
    with time_machine.travel(crl.next_update + timedelta(seconds=1), tick=False):
        stale = (await client.get("/health")).json()

    assert "no CRL published yet" in waiting["warnings"]
    assert body["ocsp"] == "enabled" and body["warnings"] == []
    assert body["crl"]["crl_number"] == 1 and body["crl"]["refresh"] == "unknown"  # no launcher
    assert datetime.fromisoformat(body["crl"]["next_update"]) == crl.next_update
    assert 0 <= body["crl"]["age_seconds"] < 60
    assert "the CRL is out of date" in stale["warnings"] and stale["status"] == "degraded"


async def test_parent_check_and_revoked_ca(client: AsyncClient, make_root: RootFactory) -> None:
    authority = await make_root()
    checked = datetime(2026, 11, 26, 12, tzinfo=UTC)
    await Authority.filter(id=authority.id).update(
        parent_check_at=checked, parent_check_result="unreachable"
    )
    unreachable = (await client.get("/health")).json()
    await Authority.filter(id=authority.id).update(
        status=AuthorityStatus.REVOKED, parent_check_result="revoked"
    )

    revoked = (await client.get("/health")).json()

    assert unreachable["parent_check"] == {
        "result": "unreachable",
        "checked_at": "2026-11-26T12:00:00Z",
    }
    assert "the status check with the parent CA failed (unreachable)" in unreachable["warnings"]
    assert revoked["authority"] == "revoked"
    assert revoked["warnings"] == [
        "the local CA has been revoked by its parent: it no longer issues"
    ]
