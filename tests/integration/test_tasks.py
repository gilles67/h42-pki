"""Scheduled tasks of phase 3: CRL freshness, expired status (B34), purge of HTTPS keys (B44)."""

import asyncio
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import time_machine
from httpx import AsyncClient

from h42pki.core.keys import KeyAlgorithm
from h42pki.errors import Conflict
from h42pki.keystore import KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    Certificate,
    CertificateRequest,
    CertificateStatus,
    KeyPurpose,
    PrivateKey,
)
from h42pki.services.crl import CrlService
from h42pki.services.maintenance import MaintenanceService
from h42pki.services.tls_service import TlsServiceManager
from h42pki.tasks.maintenance import crl_task, expiry_task, parent_check_task, purge_task
from h42pki.tasks.periodic import PeriodicTask
from tests.conftest import IssueFactory, RootFactory
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], Any]


def server_csr(key_for: KeyFor, host: str = "www.example.test") -> str:
    return csr_pem(make_csr(key_for(KeyAlgorithm.EC_P256), name(CN=host), sans=[f"dns:{host}"]))


# --- expired status (B34) ---------------------------------------------------------------------


async def test_regression_B34_expired_status_persisted(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root()
    request = await issue("tls_server", server_csr(key_for))
    certificate = await Certificate.get(id=request.certificate_id)

    with time_machine.travel(certificate.not_after - timedelta(seconds=1), tick=False):
        assert await MaintenanceService.expire() == 0
    with time_machine.travel(certificate.not_after, tick=False):
        assert await expiry_task().run_once()
        assert await MaintenanceService.expire() == 0  # already written

    stored = await Certificate.get(id=certificate.id)
    assert stored.status is CertificateStatus.EXPIRED
    entry = await AuditLog.get(action="certificate.expire")
    assert entry.actor == "system" and entry.details["count"] == 1
    assert entry.details["certificate_ids"] == [str(certificate.id)]
    body = (await client.get("/api/v1/certificates", params={"status": "expired"})).json()
    assert [item["id"] for item in body["items"]] == [str(certificate.id)]


async def test_revoked_certificates_stay_revoked(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor, keystore: KeyStore
) -> None:
    from h42pki.services.revocation import RevocationService

    await make_root()
    request = await issue("tls_server", server_csr(key_for))
    certificate = await Certificate.get(id=request.certificate_id)
    await RevocationService(keystore).revoke(certificate.id, reason="superseded", actor="cli")

    with time_machine.travel(certificate.not_after + timedelta(days=1), tick=False):
        await MaintenanceService.expire()

    assert (await Certificate.get(id=certificate.id)).status is CertificateStatus.REVOKED


# --- purge of the built-in HTTPS certificates (B44) -------------------------------------------


async def test_regression_B44_superseded_service_tls_purged(
    make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    first = (await TlsServiceManager(keystore, ["pki.home42.test"]).ensure()).certificate
    second = (await TlsServiceManager(keystore, ["pki2.home42.test"]).ensure()).certificate
    assert first is not None and second is not None and first.id != second.id

    with time_machine.travel(first.not_after - timedelta(seconds=1), tick=False):
        assert (await MaintenanceService.purge_service_tls()).certificates == []
    with time_machine.travel(first.not_after, tick=False):
        assert await purge_task().run_once()

    assert not await Certificate.exists(id=first.id)
    assert not await CertificateRequest.exists(certificate_id=first.id)
    assert not await PrivateKey.exists(id=first.private_key_id)
    assert await Certificate.exists(id=second.id)  # the current one is kept
    assert await PrivateKey.filter(purpose=KeyPurpose.TLS).count() == 1
    assert await AuditLog.filter(action="certificate.purge").count() == 1
    entry = await AuditLog.get(action="private_key.delete")
    assert entry.details == {"purpose": "tls", "reason": "purge"}


async def test_latest_service_tls_is_kept_even_expired(
    make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    only = (await TlsServiceManager(keystore, ["pki.home42.test"]).ensure()).certificate
    assert only is not None

    with time_machine.travel(only.not_after + timedelta(days=30), tick=False):
        result = await MaintenanceService.purge_service_tls()

    assert result.certificates == [] and await Certificate.exists(id=only.id)


async def test_other_certificates_are_never_purged(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root()
    request = await issue("tls_server", server_csr(key_for))
    certificate = await Certificate.get(id=request.certificate_id)

    with time_machine.travel(certificate.not_after + timedelta(days=365), tick=False):
        await MaintenanceService.purge_service_tls()

    assert await Certificate.exists(id=certificate.id)


# --- CRL freshness ----------------------------------------------------------------------------


async def test_crl_task_renews_before_next_update(
    make_root: RootFactory, keystore: KeyStore
) -> None:
    authority = await make_root(crl=True)
    task = crl_task(keystore)
    assert await task.run_once()
    first = await CrlService.current(authority)
    assert first is not None

    with time_machine.travel(first.next_update - timedelta(hours=48, seconds=1), tick=False):
        assert await task.run_once()
        kept = await CrlService.current(authority)
    with time_machine.travel(first.next_update - timedelta(hours=48), tick=False):
        assert await task.run_once()
        renewed = await CrlService.current(authority)

    assert kept is not None and kept.crl_number == first.crl_number
    assert renewed is not None and renewed.crl_number == first.crl_number + 1


# --- the periodic runner ----------------------------------------------------------------------


async def test_failure_is_kept_in_the_state_then_cleared() -> None:
    outcomes: list[Exception | None] = [Conflict("busy"), RuntimeError("boom"), None]

    async def action() -> None:
        outcome = outcomes.pop(0)
        if outcome is not None:
            raise outcome

    task = PeriodicTask("test", action, interval=60)

    assert not await task.run_once()
    assert (task.state.failing, task.state.last_error) == (True, "busy")
    assert not await task.run_once()
    assert task.state.last_error == "RuntimeError"  # never the message of an unknown error
    assert await task.run_once()
    assert (task.state.failing, task.state.last_error) == (False, None)
    assert task.state.last_run is not None


async def test_runs_at_start_then_at_each_interval_until_stopped() -> None:
    runs: list[int] = []
    stop = asyncio.Event()

    async def action() -> None:
        runs.append(len(runs))
        if len(runs) == 3:
            stop.set()

    await asyncio.wait_for(PeriodicTask("test", action, interval=0.01).run(stop), timeout=5)

    assert runs == [0, 1, 2]


async def test_stop_before_the_first_run() -> None:
    stop = asyncio.Event()
    stop.set()
    runs: list[None] = []

    async def action() -> None:
        runs.append(None)

    await PeriodicTask("test", action, interval=1, first_delay=10).run(stop)

    assert runs == []


# --- check with the parent --------------------------------------------------------------------


async def test_parent_check_task_does_nothing_on_a_root(make_root: RootFactory) -> None:
    authority = await make_root()

    assert await parent_check_task(first_delay=0).run_once()

    stored = await Authority.get(id=authority.id)
    assert stored.parent_check_result is None and stored.parent_check_at is None
