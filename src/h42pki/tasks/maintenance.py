"""Scheduled tasks of phase 3 (ADR-0017): CRL, expired status (B34), purge (B44), parent check."""

from h42pki.keystore import KeyStore
from h42pki.services.crl import CrlService
from h42pki.services.maintenance import MaintenanceService
from h42pki.services.parent_check import ParentCheckService
from h42pki.tasks.periodic import PeriodicTask

CRL_INTERVAL_SECONDS = 15 * 60.0
EXPIRY_INTERVAL_SECONDS = 3600.0
PURGE_INTERVAL_SECONDS = 24 * 3600.0
PARENT_CHECK_INTERVAL_SECONDS = 24 * 3600.0
# Shortly after start-up: the listeners of a whole hierarchy restarting together come up first.
PARENT_CHECK_FIRST_DELAY_SECONDS = 60.0


def crl_task(keystore: KeyStore, *, interval: float | None = None) -> PeriodicTask:
    """Every 15 minutes (and at start-up): CRLs of the local CAs kept fresh."""
    service = CrlService(keystore)
    return PeriodicTask("crl", service.refresh_all, interval=interval or CRL_INTERVAL_SECONDS)


def expiry_task(*, interval: float | None = None) -> PeriodicTask:
    """Every hour (and at start-up): ``valid`` certificates past notAfter become ``expired``."""
    return PeriodicTask(
        "expiry", MaintenanceService.expire, interval=interval or EXPIRY_INTERVAL_SECONDS
    )


def purge_task(*, interval: float | None = None) -> PeriodicTask:
    """Every day (and at start-up): replaced and expired HTTPS certificates and keys deleted."""
    return PeriodicTask(
        "purge",
        MaintenanceService.purge_service_tls,
        interval=interval or PURGE_INTERVAL_SECONDS,
    )


def parent_check_task(
    *, interval: float | None = None, first_delay: float | None = None
) -> PeriodicTask:
    """Every day: a subordinate CA asks the OCSP of its parent about its own certificate."""
    service = ParentCheckService()

    async def check() -> None:
        if await service.is_subordinate():
            await service.check()

    return PeriodicTask(
        "parent_check",
        check,
        interval=interval or PARENT_CHECK_INTERVAL_SECONDS,
        first_delay=(PARENT_CHECK_FIRST_DELAY_SECONDS if first_delay is None else first_delay),
    )
