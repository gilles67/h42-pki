"""Service metadata and health (``GET /health``, on every active listener).

Statuses only, never a secret nor an internal detail (ADR-0012). The Docker HEALTHCHECK uses
``h42pki healthcheck`` instead, which does not depend on any port.
"""

import logging
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel
from tortoise import connections

from h42pki import __version__
from h42pki.heartbeat import HEARTBEAT_MAX_AGE_SECONDS, heartbeat_age
from h42pki.models import AuthorityStatus
from h42pki.services.authority import AuthorityService
from h42pki.services.crl import CrlService
from h42pki.services.scep_ra import ScepRaManager
from h42pki.services.settings import SettingsService

log = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


class HttpsCertificate(BaseModel):
    not_after: datetime
    renewal: Literal["ok", "failing"]


class CrlHealth(BaseModel):
    enabled: bool
    crl_number: int | None = None
    this_update: datetime | None = None
    next_update: datetime | None = None
    age_seconds: float | None = None
    refresh: Literal["ok", "failing", "unknown"] = "unknown"  # scheduled task of the launcher


class ParentCheckHealth(BaseModel):
    result: str  # good, revoked, unknown, unreachable, no_ocsp, invalid_response
    checked_at: datetime


class ScepHealth(BaseModel):
    ra_not_after: datetime | None
    renewal: Literal["ok", "failing", "unknown"] = "unknown"  # scheduled task of the launcher


class Health(BaseModel):
    status: Literal["ok", "degraded", "unavailable"]
    version: str
    database: Literal["ok", "unavailable"]
    heartbeat_age_seconds: float | None
    authority: str  # status of the local CA, or "none"
    listeners: list[str]
    https: Literal["serving", "waiting", "disabled", "unknown"]
    https_certificate: HttpsCertificate | None
    crl: CrlHealth | None  # None without a local CA
    ocsp: Literal["enabled", "disabled"] | None
    parent_check: ParentCheckHealth | None  # subordinate CA, once checked
    scep: ScepHealth | Literal["disabled"] | None  # None without a local CA
    warnings: list[str]


@router.get("/")
async def index() -> dict[str, str]:
    return {"name": "h42-pki", "version": __version__}


async def _database_ok() -> bool:
    try:
        await connections.get("default").execute_query("SELECT 1")
    except Exception:  # any failure means unavailable; details stay in the log
        log.warning("health: the database does not answer", exc_info=True)
        return False
    return True


async def _revocation(
    launcher: object | None, warnings: list[str]
) -> tuple[CrlHealth | None, Literal["enabled", "disabled"] | None, ParentCheckHealth | None]:
    """CRL, OCSP and parent check of the local CA (ADR-0017): statuses only."""
    authority = await AuthorityService().find_local()
    if authority is None:
        return None, None, None
    now = datetime.now(UTC)
    if authority.status is AuthorityStatus.REVOKED:
        warnings.append("the local CA has been revoked by its parent: it no longer issues")
    crl = CrlHealth(enabled=authority.crl_enabled)
    if authority.crl_enabled:
        tasks = getattr(launcher, "tasks", {}) or {}
        state = tasks.get("crl")
        if state is not None and state.last_run is not None:
            crl.refresh = "failing" if state.failing else "ok"
        current = await CrlService.current(authority)
        if current is None:
            warnings.append("no CRL published yet")
        else:
            crl.crl_number = current.crl_number
            crl.this_update = current.this_update
            crl.next_update = current.next_update
            crl.age_seconds = round((now - current.this_update).total_seconds(), 1)
            if current.next_update <= now:
                warnings.append("the CRL is out of date")
        if crl.refresh == "failing":
            warnings.append("the generation of the CRL is failing")
    parent_check: ParentCheckHealth | None = None
    if authority.parent_check_result is not None and authority.parent_check_at is not None:
        parent_check = ParentCheckHealth(
            result=authority.parent_check_result, checked_at=authority.parent_check_at
        )
        if authority.parent_check_result not in ("good", "revoked"):
            warnings.append(
                f"the status check with the parent CA failed ({authority.parent_check_result})"
            )
    return crl, "enabled" if authority.ocsp_enabled else "disabled", parent_check


async def _scep(
    launcher: object | None, warnings: list[str]
) -> ScepHealth | Literal["disabled"] | None:
    """SCEP and its RA certificate (ADR-0019): statuses only."""
    if await AuthorityService().find_local() is None:
        return None
    if not (await SettingsService().effective()).scep.enabled:
        return "disabled"
    ra = await ScepRaManager().current()
    health = ScepHealth(ra_not_after=ra.not_after if ra is not None else None)
    tasks = getattr(launcher, "tasks", {}) or {}
    state = tasks.get("scep_ra")
    if state is not None and state.last_run is not None:
        health.renewal = "failing" if state.failing else "ok"
    if ra is None:
        warnings.append("SCEP is enabled but has no RA certificate yet")
    if health.renewal == "failing":
        warnings.append("the renewal of the SCEP RA certificate is failing")
    return health


@router.get("/health")
async def health(request: Request, response: Response) -> Health:
    launcher = getattr(request.app.state, "launcher", None)
    warnings: list[str] = []
    database = await _database_ok()
    authority = "unknown"
    if database:
        local = await AuthorityService.local_status()
        authority = local.value if local is not None else "none"

    age: float | None = None
    listeners: list[str] = []
    https: Literal["serving", "waiting", "disabled", "unknown"] = "unknown"
    certificate: HttpsCertificate | None = None
    if launcher is not None:
        listeners = sorted(launcher.listeners)
        if launcher.heartbeat_path is not None:
            age = heartbeat_age(launcher.heartbeat_path)
        if "https" in launcher.listeners:
            https = "serving"
        elif launcher.https_waiting:
            https = "waiting"
            warnings.append("HTTPS waits for an active CA")
        else:
            https = "disabled"
        if launcher.https_certificate_not_after is not None:
            renewal: Literal["ok", "failing"] = "failing" if launcher.renewal_failing else "ok"
            certificate = HttpsCertificate(
                not_after=launcher.https_certificate_not_after, renewal=renewal
            )
            if launcher.renewal_failing:
                warnings.append("the renewal of the HTTPS certificate is failing")
        if age is None or age > HEARTBEAT_MAX_AGE_SECONDS:
            warnings.append("no recent heartbeat of the launcher")

    crl: CrlHealth | None = None
    ocsp: Literal["enabled", "disabled"] | None = None
    parent_check: ParentCheckHealth | None = None
    scep: ScepHealth | Literal["disabled"] | None = None
    if database:
        crl, ocsp, parent_check = await _revocation(launcher, warnings)
        scep = await _scep(launcher, warnings)

    if not database:
        status: Literal["ok", "degraded", "unavailable"] = "unavailable"
        response.status_code = 503
    else:
        status = "degraded" if warnings else "ok"
    return Health(
        status=status,
        version=__version__,
        database="ok" if database else "unavailable",
        heartbeat_age_seconds=round(age, 1) if age is not None else None,
        authority=authority,
        listeners=listeners,
        https=https,
        https_certificate=certificate,
        crl=crl,
        ocsp=ocsp,
        parent_check=parent_check,
        scep=scep,
        warnings=warnings,
    )
