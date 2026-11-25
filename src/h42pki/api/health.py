"""Service metadata and health (``GET /health``, on every active listener).

Statuses only, never a secret nor an internal detail (ADR-0012). The Docker HEALTHCHECK uses
``h42pki healthcheck`` instead, which does not depend on any port.
"""

import logging
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel
from tortoise import connections

from h42pki import __version__
from h42pki.heartbeat import HEARTBEAT_MAX_AGE_SECONDS, heartbeat_age
from h42pki.services.authority import AuthorityService

log = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


class HttpsCertificate(BaseModel):
    not_after: datetime
    renewal: Literal["ok", "failing"]


class Health(BaseModel):
    status: Literal["ok", "degraded", "unavailable"]
    version: str
    database: Literal["ok", "unavailable"]
    heartbeat_age_seconds: float | None
    authority: str  # status of the local CA, or "none"
    listeners: list[str]
    https: Literal["serving", "waiting", "disabled", "unknown"]
    https_certificate: HttpsCertificate | None
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
        warnings=warnings,
    )
