"""``/scep[/{profile}][/pkiclient.exe]?operation=…`` (RFC 8894), on HTTP and HTTPS.

Its security rests on CMS, not on TLS: served on both listeners. HTTP errors are plain text; a
protocol error inside PKIOperation is a CertRep FAILURE instead.
"""

import logging
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import PlainTextResponse

from h42pki.errors import H42Error
from h42pki.services.scep import ScepService

log = logging.getLogger(__name__)

CA_RA_CERT = "application/x-x509-ca-ra-cert"
_TEXT: dict[str, dict[str, str]] = {"text/plain": {}}
SCEP_RESPONSES: dict[int | str, dict[str, object]] = {
    400: {"description": "Unknown operation, or unreadable message", "content": _TEXT},
    404: {"description": "SCEP disabled, or unknown label", "content": _TEXT},
    422: {"description": "Never sent (SCEP answers 400)", "content": _TEXT},
    503: {"description": "No active CA, or no RA certificate yet", "content": _TEXT},
}

router = APIRouter(prefix="/scep", tags=["scep"], responses=SCEP_RESPONSES)


class ScepHttpError(Exception):
    """An HTTP-level SCEP error, answered in plain text."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


async def scep_error_handler(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, ScepHttpError):  # pragma: no cover - registered for it only
        raise exc
    return PlainTextResponse(exc.message + "\n", status_code=exc.status)


async def scep_call[T](operation: Callable[[], Awaitable[T]]) -> T:
    try:
        return await operation()
    except H42Error as exc:
        status = 400 if exc.status_code == 422 else exc.status_code
        if status not in (400, 404, 503):
            log.error("SCEP: unexpected error %s (%s)", type(exc).__name__, exc.detail)
            raise ScepHttpError(500, "internal error") from None
        raise ScepHttpError(status, exc.detail) from None


Operation = Annotated[str | None, Query(description="GetCACaps, GetCACert or PKIOperation")]


async def scep(request: Request, operation: Operation = None, label: str | None = None) -> Response:
    service = ScepService()

    async def run() -> Response:
        settings = await service.settings()
        await service.profile(label, settings)
        match operation:
            case "GetCACaps":
                return PlainTextResponse(service.capabilities(settings))
            case "GetCACert":
                return Response(content=await service.ca_certificates(), media_type=CA_RA_CERT)
            case _:
                raise ScepHttpError(400, f"unsupported SCEP operation {operation!r}")

    return await scep_call(run)


for path in ("", "/pkiclient.exe", "/{label}", "/{label}/pkiclient.exe"):
    router.add_api_route(
        path,
        scep,
        methods=["GET", "POST"],
        response_class=Response,
        name=f"scep{path.replace('/', '_').replace('{label}', 'label').replace('.', '_')}",
        summary="SCEP operation (RFC 8894)",
    )
