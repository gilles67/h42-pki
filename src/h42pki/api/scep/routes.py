"""``/scep[/{profile}][/pkiclient.exe]?operation=…`` (RFC 8894), on HTTP and HTTPS.

Its security rests on CMS, not on TLS: served on both listeners. HTTP errors are plain text; a
protocol error inside PKIOperation is a CertRep FAILURE instead.
"""

import base64
import binascii
import logging
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import PlainTextResponse

from h42pki.api.admin.deps import app_settings
from h42pki.config import Settings
from h42pki.core.cms import Malformed
from h42pki.errors import H42Error
from h42pki.keystore import KeyStore, optional_keystore
from h42pki.services.scep import ScepService

log = logging.getLogger(__name__)

CA_RA_CERT = "application/x-x509-ca-ra-cert"
PKI_MESSAGE = "application/x-pki-message"
MAX_MESSAGE_BYTES = 64 * 1024
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


def scep_keystore(settings: Annotated[Settings, Depends(app_settings)]) -> KeyStore | None:
    return optional_keystore(settings)


Operation = Annotated[str | None, Query(description="GetCACaps, GetCACert or PKIOperation")]
Message = Annotated[str | None, Query(description="PKIOperation by GET: the message, base64")]


async def _message(request: Request, message: str | None) -> bytes:
    """The pkiMessage: POST body (DER), or the base64 ``message`` of a GET."""
    if request.method == "POST":
        body = await request.body()
        if len(body) > MAX_MESSAGE_BYTES:
            raise ScepHttpError(400, "the message is too large")
        return body
    if message is None:
        raise ScepHttpError(400, "PKIOperation by GET needs a message parameter")
    # A "+" not URL-encoded arrives as a space in a query string.
    text = "".join(message.replace(" ", "+").split())
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise ScepHttpError(400, "the message parameter is not base64") from None


async def scep(
    request: Request,
    store: Annotated[KeyStore | None, Depends(scep_keystore)],
    operation: Operation = None,
    message: Message = None,
    label: str | None = None,
) -> Response:
    service = ScepService(store)

    async def run() -> Response:
        settings = await service.settings()
        profile = await service.profile(label, settings)
        match operation:
            case "GetCACaps":
                return PlainTextResponse(service.capabilities(settings))
            case "GetCACert":
                return Response(content=await service.ca_certificates(), media_type=CA_RA_CERT)
            case "PKIOperation":
                der = await _message(request, message)
                try:
                    answer = await service.pki_operation(der, profile=profile, settings=settings)
                except Malformed as exc:
                    raise ScepHttpError(400, f"unreadable SCEP message ({exc})") from None
                return Response(content=answer, media_type=PKI_MESSAGE)
            case _:
                raise ScepHttpError(400, f"unsupported SCEP operation {operation!r}")

    return await scep_call(run)


for path in ("", "/pkiclient.exe", "/{label}", "/{label}/pkiclient.exe"):
    suffix = path.replace("/", "_").replace("{label}", "label").replace(".", "_")
    for method in ("GET", "POST"):
        router.add_api_route(
            path,
            scep,
            methods=[method],
            response_class=Response,
            operation_id=f"scep{suffix}_{method.lower()}",
            summary=f"SCEP operation (RFC 8894), {method}",
        )
