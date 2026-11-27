"""``/.well-known/est[/{label}]/{operation}`` (RFC 7030). The label is a profile name.

HTTPS only (``api/listener.py`` serves nothing of it over HTTP). Errors are plain text, as EST
clients expect, never ``problem+json``; ``est.enabled`` false gives 404 on every route.
"""

import base64
import binascii
import logging
from collections.abc import Awaitable, Callable
from typing import Annotated

from cryptography import x509
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import PlainTextResponse

from h42pki.api.admin.deps import app_settings
from h42pki.api.client_cert import client_certificate
from h42pki.config import Settings
from h42pki.core.est import (
    CERTS_ONLY,
    CSRATTRS,
    PKCS8,
    InvalidBase64,
    Part,
    certs_only,
    csr_attrs,
    decode_base64,
    encode_base64,
    multipart_mixed,
)
from h42pki.errors import H42Error
from h42pki.keystore import optional_keystore
from h42pki.services.est import (
    EnrollResult,
    EstOperation,
    EstService,
    Issued,
    KeyedResult,
    Pending,
)

log = logging.getLogger(__name__)

PREFIX = "/.well-known/est"
BASE64_HEADERS = {"Content-Transfer-Encoding": "base64"}
# Business statuses kept as they are; 422 (refused by the profile) is 400 in EST.
KEPT_STATUSES = frozenset({400, 401, 403, 404, 409, 501, 503})

_TEXT: dict[str, dict[str, str]] = {"text/plain": {}}
# Declared so that the OpenAPI shows plain-text errors; 422 is listed only to keep FastAPI from
# adding its own JSON validation error (B30): EST answers 400 instead.
EST_RESPONSES: dict[int | str, dict[str, object]] = {
    400: {"description": "Unreadable request, or refused by the profile", "content": _TEXT},
    401: {"description": "Authentication required (Basic or client certificate)", "content": _TEXT},
    403: {"description": "Profile disabled, or request rejected", "content": _TEXT},
    404: {"description": "EST disabled, unknown label or operation", "content": _TEXT},
    422: {"description": "Never sent (EST answers 400)", "content": _TEXT},
    503: {"description": "No active CA", "content": _TEXT},
}

router = APIRouter(prefix=PREFIX, tags=["est"], responses=EST_RESPONSES)


class EstError(Exception):
    """An EST error, answered in plain text."""

    def __init__(self, status: int, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers or {}


async def est_error_handler(request: Request, exc: Exception) -> Response:
    if not isinstance(exc, EstError):  # pragma: no cover - registered for EstError only
        raise exc
    return PlainTextResponse(exc.message + "\n", status_code=exc.status, headers=exc.headers)


def _translate(exc: H42Error) -> EstError:
    status = 400 if exc.status_code == 422 else exc.status_code
    if status not in KEPT_STATUSES:
        log.error("EST: unexpected error %s (%s)", type(exc).__name__, exc.detail)
        return EstError(500, "internal error")
    return EstError(status, exc.detail, dict(exc.headers))


async def est_call[T](operation: Callable[[], Awaitable[T]]) -> T:
    try:
        return await operation()
    except H42Error as exc:
        raise _translate(exc) from None


def _basic(request: Request) -> tuple[str, str] | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic" or not value:
        return None
    try:
        decoded = base64.b64decode(value.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    username, separator, password = decoded.partition(":")
    return (username, password) if separator else None


def est_service(settings: Annotated[Settings, Depends(app_settings)]) -> EstService:
    return EstService(optional_keystore(settings))


Est = Annotated[EstService, Depends(est_service)]


async def _body(request: Request) -> bytes:
    try:
        return decode_base64(await request.body())
    except InvalidBase64 as exc:
        raise EstError(400, str(exc)) from None


def _certificates(certificates: list[x509.Certificate]) -> Response:
    return Response(
        content=encode_base64(certs_only(certificates)),
        media_type=CERTS_ONLY,
        headers=BASE64_HEADERS,
    )


def _enrolled(result: EnrollResult) -> Response:
    if isinstance(result, Issued):
        certificate = x509.load_der_x509_certificate(result.certificate.der)
        return _certificates([certificate])
    return PlainTextResponse(
        "the request waits for an approval: send it again later\n",
        status_code=202,
        headers={"Retry-After": str(result.retry_after)},
    )


# --- operations ----------------------------------------------------------------------------


async def cacerts(service: Est, label: str | None = None) -> Response:
    async def run() -> list[x509.Certificate]:
        settings = await service.settings()
        await service.profile(label, settings)
        return await service.cacerts()

    return _certificates(await est_call(run))


async def simpleenroll(request: Request, service: Est, label: str | None = None) -> Response:
    async def run() -> EnrollResult:
        settings = await service.settings()
        profile = await service.profile(label, settings)
        await service.check_enabled_profile(profile)
        identity = await service.authenticate(
            _basic(request),
            client_certificate(request, request.app.state.settings.trusted_proxies),
        )
        csr = await _body(request)
        return await service.enroll(
            identity, profile=profile, csr_der=csr, operation=EstOperation.SIMPLEENROLL
        )

    return _enrolled(await est_call(run))


async def simplereenroll(request: Request, service: Est, label: str | None = None) -> Response:
    async def run() -> EnrollResult:
        await service.settings()
        if label is not None:
            await service.profile(label, await service.settings())  # unknown label: 404
        identity = await service.authenticate(
            None,  # Basic is not enough: the certificate to renew authenticates (RFC 7030 4.2.2)
            client_certificate(request, request.app.state.settings.trusted_proxies),
            certificate_only=True,
        )
        csr = await _body(request)
        return await service.reenroll(identity, label=label, csr_der=csr)

    return _enrolled(await est_call(run))


async def serverkeygen(request: Request, service: Est, label: str | None = None) -> Response:
    async def run() -> KeyedResult:
        settings = await service.settings()
        profile = await service.profile(label, settings)
        await service.check_enabled_profile(profile)
        identity = await service.authenticate(
            _basic(request),
            client_certificate(request, request.app.state.settings.trusted_proxies),
        )
        csr = await _body(request)
        return await service.serverkeygen(identity, profile=profile, csr_der=csr)

    result = await est_call(run)
    if isinstance(result, Pending):
        return _enrolled(result)
    certificate = x509.load_der_x509_certificate(result.certificate.der)
    content_type, body = multipart_mixed(
        [Part(PKCS8, result.key.pkcs8_der), Part(CERTS_ONLY, certs_only([certificate]))]
    )
    return Response(content=body, media_type=content_type, headers={"Cache-Control": "no-store"})


async def csrattrs(service: Est, label: str | None = None) -> Response:
    async def run() -> list[x509.ObjectIdentifier]:
        settings = await service.settings()
        return await service.csr_attributes(await service.profile(label, settings))

    oids = await est_call(run)
    if not oids:
        return Response(status_code=204)
    return Response(
        content=encode_base64(csr_attrs(oids)), media_type=CSRATTRS, headers=BASE64_HEADERS
    )


async def fullcmc(service: Est, label: str | None = None) -> Response:
    async def run() -> None:
        settings = await service.settings()
        await service.profile(label, settings)

    await est_call(run)
    raise EstError(501, "fullcmc is not supported")


async def unknown(service: Est, rest: str) -> Response:
    await est_call(service.settings)
    name = rest.rstrip("/").rsplit("/", 1)[-1]
    method = METHODS.get(name)
    if method is not None and rest.count("/") <= 1:  # known operation, other method
        raise EstError(405, f"{name} expects {method}", {"Allow": method})
    raise EstError(404, "unknown EST operation")


Operation = tuple[str, str, Callable[..., Awaitable[Response]]]
OPERATIONS: list[Operation] = [
    ("cacerts", "GET", cacerts),
    ("simpleenroll", "POST", simpleenroll),
    ("simplereenroll", "POST", simplereenroll),
    ("csrattrs", "GET", csrattrs),
    ("serverkeygen", "POST", serverkeygen),
    ("fullcmc", "POST", fullcmc),
]


METHODS = {name: method for name, method, _ in OPERATIONS}


def _register(operations: list[Operation]) -> None:
    for name, method, endpoint in operations:
        for path in (f"/{name}", f"/{{label}}/{name}"):
            router.add_api_route(
                path,
                endpoint,
                methods=[method],
                response_class=Response,
                name=f"est_{name}{'_label' if '{label}' in path else ''}",
                summary=f"EST {name} (RFC 7030)",
            )
    router.add_api_route(
        "/{rest:path}",
        unknown,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        include_in_schema=False,
    )


_register(OPERATIONS)

__all__ = ["EstError", "est_error_handler", "router"]
