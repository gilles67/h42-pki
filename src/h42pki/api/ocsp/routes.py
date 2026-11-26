"""``POST /ocsp`` and ``GET /ocsp/{request}``: plain HTTP like the CRL (CLAUDE.md section 6.9).

The answer of a refused request is still an OCSP answer (HTTP 200, ``malformedRequest`` or
``unauthorized``). Only a CA created without --ocsp answers 404 (``problem+json``).
"""

import base64
import binascii
from datetime import UTC, datetime
from email.utils import format_datetime
from typing import Annotated
from urllib.parse import unquote

from cryptography.x509 import ocsp
from fastapi import APIRouter, Depends, Request, Response

from h42pki.api.admin.deps import app_settings
from h42pki.api.problems import PROBLEM_RESPONSES
from h42pki.config import Settings
from h42pki.core.ocsp import MAX_REQUEST_BYTES, build_error
from h42pki.keystore import optional_keystore
from h42pki.services.ocsp import OcspAnswer, OcspCache, OcspService

REQUEST_MEDIA_TYPE = "application/ocsp-request"
RESPONSE_MEDIA_TYPE = "application/ocsp-response"
NOT_CACHED = "no-store"

router = APIRouter(prefix="/ocsp", tags=["public"], responses=PROBLEM_RESPONSES)


def ocsp_service(
    request: Request, settings: Annotated[Settings, Depends(app_settings)]
) -> OcspService:
    cache: OcspCache = request.app.state.ocsp_cache
    return OcspService(optional_keystore(settings), cache)


Responder = Annotated[OcspService, Depends(ocsp_service)]


def _http_date(moment: datetime) -> str:
    return format_datetime(moment.astimezone(UTC), usegmt=True)


def _response(answer: OcspAnswer, *, cache_headers: bool) -> Response:
    headers = {"Cache-Control": NOT_CACHED}
    if (
        cache_headers
        and answer.cacheable
        and answer.this_update is not None
        and answer.next_update is not None
    ):
        seconds = max(0, int((answer.next_update - datetime.now(UTC)).total_seconds()))
        headers = {  # RFC 5019 section 6.2
            "Cache-Control": f"max-age={seconds}, public, no-transform, must-revalidate",
            "Last-Modified": _http_date(answer.this_update),
            "Expires": _http_date(answer.next_update),
            "ETag": answer.etag,
        }
    return Response(content=answer.der, media_type=RESPONSE_MEDIA_TYPE, headers=headers)


def _malformed() -> Response:
    der = build_error(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
    return Response(
        content=der, media_type=RESPONSE_MEDIA_TYPE, headers={"Cache-Control": NOT_CACHED}
    )


@router.post(
    "",
    response_class=Response,
    openapi_extra={"requestBody": {"content": {REQUEST_MEDIA_TYPE: {}}, "required": True}},
    responses={200: {"content": {RESPONSE_MEDIA_TYPE: {}}}},
    summary="OCSP request in DER (RFC 6960)",
)
async def ocsp_post(request: Request, responder: Responder) -> Response:
    await responder.check_enabled()
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_REQUEST_BYTES:
            return _malformed()
    return _response(await responder.answer(bytes(body)), cache_headers=False)


@router.get(
    "/{encoded:path}",
    response_class=Response,
    responses={200: {"content": {RESPONSE_MEDIA_TYPE: {}}}},
    summary="OCSP request in DER, base64 then URL-encoded (RFC 6960 appendix A.1)",
)
async def ocsp_get(encoded: str, responder: Responder) -> Response:
    await responder.check_enabled()
    # The path is already percent-decoded once; a client may have encoded twice ("%252F").
    text = unquote(encoded)
    if len(text) > MAX_REQUEST_BYTES * 2:
        return _malformed()
    try:
        der = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError):
        return _malformed()
    return _response(await responder.answer(der), cache_headers=True)
