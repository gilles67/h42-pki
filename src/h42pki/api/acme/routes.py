"""``/acme`` (RFC 8555, ADR-0020): HTTPS only, disabled by default (404 on every route).

One directory per profile (``/acme/{profile}/directory`` and ``/acme/{profile}/new-order``);
``/acme/directory`` and ``/acme/new-order`` use ``acme.default_profile``. The other resources
are common (an account is a key, whatever the profile). Every answer carries ``Replay-Nonce``,
``Link: <directory>;rel="index"`` and ``Cache-Control: no-store``; errors are ACME problem
documents (``urn:ietf:params:acme:error:*``).
"""

import json
import logging
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from h42pki.api.admin.deps import app_settings
from h42pki.config import Settings
from h42pki.core.acme.errors import AcmeError
from h42pki.keystore import optional_keystore
from h42pki.services.acme.accounts import AccountService
from h42pki.services.acme.auth import AcmeRequest, authenticate
from h42pki.services.acme.context import (
    PREFIX,
    AcmeContext,
    acme_context,
    directory_profile,
    origin,
)
from h42pki.services.acme.nonces import NonceService
from h42pki.services.acme.orders import OrderService
from h42pki.services.acme.validation import AcmeValidation
from h42pki.services.settings import SettingsService

log = logging.getLogger(__name__)

PROBLEM = "application/problem+json"
PEM_CHAIN = "application/pem-certificate-chain"


async def context(settings: Annotated[Settings, Depends(app_settings)]) -> AcmeContext:
    return await acme_context(settings)


Context = Annotated[AcmeContext, Depends(context)]
_PROBLEM_CONTENT: dict[str, dict[str, str]] = {PROBLEM: {}}
# Declared so that the OpenAPI shows ACME problems; 422 is listed only to keep FastAPI from adding
# its own JSON validation error (B30): ACME answers malformed (400) instead.
ACME_RESPONSES: dict[int | str, dict[str, object]] = {
    400: {
        "description": "ACME problem (malformed, badNonce, badCSR…)",
        "content": _PROBLEM_CONTENT,
    },
    403: {"description": "unauthorized, orderNotReady", "content": _PROBLEM_CONTENT},
    404: {"description": "ACME disabled, unknown profile or resource", "content": _PROBLEM_CONTENT},
    422: {"description": "Never sent (ACME answers malformed)", "content": _PROBLEM_CONTENT},
}
router = APIRouter(
    prefix=PREFIX, tags=["acme"], dependencies=[Depends(context)], responses=ACME_RESPONSES
)


async def _headers(acme: AcmeContext, index: str | None = None) -> dict[str, str]:
    return {
        "Replay-Nonce": await NonceService.new(acme.settings.nonce_lifetime_minutes),
        "Cache-Control": "no-store",
        "Link": f'<{index or acme.directory_url()}>;rel="index"',
    }


async def answer(
    acme: AcmeContext,
    content: Any = None,
    *,
    status: int = 200,
    location: str | None = None,
    links: tuple[str, ...] = (),
    retry_after: bool = False,
    index: str | None = None,
    media_type: str = "application/json",
    raw: bytes | None = None,
) -> Response:
    headers = await _headers(acme, index)
    if links:
        headers["Link"] = ", ".join([headers["Link"], *links])
    if location is not None:
        headers["Location"] = location
    if retry_after:
        headers["Retry-After"] = str(acme.settings.retry_after_seconds)
    body = raw if raw is not None else (b"" if content is None else json.dumps(content).encode())
    return Response(body, status_code=status, headers=headers, media_type=media_type)


async def acme_error_handler(request: Request, exc: Exception) -> Response:
    """ACME problem document, with a fresh nonce (a badNonce client retries with it)."""
    if not isinstance(exc, AcmeError):  # pragma: no cover - registered for AcmeError only
        raise exc
    acme = (await SettingsService().effective()).acme
    base = AcmeContext(acme, origin(acme, request.app.state.settings))
    if exc.code == "serverInternal":
        log.error("ACME %s %s: %s", request.method, request.url.path, exc.detail)
    return Response(
        json.dumps(exc.document()).encode(),
        status_code=exc.http_status,
        headers=await _headers(base),
        media_type=PROBLEM,
    )


async def signed(
    request: Request, acme: AcmeContext, *, jwk_allowed: bool = False, kid_allowed: bool = True
) -> AcmeRequest:
    return await authenticate(
        acme,
        await request.body(),
        content_type=request.headers.get("content-type"),
        path=request.url.path,
        jwk_allowed=jwk_allowed,
        kid_allowed=kid_allowed,
    )


def _validation(request: Request) -> AcmeValidation:
    validation: AcmeValidation = request.app.state.acme_validation
    return validation


def _orders(request: Request) -> OrderService:
    return OrderService(optional_keystore(request.app.state.settings))


# --- directory and nonces -------------------------------------------------------------------


async def _directory(acme: AcmeContext, label: str | None) -> Response:
    profile = await directory_profile(acme, label)
    meta: dict[str, Any] = {"externalAccountRequired": False, "profile": profile}
    if acme.settings.terms_of_service_url:
        meta["termsOfService"] = acme.settings.terms_of_service_url
    document = {
        "newNonce": acme.url(f"{PREFIX}/new-nonce"),
        "newAccount": acme.url(f"{PREFIX}/new-account"),
        "newOrder": acme.new_order_url(profile),
        "meta": meta,
    }
    return await answer(acme, document, index=acme.directory_url(profile))


@router.get("/directory", operation_id="acme_directory")
async def directory(acme: Context) -> Response:
    return await _directory(acme, None)


@router.head("/new-nonce", operation_id="acme_new_nonce_head")
async def new_nonce_head(acme: Context) -> Response:
    return await answer(acme, status=200)


@router.get("/new-nonce", operation_id="acme_new_nonce")
async def new_nonce(acme: Context) -> Response:
    return await answer(acme, status=204)


# --- accounts -------------------------------------------------------------------------------


@router.post("/new-account", operation_id="acme_new_account")
async def new_account(request: Request, acme: Context) -> Response:
    signed_request = await signed(request, acme, jwk_allowed=True, kid_allowed=False)
    result = await AccountService().new_account(acme, signed_request)
    return await answer(
        acme,
        AccountService.document(acme, result.account),
        status=201 if result.created else 200,
        location=acme.account_url(result.account.id),
    )


@router.post("/acct/{account_id:uuid}", operation_id="acme_account")
async def account(request: Request, acme: Context, account_id: UUID) -> Response:
    signed_request = await signed(request, acme)
    updated = await AccountService().update(acme, signed_request, account_id)
    return await answer(acme, AccountService.document(acme, updated))


@router.post("/acct/{account_id:uuid}/orders", operation_id="acme_account_orders")
async def account_orders(request: Request, acme: Context, account_id: UUID) -> Response:
    signed_request = await signed(request, acme)
    return await answer(
        acme, {"orders": await AccountService().orders(acme, signed_request, account_id)}
    )


# --- orders, authorizations, challenges -----------------------------------------------------


async def _new_order(request: Request, acme: AcmeContext, label: str | None) -> Response:
    profile = await directory_profile(acme, label)
    signed_request = await signed(request, acme)
    view = await _orders(request).new_order(acme, signed_request, profile)
    return await answer(
        acme, view.document, status=201, location=acme.order_url(view.order.id),
        index=acme.directory_url(profile),
    )  # fmt: skip


@router.post("/new-order", operation_id="acme_new_order")
async def new_order(request: Request, acme: Context) -> Response:
    return await _new_order(request, acme, None)


@router.post("/order/{order_id:uuid}", operation_id="acme_order")
async def order(request: Request, acme: Context, order_id: UUID) -> Response:
    signed_request = await signed(request, acme)
    view = await _orders(request).order(acme, signed_request, order_id)
    return await answer(acme, view.document, retry_after=view.processing)


@router.post("/order/{order_id:uuid}/finalize", operation_id="acme_finalize")
async def finalize(request: Request, acme: Context, order_id: UUID) -> Response:
    signed_request = await signed(request, acme)
    view = await _orders(request).finalize(acme, signed_request, order_id)
    return await answer(
        acme, view.document, location=acme.order_url(order_id), retry_after=view.processing
    )


@router.post("/authz/{authz_id:uuid}", operation_id="acme_authorization")
async def authorization(request: Request, acme: Context, authz_id: UUID) -> Response:
    signed_request = await signed(request, acme)
    document = await _orders(request).authorization(acme, signed_request, authz_id)
    return await answer(acme, document)


@router.post("/chall/{challenge_id:uuid}", operation_id="acme_challenge")
async def challenge(request: Request, acme: Context, challenge_id: UUID) -> Response:
    signed_request = await signed(request, acme)
    document, authz_id = await _orders(request).challenge(
        acme, signed_request, challenge_id, _validation(request).start
    )
    return await answer(
        acme,
        document,
        links=(f'<{acme.authz_url(authz_id)}>;rel="up"',),
        retry_after=document["status"] == "processing",
    )


@router.post("/cert/{order_id:uuid}", operation_id="acme_certificate")
async def certificate(request: Request, acme: Context, order_id: UUID) -> Response:
    signed_request = await signed(request, acme)
    chain = await _orders(request).certificate_chain(acme, signed_request, order_id)
    return await answer(acme, raw=chain, media_type=PEM_CHAIN)


# --- per profile (declared last: the fixed paths above come first) --------------------------


@router.get("/{label}/directory", operation_id="acme_profile_directory")
async def profile_directory(acme: Context, label: str) -> Response:
    return await _directory(acme, label)


@router.post("/{label}/new-order", operation_id="acme_profile_new_order")
async def profile_new_order(request: Request, acme: Context, label: str) -> Response:
    return await _new_order(request, acme, label)
