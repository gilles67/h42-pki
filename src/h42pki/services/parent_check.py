"""A subordinate CA checks its own status with the OCSP of its parent (ADR-0017).

The URL is the AIA OCSP of the CA's own certificate (written by the parent). The answer must be
signed by the parent CA itself, which the child pinned at enrolment (ADR-0015); over https, TLS is
verified with that same pinned CA. ``revoked`` makes the local CA ``revoked``: it then refuses any
issuance but keeps publishing its CRL and answering OCSP. Anything else (parent unreachable, no
OCSP, invalid answer) is only a warning: the state does not change.
"""

import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from tortoise.transactions import in_transaction

from h42pki.core.inspection import ocsp_url
from h42pki.core.ocsp import (
    CertState,
    CertStatus,
    InvalidResponse,
    build_request,
    verify_response,
)
from h42pki.errors import InvalidRequest
from h42pki.models import AuditLog, Authority, AuthorityStatus, Certificate, CertificateStatus
from h42pki.services.authority import AuthorityService
from h42pki.services.federation_client import pinned_context

log = logging.getLogger(__name__)

SYSTEM_ACTOR = "system"
TIMEOUT_SECONDS = 10.0
MAX_ANSWER_BYTES = 64 * 1024
NONCE_BYTES = 16


class ParentStatus(StrEnum):
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"  # the parent does not know this certificate
    UNREACHABLE = "unreachable"
    NO_OCSP = "no_ocsp"
    INVALID_RESPONSE = "invalid_response"


@dataclass(frozen=True)
class ParentCheck:
    result: ParentStatus
    detail: str
    checked_at: datetime


class Unreachable(Exception):
    pass


class NoOcsp(Exception):
    pass


class ParentCheckService:
    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    @staticmethod
    async def is_subordinate() -> bool:
        authority = await AuthorityService().find_local()
        return authority is not None and authority.parent_id is not None

    async def check(self, *, actor: str = SYSTEM_ACTOR, now: datetime | None = None) -> ParentCheck:
        """Ask the parent now; the result is stored on the local CA (CLI and /health see it)."""
        authority = await AuthorityService().get_local()
        parent = authority.parent
        if parent is None:
            raise InvalidRequest("the local CA is a root: it has no parent to ask")
        now = now or datetime.now(UTC)
        own = x509.load_der_x509_certificate(authority.certificate.der)
        parent_cert = x509.load_der_x509_certificate(parent.certificate.der)
        result, detail, state = await self._ask(own, parent_cert, now)
        if state is not None and authority.status is not AuthorityStatus.REVOKED:
            await self._revoked(authority, state, detail, actor=actor)
        await Authority.filter(id=authority.id).update(
            parent_check_at=now, parent_check_result=result.value
        )
        if result is ParentStatus.REVOKED:
            log.error("the parent CA reports this CA as revoked (%s): issuance stops", detail)
        elif result is not ParentStatus.GOOD:
            log.warning("status check with the parent CA: %s (%s)", result.value, detail)
        else:
            log.info("status check with the parent CA: good")
        return ParentCheck(result, detail, now)

    async def _ask(
        self, own: x509.Certificate, parent_cert: x509.Certificate, now: datetime
    ) -> tuple[ParentStatus, str, CertState | None]:
        """Result, detail, and the state given by the parent when it says revoked."""
        url = ocsp_url(own)
        if url is None:
            return ParentStatus.NO_OCSP, "the certificate of this CA has no OCSP URL", None
        nonce = os.urandom(NONCE_BYTES)
        try:
            der = await self._post(url, build_request(own, parent_cert, nonce=nonce), parent_cert)
        except NoOcsp as exc:
            return ParentStatus.NO_OCSP, str(exc), None
        except Unreachable as exc:
            return ParentStatus.UNREACHABLE, str(exc), None
        try:
            state = verify_response(der, certificate=own, issuer=parent_cert, nonce=nonce, now=now)
        except InvalidResponse as exc:
            return ParentStatus.INVALID_RESPONSE, str(exc), None
        match state.status:
            case CertStatus.GOOD:
                return ParentStatus.GOOD, url, None
            case CertStatus.REVOKED:
                reason = state.reason.name if state.reason is not None else "unspecified"
                return ParentStatus.REVOKED, f"reason {reason}", state
            case _:
                return ParentStatus.UNKNOWN, "the parent does not know this certificate", None

    async def _post(self, url: str, body: bytes, parent_cert: x509.Certificate) -> bytes:
        https = urlsplit(url).scheme == "https"
        try:
            async with (
                httpx.AsyncClient(
                    verify=pinned_context(parent_cert) if https else True,
                    transport=self._transport,
                    trust_env=False,
                    timeout=TIMEOUT_SECONDS,
                ) as client,
                client.stream(
                    "POST",
                    url,
                    content=body,
                    headers={"Content-Type": "application/ocsp-request"},
                ) as response,
            ):
                if response.status_code == 404:
                    raise NoOcsp(f"{url} answers 404: the parent has no OCSP")
                if response.status_code != 200:
                    raise Unreachable(f"{url} answers {response.status_code}")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data += chunk
                    if len(data) > MAX_ANSWER_BYTES:
                        raise Unreachable(f"the answer of {url} is too large")
                return bytes(data)
        except httpx.HTTPError as exc:
            raise Unreachable(f"cannot reach {url} ({type(exc).__name__})") from None

    @staticmethod
    async def _revoked(authority: Authority, state: CertState, detail: str, *, actor: str) -> None:
        async with in_transaction():
            await Authority.filter(id=authority.id).update(status=AuthorityStatus.REVOKED)
            await Certificate.filter(authority_id=authority.id).update(
                status=CertificateStatus.REVOKED,
                revoked_at=state.revoked_at or datetime.now(UTC),
                revocation_reason=state.reason,
            )
            await AuditLog.record(
                actor=actor,
                action="authority.revoked_by_parent",
                object_type="authority",
                object_id=authority.id,
                details={"name": authority.name, "detail": detail},
            )
