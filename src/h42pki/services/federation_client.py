"""HTTP client of a child CA towards its parent (ADR-0015).

Only the download of the chain is made without verifying TLS: nothing is sent, and the result is
only believed once its fingerprint matches. Every other call verifies the TLS certificate of the
parent against the pinned CA certificate and the host name of the URL. Python 3.13 contexts accept
an intermediate CA as anchor (``VERIFY_X509_PARTIAL_CHAIN``) and are strict about RFC 5280.

Messages never contain the token.
"""

import asyncio
import ssl
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, ConfigDict, ValidationError

from h42pki.errors import H42Error, InvalidRequest

TIMEOUT_SECONDS = 10.0
DOWNLOAD_SECONDS = 30.0  # whole unverified download
MAX_CHAIN_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 256 * 1024


class InvalidParentUrl(InvalidRequest):
    title = "Invalid Parent URL"


class ParentUnreachable(H42Error):
    """Network or TLS failure, or a server error: the enrolment may be tried again."""

    status_code = 502
    title = "Parent CA Unreachable"


class ParentRefused(H42Error):
    """The parent answered and refused (4xx)."""

    status_code = 502
    title = "Refused By The Parent CA"

    def __init__(self, detail: str, *, code: int) -> None:
        super().__init__(detail)
        self.code = code


class EnrollAnswer(BaseModel):
    model_config = ConfigDict(extra="ignore")  # a newer parent may say more

    status: Literal["pending", "issued", "rejected", "failed"]
    enrollment_id: UUID
    certificate_pem: str | None = None
    chain_pem: str | None = None
    reason: str | None = None
    retry_after: int | None = None


def normalize_parent_url(url: str) -> str:
    """https only, host required, no credentials, query or fragment, no trailing slash."""
    try:
        parts = urlsplit(url.strip())
        _ = parts.port
    except ValueError:
        raise InvalidParentUrl("the parent URL is not valid") from None
    if parts.scheme.lower() != "https":
        raise InvalidParentUrl("the parent URL must use https")
    if not parts.hostname:
        raise InvalidParentUrl("the parent URL has no host")
    if parts.username is not None or parts.password is not None:
        raise InvalidParentUrl("the parent URL must not contain credentials")
    if parts.query or parts.fragment or "?" in url or "#" in url:
        raise InvalidParentUrl("the parent URL must not contain a query string or a fragment")
    return f"https://{parts.netloc.lower()}{parts.path.rstrip('/')}"


def pinned_context(anchor: x509.Certificate) -> ssl.SSLContext:
    """TLS context that trusts the pinned parent CA and nothing else."""
    pem = anchor.public_bytes(serialization.Encoding.PEM).decode("ascii")
    # cadata given: the system trust store is not loaded.
    context = ssl.create_default_context(cadata=pem)
    # Already the defaults of Python 3.13, stated because the pinning depends on them.
    context.verify_flags |= ssl.VerifyFlags.VERIFY_X509_PARTIAL_CHAIN
    context.verify_flags |= ssl.VerifyFlags.VERIFY_X509_STRICT
    return context


def _tls_error(exc: BaseException) -> ssl.SSLError | None:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, ssl.SSLError):
            return current
        current = current.__cause__ or current.__context__
    return None


def _unreachable(url: str, exc: httpx.HTTPError) -> ParentUnreachable:
    tls = _tls_error(exc)
    if isinstance(tls, ssl.SSLCertVerificationError):
        return ParentUnreachable(
            f"the TLS certificate of {url} is refused: {tls.verify_message} (the host must be in "
            "H42_PKI_SERVER_HOSTNAME or H42_PKI_SERVER_ALT_NAMES of the parent)"
        )
    if tls is not None:
        return ParentUnreachable(f"TLS error with {url}: {tls.reason or type(tls).__name__}")
    if isinstance(exc, httpx.TimeoutException):
        return ParentUnreachable(f"{url} does not answer in time")
    return ParentUnreachable(f"cannot reach {url} ({type(exc).__name__})")


async def _read(response: httpx.Response, limit: int, url: str) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body += chunk
        if len(body) > limit:
            raise ParentUnreachable(f"the answer of {url} is too large")
    return bytes(body)


async def fetch_chain(
    parent_url: str, *, transport: httpx.AsyncBaseTransport | None = None
) -> bytes:
    """``/ca/chain.pem`` of the parent, TLS **not** verified: check the fingerprint first."""
    url = f"{parent_url}/ca/chain.pem"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        async with (
            asyncio.timeout(DOWNLOAD_SECONDS),
            httpx.AsyncClient(
                verify=context, transport=transport, trust_env=False, timeout=TIMEOUT_SECONDS
            ) as client,
            client.stream("GET", url) as response,
        ):
            if response.status_code != 200:
                raise ParentUnreachable(
                    f"{url} answers {response.status_code}: is it an active h42-pki CA?"
                )
            return await _read(response, MAX_CHAIN_BYTES, url)
    except TimeoutError:
        raise ParentUnreachable(f"{url} does not answer in time") from None
    except httpx.HTTPError as exc:
        raise _unreachable(parent_url, exc) from None


class FederationClient:
    """Authenticated calls, TLS verified with the pinned parent CA."""

    def __init__(
        self,
        parent_url: str,
        anchor: x509.Certificate,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = parent_url
        self._context = pinned_context(anchor)
        self._transport = transport

    async def enroll(
        self, token: str, *, csr_pem: str, name: str, public_base_url: str | None
    ) -> EnrollAnswer:
        body = {"csr_pem": csr_pem, "name": name, "public_base_url": public_base_url}
        return await self._call("POST", "", token, body)

    async def status(self, token: str, enrollment_id: UUID) -> EnrollAnswer:
        return await self._call("GET", f"/{enrollment_id}", token, None)

    async def _call(
        self, method: str, path: str, token: str, body: dict[str, Any] | None
    ) -> EnrollAnswer:
        url = f"{self._url}/api/v1/federation/enroll{path}"
        try:
            async with (
                httpx.AsyncClient(
                    verify=self._context,
                    transport=self._transport,
                    trust_env=False,
                    timeout=TIMEOUT_SECONDS,
                ) as client,
                client.stream(
                    method, url, json=body, headers={"Authorization": f"Bearer {token}"}
                ) as response,
            ):
                raw = await _read(response, MAX_RESPONSE_BYTES, self._url)
        except httpx.HTTPError as exc:
            raise _unreachable(self._url, exc) from None
        return self._answer(response, raw)

    def _answer(self, response: httpx.Response, raw: bytes) -> EnrollAnswer:
        code = response.status_code
        if code >= 300:
            detail = self._detail(raw)
            if code >= 500 or code in (408, 429):
                raise ParentUnreachable(f"the parent cannot answer now ({code}): {detail}")
            raise ParentRefused(f"the parent refuses ({code}): {detail}", code=code)
        try:
            answer = EnrollAnswer.model_validate_json(raw)
        except ValidationError:
            raise ParentUnreachable(f"unexpected answer of {self._url}") from None
        retry_after = response.headers.get("retry-after", "")
        return answer.model_copy(
            update={"retry_after": int(retry_after) if retry_after.isdecimal() else None}
        )

    @staticmethod
    def _detail(raw: bytes) -> str:
        """``detail`` of a problem document, made safe to print."""

        class Detail(BaseModel):
            detail: str = "no detail"

        try:
            text = Detail.model_validate_json(raw).detail
        except ValidationError:
            return "no detail"
        return "".join(char if char.isprintable() else " " for char in text[:300])
