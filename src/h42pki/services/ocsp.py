"""OCSP responder of the container: answers for the local CAs created with --ocsp (ADR-0017).

Every answer is signed by the key of the CA itself, so answers without nonce are cached in memory
by (CA, serial, CertID hash) and reused until half their validity. The status of the certificate is
read from the database for every request (needed anyway to tell ``unknown``): a cached answer is
reused only if that status did not change, which also covers a revocation made by the CLI in
another process. A revocation in this process also drops the entry at once.
"""

import asyncio
import hashlib
import logging
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp

from h42pki.core.ocsp import (
    CertState,
    CertStatus,
    MalformedRequest,
    ParsedRequest,
    build_error,
    build_response,
    issued_by,
    parse_request,
    response_window,
)
from h42pki.errors import MissingPassphrase, NotFound
from h42pki.keystore import KEY_OPERATIONS_REQUIREMENT, KeyStore
from h42pki.models import (
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    CertificateStatus,
    PrivateKey,
)
from h42pki.services.authority import AuthorityService
from h42pki.services.crl import CrlService
from h42pki.services.settings import SettingsService

log = logging.getLogger(__name__)

# The current CA and the previous generations still answer for what they issued.
ANSWERING_STATUSES = (
    AuthorityStatus.ACTIVE,
    AuthorityStatus.REVOKED,
    AuthorityStatus.ROLLING_OVER,
    AuthorityStatus.RETIRED,
)
MAX_CACHED_ANSWERS = 10_000

# What a cached answer depends on: the stored status of the certificate.
Fingerprint = tuple[str, datetime | None, str | None]


@dataclass(frozen=True)
class OcspAnswer:
    der: bytes
    successful: bool
    has_nonce: bool
    this_update: datetime | None = None
    next_update: datetime | None = None

    @property
    def cacheable(self) -> bool:
        """HTTP caching (RFC 5019): a signed answer without nonce."""
        return self.successful and not self.has_nonce and self.next_update is not None

    @property
    def etag(self) -> str:
        return f'"{hashlib.sha256(self.der).hexdigest()}"'


@dataclass(frozen=True)
class _Cached:
    answer: OcspAnswer
    fingerprint: Fingerprint


class OcspCache:
    """Answers without nonce, by (CA id, serial, CertID hash); bounded, oldest dropped first."""

    def __init__(self, max_entries: int = MAX_CACHED_ANSWERS) -> None:
        self._entries: OrderedDict[tuple[UUID, str, str], _Cached] = OrderedDict()
        self._max = max_entries

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: tuple[UUID, str, str]) -> _Cached | None:
        return self._entries.get(key)

    def put(self, key: tuple[UUID, str, str], value: _Cached) -> None:
        self._entries[key] = value
        self._entries.move_to_end(key)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def invalidate(self, issuer_id: UUID, serial_hex: str) -> None:
        """Called by RevocationService: drop every answer about this certificate."""
        for key in [key for key in self._entries if key[:2] == (issuer_id, serial_hex)]:
            del self._entries[key]


def _fingerprint(certificate: Certificate | None) -> Fingerprint:
    if certificate is None:
        return ("unknown", None, None)
    reason = certificate.revocation_reason.name if certificate.revocation_reason else None
    return (certificate.status.value, certificate.revoked_at, reason)


def _state(certificate: Certificate | None) -> CertState:
    if certificate is None:
        return CertState(CertStatus.UNKNOWN)  # never "good" for a serial never issued
    if certificate.status is CertificateStatus.REVOKED:
        return CertState(CertStatus.REVOKED, certificate.revoked_at, certificate.revocation_reason)
    return CertState(CertStatus.GOOD)  # valid or expired: not revoked


def _error(status: ocsp.OCSPResponseStatus) -> OcspAnswer:
    return OcspAnswer(build_error(status), successful=False, has_nonce=False)


class OcspService:
    def __init__(self, keystore: KeyStore | None, cache: OcspCache) -> None:
        self._key_store = keystore
        self._cache = cache

    @property
    def _keystore(self) -> KeyStore:
        if self._key_store is None:
            raise MissingPassphrase(KEY_OPERATIONS_REQUIREMENT)
        return self._key_store

    @staticmethod
    async def check_enabled() -> None:
        """404 when the current local CA was created without OCSP (or there is none)."""
        authority = await AuthorityService().find_local()
        if authority is None or not authority.ocsp_enabled:
            raise NotFound("this CA has no OCSP responder (created without --ocsp)")

    async def answer(self, der: bytes, *, now: datetime | None = None) -> OcspAnswer:
        """The DER answer to a DER request; unsuccessful answers are never cached."""
        await self.check_enabled()
        try:
            request = parse_request(der)
        except MalformedRequest as exc:
            log.debug("OCSP request refused: %s", exc)
            return _error(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
        found = await self._issuer(request)
        if found is None:
            return _error(ocsp.OCSPResponseStatus.UNAUTHORIZED)
        authority, issuer_cert = found
        now = now or datetime.now(UTC)
        certificate = await Certificate.get_or_none(
            issuer_id=authority.id, serial_hex=request.serial_hex
        )
        fingerprint = _fingerprint(certificate)
        key = (authority.id, request.serial_hex, request.algorithm.name)
        if request.nonce is None:
            cached = self._cache.get(key)
            if cached is not None and self._reusable(cached, fingerprint, now):
                return cached.answer
        answer = await self._sign(request, authority, issuer_cert, _state(certificate), now)
        if request.nonce is None:
            self._cache.put(key, _Cached(answer, fingerprint))
        return answer

    @staticmethod
    def _reusable(cached: _Cached, fingerprint: Fingerprint, now: datetime) -> bool:
        answer = cached.answer
        if cached.fingerprint != fingerprint or answer.this_update is None:
            return False
        if answer.next_update is None:  # pragma: no cover - always set by this responder
            return False
        half = answer.this_update + (answer.next_update - answer.this_update) / 2
        return now < half  # regenerated once half of its validity has passed

    @staticmethod
    async def _issuer(request: ParsedRequest) -> tuple[Authority, x509.Certificate] | None:
        """The local CA (with OCSP) designated by the CertID, if any."""
        candidates = await Authority.filter(
            kind=AuthorityKind.LOCAL, ocsp_enabled=True, status__in=ANSWERING_STATUSES
        ).prefetch_related("certificate")
        for authority in candidates:
            issuer_cert = x509.load_der_x509_certificate(authority.certificate.der)
            if issued_by(request, issuer_cert):
                return authority, issuer_cert
        return None

    async def _sign(
        self,
        request: ParsedRequest,
        authority: Authority,
        issuer_cert: x509.Certificate,
        state: CertState,
        now: datetime,
    ) -> OcspAnswer:
        settings = (await SettingsService().effective()).ocsp
        crl_next_update = None
        if authority.crl_enabled:
            crl = await CrlService.current(authority)
            crl_next_update = crl.next_update if crl is not None else None
        this_update, next_update = response_window(
            now,
            validity_hours=settings.response_validity_hours,
            crl_next_update=crl_next_update,
        )
        if authority.private_key_id is None:  # pragma: no cover - local CAs have a key
            return _error(ocsp.OCSPResponseStatus.INTERNAL_ERROR)
        stored = await PrivateKey.get(id=authority.private_key_id)
        issuer_key = await self._keystore.load(stored.encrypted_key)
        response = await asyncio.to_thread(
            build_response,
            request,
            issuer_cert,
            issuer_key,
            state,
            this_update=this_update,
            next_update=next_update,
        )
        return OcspAnswer(
            response.public_bytes(serialization.Encoding.DER),
            successful=True,
            has_nonce=request.nonce is not None,
            this_update=this_update,
            next_update=next_update,
        )
