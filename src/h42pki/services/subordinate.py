"""Subordinate CA: enrolment of the local CA with its parent (ADR-0015).

``start`` pins the parent, creates the local CA in ``pending_signature`` and sends the request;
``resume`` goes on with a stored enrolment. The token is only held in memory (ADR-0011).
"""

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tortoise.transactions import in_transaction

from h42pki.core.chain import (
    ancestor_name,
    check_issued_ca,
    fingerprint_of,
    load_chain,
    normalize_fingerprint,
    verify_parent_chain,
)
from h42pki.core.csr import build_ca_csr, parse_csr
from h42pki.core.errors import FingerprintMismatch, InvalidIssuedCertificate
from h42pki.core.federation import parse_token
from h42pki.core.keys import KeyAlgorithm
from h42pki.core.names import Subject, rfc4514
from h42pki.core.publication import normalize_public_base_url, validate_authority_name
from h42pki.errors import Conflict, H42Error, InvalidRequest, NotFound
from h42pki.keystore import KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    CertificateStatus,
    Channel,
    KeyPurpose,
    PrivateKey,
)
from h42pki.services import federation_client
from h42pki.services.federation_client import (
    EnrollAnswer,
    FederationClient,
    ParentRefused,
    ParentUnreachable,
    normalize_parent_url,
)
from h42pki.services.x509_fields import signed_fields

DEFAULT_RETRY_SECONDS = 10
MIN_RETRY_SECONDS = 1
MAX_RETRY_SECONDS = 60


class EnrolmentRejected(H42Error):
    """The parent said no for good: the pending CA and its key were removed."""

    status_code = 409
    title = "Enrolment Rejected"


class ParentApi(Protocol):
    async def enroll(
        self, token: str, *, csr_pem: str, name: str, public_base_url: str | None
    ) -> EnrollAnswer: ...

    async def status(self, token: str, enrollment_id: UUID) -> EnrollAnswer: ...


@dataclass(frozen=True)
class Parent:
    """The pinned parent: its chain, parent CA first."""

    url: str
    chain: Sequence[x509.Certificate]


def check_token(token: str) -> str:
    """Refuse a malformed token before anything is sent (its text is never repeated)."""
    if parse_token(token.strip()) is None:
        raise InvalidRequest("this is not an invitation token")
    return token.strip()


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


class SubordinateService:
    def __init__(
        self,
        keystore: KeyStore | None = None,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """``keystore`` is only needed by ``start`` (the new CA key)."""
        self._keystore = keystore
        self._sleep = sleep

    @staticmethod
    async def find_pending() -> Authority | None:
        return (
            await Authority.filter(
                kind=AuthorityKind.LOCAL, status=AuthorityStatus.PENDING_SIGNATURE
            )
            .prefetch_related("private_key", "parent__certificate")
            .first()
        )

    async def pending(self) -> Authority:
        authority = await self.find_pending()
        if authority is None:
            raise NotFound("no enrolment in progress")
        return authority

    # --- start ----------------------------------------------------------------------------

    async def start(
        self,
        *,
        parent_url: str,
        parent_fingerprint: str,
        token: str,
        name: str,
        subject: Subject,
        key_algorithm: KeyAlgorithm,
        public_base_url: str | None,
        crl: bool = False,
        ocsp: bool = False,
        actor: str,
    ) -> Authority:
        """Pin the parent, create the pending CA, send the request; returns the local CA.

        A definitive refusal of this first request leaves nothing behind. A network failure keeps
        the pending CA: the request may have been received, ``resume`` sends it again.
        """
        token = check_token(token)
        validate_authority_name(name)
        if public_base_url is not None:
            public_base_url = normalize_public_base_url(public_base_url).url
        await self._check_free(name)
        parent = await self._pin(parent_url, parent_fingerprint)
        authority = await self._create(
            parent=parent,
            name=name,
            subject=subject,
            key_algorithm=key_algorithm,
            public_base_url=public_base_url,
            crl=crl,
            ocsp=ocsp,
            actor=actor,
        )
        try:
            return await self._advance(authority, token, actor=actor)
        except ParentRefused as exc:
            await self.discard(authority, reason=exc.detail, actor=actor)
            raise

    @staticmethod
    async def _check_free(name: str) -> None:
        local = (
            await Authority.filter(kind=AuthorityKind.LOCAL)
            .exclude(status=AuthorityStatus.RETIRED)
            .first()
        )
        if local is not None:
            hint = (
                ": resume it with `h42pki authority init --resume --token -`, or drop it with "
                "`h42pki authority abandon`"
                if local.status is AuthorityStatus.PENDING_SIGNATURE
                else ""
            )
            raise Conflict(f"a local certificate authority already exists{hint}")
        if await Authority.exists(name=name):
            raise Conflict(f"an authority named {name!r} already exists")

    @staticmethod
    async def _pin(parent_url: str, parent_fingerprint: str) -> Parent:
        """The only step without verified TLS; nothing is sent before the fingerprint matches."""
        fingerprint = normalize_fingerprint(parent_fingerprint)
        url = normalize_parent_url(parent_url)
        chain = load_chain(await federation_client.fetch_chain(url))
        verify_parent_chain(chain, fingerprint, now=datetime.now(UTC))
        return Parent(url, chain)

    async def _create(
        self,
        *,
        parent: Parent,
        name: str,
        subject: Subject,
        key_algorithm: KeyAlgorithm,
        public_base_url: str | None,
        crl: bool,
        ocsp: bool,
        actor: str,
    ) -> Authority:
        if self._keystore is None:  # pragma: no cover - programming error
            raise ValueError("a key store is needed to create a CA")
        stored = await self._keystore.generate(key_algorithm)
        key = await self._keystore.load(stored.encrypted_key)
        csr_der = await asyncio.to_thread(build_ca_csr, key, subject)
        async with in_transaction():
            above: Authority | None = None
            for certificate in reversed(parent.chain):  # root first
                above = await self._ancestor(certificate, above)
            if above is None:  # pragma: no cover - an empty chain is refused by the pinning
                raise InvalidRequest("the chain of the parent is empty")
            await Authority.filter(id=above.id).update(
                federation_url=parent.url, pinned_fingerprint=fingerprint_of(parent.chain[0])
            )
            private_key = await PrivateKey.create(
                algorithm=key_algorithm,
                purpose=KeyPurpose.CA,
                encrypted_key=stored.encrypted_key,
                public_key_der=stored.public_key_der,
            )
            authority = await Authority.create(
                name=name,
                kind=AuthorityKind.LOCAL,
                status=AuthorityStatus.PENDING_SIGNATURE,
                private_key=private_key,
                parent=above,
                public_base_url=public_base_url,
                pending_csr_der=csr_der,
                crl_enabled=crl,  # fixed for the life of the CA (ADR-0017)
                ocsp_enabled=ocsp,
            )
            await AuditLog.record(
                actor=actor,
                action="authority.init",
                object_type="authority",
                object_id=authority.id,
                details={
                    "name": name,
                    "mode": "subordinate",
                    "key_algorithm": key_algorithm.value,
                    "crl_enabled": crl,
                    "ocsp_enabled": ocsp,
                    "subject_dn": rfc4514(subject.x509_name()),
                    "parent_url": parent.url,
                    "parent_fingerprint": fingerprint_of(parent.chain[0]),
                },
            )
        return await self.pending()

    @staticmethod
    async def _ancestor(certificate: x509.Certificate, above: Authority | None) -> Authority:
        """Record an ancestor CA and its certificate (shared with a retired local CA if any)."""
        fingerprint = fingerprint_of(certificate)
        known = await Certificate.get_or_none(sha256_fingerprint=fingerprint)
        if known is not None and known.authority_id is not None:
            return await Authority.get(id=known.authority_id)
        basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        ancestor = await Authority.create(
            name=ancestor_name(certificate),
            kind=AuthorityKind.PARENT,
            status=AuthorityStatus.ACTIVE,
            parent=above,
            path_length=basic.path_length,
        )
        await Certificate.create(
            issuer=above,
            authority=ancestor,
            channel=Channel.FEDERATION,
            status=CertificateStatus.VALID,
            **signed_fields(certificate),
        )
        return ancestor

    # --- exchange with the parent -----------------------------------------------------------

    @staticmethod
    def _client(authority: Authority) -> ParentApi:
        parent = authority.parent
        if parent is None or parent.federation_url is None:  # pragma: no cover - set by _create
            raise Conflict("the local CA has no parent to enrol with")
        anchor = x509.load_der_x509_certificate(parent.certificate.der)
        if fingerprint_of(anchor) != parent.pinned_fingerprint:
            raise FingerprintMismatch("the stored parent certificate is not the pinned one")
        return FederationClient(parent.federation_url, anchor)

    async def _ask(self, authority: Authority, token: str) -> EnrollAnswer:
        client = self._client(authority)
        if authority.pending_enrollment_id is not None:
            return await client.status(token, authority.pending_enrollment_id)
        csr = x509.load_der_x509_csr(authority.pending_csr_der or b"")
        return await client.enroll(
            token,
            csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            name=authority.name,
            public_base_url=authority.public_base_url,
        )

    async def _advance(self, authority: Authority, token: str, *, actor: str) -> Authority:
        answer = await self._ask(authority, token)
        return await self._apply(authority, answer, actor=actor)

    async def _apply(self, authority: Authority, answer: EnrollAnswer, *, actor: str) -> Authority:
        if answer.status == "issued":
            return await self._activate(authority, answer, actor=actor)
        if answer.status == "pending":
            await Authority.filter(id=authority.id).update(
                pending_enrollment_id=answer.enrollment_id
            )
            return await self.pending()
        reason = answer.reason or "no reason given"
        await self.discard(authority, reason=reason, actor=actor)
        raise EnrolmentRejected(f"the parent {answer.status} the enrolment: {reason}")

    async def resume(self, token: str, *, actor: str) -> Authority:
        """Ask once; the pending CA is kept on any refusal (see ``authority abandon``)."""
        return await self._advance(await self.pending(), check_token(token), actor=actor)

    async def wait(self, token: str, *, seconds: float, actor: str) -> Authority:
        """Poll until a decision or the end of ``seconds``; returns the (maybe pending) CA.

        ``Retry-After`` is followed, between 1 and 60 seconds. Network failures are retried.
        """
        token = check_token(token)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + seconds
        delay = float(DEFAULT_RETRY_SECONDS)
        authority = await self.pending()
        while authority.status is AuthorityStatus.PENDING_SIGNATURE:
            left = deadline - loop.time()
            if left <= 0:
                break
            await self._sleep(min(delay, left))
            try:
                answer = await self._ask(authority, token)
            except ParentUnreachable:
                continue
            retry = answer.retry_after or DEFAULT_RETRY_SECONDS
            delay = float(min(max(retry, MIN_RETRY_SECONDS), MAX_RETRY_SECONDS))
            authority = await self._apply(authority, answer, actor=actor)
        return authority

    async def _activate(
        self, authority: Authority, answer: EnrollAnswer, *, actor: str
    ) -> Authority:
        """Check the received certificate, then make the local CA active."""
        parent = authority.parent
        if parent is None:  # pragma: no cover - set by _create
            raise Conflict("the local CA has no parent")
        anchor = x509.load_der_x509_certificate(parent.certificate.der)
        certificate = self._received(answer, anchor)
        csr = parse_csr(authority.pending_csr_der or b"")
        path_length = check_issued_ca(certificate, csr, anchor, now=datetime.now(UTC))
        fields = signed_fields(certificate)
        async with in_transaction():
            await Certificate.create(
                issuer=parent,
                authority=authority,
                private_key=authority.private_key,
                channel=Channel.FEDERATION,
                status=CertificateStatus.VALID,
                **fields,
            )
            await Authority.filter(id=authority.id).update(
                status=AuthorityStatus.ACTIVE,
                path_length=path_length,
                pending_enrollment_id=None,
                pending_csr_der=None,
            )
            await AuditLog.record(
                actor=actor,
                action="authority.activate",
                object_type="authority",
                object_id=authority.id,
                details={
                    "name": authority.name,
                    "enrollment_id": str(answer.enrollment_id),
                    "serial_hex": fields["serial_hex"],
                    "sha256_fingerprint": fields["sha256_fingerprint"],
                    "path_length": path_length,
                    "not_after": fields["not_after"].isoformat(),
                },
            )
        return await Authority.get(id=authority.id).prefetch_related("certificate", "private_key")

    @staticmethod
    def _received(answer: EnrollAnswer, anchor: x509.Certificate) -> x509.Certificate:
        try:
            certificate = x509.load_pem_x509_certificate((answer.certificate_pem or "").encode())
        except ValueError:
            raise InvalidIssuedCertificate("the parent sent no readable certificate") from None
        chain = load_chain((answer.chain_pem or "").encode())
        if fingerprint_of(chain[0]) != fingerprint_of(anchor):
            raise InvalidIssuedCertificate("the chain of the answer is not the pinned one")
        return certificate

    # --- giving up --------------------------------------------------------------------------

    async def abandon(self, *, actor: str) -> str:
        """Drop the pending CA; returns its name. Nothing is said to the parent."""
        authority = await self.pending()
        await self.discard(authority, reason="abandoned", actor=actor)
        return authority.name

    @staticmethod
    async def discard(authority: Authority, *, reason: str, actor: str) -> None:
        """Remove a CA that was never certified, its key, and its now useless ancestors."""
        private_key_id = authority.private_key_id
        async with in_transaction():
            deleted = await Authority.filter(
                id=authority.id, status=AuthorityStatus.PENDING_SIGNATURE
            ).delete()
            if not deleted:
                raise Conflict("the local CA is not waiting for its certificate any more")
            key = await PrivateKey.get(id=private_key_id)
            await key.delete()
            parent_id = authority.parent_id
            while parent_id is not None and not await Authority.exists(parent_id=parent_id):
                ancestor = await Authority.get(id=parent_id)
                await Certificate.filter(authority_id=ancestor.id).delete()
                parent_id = ancestor.parent_id
                await ancestor.delete()
            await AuditLog.record(
                actor=actor,
                action="authority.abandon",
                object_type="authority",
                object_id=authority.id,
                details={"name": authority.name, "reason": reason},
            )
            await AuditLog.record(
                actor=actor,
                action="private_key.delete",
                object_type="private_key",
                object_id=key.id,
                details={"algorithm": key.algorithm.value},
            )
