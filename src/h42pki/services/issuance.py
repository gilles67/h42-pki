"""Certificate requests and issuance: the only way to get a certificate signed by the CA."""

import asyncio
import hashlib
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tortoise.transactions import in_transaction

from h42pki.core.csr import ParsedCsr, build_csr, parse_csr
from h42pki.core.federation import SubCaConstraints, constrain_sub_ca
from h42pki.core.issuance import build_issued, plan_issuance
from h42pki.core.keys import KeyAlgorithm
from h42pki.core.names import rfc4514
from h42pki.core.profiles import SERVICE_TLS_PROFILE, SUB_CA_PROFILE, ProfileSpec
from h42pki.core.publication import ca_certificate_url, validate_authority_name
from h42pki.errors import Conflict, H42Error, MissingPassphrase, NoActiveAuthority, Unprocessable
from h42pki.keystore import KEY_OPERATIONS_REQUIREMENT, KeyStore, StoredKey
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    CertificateRequest,
    CertificateStatus,
    Channel,
    KeyPurpose,
    PrivateKey,
    Profile,
    RequestStatus,
)
from h42pki.services.authority import AuthorityService
from h42pki.services.profiles import ProfileService, spec_of
from h42pki.services.x509_fields import signed_fields

AUTO_APPROVE = "auto-approve"
SYSTEM_ACTOR = "system"
# Key of the built-in HTTPS server: fast to generate and accepted by every TLS client.
SERVICE_TLS_KEY_ALGORITHM = KeyAlgorithm.EC_P256


def _ca_issuers_url(authority: Authority) -> str | None:
    """AIA caIssuers of the certificates this CA issues, if it publishes its certificate."""
    if authority.public_base_url is None:
        return None
    return ca_certificate_url(authority.public_base_url, authority.name)


@dataclass(frozen=True)
class ChildCa:
    """What a child CA says about itself when it enrols."""

    name: str
    public_base_url: str | None


@dataclass(frozen=True)
class PreparedRequest:
    profile: Profile
    spec: ProfileSpec
    parsed: ParsedCsr
    subject_dn: str


def child_of(request: CertificateRequest) -> ChildCa | None:
    """The child CA behind a federation request, None for any other request."""
    federation = request.metadata.get("federation")
    if federation is None:
        return None
    return ChildCa(name=federation["name"], public_base_url=federation["public_base_url"])


def _constraints_of(request: CertificateRequest) -> SubCaConstraints:
    federation = request.metadata["federation"]
    return SubCaConstraints(
        path_length=federation["path_length"],
        validity_days=federation["validity_days"],
        auto_approve=federation["auto_approve"],
    )


class IssuanceService:
    """submit -> (auto_approve | approve) -> _issue; reject. ``_issue`` is the single path."""

    def __init__(self, keystore: KeyStore | None = None) -> None:
        """``keystore`` is only needed by operations that sign (B32)."""
        self._key_store = keystore
        self._authorities = AuthorityService(keystore)

    @property
    def _keystore(self) -> KeyStore:
        if self._key_store is None:
            raise MissingPassphrase(KEY_OPERATIONS_REQUIREMENT)
        return self._key_store

    # --- queries --------------------------------------------------------------------------

    async def get(self, request_id: UUID) -> CertificateRequest:
        return await CertificateRequest.get(id=request_id).prefetch_related("profile", "invitation")

    async def list(self, status: RequestStatus | None = None) -> list[CertificateRequest]:
        query = CertificateRequest.all().prefetch_related("profile", "invitation")
        if status is not None:
            query = query.filter(status=status)
        return await query

    # --- workflow -------------------------------------------------------------------------

    async def submit(
        self,
        *,
        csr: bytes | str,
        profile_name: str,
        validity_days: int | None,
        actor: str,
        channel: Channel = Channel.API,
    ) -> CertificateRequest:
        """Record a request; issue it at once when the profile auto-approves.

        The request is checked against the profile and the active CA before being stored: a
        request that could never be issued is refused (422) instead of waiting for a decision.
        """
        prepared = await self._prepare(
            csr=csr,
            profile_name=profile_name,
            validity_days=validity_days,
            actor=actor,
            channel=channel,
        )
        async with in_transaction():
            request = await self._record(
                prepared, validity_days=validity_days, actor=actor, channel=channel
            )
        if prepared.spec.auto_approve:
            return await self._issue(
                request, parsed=prepared.parsed, actor=actor, decided_by=AUTO_APPROVE
            )
        return await self.get(request.id)

    async def submit_child(
        self,
        *,
        csr: bytes | str,
        child: ChildCa,
        constraints: SubCaConstraints,
        actor: str,
        on_recorded: Callable[[CertificateRequest], Awaitable[None]],
    ) -> CertificateRequest:
        """Enrolment of a child CA (federation): a ``sub_ca`` request under an invitation.

        ``on_recorded`` runs in the transaction that records the request: it consumes the
        invitation, and cancels everything by raising. A refused CSR consumes nothing.
        """
        prepared = await self._prepare(
            csr=csr,
            profile_name=SUB_CA_PROFILE,
            validity_days=constraints.validity_days,
            actor=actor,
            channel=Channel.FEDERATION,
            constraints=constraints,
            child=child,
        )
        async with in_transaction():
            request = await self._record(
                prepared,
                validity_days=constraints.validity_days,
                actor=actor,
                channel=Channel.FEDERATION,
                federation={**asdict(child), **asdict(constraints)},
            )
            await on_recorded(request)
        if constraints.auto_approve:
            return await self._issue(
                request, parsed=prepared.parsed, actor=actor, decided_by=AUTO_APPROVE
            )
        return await self.get(request.id)

    async def _prepare(
        self,
        *,
        csr: bytes | str,
        profile_name: str,
        validity_days: int | None,
        actor: str,
        channel: Channel,
        constraints: SubCaConstraints | None = None,
        child: ChildCa | None = None,
    ) -> PreparedRequest:
        """Check a request without a key and without storing it; a refusal is audited (B35)."""
        parsed: ParsedCsr | None = None
        try:
            profile = await Profile.get_or_none(name=profile_name)
            if profile is None:
                raise Unprocessable(f"unknown profile {profile_name!r}")
            spec = spec_of(profile)
            if spec.internal:
                raise Unprocessable(
                    f"profile {profile_name!r} is internal: the CA issues it for its own server "
                    "only"
                )
            if profile.name in await ProfileService.disabled():
                raise Unprocessable(f"profile {profile_name!r} is disabled on this CA")
            if constraints is not None:
                spec = constrain_sub_ca(spec, constraints)
            if child is not None:
                await self._check_child_name(child.name)
            authority = await self._authorities.get_local()
            parsed = parse_csr(csr)
            now = datetime.now(UTC)
            issuer_cert = await self._issuer_certificate(authority, now)
            plan = plan_issuance(parsed, spec, issuer_cert, validity_days=validity_days, now=now)
        except H42Error as exc:
            await self._audit_refusal(
                exc, csr=csr, parsed=parsed, profile_name=profile_name, actor=actor, channel=channel
            )
            raise
        return PreparedRequest(profile, spec, parsed, rfc4514(plan.subject))

    async def _record(
        self,
        prepared: PreparedRequest,
        *,
        validity_days: int | None,
        actor: str,
        channel: Channel,
        federation: dict[str, Any] | None = None,
    ) -> CertificateRequest:
        """Store a checked request (inside the transaction of the caller)."""
        ignored = [*prepared.parsed.ignored_extensions]
        metadata: dict[str, Any] = {"ignored_extensions": ignored}
        if federation is not None:
            metadata["federation"] = federation
        request = await CertificateRequest.create(
            csr_der=prepared.parsed.csr.public_bytes(serialization.Encoding.DER),
            profile=prepared.profile,
            requested_validity_days=validity_days,
            requester=actor,
            channel=channel,
            subject_dn=prepared.subject_dn,
            metadata=metadata,
        )
        await self._audit(
            actor,
            "request.submit",
            request,
            {
                "profile": prepared.profile.name,
                "subject_dn": request.subject_dn,
                "requested_validity_days": validity_days,
                "ignored_extensions": ignored,
            },
        )
        return request

    @staticmethod
    async def _check_child_name(name: str, *, approving: bool = False) -> None:
        """409 when the name belongs to a known CA or to another pending enrolment."""
        validate_authority_name(name)
        if await Authority.exists(name=name):
            raise Conflict(f"an authority named {name!r} already exists")
        if not approving:
            pending = await CertificateRequest.filter(
                channel=Channel.FEDERATION, status=RequestStatus.PENDING
            )
            if any(other.metadata["federation"]["name"] == name for other in pending):
                raise Conflict(f"an enrolment for a CA named {name!r} is already pending")

    async def issue_service_certificate(
        self, names: Sequence[str], *, validity_days: int
    ) -> CertificateRequest:
        """Certificate of the built-in HTTPS server (ADR-0013): internal, never exposed.

        A new key (``purpose = tls``) and a CSR are made here, then the request follows the same
        path as any other: checked against the internal ``service_tls`` profile, recorded, and
        issued by ``_issue``. CN = the first name, SANs = all names.
        """
        profile = await Profile.get(name=SERVICE_TLS_PROFILE)
        spec = spec_of(profile)
        authority = await self._authorities.get_local()
        stored = await self._keystore.generate(SERVICE_TLS_KEY_ALGORITHM)
        key = await self._keystore.load(stored.encrypted_key)
        csr_der = await asyncio.to_thread(build_csr, key, names[0], names)
        parsed = parse_csr(csr_der)
        now = datetime.now(UTC)
        issuer_cert = await self._issuer_certificate(authority, now)
        plan = plan_issuance(parsed, spec, issuer_cert, validity_days=validity_days, now=now)
        async with in_transaction():
            request = await CertificateRequest.create(
                csr_der=csr_der,
                profile=profile,
                requested_validity_days=validity_days,
                requester=SYSTEM_ACTOR,
                channel=Channel.SYSTEM,
                subject_dn=rfc4514(plan.subject),
                metadata={"ignored_extensions": []},
            )
            await self._audit(
                SYSTEM_ACTOR,
                "request.submit",
                request,
                {
                    "profile": profile.name,
                    "subject_dn": request.subject_dn,
                    "requested_validity_days": validity_days,
                    "ignored_extensions": [],
                },
            )
        return await self._issue(
            request, parsed=parsed, actor=SYSTEM_ACTOR, decided_by=AUTO_APPROVE, tls_key=stored
        )

    async def approve(self, request_id: UUID, *, actor: str) -> CertificateRequest:
        request = await self._pending(request_id)
        profile = await Profile.get(id=request.profile_id)
        if profile.name in await ProfileService.disabled():
            raise Conflict(
                f"profile {profile.name!r} is disabled on this CA: the request can only be rejected"
            )
        child = child_of(request)
        if child is not None:  # refused before any change: the request can still be rejected
            await self._check_child_name(child.name, approving=True)
        await self._audit(actor, "request.approve", request, {})
        return await self._issue(
            request, parsed=parse_csr(request.csr_der), actor=actor, decided_by=actor
        )

    async def reject(self, request_id: UUID, *, reason: str, actor: str) -> CertificateRequest:
        request = await self._pending(request_id)
        async with in_transaction():
            updated = await CertificateRequest.filter(
                id=request.id, status=RequestStatus.PENDING
            ).update(
                status=RequestStatus.REJECTED,
                rejection_reason=reason,
                decided_by=actor,
                decided_at=datetime.now(UTC),
            )
            if not updated:
                raise Conflict("the request has already been decided")
            await self._audit(actor, "request.reject", request, {"reason": reason})
        return await self.get(request.id)

    # --- internals ------------------------------------------------------------------------

    async def _pending(self, request_id: UUID) -> CertificateRequest:
        request = await CertificateRequest.get(id=request_id)
        if request.status is not RequestStatus.PENDING:
            raise Conflict(f"the request has already been decided (status {request.status.value})")
        return request

    async def _issuer_certificate(self, authority: Authority, now: datetime) -> x509.Certificate:
        record = await self._authorities.certificate_of(authority)
        if record.not_after <= now:
            raise NoActiveAuthority("the certificate of the local CA has expired")
        return x509.load_der_x509_certificate(record.der)

    async def _issue(
        self,
        request: CertificateRequest,
        *,
        parsed: ParsedCsr,
        actor: str,
        decided_by: str,
        tls_key: StoredKey | None = None,
    ) -> CertificateRequest:
        """The single issuance path for certificates signed by the CA.

        ``tls_key``: key generated here for the certificate (built-in HTTPS server), stored in the
        same transaction as the certificate.
        """
        profile = await Profile.get(id=request.profile_id)
        spec = spec_of(profile)
        child = child_of(request)
        if child is not None:
            spec = constrain_sub_ca(spec, _constraints_of(request))
        now = datetime.now(UTC)
        try:
            authority = await self._authorities.get_local()
            issuer_cert, issuer_key = await self._authorities.signing_material(authority, now=now)
            issued = await asyncio.to_thread(
                build_issued,
                parsed,
                spec,
                issuer_cert,
                issuer_key,
                validity_days=request.requested_validity_days,
                now=now,
                ca_issuers_url=_ca_issuers_url(authority),
            )
        except H42Error as exc:
            await self._fail(request, exc, actor=actor, decided_by=decided_by)
            raise

        fields = signed_fields(issued.certificate)
        metadata: dict[str, Any] = {
            **request.metadata,
            "validity_truncated": issued.validity_truncated,
        }
        async with in_transaction():
            private_key: PrivateKey | None = None
            if tls_key is not None:
                private_key = await PrivateKey.create(
                    algorithm=SERVICE_TLS_KEY_ALGORITHM,
                    purpose=KeyPurpose.TLS,
                    encrypted_key=tls_key.encrypted_key,
                    public_key_der=tls_key.public_key_der,
                )
                await AuditLog.record(
                    actor=actor,
                    action="private_key.generate",
                    object_type="private_key",
                    object_id=private_key.id,
                    details={
                        "algorithm": private_key.algorithm.value,
                        "backend": private_key.backend.value,
                        "purpose": private_key.purpose.value,
                    },
                )
            child_authority: Authority | None = None
            if child is not None:
                basic = issued.certificate.extensions.get_extension_for_class(x509.BasicConstraints)
                child_authority = await Authority.create(
                    name=child.name,
                    kind=AuthorityKind.CHILD,
                    status=AuthorityStatus.ACTIVE,
                    parent=authority,
                    path_length=basic.value.path_length,
                    public_base_url=child.public_base_url,
                )
            certificate = await Certificate.create(
                issuer=authority,
                authority=child_authority,
                profile=profile,
                channel=request.channel,
                status=CertificateStatus.VALID,
                private_key=private_key,
                **fields,
            )
            # Conditional update: a concurrent decision on the same request loses here.
            updated = await CertificateRequest.filter(
                id=request.id, status=RequestStatus.PENDING
            ).update(
                status=RequestStatus.ISSUED,
                certificate_id=certificate.id,
                decided_by=decided_by,
                decided_at=now,
                metadata=metadata,
            )
            if not updated:
                raise Conflict("the request has already been decided")
            await self._audit(
                actor,
                "certificate.issue",
                request,
                {
                    "certificate_id": str(certificate.id),
                    "profile": profile.name,
                    "serial_hex": fields["serial_hex"],
                    "subject_dn": fields["subject_dn"],
                    "not_after": fields["not_after"].isoformat(),
                    "validity_truncated": issued.validity_truncated,
                    "decided_by": decided_by,
                    "channel": request.channel.value,
                },
            )
        return await self.get(request.id)

    @staticmethod
    async def _audit_refusal(
        exc: H42Error,
        *,
        csr: bytes | str,
        parsed: ParsedCsr | None,
        profile_name: str,
        actor: str,
        channel: Channel,
    ) -> None:
        """Trace a request refused before being stored (B35): never the CSR itself."""
        if parsed is not None:
            data = parsed.csr.public_bytes(serialization.Encoding.DER)
        else:  # unreadable CSR: fingerprint of what was received
            data = csr.encode("utf-8", errors="replace") if isinstance(csr, str) else csr
        fingerprint = hashlib.sha256(data).hexdigest()
        await AuditLog.record(
            actor=actor,
            action="request.refuse",
            object_type="certificate_request",
            object_id=fingerprint,
            details={
                "profile": profile_name,
                "channel": channel.value,
                "reason": exc.detail,
                "csr_sha256": fingerprint,
                "csr_sha256_of": "der" if parsed is not None else "received",
                "subject_dn": rfc4514(parsed.csr.subject) if parsed is not None else None,
            },
        )

    async def _fail(
        self, request: CertificateRequest, exc: H42Error, *, actor: str, decided_by: str
    ) -> None:
        await CertificateRequest.filter(id=request.id, status=RequestStatus.PENDING).update(
            status=RequestStatus.FAILED,
            decided_by=decided_by,
            decided_at=datetime.now(UTC),
            metadata={**request.metadata, "failure": exc.detail},
        )
        await self._audit(actor, "request.fail", request, {"failure": exc.detail})

    @staticmethod
    async def _audit(
        actor: str, action: str, request: CertificateRequest, details: dict[str, Any]
    ) -> None:
        await AuditLog.record(
            actor=actor,
            action=action,
            object_type="certificate_request",
            object_id=request.id,
            details=details,
        )
