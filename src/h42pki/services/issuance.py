"""Certificate requests and issuance: the only way to get a certificate signed by the CA."""

import asyncio
import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tortoise.transactions import in_transaction

from h42pki.core.csr import ParsedCsr, parse_csr
from h42pki.core.issuance import build_issued, plan_issuance
from h42pki.core.names import rfc4514
from h42pki.core.publication import ca_certificate_url
from h42pki.errors import Conflict, H42Error, NoActiveAuthority, Unprocessable
from h42pki.keystore import KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    Certificate,
    CertificateRequest,
    CertificateStatus,
    Channel,
    Profile,
    RequestStatus,
)
from h42pki.services.authority import AuthorityService
from h42pki.services.profiles import ProfileService, spec_of
from h42pki.services.x509_fields import signed_fields

AUTO_APPROVE = "auto-approve"


def _ca_issuers_url(authority: Authority) -> str | None:
    """AIA caIssuers of the certificates this CA issues, if it publishes its certificate."""
    if authority.public_base_url is None:
        return None
    return ca_certificate_url(authority.public_base_url, authority.name)


class IssuanceService:
    """submit -> (auto_approve | approve) -> _issue; reject. ``_issue`` is the single path."""

    def __init__(self, keystore: KeyStore) -> None:
        self._authorities = AuthorityService(keystore)

    # --- queries --------------------------------------------------------------------------

    async def get(self, request_id: UUID) -> CertificateRequest:
        return await CertificateRequest.get(id=request_id).prefetch_related("profile")

    async def list(self, status: RequestStatus | None = None) -> list[CertificateRequest]:
        query = CertificateRequest.all().prefetch_related("profile")
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

        async with in_transaction():
            request = await CertificateRequest.create(
                csr_der=parsed.csr.public_bytes(serialization.Encoding.DER),
                profile=profile,
                requested_validity_days=validity_days,
                requester=actor,
                channel=channel,
                subject_dn=rfc4514(plan.subject),
                metadata={"ignored_extensions": list(parsed.ignored_extensions)},
            )
            await self._audit(
                actor,
                "request.submit",
                request,
                {
                    "profile": profile.name,
                    "subject_dn": request.subject_dn,
                    "requested_validity_days": validity_days,
                    "ignored_extensions": list(parsed.ignored_extensions),
                },
            )
        if spec.auto_approve:
            return await self._issue(request, parsed=parsed, actor=actor, decided_by=AUTO_APPROVE)
        return await self.get(request.id)

    async def approve(self, request_id: UUID, *, actor: str) -> CertificateRequest:
        request = await self._pending(request_id)
        profile = await Profile.get(id=request.profile_id)
        if profile.name in await ProfileService.disabled():
            raise Conflict(
                f"profile {profile.name!r} is disabled on this CA: the request can only be rejected"
            )
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
        self, request: CertificateRequest, *, parsed: ParsedCsr, actor: str, decided_by: str
    ) -> CertificateRequest:
        """The single issuance path for certificates signed by the CA."""
        profile = await Profile.get(id=request.profile_id)
        spec = spec_of(profile)
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
            certificate = await Certificate.create(
                issuer=authority,
                profile=profile,
                channel=request.channel,
                status=CertificateStatus.VALID,
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
