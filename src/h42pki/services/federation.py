"""Federation, parent side: invitations, enrolment and revocation of child CAs (ADR-0015).

An enrolment is a ``CertificateRequest`` (``sub_ca`` profile, ``federation`` channel) that follows
the single issuance path. The token of an invitation is never stored, logged nor audited.
"""

import builtins
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tortoise.transactions import in_transaction

from h42pki.core.csr import parse_csr
from h42pki.core.errors import InvalidValidity, PathLengthExceeded
from h42pki.core.federation import (
    DEFAULT_EXPIRES_IN_HOURS,
    InvitationToken,
    SubCaConstraints,
    effective_path_length,
    hash_secret,
    new_token,
    parse_token,
    secret_matches,
)
from h42pki.core.profiles import SUB_CA_PROFILE
from h42pki.core.publication import normalize_public_base_url, validate_authority_name
from h42pki.errors import Conflict, H42Error, NotFound, Unauthorized
from h42pki.keystore import KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    CertificateRequest,
    FederationInvitation,
    InvitationStatus,
    Profile,
    RequestStatus,
)
from h42pki.services.authority import AuthorityService
from h42pki.services.certificates import CertificateService
from h42pki.services.issuance import ChildCa, IssuanceService, child_of
from h42pki.services.revocation import RevocationListener, RevocationService

# After the decision, the token still gives access to its own enrolment for this long.
GRACE_PERIOD = timedelta(hours=24)


class CaRevocationReason(StrEnum):
    """RFC 5280 reasons that make sense for a CA certificate (names of ``x509.ReasonFlags``)."""

    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    CA_COMPROMISE = "ca_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"


@dataclass(frozen=True, repr=False)
class CreatedInvitation:
    invitation: FederationInvitation
    token: InvitationToken
    parent_fingerprint: str
    effective_path_length: int | None  # None: unlimited


@dataclass(frozen=True)
class Enrolment:
    request: CertificateRequest
    certificate: Certificate | None
    chain: list[Certificate]  # of the parent CA, root included; empty until issued


def effective_status(invitation: FederationInvitation, now: datetime) -> InvitationStatus:
    if invitation.status is InvitationStatus.ACTIVE and invitation.expires_at <= now:
        return InvitationStatus.EXPIRED
    return invitation.status


def _refused() -> Unauthorized:
    # One message whatever the reason: absent, malformed, unknown, expired, revoked, other request.
    return Unauthorized("a valid invitation token is required")


class FederationService:
    def __init__(
        self, keystore: KeyStore | None = None, *, on_revoked: RevocationListener | None = None
    ) -> None:
        """``keystore`` signs: an auto-approved enrolment, the CRL after a child's revocation."""
        self._keystore = keystore
        self._on_revoked = on_revoked

    # --- invitations ----------------------------------------------------------------------

    async def invite(
        self,
        *,
        label: str | None = None,
        path_length: int | None = None,
        validity_days: int | None = None,
        auto_approve: bool = False,
        expires_in_hours: int = DEFAULT_EXPIRES_IN_HOURS,
        actor: str,
    ) -> CreatedInvitation:
        authorities = AuthorityService()
        record = await authorities.certificate_of(await authorities.get_issuing())
        issuer = x509.load_der_x509_certificate(record.der)
        ceiling = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
        if ceiling == 0:
            raise PathLengthExceeded("this CA has pathLen 0 and cannot sign another CA")
        profile = await Profile.get(name=SUB_CA_PROFILE)
        if validity_days is not None and validity_days > profile.max_validity_days:
            raise InvalidValidity(
                f"profile {profile.name} allows at most {profile.max_validity_days} days, "
                f"not {validity_days}"
            )
        token = new_token(uuid4())
        async with in_transaction():
            invitation = await FederationInvitation.create(
                id=token.invitation_id,
                label=label,
                secret_hash=hash_secret(token.secret),
                path_length=path_length,
                validity_days=validity_days,
                auto_approve=auto_approve,
                expires_at=datetime.now(UTC) + timedelta(hours=expires_in_hours),
                created_by=actor,
            )
            await self._audit(
                actor,
                "federation.invite",
                invitation,
                {
                    "label": label,
                    "path_length": path_length,
                    "validity_days": validity_days,
                    "auto_approve": auto_approve,
                    "expires_at": invitation.expires_at.isoformat(),
                },
            )
        return CreatedInvitation(
            invitation=invitation,
            token=token,
            parent_fingerprint=record.sha256_fingerprint,
            effective_path_length=effective_path_length(path_length, ceiling),
        )

    async def list(self) -> builtins.list[FederationInvitation]:
        return await FederationInvitation.all()

    async def get(self, invitation_id: UUID) -> FederationInvitation:
        return await FederationInvitation.get(id=invitation_id)

    async def revoke_invitation(self, invitation_id: UUID, *, actor: str) -> FederationInvitation:
        invitation = await self.get(invitation_id)
        async with in_transaction():
            updated = await FederationInvitation.filter(
                id=invitation.id, status=InvitationStatus.ACTIVE
            ).update(status=InvitationStatus.REVOKED)
            if not updated:
                current = await self.get(invitation_id)
                raise Conflict(f"the invitation is already {current.status.value}")
            await self._audit(actor, "federation.invitation_revoke", invitation, {})
        return await self.get(invitation_id)

    # --- enrolment (authenticated by the token) -------------------------------------------

    async def authenticate(self, token_text: str | None) -> FederationInvitation:
        """The invitation of a usable token; the same 401 in every other case.

        ``expires_at`` limits the first use. Once used, the token is only good for its own
        request, until 24 hours after the decision.
        """
        token = parse_token(token_text) if token_text is not None else None
        invitation = (
            await FederationInvitation.get_or_none(id=token.invitation_id).prefetch_related(
                "request__profile"
            )
            if token is not None
            else None
        )
        secret_ok = secret_matches(
            token.secret if token is not None else "",
            invitation.secret_hash if invitation is not None else None,
        )
        if invitation is None or not secret_ok:
            raise _refused()
        now = datetime.now(UTC)
        status = effective_status(invitation, now)
        if status is InvitationStatus.ACTIVE:
            return invitation
        request = invitation.request
        if status is InvitationStatus.USED and request is not None:
            if request.status is RequestStatus.PENDING:
                return invitation
            if request.decided_at is not None and now < request.decided_at + GRACE_PERIOD:
                return invitation
        raise _refused()

    async def enroll(
        self, token_text: str | None, *, csr: str, name: str, public_base_url: str | None
    ) -> Enrolment:
        """Consume the invitation, or return the enrolment it already made.

        Idempotent: the same CSR, name and URL give the current state, so that a child whose
        answer was lost can send its request again. Anything else is another request: 401.
        """
        invitation = await self.authenticate(token_text)
        if invitation.request is not None:
            if not self._is_same(invitation.request, csr, name, public_base_url):
                raise _refused()
            return await self._enrolment(invitation.request)

        validate_authority_name(name)
        if public_base_url is not None:
            public_base_url = normalize_public_base_url(public_base_url).url
        actor = f"invitation:{invitation.id}"

        async def consume(request: CertificateRequest) -> None:
            now = datetime.now(UTC)
            updated = await FederationInvitation.filter(
                id=invitation.id, status=InvitationStatus.ACTIVE, expires_at__gt=now
            ).update(status=InvitationStatus.USED, used_at=now, request_id=request.id)
            if not updated:  # concurrent use or revocation
                raise _refused()
            await self._audit(
                actor,
                "federation.enroll",
                invitation,
                {"request_id": str(request.id), "name": name, "subject_dn": request.subject_dn},
            )

        request = await IssuanceService(self._keystore).submit_child(
            csr=csr,
            child=ChildCa(name=name, public_base_url=public_base_url),
            constraints=SubCaConstraints(
                path_length=invitation.path_length,
                validity_days=invitation.validity_days,
                auto_approve=invitation.auto_approve,
            ),
            actor=actor,
            on_recorded=consume,
        )
        return await self._enrolment(request)

    async def enrolment(self, token_text: str | None, enrolment_id: UUID) -> Enrolment:
        invitation = await self.authenticate(token_text)
        if invitation.request is None or invitation.request.id != enrolment_id:
            raise _refused()
        return await self._enrolment(invitation.request)

    @staticmethod
    def _is_same(
        request: CertificateRequest, csr: str, name: str, public_base_url: str | None
    ) -> bool:
        try:
            der = parse_csr(csr).csr.public_bytes(serialization.Encoding.DER)
            url = normalize_public_base_url(public_base_url).url if public_base_url else None
        except H42Error:  # a replay is valid by definition: anything else is another request
            return False
        return der == request.csr_der and child_of(request) == ChildCa(name, url)

    @staticmethod
    async def _enrolment(request: CertificateRequest) -> Enrolment:
        if request.certificate_id is None:
            return Enrolment(request, None, [])
        certificate = await Certificate.get(id=request.certificate_id)
        chain = await CertificateService().chain(certificate)
        return Enrolment(request, certificate, chain[1:])

    # --- child CAs ------------------------------------------------------------------------

    async def children(self) -> builtins.list[Authority]:
        return (
            await Authority.filter(kind=AuthorityKind.CHILD)
            .order_by("name")
            .prefetch_related("certificate")
        )

    async def revoke_child(self, name: str, *, reason: CaRevocationReason, actor: str) -> Authority:
        """Revoke a child CA: its certificate through RevocationService (CRL, OCSP, audit).

        The child learns it from the OCSP of this CA (daily check, ADR-0017).
        """
        child = (
            await Authority.filter(kind=AuthorityKind.CHILD, name=name)
            .prefetch_related("certificate")
            .first()
        )
        if child is None:
            raise NotFound(f"no child CA named {name!r}")
        if child.status is AuthorityStatus.REVOKED:
            raise Conflict(f"the child CA {name!r} is already revoked")
        certificate = child.certificate
        await RevocationService(self._keystore, on_revoked=self._on_revoked).revoke(
            certificate.id, reason=x509.ReasonFlags[reason.value], actor=actor
        )
        await AuditLog.record(
            actor=actor,
            action="federation.child_revoke",
            object_type="authority",
            object_id=child.id,
            details={
                "name": name,
                "reason": reason.value,
                "certificate_id": str(certificate.id),
                "serial_hex": certificate.serial_hex,
            },
        )
        return await Authority.get(id=child.id).prefetch_related("certificate")

    @staticmethod
    async def _audit(
        actor: str, action: str, invitation: FederationInvitation, details: dict[str, object]
    ) -> None:
        await AuditLog.record(
            actor=actor,
            action=action,
            object_type="federation_invitation",
            object_id=invitation.id,
            details=details,
        )
