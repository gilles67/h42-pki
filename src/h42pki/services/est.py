"""EST (RFC 7030, ADR-0018): authentication, profile of a label, enrolment and its retries.

Every certificate goes through ``IssuanceService`` (channel ``est``). A request is found again by
(authenticated identity, SHA-256 of the CSR, operation): a client that got ``202`` sends the same
request again and gets the certificate once approved, without a new request; the same request
after issuance gives the same certificate.
"""

import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from h42pki.core.csr import ParsedCsr, parse_csr
from h42pki.core.names import SUBJECT_OIDS
from h42pki.core.settings_schema import EstSettings
from h42pki.errors import (
    Forbidden,
    InvalidRequest,
    NotFound,
    ServiceUnavailable,
    Unauthorized,
)
from h42pki.keystore import KeyStore
from h42pki.models import (
    AuditLog,
    Certificate,
    CertificateRequest,
    CertificateStatus,
    Channel,
    EnrollmentCredential,
    Profile,
    RequestStatus,
)
from h42pki.services.client_auth import (
    ClientCertificateRefused,
    VerifiedClient,
    verify_client_certificate,
)
from h42pki.services.est_accounts import EstAccountService
from h42pki.services.issuance import IssuanceService
from h42pki.services.profiles import ProfileService, spec_of
from h42pki.services.publication import PublicationService
from h42pki.services.settings import SettingsService

log = logging.getLogger(__name__)

REALM = "h42pki-est"
PROFILE_NAME = re.compile(r"^[a-z0-9_]{1,64}$")


class EstOperation(StrEnum):
    SIMPLEENROLL = "simpleenroll"
    SIMPLEREENROLL = "simplereenroll"
    SERVERKEYGEN = "serverkeygen"


AUDIT_ACTIONS = {
    EstOperation.SIMPLEENROLL: "est.enroll",
    EstOperation.SIMPLEREENROLL: "est.reenroll",
    EstOperation.SERVERKEYGEN: "est.serverkeygen",
}
# id-cmc-changeSubjectName (RFC 6402): asks for another subject at re-enrolment, not supported.
CHANGE_SUBJECT_NAME = x509.ObjectIdentifier("1.3.6.1.5.5.7.7.36")


class EstUnauthorized(Unauthorized):
    """401 with the Basic challenge of EST; the message never says what failed."""

    headers = {"WWW-Authenticate": f'Basic realm="{REALM}"', "Cache-Control": "no-store"}


@dataclass(frozen=True)
class Identity:
    requester: str  # est:<user> or est-cert:<SHA-256 of the client certificate>
    account: EnrollmentCredential | None = None
    client: VerifiedClient | None = None


@dataclass(frozen=True)
class Issued:
    request: CertificateRequest
    certificate: Certificate


@dataclass(frozen=True)
class Pending:
    request: CertificateRequest
    retry_after: int


EnrollResult = Issued | Pending


def csr_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _sans(extensions: x509.Extensions) -> set[x509.GeneralName]:
    try:
        return set(extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return set()


def check_same_identity(csr: x509.CertificateSigningRequest, current: x509.Certificate) -> None:
    """Re-enrolment keeps the subject and the SANs exactly (RFC 7030 section 4.2.2); 400 else."""
    for attribute in csr.attributes:
        if attribute.oid == CHANGE_SUBJECT_NAME:
            raise InvalidRequest("ChangeSubjectName is not supported")
    if csr.subject.public_bytes() != current.subject.public_bytes():
        raise InvalidRequest("re-enrolment keeps the subject of the current certificate")
    if _sans(csr.extensions) != _sans(current.extensions):
        raise InvalidRequest(
            "re-enrolment keeps the subject alternative names of the current certificate"
        )


class EstService:
    def __init__(self, keystore: KeyStore | None = None) -> None:
        self._keystore = keystore

    # --- availability, profile ------------------------------------------------------------

    @staticmethod
    async def settings() -> EstSettings:
        """EST settings; 404 while ``est.enabled`` is false (disabled by default, ADR-0018)."""
        settings = (await SettingsService().effective()).est
        if not settings.enabled:
            raise NotFound("EST is not enabled on this CA")
        return settings

    @staticmethod
    async def profile(label: str | None, settings: EstSettings) -> str:
        """Profile of a label (a profile name), or ``est.default_profile`` without label."""
        name = label if label is not None else settings.default_profile
        if not name:
            raise NotFound(
                "no default EST profile: use /.well-known/est/{profile}/... "
                "(or set est.default_profile)"
            )
        profile = await Profile.get_or_none(name=name) if PROFILE_NAME.fullmatch(name) else None
        if profile is None or spec_of(profile).internal:
            raise NotFound(f"no EST profile named {name!r}")
        return profile.name

    @staticmethod
    async def check_enabled_profile(name: str) -> None:
        if name in await ProfileService.disabled():
            raise Forbidden(f"profile {name!r} is disabled on this CA")

    # --- authentication -------------------------------------------------------------------

    @staticmethod
    async def authenticate(
        basic: tuple[str, str] | None,
        certificate: x509.Certificate | None,
        *,
        certificate_only: bool = False,
    ) -> Identity:
        """A verified client certificate (B45), else an EST account; 401 otherwise."""
        now = datetime.now(UTC)
        if certificate is not None:
            try:
                client = await verify_client_certificate(
                    certificate, now=now, local_only=certificate_only
                )
            except ClientCertificateRefused as exc:
                log.info("EST: client certificate refused (%s)", exc.detail)
            else:
                return Identity(f"est-cert:{client.fingerprint}", client=client)
        if certificate_only:
            raise EstUnauthorized("a valid client certificate issued by this CA is required")
        if basic is not None:
            account = await EstAccountService().authenticate(*basic)
            if account is not None:
                return Identity(f"est:{account.identifier}", account=account)
        raise EstUnauthorized("authentication required")

    # --- operations -----------------------------------------------------------------------

    @staticmethod
    async def cacerts() -> list[x509.Certificate]:
        """The local CA and its ancestors, root included."""
        return [
            x509.load_der_x509_certificate(record.der)
            for record in await PublicationService().chain()
        ]

    async def enroll(
        self,
        identity: Identity,
        *,
        profile: str,
        csr_der: bytes,
        operation: EstOperation = EstOperation.SIMPLEENROLL,
        audit: dict[str, object] | None = None,
    ) -> EnrollResult:
        """Issue, or find again the request this identity already sent with this CSR."""
        settings = await self.settings()
        parsed = parse_csr(csr_der)
        return await self._enroll(
            identity, profile, parsed, operation, settings=settings, audit=audit or {}
        )

    async def _enroll(
        self,
        identity: Identity,
        profile: str,
        parsed: ParsedCsr,
        operation: EstOperation,
        *,
        settings: EstSettings,
        audit: dict[str, object],
    ) -> EnrollResult:
        canonical = parsed.csr.public_bytes(serialization.Encoding.DER)
        digest = csr_sha256(canonical)
        previous = await self._previous(identity.requester, digest, operation)
        if previous is not None:
            found = await self._outcome(previous, settings)
            if found is not None:
                return found
        await self.check_enabled_profile(profile)
        request = await IssuanceService(self._keystore).submit(
            csr=canonical,
            profile_name=profile,
            validity_days=None,
            actor=identity.requester,
            channel=Channel.EST,
            metadata={"est": {"operation": operation.value, "csr_sha256": digest}},
        )
        await AuditLog.record(
            actor=identity.requester,
            action=AUDIT_ACTIONS[operation],
            object_type="certificate_request",
            object_id=request.id,
            details={
                "profile": profile,
                "status": request.status.value,
                "csr_sha256": digest,
                **audit,
            },
        )
        outcome = await self._outcome(request, settings)
        if outcome is None:  # pragma: no cover - a fresh request is pending or issued
            raise ServiceUnavailable("the request could not be issued")
        return outcome

    async def reenroll(
        self, identity: Identity, *, label: str | None, csr_der: bytes
    ) -> EnrollResult:
        """RFC 7030 section 4.2.2: same subject and SANs as the certificate presented.

        ``identity`` comes from a client certificate issued by a local CA (``certificate_only``);
        its profile is the profile of that certificate. The old certificate is not revoked.
        """
        settings = await self.settings()
        client = identity.client
        record = client.record if client is not None else None
        if client is None or record is None:
            raise EstUnauthorized("a valid client certificate issued by this CA is required")
        await record.fetch_related("profile")
        if record.profile is None:  # pragma: no cover - CA certificates cannot authenticate
            raise InvalidRequest("this certificate has no profile to re-enrol with")
        profile = record.profile.name
        if label is not None and label != profile:
            raise InvalidRequest(
                f"the certificate presented has profile {profile!r}, not {label!r}"
            )
        parsed = parse_csr(csr_der)
        check_same_identity(parsed.csr, client.certificate)
        return await self._enroll(
            identity,
            profile,
            parsed,
            EstOperation.SIMPLEREENROLL,
            settings=settings,
            audit={"previous_serial_hex": record.serial_hex},
        )

    @staticmethod
    async def csr_attributes(profile: str) -> list[x509.ObjectIdentifier]:
        """What the profile requires of a CSR: subject attributes, and SANs if required."""
        spec = spec_of(await Profile.get(name=profile))
        oids = [SUBJECT_OIDS[field] for field in spec.subject_policy.required]
        if spec.san_policy.required:
            oids.append(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return oids

    @staticmethod
    async def _previous(
        requester: str, digest: str, operation: EstOperation
    ) -> CertificateRequest | None:
        requests = await CertificateRequest.filter(
            channel=Channel.EST, requester=requester
        ).order_by("-created_at")
        for request in requests:
            est = request.metadata.get("est") or {}
            if est.get("csr_sha256") == digest and est.get("operation") == operation.value:
                return request
        return None

    @staticmethod
    async def _outcome(request: CertificateRequest, settings: EstSettings) -> EnrollResult | None:
        """What a (new or retried) request gives; None when a new request must be made."""
        match request.status:
            case RequestStatus.PENDING:
                return Pending(request, settings.retry_after_seconds)
            case RequestStatus.ISSUED:
                certificate = await Certificate.get(id=request.certificate_id)
                now = datetime.now(UTC)
                if certificate.status is CertificateStatus.VALID and certificate.not_after > now:
                    return Issued(request, certificate)
                return None  # revoked or expired since: the client gets a new one
            case RequestStatus.REJECTED:
                raise Forbidden(f"the request was rejected: {request.rejection_reason or '-'}")
            case _:
                failure = request.metadata.get("failure", "unknown failure")
                raise ServiceUnavailable(f"the request could not be issued: {failure}")
