"""SCEP (RFC 8894, ADR-0019): GetCACaps, GetCACert and PKIOperation.

SCEP never uses the CA key: the RA certificate (``services/scep_ra.py``) decrypts the requests and
signs the answers, through the key store; the CA key only signs the certificates issued, on the
single issuance path (``IssuanceService``). An unreadable outer message is an HTTP 400
(``Malformed``); any other problem is a CertRep FAILURE with its failInfo, never a detail of what
failed inside.
"""

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tortoise.exceptions import IntegrityError

from h42pki.core.cms import (
    Envelope,
    FailInfo,
    MessageType,
    PkiMessage,
    PkiStatus,
    ScepError,
    capabilities,
    cert_rep,
    certs_only,
    decrypt_content,
    envelope,
    parse_envelope,
    parse_issuer_and_serial,
    parse_pki_message,
    verify,
)
from h42pki.core.csr import parse_csr
from h42pki.core.settings_schema import ScepSettings
from h42pki.errors import H42Error, MissingPassphrase, NotFound, ServiceUnavailable
from h42pki.keystore import KEY_OPERATIONS_REQUIREMENT, KeyOperationFailed, KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    CertificateRequest,
    Channel,
    EnrollmentCredential,
    Profile,
    RequestStatus,
    ScepNonce,
    ScepTransaction,
    ScepTransactionStatus,
)
from h42pki.services.authority import AuthorityService
from h42pki.services.client_auth import (
    ClientCertificateRefused,
    VerifiedClient,
    verify_client_certificate,
)
from h42pki.services.crl import CrlService
from h42pki.services.issuance import IssuanceService
from h42pki.services.profiles import ProfileService, spec_of
from h42pki.services.publication import PublicationService
from h42pki.services.scep_challenges import ScepChallengeService
from h42pki.services.scep_ra import RaKey, ScepRaManager
from h42pki.services.settings import SettingsService

log = logging.getLogger(__name__)

CHALLENGE_PASSWORD = x509.ObjectIdentifier("1.2.840.113549.1.9.7")
LOCAL_SIGNERS = (
    AuthorityStatus.ACTIVE,
    AuthorityStatus.REVOKED,
    AuthorityStatus.ROLLING_OVER,
    AuthorityStatus.RETIRED,
)

PROFILE_NAME = re.compile(r"^[a-z0-9_]{1,64}$")


@dataclass(frozen=True)
class Outcome:
    """What a PKIOperation answers, before it is encrypted and signed."""

    status: PkiStatus
    fail_info: FailInfo | None = None
    certificates: tuple[x509.Certificate, ...] = ()
    crls: tuple[x509.CertificateRevocationList, ...] = ()


def failure(fail_info: FailInfo) -> Outcome:
    return Outcome(PkiStatus.FAILURE, fail_info)


def _challenge_of(csr: x509.CertificateSigningRequest) -> str | None:
    try:
        value = csr.attributes.get_attribute_for_oid(CHALLENGE_PASSWORD).value
    except x509.AttributeNotFound:
        return None
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else None


class ScepService:
    def __init__(self, keystore: KeyStore | None = None) -> None:
        """``keystore`` is needed by PKIOperation (RA decryption and signature, issuance)."""
        self._key_store = keystore

    @property
    def _keystore(self) -> KeyStore:
        if self._key_store is None:
            raise MissingPassphrase(KEY_OPERATIONS_REQUIREMENT)
        return self._key_store

    @staticmethod
    async def settings() -> ScepSettings:
        """SCEP settings; 404 while ``scep.enabled`` is false (disabled by default, ADR-0018)."""
        settings = (await SettingsService().effective()).scep
        if not settings.enabled:
            raise NotFound("SCEP is not enabled on this CA")
        return settings

    @staticmethod
    async def profile(label: str | None, settings: ScepSettings) -> str:
        """Profile of a label (a profile name), or ``scep.default_profile`` without label."""
        name = label if label is not None else settings.default_profile
        if not name:
            raise NotFound(
                "no default SCEP profile: use /scep/{profile} (or set scep.default_profile)"
            )
        profile = await Profile.get_or_none(name=name) if PROFILE_NAME.fullmatch(name) else None
        if profile is None or spec_of(profile).internal:
            raise NotFound(f"no SCEP profile named {name!r}")
        return profile.name

    @staticmethod
    def capabilities(settings: ScepSettings) -> str:
        return "\n".join(capabilities(settings.allow_legacy_crypto)) + "\n"

    @staticmethod
    async def ca_certificates() -> bytes:
        """GetCACert: degenerate SignedData with the CA, the RA, then the ancestors of the CA."""
        ra = await ScepRaManager().current()
        if ra is None:
            raise ServiceUnavailable("the SCEP RA certificate is not issued yet: try again soon")
        chain = [
            x509.load_der_x509_certificate(record.der)
            for record in await PublicationService().chain()
        ]
        return certs_only([chain[0], x509.load_der_x509_certificate(ra.der), *chain[1:]])

    # --- PKIOperation ---------------------------------------------------------------------

    async def pki_operation(self, der: bytes, *, profile: str, settings: ScepSettings) -> bytes:
        """A signed CertRep for a pkiMessage; ``Malformed`` (HTTP 400) when it is unreadable."""
        message = parse_pki_message(der)  # Malformed: no CertRep possible
        ra_keys = await ScepRaManager().decryption_keys()
        if not ra_keys:
            raise ServiceUnavailable("the SCEP RA certificate is not issued yet: try again soon")
        algorithm = "aes128_cbc"
        signer = ra_keys[0]  # the current RA, unless an older one decrypted the request
        try:
            verify(message, legacy=settings.allow_legacy_crypto)
            sealed = parse_envelope(message.content, legacy=settings.allow_legacy_crypto)
            algorithm = sealed.algorithm
            content, signer = await self._decrypt(sealed, ra_keys)
            await self._check_nonce(message)
            outcome = await self._dispatch(message, content, profile=profile, settings=settings)
        except ScepError as exc:
            log.info(
                "SCEP %s %s: FAILURE %s (%s)",
                message.message_type.name,
                message.transaction_id,
                exc.fail_info.name,
                exc.reason,
            )
            outcome = failure(exc.fail_info)
        # Signed by the RA the client encrypted for: the one it knows (from its GetCACert).
        return await self._answer(message, outcome, algorithm, signer)

    async def _decrypt(self, sealed: Envelope, ra_keys: list[RaKey]) -> tuple[bytes, RaKey]:
        """Content of the request, by the RA it is addressed to; one failure for every cause."""
        for ra in ra_keys:
            certificate = x509.load_der_x509_certificate(ra.certificate.der)
            if (
                certificate.serial_number == sealed.recipient_serial
                and certificate.issuer.public_bytes() == sealed.recipient_issuer
            ):
                try:
                    content_key = await self._keystore.decrypt(
                        ra.encrypted_key, sealed.encrypted_key
                    )
                except KeyOperationFailed:
                    content_key = b""  # same path as a wrong padding (implicit rejection)
                return decrypt_content(sealed, content_key), ra
        raise ScepError(FailInfo.BAD_MESSAGE_CHECK, "the content cannot be decrypted")

    @staticmethod
    async def _check_nonce(message: PkiMessage) -> None:
        """A senderNonce seen on another transaction is a replay; a retransmission is not."""
        authority = await _local_authority()
        nonce = message.sender_nonce.hex()
        seen = await ScepNonce.get_or_none(authority_id=authority.id, nonce=nonce)
        if seen is not None:
            if seen.transaction_id != message.transaction_id:
                raise ScepError(FailInfo.BAD_REQUEST, "senderNonce replayed")
            return
        try:
            await ScepNonce.create(
                authority_id=authority.id, nonce=nonce, transaction_id=message.transaction_id
            )
        except IntegrityError:  # pragma: no cover - concurrent identical message
            raise ScepError(FailInfo.BAD_REQUEST, "senderNonce replayed") from None

    async def _dispatch(
        self, message: PkiMessage, content: bytes, *, profile: str, settings: ScepSettings
    ) -> Outcome:
        match message.message_type:
            case MessageType.PKCS_REQ | MessageType.RENEWAL_REQ:
                return await self._enrol(message, content, profile=profile)
            case MessageType.CERT_POLL:
                return await self._poll(message)
            case MessageType.GET_CERT:
                return await self._get_cert(message, content)
            case MessageType.GET_CRL:
                return await self._get_crl(message, content)
            case _:
                raise ScepError(FailInfo.BAD_REQUEST, "unexpected message type")

    # --- PKCSReq, RenewalReq, CertPoll ----------------------------------------------------

    async def _enrol(self, message: PkiMessage, content: bytes, *, profile: str) -> Outcome:
        authority = await _local_authority()
        transaction = await ScepTransaction.get_or_none(
            authority_id=authority.id, transaction_id=message.transaction_id
        )
        if transaction is not None:  # retransmission: same answer, nothing new
            if transaction.signer_cert_der != _der(message.signer):
                raise ScepError(FailInfo.BAD_REQUEST, "transactionID of another client")
            return await self._state(transaction)
        try:
            parsed = parse_csr(content)
        except H42Error:
            raise ScepError(FailInfo.BAD_REQUEST, "unreadable CSR") from None
        renewal = message.message_type is MessageType.RENEWAL_REQ
        requester, profile, credential, previous = await self._authorize(
            message, parsed.csr, profile=profile, renewal=renewal
        )
        if profile in await ProfileService.disabled():
            raise ScepError(FailInfo.BAD_REQUEST, f"profile {profile} is disabled")

        async def consume(request: CertificateRequest) -> None:
            if credential is not None:
                await ScepChallengeService().consume(credential, actor=requester)

        try:
            request = await IssuanceService(self._keystore).submit(
                csr=content,
                profile_name=profile,
                validity_days=None,
                actor=requester,
                channel=Channel.SCEP,
                metadata={"scep": {"transaction_id": message.transaction_id}},
                sealed_csr=True,
                on_recorded=consume,
            )
        except H42Error as exc:
            raise ScepError(FailInfo.BAD_REQUEST, exc.detail) from None
        transaction = await ScepTransaction.create(
            authority_id=authority.id,
            transaction_id=message.transaction_id,
            message_type=int(message.message_type),
            sender_nonce=message.sender_nonce.hex(),
            signer_cert_der=_der(message.signer),
            status=ScepTransactionStatus.PENDING,
            request_id=request.id,
        )
        await AuditLog.record(
            actor=requester,
            action="scep.renew" if renewal else "scep.enroll",
            object_type="certificate_request",
            object_id=request.id,
            details={
                "transaction_id": message.transaction_id,
                "profile": profile,
                "status": request.status.value,
                "previous_serial_hex": previous.serial_hex if previous is not None else None,
            },
        )
        return await self._state(transaction)

    async def _authorize(
        self,
        message: PkiMessage,
        csr: x509.CertificateSigningRequest,
        *,
        profile: str,
        renewal: bool,
    ) -> tuple[str, str, EnrollmentCredential | None, Certificate | None]:
        """Requester, profile, challenge to consume and renewed certificate of a request."""
        if not renewal:
            credential = await ScepChallengeService().check(_challenge_of(csr))
            if credential is None:
                raise ScepError(FailInfo.BAD_REQUEST, "invalid challenge password")
            return f"scep:{credential.identifier}", profile, credential, None
        # RenewalReq: signed by a valid certificate of this CA, same subject, its profile.
        client = await _local_signer(message)
        record = client.record
        if record is None:  # pragma: no cover - local_only
            raise ScepError(FailInfo.BAD_REQUEST, "renewal of an unknown certificate")
        if csr.subject.public_bytes() != client.certificate.subject.public_bytes():
            raise ScepError(FailInfo.BAD_REQUEST, "a renewal keeps the subject")
        await record.fetch_related("profile")
        if record.profile is None or spec_of(record.profile).internal:
            raise ScepError(FailInfo.BAD_REQUEST, "this certificate cannot be renewed by SCEP")
        return f"scep-cert:{client.fingerprint}", record.profile.name, None, record

    async def _poll(self, message: PkiMessage) -> Outcome:
        authority = await _local_authority()
        transaction = await ScepTransaction.get_or_none(
            authority_id=authority.id, transaction_id=message.transaction_id
        )
        if transaction is None or transaction.signer_cert_der != _der(message.signer):
            raise ScepError(FailInfo.BAD_CERT_ID, "unknown transaction")
        return await self._state(transaction)

    @staticmethod
    async def _state(transaction: ScepTransaction) -> Outcome:
        """Current answer of a transaction; follows the decision on its request."""
        if transaction.status is ScepTransactionStatus.ISSUED and transaction.certificate_id:
            certificate = await Certificate.get(id=transaction.certificate_id)
            return Outcome(PkiStatus.SUCCESS, certificates=(_x509(certificate),))
        if transaction.status is ScepTransactionStatus.FAILED:
            return failure(FailInfo(transaction.fail_info or FailInfo.BAD_REQUEST))
        request = (
            await CertificateRequest.get_or_none(id=transaction.request_id)
            if transaction.request_id is not None
            else None
        )
        if request is None or request.status in (RequestStatus.REJECTED, RequestStatus.FAILED):
            await ScepTransaction.filter(id=transaction.id).update(
                status=ScepTransactionStatus.FAILED, fail_info=int(FailInfo.BAD_REQUEST)
            )
            return failure(FailInfo.BAD_REQUEST)
        if request.status is RequestStatus.ISSUED and request.certificate_id is not None:
            await ScepTransaction.filter(id=transaction.id).update(
                status=ScepTransactionStatus.ISSUED, certificate_id=request.certificate_id
            )
            certificate = await Certificate.get(id=request.certificate_id)
            return Outcome(PkiStatus.SUCCESS, certificates=(_x509(certificate),))
        return Outcome(PkiStatus.PENDING)

    # --- GetCert, GetCRL ------------------------------------------------------------------

    @staticmethod
    async def _get_cert(message: PkiMessage, content: bytes) -> Outcome:
        await _local_signer(message)
        issuer, serial = parse_issuer_and_serial(content)
        authority = await _issuer_named(issuer)
        record = (
            await Certificate.get_or_none(issuer_id=authority.id, serial_hex=format(serial, "x"))
            if authority is not None
            else None
        )
        if record is None:
            raise ScepError(FailInfo.BAD_CERT_ID, "no such certificate")
        return Outcome(PkiStatus.SUCCESS, certificates=(_x509(record),))

    @staticmethod
    async def _get_crl(message: PkiMessage, content: bytes) -> Outcome:
        await _local_signer(message)
        issuer, _ = parse_issuer_and_serial(content)
        authority = await _issuer_named(issuer)
        if authority is None:
            raise ScepError(FailInfo.BAD_CERT_ID, "unknown issuer")
        crl = await CrlService.current(authority) if authority.crl_enabled else None
        if crl is None:
            raise ScepError(FailInfo.BAD_REQUEST, "this CA publishes no CRL")
        return Outcome(PkiStatus.SUCCESS, crls=(x509.load_der_x509_crl(crl.der),))

    # --- CertRep --------------------------------------------------------------------------

    async def _answer(
        self, message: PkiMessage, outcome: Outcome, algorithm: str, ra: RaKey
    ) -> bytes:
        """The CertRep, encrypted for the signer of the request, signed by the current RA."""
        content = b""
        status, fail_info = outcome.status, outcome.fail_info
        if status is PkiStatus.SUCCESS:
            try:
                content = envelope(
                    certs_only(outcome.certificates, outcome.crls), message.signer, algorithm
                )
            except ScepError as exc:
                status, fail_info = PkiStatus.FAILURE, exc.fail_info
        unsigned = cert_rep(
            ra=_x509(ra.certificate),
            digest_algorithm=message.digest_algorithm,
            transaction_id=message.transaction_id,
            recipient_nonce=message.sender_nonce,
            status=status,
            fail_info=fail_info,
            content=content,
        )
        signature = await self._keystore.sign(
            ra.encrypted_key, unsigned.to_sign, unsigned.hash_algorithm
        )
        return unsigned.assemble(signature)


def _der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def _x509(record: Certificate) -> x509.Certificate:
    return x509.load_der_x509_certificate(record.der)


async def _local_authority() -> Authority:
    authority = await AuthorityService().find_local()  # active, or revoked by its parent
    if authority is None:
        raise ScepError(FailInfo.BAD_REQUEST, "no local CA")
    return authority


async def _issuer_named(name_der: bytes) -> Authority | None:
    """The local CA whose subject is ``name_der``."""
    for authority in await Authority.filter(
        kind=AuthorityKind.LOCAL, status__in=LOCAL_SIGNERS
    ).prefetch_related("certificate"):
        if _x509(authority.certificate).subject.public_bytes() == name_der:
            return authority
    return None


async def _local_signer(message: PkiMessage) -> VerifiedClient:
    """The signer must hold a valid certificate issued by a local CA, not revoked."""
    try:
        return await verify_client_certificate(
            message.signer, now=datetime.now(UTC), local_only=True, tls_usage=False
        )
    except ClientCertificateRefused as exc:
        raise ScepError(
            FailInfo.BAD_TIME if exc.expired else FailInfo.BAD_REQUEST, exc.detail
        ) from None


__all__ = ["Outcome", "ScepService"]
