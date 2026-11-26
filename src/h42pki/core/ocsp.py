"""OCSP (RFC 6960, RFC 5019 profile, RFC 8954 nonce), signed directly by the CA key (ADR-0017).

Pure: parsing a request, matching its issuer, building and signing a response, and, for a child
CA checking its own status, building a request and verifying the answer of its parent.

Checked with ``cryptography`` 48 (spike of phase 3): one CertID per request only (more raise
``NotImplementedError``), SHA-1 and SHA-256 CertIDs, nonce read through ``x509.OCSPNonce``,
responses signed by EC, RSA and Ed25519 keys, ``add_response_by_hash`` to answer a serial number
for which no certificate exists.
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import ocsp

from h42pki.core.keys import SupportedPrivateKey, signature_hash

MAX_REQUEST_BYTES = 64 * 1024
MIN_NONCE_BYTES = 1  # RFC 8954 section 2.1
MAX_NONCE_BYTES = 32
# CertID hash algorithms accepted (RFC 5019 clients use SHA-1, newer ones SHA-256).
CERT_ID_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}
# Tolerated clock difference when a child checks the answer of its parent.
CLOCK_SKEW = timedelta(minutes=5)


class MalformedRequest(ValueError):
    """The request cannot be answered: ``malformedRequest``."""


class InvalidResponse(ValueError):
    """An OCSP answer that cannot be trusted (child side)."""


class CertStatus(StrEnum):
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ParsedRequest:
    issuer_name_hash: bytes
    issuer_key_hash: bytes
    serial_number: int
    algorithm: hashes.HashAlgorithm
    nonce: bytes | None

    @property
    def serial_hex(self) -> str:
        return format(self.serial_number, "x")  # as stored (core.serial)


@dataclass(frozen=True)
class CertState:
    status: CertStatus
    revoked_at: datetime | None = None
    reason: x509.ReasonFlags | None = None


# --- requests ---------------------------------------------------------------------------------


def parse_request(der: bytes) -> ParsedRequest:
    """One CertID, a supported hash, an optional nonce of 1 to 32 bytes; MalformedRequest else."""
    if not der or len(der) > MAX_REQUEST_BYTES:
        raise MalformedRequest("empty or oversized request")
    try:
        request = ocsp.load_der_ocsp_request(der)
        algorithm = request.hash_algorithm
        nonce_extension = _nonce(request.extensions)
    except NotImplementedError:
        raise MalformedRequest("more than one certificate in the request") from None
    except (ValueError, x509.UnsupportedGeneralNameType) as exc:
        raise MalformedRequest(f"unreadable request ({type(exc).__name__})") from None
    if algorithm.name not in CERT_ID_HASHES:
        raise MalformedRequest(f"unsupported CertID hash {algorithm.name}")
    if nonce_extension is not None and not (
        MIN_NONCE_BYTES <= len(nonce_extension) <= MAX_NONCE_BYTES
    ):
        raise MalformedRequest("the nonce must be 1 to 32 bytes long (RFC 8954)")
    return ParsedRequest(
        issuer_name_hash=request.issuer_name_hash,
        issuer_key_hash=request.issuer_key_hash,
        serial_number=request.serial_number,
        algorithm=algorithm,
        nonce=nonce_extension,
    )


def _nonce(extensions: x509.Extensions) -> bytes | None:
    try:
        return extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    except x509.ExtensionNotFound:
        return None


def _bit_string_contents(spki_der: bytes) -> bytes:
    """The subjectPublicKey BIT STRING value (without the unused-bits byte) of an SPKI."""

    def header(data: bytes, offset: int) -> tuple[int, int, int]:
        tag = data[offset]
        length = data[offset + 1]
        offset += 2
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(data[offset : offset + count], "big")
            offset += count
        return tag, length, offset

    _, _, offset = header(spki_der, 0)  # SubjectPublicKeyInfo SEQUENCE
    _, length, start = header(spki_der, offset)  # AlgorithmIdentifier SEQUENCE
    tag, length, start = header(spki_der, start + length)  # subjectPublicKey BIT STRING
    if tag != 0x03:  # pragma: no cover - always a BIT STRING in an SPKI
        raise ValueError("not a SubjectPublicKeyInfo")
    return spki_der[start + 1 : start + length]


def issuer_hashes(issuer: x509.Certificate, algorithm: hashes.HashAlgorithm) -> tuple[bytes, bytes]:
    """issuerNameHash and issuerKeyHash of ``issuer`` (RFC 6960 section 4.1.1)."""
    name = issuer.subject.public_bytes()
    spki = issuer.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return (
        hashlib.new(algorithm.name, name).digest(),
        hashlib.new(algorithm.name, _bit_string_contents(spki)).digest(),
    )


def issued_by(request: ParsedRequest, issuer: x509.Certificate) -> bool:
    """Whether the CertID of ``request`` designates ``issuer``."""
    name_hash, key_hash = issuer_hashes(issuer, request.algorithm)
    return (request.issuer_name_hash, request.issuer_key_hash) == (name_hash, key_hash)


def build_request(
    certificate: x509.Certificate, issuer: x509.Certificate, *, nonce: bytes | None
) -> bytes:
    """Request for ``certificate`` (SHA-1 CertID, understood by every responder)."""
    builder = ocsp.OCSPRequestBuilder().add_certificate(certificate, issuer, hashes.SHA1())  # noqa: S303
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    return builder.build().public_bytes(serialization.Encoding.DER)


# --- responses --------------------------------------------------------------------------------


def response_window(
    now: datetime, *, validity_hours: int, crl_next_update: datetime | None
) -> tuple[datetime, datetime]:
    """thisUpdate and nextUpdate: ``validity_hours``, never after the nextUpdate of the CRL."""
    this_update = now.replace(microsecond=0)
    next_update = this_update + timedelta(hours=validity_hours)
    if crl_next_update is not None:
        # A stale CRL (failing task) must not give a nextUpdate in the past.
        next_update = max(min(next_update, crl_next_update), this_update + timedelta(minutes=1))
    return this_update, next_update


def build_response(
    request: ParsedRequest,
    issuer: x509.Certificate,
    issuer_key: SupportedPrivateKey,
    state: CertState,
    *,
    this_update: datetime,
    next_update: datetime,
) -> ocsp.OCSPResponse:
    """Signed ``successful`` answer: the CertID of the request echoed, the CA as responder."""
    status = {
        CertStatus.GOOD: ocsp.OCSPCertStatus.GOOD,
        CertStatus.REVOKED: ocsp.OCSPCertStatus.REVOKED,
        CertStatus.UNKNOWN: ocsp.OCSPCertStatus.UNKNOWN,
    }[state.status]
    revoked_at = reason = None
    if state.status is CertStatus.REVOKED:
        revoked_at = (state.revoked_at or this_update).replace(microsecond=0)
        if state.reason is not x509.ReasonFlags.unspecified:
            reason = state.reason
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response_by_hash(
            issuer_name_hash=request.issuer_name_hash,
            issuer_key_hash=request.issuer_key_hash,
            serial_number=request.serial_number,
            algorithm=request.algorithm,
            cert_status=status,
            this_update=this_update,
            next_update=next_update,
            revocation_time=revoked_at,
            revocation_reason=reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer)
        .certificates([issuer])
    )
    if request.nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(request.nonce), critical=False)
    return builder.sign(issuer_key, signature_hash(issuer_key))


def build_error(status: ocsp.OCSPResponseStatus) -> bytes:
    """Unsigned answer: ``malformedRequest``, ``unauthorized``, ``internalError``…"""
    return ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(
        serialization.Encoding.DER
    )


# --- checking an answer (child CA) ------------------------------------------------------------


def _signature_valid(response: ocsp.OCSPResponse, issuer: x509.Certificate) -> bool:
    key = issuer.public_key()
    algorithm = response.signature_hash_algorithm
    try:
        if isinstance(key, rsa.RSAPublicKey) and algorithm is not None:
            key.verify(
                response.signature, response.tbs_response_bytes, padding.PKCS1v15(), algorithm
            )
        elif isinstance(key, ec.EllipticCurvePublicKey) and algorithm is not None:
            key.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(algorithm))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(response.signature, response.tbs_response_bytes)
        else:
            return False
    except InvalidSignature:
        return False
    return True


def verify_response(
    der: bytes,
    *,
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    nonce: bytes | None,
    now: datetime,
) -> CertState:
    """Status of ``certificate`` in an answer signed by ``issuer`` itself; InvalidResponse else.

    Checked: successful status, responder = the issuer (key hash or name), signature, CertID
    (serial and issuer), nonce echoed when sent and given back, thisUpdate and nextUpdate.
    """
    try:
        response = ocsp.load_der_ocsp_response(der)
    except ValueError:
        raise InvalidResponse("unreadable OCSP answer") from None
    if response.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise InvalidResponse(f"OCSP answer {response.response_status.name}")
    sha1_key_hash = issuer_hashes(issuer, hashes.SHA1())[1]  # noqa: S303 - responder id
    if response.responder_key_hash != sha1_key_hash and response.responder_name != issuer.subject:
        raise InvalidResponse("the answer is not signed by the parent CA itself")
    if not _signature_valid(response, issuer):
        raise InvalidResponse("the signature of the OCSP answer does not verify")
    name_hash, key_hash = issuer_hashes(issuer, response.hash_algorithm)
    if (
        response.serial_number != certificate.serial_number
        or response.issuer_key_hash != key_hash
        or response.issuer_name_hash != name_hash
    ):
        raise InvalidResponse("the OCSP answer is about another certificate")
    echoed = _nonce(response.extensions)
    if nonce is not None and echoed is not None and echoed != nonce:
        raise InvalidResponse("the OCSP answer does not repeat the nonce")
    if response.this_update_utc > now + CLOCK_SKEW:
        raise InvalidResponse("the OCSP answer is dated in the future")
    next_update = response.next_update_utc
    if next_update is not None and next_update < now - CLOCK_SKEW:
        raise InvalidResponse("the OCSP answer is outdated")
    match response.certificate_status:
        case ocsp.OCSPCertStatus.GOOD:
            return CertState(CertStatus.GOOD)
        case ocsp.OCSPCertStatus.REVOKED:
            return CertState(
                CertStatus.REVOKED,
                revoked_at=response.revocation_time_utc,
                reason=response.revocation_reason,
            )
        case _:
            return CertState(CertStatus.UNKNOWN)
