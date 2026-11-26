"""core.ocsp: requests, responses signed by the CA, checking an answer (ADR-0017)."""

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.core.ocsp import (
    CertState,
    CertStatus,
    InvalidResponse,
    MalformedRequest,
    ParsedRequest,
    build_error,
    build_request,
    build_response,
    issued_by,
    issuer_hashes,
    parse_request,
    response_window,
    verify_response,
)
from tests.unit.core.test_issued import NOW, _issue, _root

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]
FIXTURES = Path(__file__).parents[2] / "fixtures"
LATER = NOW + timedelta(hours=24)
SHA1 = hashes.SHA1()  # noqa: S303 - CertID of RFC 5019 clients


def ca_and_leaf(
    key_for: KeyFor, algorithm: KeyAlgorithm = KeyAlgorithm.EC_P384
) -> tuple[x509.Certificate, SupportedPrivateKey, x509.Certificate]:
    key = key_for(algorithm)
    issuer = _root(key)
    leaf = _issue(
        (issuer, key), "tls_server", key_for(KeyAlgorithm.EC_P256), sans=["dns:a.example.test"]
    ).certificate
    return issuer, key, leaf


def request_for(
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    *,
    algorithm: hashes.HashAlgorithm | None = None,
    nonce: bytes | None = None,
) -> bytes:
    builder = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, algorithm or SHA1)
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    return builder.build().public_bytes(serialization.Encoding.DER)


def answer(
    request: ParsedRequest,
    issuer: x509.Certificate,
    key: SupportedPrivateKey,
    state: CertState,
) -> ocsp.OCSPResponse:
    return build_response(request, issuer, key, state, this_update=NOW, next_update=LATER)


# --- requests ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "algorithm", [KeyAlgorithm.RSA2048, KeyAlgorithm.EC_P256, KeyAlgorithm.ED25519]
)
@pytest.mark.parametrize("hash_type", [hashes.SHA1, hashes.SHA256])
def test_cert_id_sha1_and_sha256(
    key_for: KeyFor, algorithm: KeyAlgorithm, hash_type: type[hashes.HashAlgorithm]
) -> None:
    issuer, _, leaf = ca_and_leaf(key_for, algorithm)

    parsed = parse_request(request_for(leaf, issuer, algorithm=hash_type()))

    assert parsed.algorithm.name == hash_type.name
    assert parsed.serial_number == leaf.serial_number
    assert parsed.serial_hex == format(leaf.serial_number, "x")
    assert (parsed.issuer_name_hash, parsed.issuer_key_hash) == issuer_hashes(issuer, hash_type())
    assert issued_by(parsed, issuer)
    assert parsed.nonce is None


def test_other_issuer_does_not_match(key_for: KeyFor) -> None:
    issuer, _, leaf = ca_and_leaf(key_for)
    other = _root(key_for(KeyAlgorithm.EC_P256))

    assert not issued_by(parse_request(request_for(leaf, issuer)), other)


def test_nonce_is_read(key_for: KeyFor) -> None:
    issuer, _, leaf = ca_and_leaf(key_for)

    for size in (1, 16, 32):
        nonce = bytes(range(size))
        assert parse_request(request_for(leaf, issuer, nonce=nonce)).nonce == nonce


def test_oversized_nonce_is_malformed(key_for: KeyFor) -> None:
    issuer, _, leaf = ca_and_leaf(key_for)

    with pytest.raises(MalformedRequest, match="1 to 32 bytes"):
        parse_request(request_for(leaf, issuer, nonce=bytes(33)))


@pytest.mark.parametrize("der", [b"", b"garbage", b"\x30\x03\x02\x01\x01", bytes(70 * 1024)])
def test_unreadable_request_is_malformed(der: bytes) -> None:
    with pytest.raises(MalformedRequest):
        parse_request(der)


def test_two_cert_ids_are_malformed() -> None:
    # Made by `openssl ocsp -serial 1 -serial 2 -reqout`: cryptography handles one CertID only.
    der = (FIXTURES / "ocsp-two-certids.der").read_bytes()

    with pytest.raises(MalformedRequest, match="more than one"):
        parse_request(der)


def test_build_request_with_nonce(key_for: KeyFor) -> None:
    issuer, _, leaf = ca_and_leaf(key_for)

    parsed = parse_request(build_request(leaf, issuer, nonce=b"0123456789abcdef"))

    assert parsed.algorithm.name == "sha1" and parsed.nonce == b"0123456789abcdef"
    assert issued_by(parsed, issuer)


# --- responses --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "algorithm",
    [KeyAlgorithm.RSA2048, KeyAlgorithm.EC_P256, KeyAlgorithm.EC_P384, KeyAlgorithm.ED25519],
)
def test_good_signed_by_the_ca(key_for: KeyFor, algorithm: KeyAlgorithm) -> None:
    issuer, key, leaf = ca_and_leaf(key_for, algorithm)
    request = parse_request(request_for(leaf, issuer, nonce=b"nonce"))

    response = answer(request, issuer, key, CertState(CertStatus.GOOD))

    assert response.response_status is ocsp.OCSPResponseStatus.SUCCESSFUL
    assert response.certificate_status is ocsp.OCSPCertStatus.GOOD
    assert response.this_update_utc == NOW and response.next_update_utc == LATER
    assert response.responder_key_hash == issuer_hashes(issuer, SHA1)[1]
    assert response.certificates == [issuer]
    assert response.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce == b"nonce"
    der = response.public_bytes(serialization.Encoding.DER)
    state = verify_response(der, certificate=leaf, issuer=issuer, nonce=b"nonce", now=NOW)
    assert state.status is CertStatus.GOOD


def test_revoked_with_reason_and_time(key_for: KeyFor) -> None:
    issuer, key, leaf = ca_and_leaf(key_for)
    request = parse_request(request_for(leaf, issuer, algorithm=hashes.SHA256()))
    revoked_at = NOW - timedelta(hours=2, microseconds=7)

    response = answer(
        request,
        issuer,
        key,
        CertState(CertStatus.REVOKED, revoked_at, x509.ReasonFlags.key_compromise),
    )

    assert response.certificate_status is ocsp.OCSPCertStatus.REVOKED
    assert response.revocation_time_utc == NOW - timedelta(hours=2, seconds=1)
    assert response.revocation_reason is x509.ReasonFlags.key_compromise
    assert response.hash_algorithm.name == "sha256"
    der = response.public_bytes(serialization.Encoding.DER)
    state = verify_response(der, certificate=leaf, issuer=issuer, nonce=None, now=NOW)
    assert (state.status, state.reason) == (CertStatus.REVOKED, x509.ReasonFlags.key_compromise)


def test_unspecified_reason_is_omitted(key_for: KeyFor) -> None:
    issuer, key, leaf = ca_and_leaf(key_for)
    request = parse_request(request_for(leaf, issuer))

    response = answer(
        request, issuer, key, CertState(CertStatus.REVOKED, NOW, x509.ReasonFlags.unspecified)
    )

    assert response.revocation_reason is None


def test_unknown_serial_echoes_the_cert_id(key_for: KeyFor) -> None:
    issuer, key, leaf = ca_and_leaf(key_for)
    request = parse_request(request_for(leaf, issuer))

    response = answer(request, issuer, key, CertState(CertStatus.UNKNOWN))

    assert response.certificate_status is ocsp.OCSPCertStatus.UNKNOWN
    assert response.serial_number == leaf.serial_number
    assert response.issuer_key_hash == request.issuer_key_hash


@pytest.mark.parametrize(
    ("status", "name"),
    [
        (ocsp.OCSPResponseStatus.MALFORMED_REQUEST, "MALFORMED_REQUEST"),
        (ocsp.OCSPResponseStatus.UNAUTHORIZED, "UNAUTHORIZED"),
    ],
)
def test_unsuccessful_answers(status: ocsp.OCSPResponseStatus, name: str) -> None:
    assert ocsp.load_der_ocsp_response(build_error(status)).response_status.name == name


def test_response_window_is_bounded_by_the_crl() -> None:
    crl_next = NOW + timedelta(hours=5)

    assert response_window(NOW, validity_hours=24, crl_next_update=None) == (
        NOW,
        NOW + timedelta(hours=24),
    )
    assert response_window(NOW, validity_hours=24, crl_next_update=crl_next) == (NOW, crl_next)
    assert response_window(NOW, validity_hours=2, crl_next_update=crl_next)[1] == NOW + timedelta(
        hours=2
    )
    # A stale CRL never gives a nextUpdate in the past.
    stale = response_window(NOW, validity_hours=24, crl_next_update=NOW - timedelta(hours=1))
    assert stale[1] == NOW + timedelta(minutes=1)


# --- checking an answer (child CA) ------------------------------------------------------------


def test_altered_signature_is_refused(key_for: KeyFor) -> None:
    issuer, key, leaf = ca_and_leaf(key_for)
    request = parse_request(request_for(leaf, issuer))
    response = answer(request, issuer, key, CertState(CertStatus.GOOD))
    der = bytearray(response.public_bytes(serialization.Encoding.DER))
    position = bytes(der).rindex(response.signature) + 10
    der[position] ^= 0x01

    with pytest.raises(InvalidResponse, match="signature"):
        verify_response(bytes(der), certificate=leaf, issuer=issuer, nonce=None, now=NOW)


def test_answer_checks(key_for: KeyFor) -> None:
    issuer, key, leaf = ca_and_leaf(key_for)
    _, _, other_leaf = ca_and_leaf(key_for)
    request = parse_request(request_for(leaf, issuer, nonce=b"sent"))
    der = answer(request, issuer, key, CertState(CertStatus.GOOD)).public_bytes(
        serialization.Encoding.DER
    )
    stranger = _root(key_for(KeyAlgorithm.RSA2048))

    def check(**changes: object) -> CertState:
        options: dict[str, object] = {
            "certificate": leaf,
            "issuer": issuer,
            "nonce": b"sent",
            "now": NOW,
        }
        options.update(changes)
        return verify_response(der, **options)  # type: ignore[arg-type]

    assert check().status is CertStatus.GOOD
    with pytest.raises(InvalidResponse, match="nonce"):
        check(nonce=b"other")
    with pytest.raises(InvalidResponse, match="outdated"):
        check(now=LATER + timedelta(hours=1))
    with pytest.raises(InvalidResponse, match="future"):
        check(now=NOW - timedelta(hours=1))
    with pytest.raises(InvalidResponse, match="not signed by the parent"):
        check(issuer=stranger)
    with pytest.raises(InvalidResponse, match="another certificate"):
        verify_response(der, certificate=other_leaf, issuer=issuer, nonce=None, now=NOW)
    with pytest.raises(InvalidResponse, match="UNAUTHORIZED"):
        verify_response(
            build_error(ocsp.OCSPResponseStatus.UNAUTHORIZED),
            certificate=leaf,
            issuer=issuer,
            nonce=None,
            now=NOW,
        )
    with pytest.raises(InvalidResponse, match="unreadable"):
        verify_response(b"junk", certificate=leaf, issuer=issuer, nonce=None, now=NOW)
