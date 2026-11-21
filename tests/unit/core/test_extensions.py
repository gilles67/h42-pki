from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import ValidationError

from h42pki.core.errors import InvalidExtensions
from h42pki.core.extensions import EKU_OIDS, BasicConstraints, Extensions, validate_for_key
from h42pki.core.keys import KeyAlgorithm

CA = {"basic_constraints": {"ca": True}, "key_usage": {"key_cert_sign": True, "crl_sign": True}}


def _built(extensions: Extensions) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=UTC))
    )
    return extensions.apply(builder).sign(key, hashes.SHA256())


# --- BasicConstraints (B10) ---------------------------------------------------------------


def test_path_length_absent_by_default() -> None:
    assert BasicConstraints(ca=True).path_length is None
    assert BasicConstraints().path_length is None


def test_path_length_allowed_for_ca() -> None:
    assert BasicConstraints(ca=True, path_length=0).path_length == 0


def test_path_length_forbidden_without_ca() -> None:
    with pytest.raises(ValidationError, match="path_length is only allowed when ca is true"):
        BasicConstraints(ca=False, path_length=0)


def test_negative_path_length_rejected() -> None:
    with pytest.raises(ValidationError):
        BasicConstraints(ca=True, path_length=-1)


def test_ca_without_path_length_is_unconstrained() -> None:
    cert = _built(Extensions.model_validate(CA))

    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.value.ca is True
    assert basic.value.path_length is None


# --- KeyUsage ------------------------------------------------------------------------------


def test_key_cert_sign_forbidden_without_ca() -> None:
    with pytest.raises(ValidationError, match="key_cert_sign requires"):
        Extensions.model_validate({"key_usage": {"key_cert_sign": True}})
    with pytest.raises(ValidationError, match="key_cert_sign requires"):
        Extensions.model_validate(
            {"basic_constraints": {"ca": False}, "key_usage": {"key_cert_sign": True}}
        )


@pytest.mark.parametrize("flag", ["encipher_only", "decipher_only"])
def test_encipher_decipher_only_require_key_agreement(flag: str) -> None:
    with pytest.raises(ValidationError, match="require key_agreement"):
        Extensions.model_validate({"key_usage": {flag: True}})

    extensions = Extensions.model_validate({"key_usage": {flag: True, "key_agreement": True}})
    assert extensions.key_usage is not None


def test_empty_key_usage_rejected() -> None:
    with pytest.raises(ValidationError, match="at least one usage"):
        Extensions.model_validate({"key_usage": {}})


def test_key_usage_is_critical() -> None:
    cert = _built(Extensions.model_validate(CA))

    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.critical
    assert usage.value.key_cert_sign and usage.value.crl_sign
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).critical


# --- Extended key usage (B9) --------------------------------------------------------------


def test_extended_key_usage_is_applied_and_not_critical() -> None:
    cert = _built(Extensions.model_validate({"extended_key_usage": ["server_auth", "client_auth"]}))

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert not eku.critical
    assert list(eku.value) == [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]


def test_no_extended_key_usage_extension_when_empty() -> None:
    cert = _built(Extensions.model_validate(CA))

    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)


def test_every_eku_name_has_an_oid() -> None:
    extensions = Extensions.model_validate({"extended_key_usage": list(EKU_OIDS)})

    assert len(extensions.extended_key_usage) == 6


@pytest.mark.parametrize("eku", [["ServerAuthentication"], ["server_auth", "server_auth"], ["any"]])
def test_invalid_extended_key_usage_rejected(eku: list[str]) -> None:
    with pytest.raises(ValidationError):
        Extensions.model_validate({"extended_key_usage": eku})


# --- Algorithm-dependent rules --------------------------------------------------------------

NON_RSA = [KeyAlgorithm.EC_P256, KeyAlgorithm.EC_P384, KeyAlgorithm.ED25519]
NON_EC = [KeyAlgorithm.RSA2048, KeyAlgorithm.RSA3072, KeyAlgorithm.RSA4096, KeyAlgorithm.ED25519]


@pytest.mark.parametrize("algorithm", NON_RSA)
@pytest.mark.parametrize("flag", ["key_encipherment", "data_encipherment"])
def test_encipherment_requires_rsa(algorithm: KeyAlgorithm, flag: str) -> None:
    extensions = Extensions.model_validate({"key_usage": {flag: True}})

    with pytest.raises(InvalidExtensions, match="require an RSA key"):
        validate_for_key(extensions, algorithm)
    validate_for_key(extensions, KeyAlgorithm.RSA2048)


@pytest.mark.parametrize("algorithm", NON_EC)
def test_key_agreement_requires_ec(algorithm: KeyAlgorithm) -> None:
    extensions = Extensions.model_validate({"key_usage": {"key_agreement": True}})

    with pytest.raises(InvalidExtensions, match="requires an EC key"):
        validate_for_key(extensions, algorithm)
    validate_for_key(extensions, KeyAlgorithm.EC_P384)


@pytest.mark.parametrize("algorithm", list(KeyAlgorithm))
def test_ca_usages_accepted_for_every_algorithm(algorithm: KeyAlgorithm) -> None:
    validate_for_key(Extensions.model_validate(CA), algorithm)


def test_no_key_usage_always_accepted() -> None:
    validate_for_key(Extensions(), KeyAlgorithm.ED25519)


# --- snake_case only (ADR-0006) -------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"BasicConstraints": {"ca": True}},
        {"basic_constraints": {"CertificateAuthority": True, "PathLength": 0}},
        {"basic_constraints": {"ca": True, "PathLength": 0}},
        {"key_usage": {"KeyCertSign": True}},
        {"ExtendedKeyUsage": ["server_auth"]},
    ],
)
def test_pascal_case_rejected(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Extensions.model_validate(payload)
