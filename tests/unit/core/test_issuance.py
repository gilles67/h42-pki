from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from h42pki.core.errors import InvalidExtensions, InvalidValidity, NotARootCA
from h42pki.core.extensions import Extensions, KeyUsage
from h42pki.core.issuance import (
    CLOCK_SKEW,
    DEFAULT_CA_VALIDITY_DAYS,
    MAX_VALIDITY_DAYS,
    MIN_VALIDITY_DAYS,
    build_self_signed,
)
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.core.names import Subject
from h42pki.core.serial import new_serial_hex
from tests.conftest import ALL_ALGORITHMS

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]

FROZEN = datetime(2026, 11, 21, 12, 34, 56, 789000, tzinfo=UTC)
SUBJECT = Subject(country_name="FR", organization_name="Home42", common_name="h42 Root CA")
ROOT_CA = Extensions.model_validate(
    {
        "basic_constraints": {"ca": True, "path_length": 1},
        "key_usage": {"key_cert_sign": True, "crl_sign": True, "digital_signature": True},
    }
)
EXPECTED_HASH: dict[KeyAlgorithm, type[hashes.HashAlgorithm] | None] = {
    KeyAlgorithm.RSA2048: hashes.SHA256,
    KeyAlgorithm.RSA3072: hashes.SHA256,
    KeyAlgorithm.RSA4096: hashes.SHA256,
    KeyAlgorithm.EC_P256: hashes.SHA256,
    KeyAlgorithm.EC_P384: hashes.SHA384,
    KeyAlgorithm.ED25519: None,
}


def _build(
    key: SupportedPrivateKey,
    *,
    extensions: Extensions = ROOT_CA,
    serial_hex: str | None = None,
    validity_days: int = DEFAULT_CA_VALIDITY_DAYS,
    now: datetime = FROZEN,
) -> x509.Certificate:
    return build_self_signed(
        SUBJECT,
        extensions,
        key,
        serial_hex=serial_hex or new_serial_hex(),
        validity_days=validity_days,
        now=now,
    )


@pytest.mark.parametrize("algorithm", ALL_ALGORITHMS)
def test_self_signed_root_ca(algorithm: KeyAlgorithm, key_for: KeyFor) -> None:
    key = key_for(algorithm)
    serial_hex = new_serial_hex()

    with time_machine.travel(FROZEN, tick=False):
        cert = _build(key, serial_hex=serial_hex, now=datetime.now(UTC))

    assert cert.version is x509.Version.v3
    assert cert.serial_number == int(serial_hex, 16)
    assert cert.subject == cert.issuer == SUBJECT.x509_name()

    # Validity: exact, aware, backdated by the clock skew, truncated to the second (B17).
    expected_not_before = FROZEN.replace(microsecond=0) - CLOCK_SKEW
    assert cert.not_valid_before_utc == expected_not_before
    assert cert.not_valid_after_utc == expected_not_before + timedelta(days=3650)
    assert cert.not_valid_before_utc.tzinfo is not None

    # Extensions and criticality (B12).
    assert len(cert.extensions) == 4
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.critical and basic.value.ca and basic.value.path_length == 1
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert usage.critical and usage.value.key_cert_sign and usage.value.crl_sign
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert not ski.critical and not aki.critical
    assert aki.value.key_identifier == ski.value.digest
    assert ski.value == x509.SubjectKeyIdentifier.from_public_key(key.public_key())

    # Signature hash and signature.
    expected_hash = EXPECTED_HASH[algorithm]
    if expected_hash is None:
        assert cert.signature_hash_algorithm is None
    else:
        assert isinstance(cert.signature_hash_algorithm, expected_hash)
    cert.verify_directly_issued_by(cert)


def test_extended_key_usage_is_included(key_for: KeyFor) -> None:
    extensions = ROOT_CA.model_copy(update={"extended_key_usage": ["ocsp_signing"]})

    cert = _build(key_for(KeyAlgorithm.EC_P256), extensions=extensions)

    assert not cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).critical


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"basic_constraints": {"ca": False}, "key_usage": {"digital_signature": True}},
        {"basic_constraints": {"ca": True}, "key_usage": {"crl_sign": True}},
        {"basic_constraints": {"ca": True}},
    ],
)
def test_non_root_ca_rejected(payload: dict[str, Any], key_for: KeyFor) -> None:
    with pytest.raises(NotARootCA):
        _build(key_for(KeyAlgorithm.EC_P256), extensions=Extensions.model_validate(payload))


@pytest.mark.parametrize("validity_days", [MIN_VALIDITY_DAYS - 1, MAX_VALIDITY_DAYS + 1, -5])
def test_validity_out_of_bounds_rejected(validity_days: int, key_for: KeyFor) -> None:
    with pytest.raises(InvalidValidity):
        _build(key_for(KeyAlgorithm.EC_P256), validity_days=validity_days)


@pytest.mark.parametrize("validity_days", [MIN_VALIDITY_DAYS, 365, MAX_VALIDITY_DAYS])
def test_validity_bounds_accepted(validity_days: int, key_for: KeyFor) -> None:
    cert = _build(key_for(KeyAlgorithm.EC_P256), validity_days=validity_days)

    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=validity_days)


def test_naive_now_rejected(key_for: KeyFor) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        _build(key_for(KeyAlgorithm.EC_P256), now=FROZEN.replace(tzinfo=None))


def test_key_usage_must_fit_the_key(key_for: KeyFor) -> None:
    extensions = ROOT_CA.model_copy(
        update={"key_usage": KeyUsage(key_cert_sign=True, key_encipherment=True)}
    )

    with pytest.raises(InvalidExtensions):
        _build(key_for(KeyAlgorithm.ED25519), extensions=extensions)
