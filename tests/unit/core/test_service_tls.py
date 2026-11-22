import ipaddress
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from h42pki.core.csr import build_csr, parse_csr
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.core.service_tls import certificate_names, common_name, issue_reason
from tests.x509_helpers import name

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
NAMES = ["pki.home42.test", "localhost", "127.0.0.1"]


def _certificate(
    cn: str | None, names: list[str], *, days_left: float, sans: bool = True
) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = name(CN=cn) if cn else x509.Name([])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(name(CN="ca"))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=days_left))
    )
    if sans:
        general: list[x509.GeneralName] = []
        for value in names:
            try:
                general.append(x509.IPAddress(ipaddress.ip_address(value)))
            except ValueError:
                general.append(x509.DNSName(value))
        builder = builder.add_extension(x509.SubjectAlternativeName(general), critical=False)
    return builder.sign(key, hashes.SHA256())


def test_no_certificate() -> None:
    assert issue_reason(None, NAMES, renew_before_days=15, now=NOW) == "no certificate yet"


def test_valid_certificate_is_kept() -> None:
    cert = _certificate(NAMES[0], NAMES, days_left=30)

    assert issue_reason(cert, NAMES, renew_before_days=15, now=NOW) is None
    # Order of the extra names does not matter, only the set and the CN.
    assert issue_reason(cert, [NAMES[0], NAMES[2], NAMES[1]], renew_before_days=15, now=NOW) is None


@pytest.mark.parametrize(
    ("cn", "names", "days_left", "reason"),
    [
        (NAMES[0], NAMES, -0.001, "expired"),
        (NAMES[0], NAMES, 0, "expired"),
        (NAMES[0], NAMES, 15, "renewal due"),
        (NAMES[0], NAMES, 3, "renewal due"),
        ("other.home42.test", NAMES, 30, "server names changed"),
        (NAMES[0], NAMES[:2], 30, "server names changed"),
        (NAMES[0], [*NAMES, "pki-int"], 30, "server names changed"),
        (None, NAMES, 30, "server names changed"),
    ],
)
def test_reasons(cn: str | None, names: list[str], days_left: float, reason: str) -> None:
    cert = _certificate(cn, names, days_left=days_left)

    result = issue_reason(cert, NAMES, renew_before_days=15, now=NOW)

    assert result is not None and result.startswith(reason)


def test_just_above_the_renewal_threshold() -> None:
    cert = _certificate(NAMES[0], NAMES, days_left=15 + 1 / 86400)

    assert issue_reason(cert, NAMES, renew_before_days=15, now=NOW) is None


def test_certificate_names_and_common_name() -> None:
    cert = _certificate(NAMES[0], NAMES, days_left=1)

    assert certificate_names(cert) == NAMES
    assert common_name(cert) == NAMES[0]
    assert certificate_names(_certificate(None, [], days_left=1, sans=False)) == []
    assert common_name(_certificate(None, [], days_left=1, sans=False)) is None


@pytest.mark.parametrize(
    "algorithm", [KeyAlgorithm.EC_P256, KeyAlgorithm.ED25519, KeyAlgorithm.RSA2048]
)
def test_build_csr(
    key_for: Callable[[KeyAlgorithm], SupportedPrivateKey], algorithm: KeyAlgorithm
) -> None:
    key = key_for(algorithm)
    parsed = parse_csr(build_csr(key, NAMES[0], NAMES))

    assert parsed.subject.common_name == NAMES[0]
    assert [(san.type, san.value) for san in parsed.sans] == [
        ("dns", "pki.home42.test"),
        ("dns", "localhost"),
        ("ip", "127.0.0.1"),
    ]
    assert parsed.csr.is_signature_valid
