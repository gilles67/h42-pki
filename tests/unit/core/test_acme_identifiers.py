"""ACME identifiers, CSR of finalize and status transitions (RFC 8555, RFC 8738)."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from h42pki.core.acme import states
from h42pki.core.acme.errors import AcmeError
from h42pki.core.acme.identifiers import Identifier, check_csr, parse_identifiers
from h42pki.core.csr import parse_csr
from tests.acme_client import csr_der

NOW = datetime(2026, 11, 28, tzinfo=UTC)
LATER = NOW + timedelta(days=1)


def dns(*values: str) -> list[dict[str, str]]:
    return [{"type": "dns", "value": value} for value in values]


def code(function: object, *args: object, **kwargs: object) -> str:
    with pytest.raises(AcmeError) as raised:
        function(*args, **kwargs)  # type: ignore[operator]
    return raised.value.code


def test_parse_normalizes_and_deduplicates() -> None:
    parsed = parse_identifiers(
        dns("WWW.Example.Test.", "www.example.test", "api.example.test"),
        allow_wildcard=False,
        allow_ip=False,
    )

    assert parsed == [Identifier("dns", "www.example.test"), Identifier("dns", "api.example.test")]


def test_wildcards_and_ips_when_allowed() -> None:
    parsed = parse_identifiers(
        [*dns("*.Example.test"), {"type": "ip", "value": "2001:DB8::1"}],
        allow_wildcard=True,
        allow_ip=True,
    )

    assert parsed == [Identifier("dns", "*.example.test"), Identifier("ip", "2001:db8::1")]
    assert parsed[0].wildcard and parsed[0].authorized_value == "example.test"
    assert not parsed[1].wildcard and parsed[1].authorized_value == "2001:db8::1"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (dns("*.example.test"), "rejectedIdentifier"),  # wildcard not allowed
        (dns("*.*.example.test"), "rejectedIdentifier"),
        (dns("a..example.test"), "rejectedIdentifier"),
        (dns("192.0.2.1"), "rejectedIdentifier"),  # an IP as dns
        (dns("single"), "rejectedIdentifier"),
        ([{"type": "ip", "value": "192.0.2.1"}], "unsupportedIdentifier"),
        ([{"type": "email", "value": "a@b.test"}], "unsupportedIdentifier"),
        ([{"type": "dns"}], "malformed"),
        ([], "malformed"),
        ("www.example.test", "malformed"),
        (dns(*(f"n{i}.example.test" for i in range(101))), "rejectedIdentifier"),
    ],
)
def test_refused(raw: object, expected: str) -> None:
    assert code(parse_identifiers, raw, allow_wildcard=False, allow_ip=False) == expected


def test_bad_ip() -> None:
    raw = [{"type": "ip", "value": "999.1.1.1"}]

    assert code(parse_identifiers, raw, allow_wildcard=True, allow_ip=True) == "malformed"


@pytest.fixture(scope="module")
def key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def test_csr_matches(key: ec.EllipticCurvePrivateKey) -> None:
    identifiers = [Identifier("dns", "a.example.test"), Identifier("ip", "192.0.2.1")]
    parsed = parse_csr(
        csr_der(key, ["A.example.test"], common_name="a.example.test", ips=["192.0.2.1"])
    )

    check_csr(parsed, identifiers)  # no error


@pytest.mark.parametrize(
    ("names", "common_name"),
    [
        (["a.example.test", "b.example.test"], None),
        ([], "a.example.test"),  # no SAN at all
        (["a.example.test"], "b.example.test"),
    ],
)
def test_csr_refused(
    key: ec.EllipticCurvePrivateKey, names: list[str], common_name: str | None
) -> None:
    parsed = parse_csr(csr_der(key, names, common_name=common_name))

    assert code(check_csr, parsed, [Identifier("dns", "a.example.test")]) == "badCSR"


def test_csr_with_other_subject_attribute(key: ec.EllipticCurvePrivateKey) -> None:
    der = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X")]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("a.example.test")]), False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )

    assert code(check_csr, parse_csr(der), [Identifier("dns", "a.example.test")]) == "badCSR"


def test_authorization_transitions() -> None:
    status = states.authorization_status

    assert status("pending", ["pending"], expires_at=LATER, now=NOW) == "pending"
    assert status("pending", ["processing", "valid"], expires_at=LATER, now=NOW) == "valid"
    assert status("pending", ["invalid", "invalid"], expires_at=LATER, now=NOW) == "invalid"
    assert status("pending", ["invalid", "pending"], expires_at=LATER, now=NOW) == "pending"
    assert status("pending", ["pending"], expires_at=NOW, now=NOW) == "expired"
    assert status("deactivated", ["valid"], expires_at=LATER, now=NOW) == "deactivated"


def test_order_transitions() -> None:
    status = states.order_status

    assert status("pending", ["valid", "pending"], expires_at=LATER, now=NOW) == "pending"
    assert status("pending", ["valid", "valid"], expires_at=LATER, now=NOW) == "ready"
    assert status("pending", ["valid", "invalid"], expires_at=LATER, now=NOW) == "invalid"
    assert status("ready", ["valid"], expires_at=NOW, now=NOW) == "invalid"
    assert status("pending", ["deactivated"], expires_at=LATER, now=NOW) == "invalid"
    assert status("processing", ["valid"], expires_at=NOW, now=NOW) == "processing"
    requests = ("pending", "issued", "rejected", "failed")
    assert [states.order_status_of_request(s) for s in requests] == [
        "processing", "valid", "invalid", "invalid",
    ]  # fmt: skip
