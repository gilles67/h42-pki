from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from h42pki.core.chain import (
    ancestor_name,
    check_issued_ca,
    fingerprint_of,
    load_chain,
    normalize_fingerprint,
    verify_parent_chain,
)
from h42pki.core.csr import build_ca_csr, parse_csr
from h42pki.core.errors import FingerprintMismatch, InvalidChain, InvalidIssuedCertificate
from h42pki.core.names import Subject
from h42pki.core.publication import validate_authority_name
from tests.x509_helpers import name

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


@dataclass
class Ca:
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate


def make_ca(
    cn: str,
    issuer: Ca | None = None,
    *,
    path_length: int | None = None,
    ca: bool = True,
    cert_sign: bool = True,
    key: ec.EllipticCurvePrivateKey | None = None,
    start: timedelta = timedelta(days=-1),
    end: timedelta = timedelta(days=100),
) -> Ca:
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(CN=cn))
        .issuer_name(issuer.cert.subject if issuer else name(CN=cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW + start)
        .not_valid_after(NOW + end)
        .add_extension(x509.BasicConstraints(ca, path_length if ca else None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, cert_sign, cert_sign, False, False),
            critical=True,
        )
    )
    return Ca(key, builder.sign(issuer.key if issuer else key, hashes.SHA256()))


def check(*chain: Ca, fingerprint: str | None = None) -> None:
    certs = [ca.cert for ca in chain]
    verify_parent_chain(certs, fingerprint or fingerprint_of(certs[0]), now=NOW)


def test_fingerprints() -> None:
    cert = make_ca("root").cert
    expected = fingerprint_of(cert)
    colons = ":".join(expected.upper()[i : i + 2] for i in range(0, 64, 2))

    assert normalize_fingerprint(f" {colons}\n") == expected
    for bad in ("", "abc", "g" * 64, "a" * 63, "a" * 65):
        with pytest.raises(InvalidChain):
            normalize_fingerprint(bad)


def test_valid_chains() -> None:
    root = make_ca("root", path_length=2)
    intermediate = make_ca("int", root, path_length=1)

    check(root)
    check(intermediate, root)


def test_wrong_fingerprint_comes_first() -> None:
    root = make_ca("root", path_length=0)  # also wrong, but never looked at
    with pytest.raises(FingerprintMismatch):
        check(root, fingerprint="0" * 64)
    with pytest.raises(FingerprintMismatch):
        verify_parent_chain([], "0" * 64, now=NOW)


def test_incoherent_chains() -> None:
    root = make_ca("root")
    intermediate = make_ca("int", root)
    other_root = make_ca("root")  # same name, other key
    chains: list[tuple[list[Ca], str]] = [
        ([intermediate], "not a self-signed root"),
        ([intermediate, other_root], "not signed by the next"),
        ([root, intermediate], "not signed by the next"),
        ([make_ca("x", ca=False)], "not a CA"),
        ([make_ca("x", cert_sign=False)], "not a CA"),
        ([make_ca("x", path_length=0)], "leaves no room"),
        ([intermediate, make_ca("root", path_length=1, key=root.key)], "leaves no room"),
        ([make_ca("x", end=timedelta(0))], "validity period"),
        ([make_ca("x", start=timedelta(seconds=1))], "validity period"),
    ]
    for chain, message in chains:
        with pytest.raises(InvalidChain, match=message):
            check(*chain)


def test_load_chain() -> None:
    pem = make_ca("root").cert.public_bytes(serialization.Encoding.PEM)

    assert len(load_chain(pem * 2)) == 2
    with pytest.raises(InvalidChain, match="more than 16"):
        load_chain(pem * 17)
    for bad in (b"", b"garbage"):
        with pytest.raises(InvalidChain):
            load_chain(bad)


def test_issued_certificate() -> None:
    root = make_ca("root", path_length=2)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = parse_csr(build_ca_csr(key, Subject(common_name="child")))
    other = make_ca("root", path_length=2)

    good = make_ca("child", root, key=key, path_length=1)
    assert check_issued_ca(good.cert, csr, root.cert, now=NOW) == 1

    cases = [
        (make_ca("child", root, path_length=1), "another key"),
        (make_ca("other", root, key=key, path_length=1), "another subject"),
        (make_ca("child", other, key=key, path_length=1), "not signed by the parent"),
        (make_ca("child", root, key=key, ca=False), "not a CA"),
        (make_ca("child", root, key=key, path_length=2), "exceeds the pathLen"),
        (make_ca("child", root, key=key), "exceeds the pathLen"),
        (make_ca("child", root, key=key, path_length=1, end=timedelta(0)), "validity"),
        (make_ca("child", root, key=key, path_length=1, end=timedelta(days=101)), "outlives"),
    ]
    for ca, message in cases:
        with pytest.raises(InvalidIssuedCertificate, match=message):
            check_issued_ca(ca.cert, csr, root.cert, now=NOW)


def test_ca_csr_has_no_extension() -> None:
    csr = parse_csr(
        build_ca_csr(
            ec.generate_private_key(ec.SECP384R1()),
            Subject(common_name="child", organization_name="Home42"),
        )
    )
    assert csr.subject.organization_name == "Home42"
    assert csr.sans == () and csr.ignored_extensions == ()


@pytest.mark.parametrize("cn", ["Home42 Root CA", "é", "-", "X" * 200, "a/../b"])
def test_ancestor_names_are_valid(cn: str) -> None:
    cert = make_ca(cn[:64]).cert
    assert validate_authority_name(ancestor_name(cert)) == ancestor_name(cert)
    assert ancestor_name(cert).endswith(fingerprint_of(cert)[:12])
