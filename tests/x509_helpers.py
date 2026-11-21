"""Helpers to build CSRs in tests."""

import ipaddress
from collections.abc import Iterable, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from h42pki.core.keys import SupportedPrivateKey

OIDS = {
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
    "emailAddress": NameOID.EMAIL_ADDRESS,
}


def name(**attributes: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(OIDS[key], value) for key, value in attributes.items()])


def general_name(san: str) -> x509.GeneralName:
    """``dns:example.test``, ``ip:192.0.2.1``, ``email:a@b``, ``uri:https://…``."""
    kind, _, value = san.partition(":")
    match kind:
        case "dns":
            return x509.DNSName(value)
        case "ip":
            return x509.IPAddress(ipaddress.ip_address(value))
        case "email":
            return x509.RFC822Name(value)
        case "uri":
            return x509.UniformResourceIdentifier(value)
    raise ValueError(san)


def _hash(key: SupportedPrivateKey) -> hashes.SHA256 | None:
    return None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()


def make_csr(
    key: SupportedPrivateKey | rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    subject: x509.Name | None = None,
    *,
    sans: Sequence[str] = (),
    extensions: Iterable[tuple[x509.ExtensionType, bool]] = (),
) -> x509.CertificateSigningRequest:
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject or x509.Name([]))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([general_name(san) for san in sans]), critical=False
        )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(key, _hash(key))


def csr_pem(csr: x509.CertificateSigningRequest) -> str:
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
