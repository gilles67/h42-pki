"""Certificate signing requests: parsing and validation.

A CSR only contributes its public key, its subject and its subject alternative names; every
other requested extension is listed as ignored and never copied into a certificate (B2,
CLAUDE.md section 6.3).
"""

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.x509.oid import NameOID

from h42pki.core.errors import InvalidCsr, InvalidSan
from h42pki.core.hostnames import is_ip_address
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey, public_key_algorithm, signature_hash
from h42pki.core.names import NameAttributes, Subject, name_attributes
from h42pki.core.profiles import SanType

MIN_RSA_KEY_SIZE = 2048
# Broken hash functions: a CSR signed with them is refused even if the signature verifies.
WEAK_HASHES = (hashes.SHA1, hashes.MD5)

PEM_MARKER = b"-----BEGIN"


@dataclass(frozen=True)
class SanEntry:
    type: SanType
    value: str


@dataclass(frozen=True)
class ParsedCsr:
    csr: x509.CertificateSigningRequest
    key_algorithm: KeyAlgorithm
    subject: NameAttributes
    sans: tuple[SanEntry, ...]
    ignored_extensions: tuple[str, ...]

    @property
    def public_key(self) -> CertificatePublicKeyTypes:
        return self.csr.public_key()


def _load(data: bytes | str) -> x509.CertificateSigningRequest:
    raw = data.encode("ascii", errors="replace") if isinstance(data, str) else data
    try:
        if raw.lstrip().startswith(PEM_MARKER):
            return x509.load_pem_x509_csr(raw.strip())
        return x509.load_der_x509_csr(raw)
    except ValueError:
        raise InvalidCsr("the CSR cannot be parsed (PEM or DER PKCS#10 expected)") from None


def san_entry(name: x509.GeneralName) -> SanEntry:
    """Map a supported general name to a :class:`SanEntry` (dns, ip, email, uri)."""
    if isinstance(name, x509.DNSName):
        return SanEntry("dns", name.value)
    if isinstance(name, x509.IPAddress):
        return SanEntry("ip", str(name.value))
    if isinstance(name, x509.RFC822Name):
        return SanEntry("email", name.value)
    if isinstance(name, x509.UniformResourceIdentifier):
        return SanEntry("uri", name.value)
    raise InvalidSan(f"SAN type {type(name).__name__} is not supported (dns, ip, email, uri)")


def _extension_label(extension: x509.Extension[x509.ExtensionType]) -> str:
    kind = type(extension.value).__name__
    dotted = extension.oid.dotted_string
    return dotted if kind == "UnrecognizedExtension" else f"{kind} ({dotted})"


def _check_signature_hash(csr: x509.CertificateSigningRequest) -> None:
    try:
        algorithm = csr.signature_hash_algorithm  # None for Ed25519
    except UnsupportedAlgorithm:
        raise InvalidCsr("the CSR signature algorithm is not supported") from None
    if isinstance(algorithm, WEAK_HASHES):
        raise InvalidCsr(
            f"CSRs signed with {algorithm.name.upper()} are refused; sign it with SHA-256 or better"
        )


def parse_csr(data: bytes | str) -> ParsedCsr:
    """Parse and validate a PEM or DER CSR."""
    csr = _load(data)
    _check_signature_hash(csr)  # before the signature check, for an explicit message (B36)
    if not csr.is_signature_valid:
        raise InvalidCsr("the CSR signature is invalid")

    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < MIN_RSA_KEY_SIZE:
        raise InvalidCsr(f"RSA keys must have at least {MIN_RSA_KEY_SIZE} bits")
    key_algorithm = public_key_algorithm(public_key)

    try:
        extensions = list(csr.extensions)
    except (ValueError, x509.DuplicateExtension):
        raise InvalidCsr("the CSR extensions cannot be parsed") from None

    sans: tuple[SanEntry, ...] = ()
    ignored: list[str] = []
    for extension in extensions:
        if isinstance(extension.value, x509.SubjectAlternativeName):
            sans = tuple(san_entry(name) for name in extension.value)
        else:
            ignored.append(_extension_label(extension))

    return ParsedCsr(
        csr=csr,
        key_algorithm=key_algorithm,
        subject=name_attributes(csr.subject),
        sans=sans,
        ignored_extensions=tuple(ignored),
    )


def build_csr(key: SupportedPrivateKey, common_name: str, names: Sequence[str]) -> bytes:
    """DER CSR for a server key held here: CN plus DNS / IP SANs (built-in HTTPS server).

    The key is handed over by the service, as for the CA key; the CSR then follows the same
    issuance path as any other request (ADR-0013).
    """
    general_names: list[x509.GeneralName] = [
        x509.IPAddress(ipaddress.ip_address(name)) if is_ip_address(name) else x509.DNSName(name)
        for name in names
    ]
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName(general_names), critical=False)
        .sign(key, signature_hash(key))
    )
    return csr.public_bytes(serialization.Encoding.DER)


def build_ca_csr(key: SupportedPrivateKey, subject: Subject) -> bytes:
    """DER CSR of a subordinate CA: key and subject only, the parent decides the extensions."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject.x509_name())
        .sign(key, signature_hash(key))
    )
    return csr.public_bytes(serialization.Encoding.DER)
