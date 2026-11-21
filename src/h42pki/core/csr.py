"""Certificate signing requests: parsing and validation.

A CSR only contributes its public key, its subject and its subject alternative names; every
other requested extension is listed as ignored and never copied into a certificate (B2,
CLAUDE.md section 6.3).
"""

from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from h42pki.core.errors import InvalidCsr, InvalidSan
from h42pki.core.keys import KeyAlgorithm, public_key_algorithm
from h42pki.core.names import NameAttributes, name_attributes
from h42pki.core.profiles import SanType

MIN_RSA_KEY_SIZE = 2048

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


def _san_entry(name: x509.GeneralName) -> SanEntry:
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


def parse_csr(data: bytes | str) -> ParsedCsr:
    """Parse and validate a PEM or DER CSR."""
    csr = _load(data)
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
            sans = tuple(_san_entry(name) for name in extension.value)
        else:
            ignored.append(_extension_label(extension))

    return ParsedCsr(
        csr=csr,
        key_algorithm=key_algorithm,
        subject=name_attributes(csr.subject),
        sans=sans,
        ignored_extensions=tuple(ignored),
    )
