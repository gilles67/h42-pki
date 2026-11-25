"""Validation of CA chains, child side of the federation (ADR-0015). Pure.

The child has no prior trust anchor: the SHA-256 fingerprint of the parent CA certificate, given
with the invitation, is the only thing it believes. Everything else is checked against it.
"""

import hmac
import re
from collections.abc import Sequence
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from h42pki.core.csr import ParsedCsr
from h42pki.core.errors import FingerprintMismatch, InvalidChain, InvalidIssuedCertificate
from h42pki.core.keys import spki_der

MAX_CHAIN_CERTIFICATES = 16
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")


def normalize_fingerprint(text: str) -> str:
    """64 lowercase hexadecimal digits; colons (``openssl``) and upper case accepted."""
    fingerprint = text.strip().replace(":", "").lower()
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise InvalidChain("the fingerprint must be a SHA-256: 64 hexadecimal digits")
    return fingerprint


def fingerprint_of(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


def load_chain(pem: bytes) -> list[x509.Certificate]:
    try:
        chain = x509.load_pem_x509_certificates(pem)
    except ValueError:
        raise InvalidChain("the chain is not a list of PEM certificates") from None
    if len(chain) > MAX_CHAIN_CERTIFICATES:
        raise InvalidChain(f"the chain has more than {MAX_CHAIN_CERTIFICATES} certificates")
    return chain


def _issued_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        certificate.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def _ca_path_length(certificate: x509.Certificate) -> int | None:
    """pathLen of a CA certificate that may sign certificates; ValueError otherwise."""
    try:
        basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        raise ValueError("missing basic constraints or key usage") from None
    if not basic.ca or not usage.key_cert_sign:
        raise ValueError("not a CA certificate")
    return basic.path_length


def verify_parent_chain(
    chain: Sequence[x509.Certificate], fingerprint: str, *, now: datetime
) -> None:
    """``chain``: parent CA first, self-signed root last. The fingerprint is checked first."""
    if not chain or not hmac.compare_digest(fingerprint_of(chain[0]), fingerprint):
        raise FingerprintMismatch(
            "the certificate of the parent CA does not have the expected fingerprint: wrong URL, "
            "wrong fingerprint, or someone in between"
        )
    for index, certificate in enumerate(chain):
        subject = certificate.subject.rfc4514_string()
        try:
            path_length = _ca_path_length(certificate)
        except ValueError as exc:
            raise InvalidChain(f"{subject}: {exc}") from None
        # CAs that will stand below this one: the new CA and the previous ones of the chain.
        if path_length is not None and path_length < index + 1:
            raise InvalidChain(f"{subject}: its pathLen {path_length} leaves no room for a new CA")
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            raise InvalidChain(f"{subject}: outside its validity period")
        issuer = chain[index + 1] if index + 1 < len(chain) else certificate
        if not _issued_by(certificate, issuer):
            raise InvalidChain(
                f"{subject} is not signed by the next certificate of the chain"
                if issuer is not certificate
                else f"{subject} ends the chain but is not a self-signed root"
            )


def check_issued_ca(
    certificate: x509.Certificate, csr: ParsedCsr, parent: x509.Certificate, *, now: datetime
) -> int | None:
    """Check the CA certificate received for ``csr``; returns its pathLen."""
    if spki_der(certificate.public_key()) != spki_der(csr.public_key):
        raise InvalidIssuedCertificate("the received certificate is for another key")
    if certificate.subject != csr.csr.subject:
        raise InvalidIssuedCertificate("the received certificate has another subject")
    if certificate.issuer != parent.subject or not _issued_by(certificate, parent):
        raise InvalidIssuedCertificate("the received certificate is not signed by the parent CA")
    try:
        path_length = _ca_path_length(certificate)
    except ValueError as exc:
        raise InvalidIssuedCertificate(f"the received certificate is refused: {exc}") from None
    ceiling = _ca_path_length(parent)
    if ceiling is not None and (path_length is None or path_length >= ceiling):
        raise InvalidIssuedCertificate("the received certificate exceeds the pathLen of the parent")
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise InvalidIssuedCertificate("the received certificate is outside its validity period")
    if certificate.not_valid_after_utc > parent.not_valid_after_utc:
        raise InvalidIssuedCertificate("the received certificate outlives the parent CA")
    return path_length


def ancestor_name(certificate: x509.Certificate) -> str:
    """Local name of an ancestor CA: certificates do not carry CA names (deterministic)."""
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    text = str(names[0].value).lower() if names else "ca"
    slug = re.sub(r"[^a-z0-9]+", "-", text).strip("-")[:48].strip("-") or "ca"
    return f"{slug}-{fingerprint_of(certificate)[:12]}"
