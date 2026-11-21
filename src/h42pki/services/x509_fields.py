"""Database columns derived from a signed certificate (the DER stays the source of truth)."""

from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from h42pki.core.keys import spki_der
from h42pki.core.names import rfc4514


def signed_fields(certificate: x509.Certificate) -> dict[str, Any]:
    return {
        "serial_hex": format(certificate.serial_number, "x"),
        "der": certificate.public_bytes(serialization.Encoding.DER),
        "public_key_der": spki_der(certificate.public_key()),
        "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
        "subject_dn": rfc4514(certificate.subject),
        "not_before": certificate.not_valid_before_utc,
        "not_after": certificate.not_valid_after_utc,
    }
