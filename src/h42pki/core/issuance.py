"""Certificate construction: the root CA certificate and certificates issued by a CA."""

from datetime import datetime

from cryptography import x509

from h42pki.core.errors import NotARootCA
from h42pki.core.extensions import Extensions, validate_for_key
from h42pki.core.keys import SupportedPrivateKey, algorithm_of, signature_hash
from h42pki.core.names import Subject
from h42pki.core.validity import (
    CLOCK_SKEW,
    DEFAULT_CA_VALIDITY_DAYS,
    MAX_VALIDITY_DAYS,
    MIN_VALIDITY_DAYS,
    check_validity_days,
    validity_window,
)

__all__ = [
    "CLOCK_SKEW",
    "DEFAULT_CA_VALIDITY_DAYS",
    "MAX_VALIDITY_DAYS",
    "MIN_VALIDITY_DAYS",
    "build_self_signed",
    "check_root_ca",
    "check_validity_days",
    "validity_window",
]


def check_root_ca(extensions: Extensions) -> None:
    """Self-signing is reserved to root CA certificates."""
    basic = extensions.basic_constraints
    usage = extensions.key_usage
    if basic is None or not basic.ca or usage is None or not usage.key_cert_sign:
        raise NotARootCA(
            "self-signing requires basic_constraints.ca = true and key_usage.key_cert_sign = true"
        )


def build_self_signed(
    subject: Subject,
    extensions: Extensions,
    private_key: SupportedPrivateKey,
    *,
    serial_hex: str,
    validity_days: int,
    now: datetime,
) -> x509.Certificate:
    """Build and sign a self-signed root CA certificate (B12, B17)."""
    check_root_ca(extensions)
    validate_for_key(extensions, algorithm_of(private_key))
    not_before, not_after = validity_window(now, validity_days)

    name = subject.x509_name()
    public_key = private_key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(int(serial_hex, 16))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    builder = extensions.apply(builder)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    ).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)

    certificate = builder.sign(private_key, signature_hash(private_key))
    certificate.verify_directly_issued_by(certificate)
    return certificate
