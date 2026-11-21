"""Certificate construction (self-signed root CA for now; issuance from a CA comes in lot 5)."""

from datetime import UTC, datetime, timedelta

from cryptography import x509

from h42pki.core.errors import InvalidValidity, NotARootCA
from h42pki.core.extensions import Extensions, validate_for_key
from h42pki.core.keys import SupportedPrivateKey, algorithm_of, signature_hash
from h42pki.core.names import Subject

# Single source of truth, also used by the API request schema.
DEFAULT_CA_VALIDITY_DAYS = 3650
MIN_VALIDITY_DAYS = 1
MAX_VALIDITY_DAYS = 10950  # 30 years
# not_before is backdated to tolerate relying parties whose clock is slightly behind.
CLOCK_SKEW = timedelta(minutes=5)


def check_validity_days(validity_days: int) -> None:
    if not MIN_VALIDITY_DAYS <= validity_days <= MAX_VALIDITY_DAYS:
        raise InvalidValidity(
            f"validity_days must be between {MIN_VALIDITY_DAYS} and {MAX_VALIDITY_DAYS}"
        )


def check_root_ca(extensions: Extensions) -> None:
    """Self-signing is reserved to root CA certificates."""
    basic = extensions.basic_constraints
    usage = extensions.key_usage
    if basic is None or not basic.ca or usage is None or not usage.key_cert_sign:
        raise NotARootCA(
            "self-signing requires basic_constraints.ca = true and key_usage.key_cert_sign = true"
        )


def validity_window(now: datetime, validity_days: int) -> tuple[datetime, datetime]:
    """``(not_before, not_after)`` for a certificate issued at ``now``.

    X.509 encodes times to the second, so ``now`` is truncated: the stored values then equal
    the certificate's, and ``not_after - not_before`` is exactly ``validity_days``.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")  # B17
    check_validity_days(validity_days)
    not_before = now.astimezone(UTC).replace(microsecond=0) - CLOCK_SKEW
    return not_before, not_before + timedelta(days=validity_days)


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
