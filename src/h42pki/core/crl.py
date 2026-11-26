"""Certificate revocation lists (RFC 5280 section 5): one full CRL per CA, no delta (ADR-0017).

Pure: the caller reads the revoked certificates and the CA key, this module builds and signs.
Revocation is final: ``certificate_hold`` and ``remove_from_crl`` are never used.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from cryptography import x509

from h42pki.core.errors import InvalidRevocation, ProfileViolation
from h42pki.core.keys import SupportedPrivateKey, signature_hash

# Reasons a revocation may carry: every RFC 5280 reason but the suspension ones.
SUSPENSION_REASONS = frozenset(
    {x509.ReasonFlags.certificate_hold, x509.ReasonFlags.remove_from_crl}
)
REVOCATION_REASONS = tuple(
    reason for reason in x509.ReasonFlags if reason not in SUSPENSION_REASONS
)


class RevocationReason(StrEnum):
    """Names accepted by the API and the CLI: ``x509.ReasonFlags`` names, suspension excluded."""

    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    CA_COMPROMISE = "ca_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    PRIVILEGE_WITHDRAWN = "privilege_withdrawn"
    AA_COMPROMISE = "aa_compromise"


def revocation_reason(name: str) -> x509.ReasonFlags:
    """The RFC 5280 reason named ``name`` (snake_case, as ``x509.ReasonFlags``); 422 otherwise."""
    try:
        reason = x509.ReasonFlags[name]
    except KeyError:
        allowed = ", ".join(reason.name for reason in REVOCATION_REASONS)
        raise InvalidRevocation(f"unknown revocation reason {name!r} (one of {allowed})") from None
    if reason in SUSPENSION_REASONS:
        raise InvalidRevocation(
            f"{reason.name} is a suspension: revocation is final on this CA (no certificateHold)"
        )
    return reason


def check_invalidity_date(invalidity_date: datetime | None, now: datetime) -> None:
    """The date the key is known or suspected to be compromised: aware, and not in the future."""
    if invalidity_date is None:
        return
    if invalidity_date.tzinfo is None:
        raise InvalidRevocation("invalidity_date must carry a time zone")
    if invalidity_date > now:
        raise InvalidRevocation("invalidity_date cannot be in the future")


@dataclass(frozen=True)
class RevokedEntry:
    serial_hex: str
    revoked_at: datetime
    reason: x509.ReasonFlags | None
    invalidity_date: datetime | None
    not_after: datetime  # an expired certificate leaves the CRL


def listed(entries: Iterable[RevokedEntry], now: datetime) -> list[RevokedEntry]:
    """Entries that still belong in the CRL: revoked certificates not expired yet."""
    return sorted(
        (entry for entry in entries if entry.not_after > now), key=lambda entry: entry.revoked_at
    )


def _authority_key_identifier(issuer_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    try:
        ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        raise ProfileViolation("the CA certificate has no subject key identifier") from None
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)


def _revoked(entry: RevokedEntry) -> x509.RevokedCertificate:
    builder = (
        x509.RevokedCertificateBuilder()
        .serial_number(int(entry.serial_hex, 16))
        .revocation_date(entry.revoked_at.replace(microsecond=0))
    )
    if entry.reason is not None and entry.reason is not x509.ReasonFlags.unspecified:
        # RFC 5280 section 5.3.1: the reason code unspecified should be absent.
        builder = builder.add_extension(x509.CRLReason(entry.reason), critical=False)
    if entry.invalidity_date is not None:
        builder = builder.add_extension(
            x509.InvalidityDate(entry.invalidity_date.replace(microsecond=0)), critical=False
        )
    return builder.build()


def build_crl(
    issuer_cert: x509.Certificate,
    issuer_key: SupportedPrivateKey,
    entries: Sequence[RevokedEntry],
    *,
    crl_number: int,
    now: datetime,
    validity_hours: int,
) -> x509.CertificateRevocationList:
    """Build and sign the full CRL of a CA; expired entries are left out.

    ``thisUpdate`` is ``now`` to the second, ``nextUpdate`` ``validity_hours`` later; extensions
    ``CRLNumber`` and ``AuthorityKeyIdentifier`` (non-critical). The signature is checked.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if crl_number < 1:
        raise ValueError("a CRL number is a positive integer")
    this_update = now.replace(microsecond=0)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(this_update)
        .next_update(this_update + timedelta(hours=validity_hours))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(_authority_key_identifier(issuer_cert), critical=False)
    )
    for entry in listed(entries, now):
        builder = builder.add_revoked_certificate(_revoked(entry))
    crl = builder.sign(issuer_key, signature_hash(issuer_key))
    if not crl.is_signature_valid(issuer_key.public_key()):  # pragma: no cover - defensive
        raise ValueError("the CRL signature does not verify")
    return crl


def crl_due(next_update: datetime | None, now: datetime, *, regenerate_before_hours: int) -> bool:
    """A new CRL is due when there is none, or ``regenerate_before_hours`` before nextUpdate."""
    return next_update is None or now >= next_update - timedelta(hours=regenerate_before_hours)
