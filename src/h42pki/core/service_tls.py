"""When the built-in HTTPS server certificate must be (re)issued (ADR-0013). Pure."""

from collections.abc import Sequence
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID

from h42pki.core.inspection import subject_alternative_names


def certificate_names(certificate: x509.Certificate) -> list[str]:
    """DNS and IP SANs of a certificate, in order."""
    return [
        san.value for san in subject_alternative_names(certificate) if san.type in ("dns", "ip")
    ]


def common_name(certificate: x509.Certificate) -> str | None:
    attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attributes[0].value) if attributes else None


def issue_reason(
    certificate: x509.Certificate | None,
    names: Sequence[str],
    *,
    renew_before_days: int,
    now: datetime,
) -> str | None:
    """Why a new certificate is needed, or None when the current one is fine.

    Renewal is computed from the expiry date of the certificate in service, not from a counter:
    it survives a container stopped for days or a manual reissue.
    """
    if certificate is None:
        return "no certificate yet"
    not_after = certificate.not_valid_after_utc
    if not_after <= now:
        return "expired"
    if common_name(certificate) != names[0] or set(certificate_names(certificate)) != set(names):
        return "server names changed"
    if not_after - now <= timedelta(days=renew_before_days):
        return f"renewal due ({renew_before_days} days or fewer left)"
    return None
