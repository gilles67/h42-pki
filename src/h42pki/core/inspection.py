"""Read back what a stored certificate contains (its DER is the source of truth)."""

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

from h42pki.core.csr import SanEntry, san_entry
from h42pki.core.errors import InvalidSan


def subject_alternative_names(certificate: x509.Certificate) -> list[SanEntry]:
    """SANs of a certificate; types this project does not issue are skipped."""
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    entries: list[SanEntry] = []
    for name in extension.value:
        try:
            entries.append(san_entry(name))
        except InvalidSan:
            continue
    return entries


def _access_url(certificate: x509.Certificate, method: x509.ObjectIdentifier) -> str | None:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        return None
    for description in extension.value:
        location = description.access_location
        if description.access_method == method and isinstance(
            location, x509.UniformResourceIdentifier
        ):
            return location.value
    return None


def ca_issuers_url(certificate: x509.Certificate) -> str | None:
    """First AIA caIssuers URI of a certificate, if any."""
    return _access_url(certificate, AuthorityInformationAccessOID.CA_ISSUERS)


def ocsp_url(certificate: x509.Certificate) -> str | None:
    """First AIA OCSP URI of a certificate, if any."""
    return _access_url(certificate, AuthorityInformationAccessOID.OCSP)


def crl_distribution_url(certificate: x509.Certificate) -> str | None:
    """First URI of the CRL distribution points of a certificate, if any."""
    try:
        extension = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return None
    for point in extension.value:
        for name in point.full_name or ():
            if isinstance(name, x509.UniformResourceIdentifier):
                return name.value
    return None
