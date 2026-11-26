"""Where a CA publishes: public base URL, AIA caIssuers, CRL and OCSP URLs, CA names."""

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from h42pki.core.errors import InvalidAuthorityName, InvalidPublicBaseUrl

# A CA name appears in URLs (/ca/{name}.crt): keep it to a DNS-label-like set of characters.
AUTHORITY_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")
# Names the public routes use for something else (/ca/chain.pem).
RESERVED_AUTHORITY_NAMES = frozenset({"chain"})

HTTPS_WARNING = (
    "an https public base URL may cause validation loops: a client may need the CA certificate "
    "to validate the TLS connection that serves it (RFC 5280 section 4.2.2.1 recommends http)"
)


@dataclass(frozen=True)
class PublicBaseUrl:
    url: str
    warnings: list[str] = field(default_factory=list)


def validate_authority_name(name: str) -> str:
    if not AUTHORITY_NAME.fullmatch(name):
        raise InvalidAuthorityName(
            f"invalid CA name {name!r}: lowercase letters, digits and inner hyphens, "
            "64 characters at most"
        )
    if name in RESERVED_AUTHORITY_NAMES:
        raise InvalidAuthorityName(f"the CA name {name!r} is reserved")
    return name


def normalize_public_base_url(url: str) -> PublicBaseUrl:
    """Validate and normalize the public HTTP base URL of a CA (no trailing slash)."""
    raw = url.strip()
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidPublicBaseUrl(f"public base URL must use http or https, not {url!r}")
    if not parts.hostname:
        raise InvalidPublicBaseUrl(f"public base URL has no host: {url!r}")
    if parts.username is not None or parts.password is not None:
        raise InvalidPublicBaseUrl("public base URL must not contain credentials")
    if parts.query or "?" in raw:
        raise InvalidPublicBaseUrl("public base URL must not contain a query string")
    if parts.fragment or "#" in raw:
        raise InvalidPublicBaseUrl("public base URL must not contain a fragment")
    normalized = f"{scheme}://{parts.netloc.lower()}{parts.path.rstrip('/')}"
    warnings = [HTTPS_WARNING] if scheme == "https" else []
    return PublicBaseUrl(url=normalized, warnings=warnings)


def ca_certificate_url(public_base_url: str, authority_name: str) -> str:
    """URL of the CA certificate (DER), as written in the AIA caIssuers of issued certificates."""
    return f"{public_base_url}/ca/{authority_name}.crt"


def crl_url(public_base_url: str, authority_name: str) -> str:
    """URL of the CRL of a CA, as written in the CRL distribution points (ADR-0017)."""
    return f"{public_base_url}/crl/{authority_name}.crl"


def ocsp_url(public_base_url: str) -> str:
    """URL of the OCSP responder of the container, as written in the AIA (ADR-0017)."""
    return f"{public_base_url}/ocsp"
