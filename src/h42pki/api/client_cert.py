"""Client certificate of a request: the only place business code reads it (ADR-0012).

1. The TLS connection itself: ``scope["extensions"]["tls"]``, set by the launcher protocol
   (chain verified by the HTTPS listener).
2. Otherwise, the ``Client-Cert`` header (RFC 9440) **only** when the peer address belongs to
   ``H42_PKI_TRUSTED_PROXIES``; the proxy must remove any incoming header of that name. With
   no trusted proxy (default) the header is always ignored (CLAUDE.md section 6.10).

The peer address is the TCP peer: Uvicorn's proxy headers are disabled by the launcher, so a
client cannot pretend to be a proxy with ``X-Forwarded-For``.
"""

import base64
import binascii
import ipaddress
import logging
from collections.abc import Sequence

from cryptography import x509
from starlette.requests import Request

from h42pki.core.hostnames import IPNetwork

log = logging.getLogger(__name__)

CLIENT_CERT_HEADER = "client-cert"


def _from_tls(request: Request) -> x509.Certificate | None:
    extensions = request.scope.get("extensions") or {}
    tls = extensions.get("tls")
    if not isinstance(tls, dict):
        return None
    chain = tls.get("client_cert_chain") or []
    if not chain:
        return None
    return x509.load_pem_x509_certificate(str(chain[0]).encode("ascii"))


def _peer_is_trusted(request: Request, proxies: Sequence[IPNetwork]) -> bool:
    if not proxies or request.client is None:
        return False
    try:
        address = ipaddress.ip_address(request.client.host)
    except ValueError:
        return False
    return any(address in network for network in proxies)


def parse_client_cert_header(value: str) -> x509.Certificate | None:
    """RFC 9440: a structured-field byte sequence, ``:<base64 DER>:``."""
    value = value.strip()
    if len(value) < 3 or not (value.startswith(":") and value.endswith(":")):
        return None
    try:
        der = base64.b64decode(value[1:-1], validate=True)
        return x509.load_der_x509_certificate(der)
    except (binascii.Error, ValueError):
        return None


def client_certificate(
    request: Request, trusted_proxies: Sequence[IPNetwork]
) -> x509.Certificate | None:
    """The client certificate of ``request``, or None."""
    certificate = _from_tls(request)
    if certificate is not None:
        return certificate
    header = request.headers.get(CLIENT_CERT_HEADER)
    if header is None:
        return None
    if not _peer_is_trusted(request, trusted_proxies):
        log.debug("Client-Cert header ignored: the peer is not a trusted proxy")
        return None
    certificate = parse_client_cert_header(header)
    if certificate is None:
        log.warning("Client-Cert header from a trusted proxy cannot be parsed: ignored")
    return certificate
