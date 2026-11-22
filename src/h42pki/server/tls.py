"""ASGI TLS extension (https://asgi.readthedocs.io/en/latest/specs/tls.html), built per connection.

Uvicorn does not implement it; the launcher protocol (``server.protocol``) puts it in
``scope["extensions"]["tls"]``, where a compliant ASGI server would.
"""

import ssl
from typing import Any

from cryptography import x509

# TLS versions as numbered by the ASGI TLS extension (IANA protocol version).
TLS_VERSIONS = {"TLSv1.2": 0x0303, "TLSv1.3": 0x0304}


def tls_extension(ssl_object: ssl.SSLObject) -> dict[str, Any]:
    """The ``tls`` extension of one TLS connection (client certificate and verified chain)."""
    leaf_der = ssl_object.getpeercert(binary_form=True)
    chain_pem: list[str] = []
    client_cert_name: str | None = None
    if leaf_der:
        # Python >= 3.13 (ADR-0014): the verified chain, leaf first, then the issuers.
        chain_pem = [ssl.DER_cert_to_PEM_cert(der) for der in ssl_object.get_verified_chain()]
        client_cert_name = x509.load_der_x509_certificate(leaf_der).subject.rfc4514_string()
    return {
        "server_cert": None,
        "client_cert_chain": chain_pem,
        "client_cert_name": client_cert_name,
        # With CERT_OPTIONAL a certificate that fails verification aborts the handshake: a
        # connection that reaches the application never carries a verification error.
        "client_cert_error": None,
        "tls_version": TLS_VERSIONS.get(ssl_object.version() or ""),
        "cipher_suite": None,  # the IANA number is not exposed by the ssl module
    }
