"""``SSLContext`` of the HTTPS listener (ADR-0012): TLS 1.2 or more, optional client certificate.

The ``ssl`` module loads a certificate and its key from files only. They go through a private
temporary directory (``0700``, files ``0600``) removed right after loading; the key file holds
the **encrypted** PKCS#8 key, its one-time password stays in memory (CLAUDE.md section 6.2).
"""

import os
import shutil
import ssl
import tempfile
from pathlib import Path

from h42pki.core.settings_schema import ServerSettings
from h42pki.services.tls_service import TlsMaterial

MIN_VERSIONS = {"tls1.2": ssl.TLSVersion.TLSv1_2, "tls1.3": ssl.TLSVersion.TLSv1_3}


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def load_certificate(context: ssl.SSLContext, material: TlsMaterial) -> None:
    """Load (or reload, hot) the server chain and key into ``context``.

    New connections get the new certificate; established ones keep theirs.
    """
    directory = Path(tempfile.mkdtemp(prefix="h42pki-tls-"))  # mode 0700
    try:
        chain_path = directory / "chain.pem"
        key_path = directory / "key.pem"
        _write_private(chain_path, material.chain_pem)
        _write_private(key_path, material.key_pem)
        context.load_cert_chain(chain_path, key_path, password=material.password)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def build_context(material: TlsMaterial, server: ServerSettings) -> ssl.SSLContext:
    """A new context for the HTTPS listener; the listener-level settings are read here."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = MIN_VERSIONS[server.tls_min_version]
    if server.tls_ciphers is not None:
        context.set_ciphers(server.tls_ciphers)  # TLS 1.2 suites only
    load_certificate(context, material)
    # Optional mTLS: a certificate is requested and verified if presented, never required.
    context.verify_mode = ssl.CERT_OPTIONAL
    context.load_verify_locations(
        cadata=material.anchors_pem + "".join(server.client_trust_anchors)
    )
    context.set_alpn_protocols(["http/1.1"])
    return context
