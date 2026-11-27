"""EST through the real launcher: client certificate read from TLS, nothing over HTTP (ADR-0018)."""

import base64
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from h42pki.core.keys import KeyAlgorithm
from h42pki.models import CertificateRequest, Channel
from h42pki.services.settings import SettingsService
from tests.integration.server.test_launcher import PkiFactory, SettingsFactory
from tests.x509_helpers import make_csr, name

CSR_HEADERS = {"Content-Type": "application/pkcs10"}


def csr_body(key_for: Any, host: str) -> bytes:
    csr = make_csr(key_for(KeyAlgorithm.EC_P256), name(CN=host), sans=[f"dns:{host}"])
    return base64.b64encode(csr.public_bytes(serialization.Encoding.DER))


async def test_client_certificate_from_tls(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory, key_for: Any
) -> None:
    pki = await make_pki()
    await SettingsService().set("est.enabled", True, actor="cli")
    async with run_launcher(server_settings()) as running:
        await running.wait_https()
        path = "/.well-known/est/tls_server/simpleenroll"
        async with httpx.AsyncClient(verify=pki.context(with_client_cert=True), timeout=10) as http:
            enrolled = await http.post(
                running.https(path), content=csr_body(key_for, "a.test"), headers=CSR_HEADERS
            )
        async with httpx.AsyncClient(verify=pki.context(), timeout=10) as http:
            anonymous = await http.post(
                running.https(path), content=csr_body(key_for, "b.test"), headers=CSR_HEADERS
            )
        async with httpx.AsyncClient(timeout=10) as http:
            plain_http = await http.get(running.http("/.well-known/est/tls_server/cacerts"))

    assert enrolled.status_code == 200, enrolled.text
    assert pkcs7.load_der_pkcs7_certificates(base64.b64decode(enrolled.content))
    client = x509.load_pem_x509_certificate(pki.client_cert.read_bytes())
    fingerprint = client.fingerprint(hashes.SHA256()).hex()
    request = await CertificateRequest.get(channel=Channel.EST)
    assert request.requester == f"est-cert:{fingerprint}"
    assert anonymous.status_code == 401
    assert plain_http.status_code == 404  # EST is HTTPS only
    assert plain_http.headers["content-type"] == "application/problem+json"
