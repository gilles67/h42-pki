"""Smoke test: root CA (as `h42pki authority init` creates it) -> issued certificate -> download."""

from collections.abc import Callable
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from httpx import AsyncClient

from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.core.names import rfc4514
from h42pki.models import Certificate
from tests.conftest import IssueFactory, RootFactory
from tests.x509_helpers import csr_pem, make_csr, name

ALGORITHMS = [KeyAlgorithm.RSA2048, KeyAlgorithm.EC_P384, KeyAlgorithm.ED25519]
KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]


async def download(client: AsyncClient, cert_id: Any) -> x509.Certificate:
    """Download as PEM and DER, check the media types and that both are the same certificate."""
    pem = await client.get(f"/api/v1/certificates/{cert_id}.pem")
    assert pem.status_code == 200, pem.text
    assert pem.headers["content-type"] == "application/x-pem-file"
    der = await client.get(f"/api/v1/certificates/{cert_id}.crt")
    assert der.status_code == 200, der.text
    assert der.headers["content-type"] == "application/pkix-cert"
    from_pem = x509.load_pem_x509_certificate(pem.content)
    from_der = x509.load_der_x509_certificate(der.content)
    assert from_pem == from_der
    return from_der


@pytest.mark.parametrize("algorithm", ALGORITHMS)
async def test_root_ca_certificate(
    client: AsyncClient, make_root: RootFactory, algorithm: KeyAlgorithm
) -> None:
    authority = await make_root(algorithm)
    record = await Certificate.get(authority=authority)

    response = await client.get(f"/api/v1/certificates/{record.id}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {
        "id",
        "serial_hex",
        "subject_dn",
        "status",
        "not_before",
        "not_after",
        "sha256_fingerprint",
        "profile",
        "channel",
        "issuer",
        "issuer_id",
        "sans",
        "ca_issuers_url",
        "ocsp_url",
        "crl_url",
        "revoked_at",
        "revocation_reason",
        "invalidity_date",
    }
    assert body["status"] == "valid"
    assert body["profile"] is None and body["issuer_id"] is None and body["channel"] == "cli"
    assert body["issuer"] is None and body["sans"] == [] and body["ca_issuers_url"] is None

    root = await download(client, record.id)
    root.verify_directly_issued_by(root)
    assert root.fingerprint(hashes.SHA256()).hex() == body["sha256_fingerprint"]
    assert root.serial_number == int(body["serial_hex"], 16)
    assert rfc4514(root.subject) == body["subject_dn"] == "CN=h42 Test Root CA,O=Home42"


@pytest.mark.parametrize("algorithm", ALGORITHMS)
async def test_issued_tls_server_certificate(
    client: AsyncClient,
    make_root: RootFactory,
    issue: IssueFactory,
    key_for: KeyFor,
    algorithm: KeyAlgorithm,
) -> None:
    authority = await make_root(algorithm)
    root_record = await Certificate.get(authority=authority)
    csr = make_csr(
        key_for(KeyAlgorithm.EC_P256), name(CN="www.example.test"), sans=["dns:www.example.test"]
    )

    request = await issue("tls_server", csr_pem(csr))

    body = (await client.get(f"/api/v1/certificates/{request.certificate_id}")).json()
    assert body["profile"] == "tls_server"
    assert body["issuer_id"] == str(authority.id)
    assert body["issuer"] == "test-root"
    assert body["sans"] == [{"type": "dns", "value": "www.example.test"}]
    assert body["ca_issuers_url"] is None  # the test root has no public base URL
    assert body["channel"] == "api"
    leaf = await download(client, request.certificate_id)
    leaf.verify_directly_issued_by(await download(client, root_record.id))
    assert leaf.fingerprint(hashes.SHA256()).hex() == body["sha256_fingerprint"]


async def test_unknown_certificate_download(client: AsyncClient) -> None:
    response = await client.get("/api/v1/certificates/00000000-0000-0000-0000-000000000000.pem")

    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
