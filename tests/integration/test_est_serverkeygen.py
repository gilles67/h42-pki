"""EST serverkeygen (RFC 7030 section 4.4) and the stored copy of the key (ADR-0018)."""

import base64
import logging
from email import message_from_bytes
from email.message import Message
from pathlib import Path

import pytest
from click.testing import Result
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from httpx import AsyncClient, Response
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.core.keys import KeyAlgorithm
from h42pki.keystore import KeyStore
from h42pki.models import (
    AuditLog,
    Certificate,
    CertificateRequest,
    Channel,
    KeyPurpose,
    PrivateKey,
)
from h42pki.services.tls_service import TlsServiceManager
from tests.cli_helpers import plain
from tests.integration.test_est import EST, KeyFor, basic, csr_body
from tests.integration.test_est import est as est  # noqa: PLC0414 - fixture
from tests.x509_helpers import make_csr, name

pytestmark = pytest.mark.usefixtures("est")


async def serverkeygen(client: AsyncClient, body: bytes, *, label: str = "tls_server") -> Response:
    return await client.post(
        f"{EST}/{label}/serverkeygen",
        content=body,
        headers={"Content-Type": "application/pkcs10", **basic()},
    )


def parts(response: Response) -> tuple[bytes, x509.Certificate]:
    """The PKCS#8 key and the certificate of a multipart/mixed answer."""
    assert response.status_code == 200, response.text
    content_type = response.headers["content-type"]
    assert content_type.startswith("multipart/mixed; boundary=")
    assert response.headers["cache-control"] == "no-store"
    message = message_from_bytes(
        f"Content-Type: {content_type}\r\n\r\n".encode() + response.content
    )
    payload = message.get_payload()
    assert isinstance(payload, list)
    key_part, cert_part = payload
    assert isinstance(key_part, Message) and isinstance(cert_part, Message)
    assert key_part.get_content_type() == "application/pkcs8"
    assert cert_part["Content-Type"] == "application/pkcs7-mime; smime-type=certs-only"
    key_der = key_part.get_payload(decode=True)
    certs_der = cert_part.get_payload(decode=True)
    assert isinstance(key_der, bytes) and isinstance(certs_der, bytes)
    [certificate] = pkcs7.load_der_pkcs7_certificates(certs_der)
    return key_der, certificate


def ca_csr(key_for: KeyFor, algorithm: KeyAlgorithm) -> bytes:
    csr = make_csr(key_for(algorithm), name(CN="Keygen Sub CA"))
    return base64.b64encode(csr.public_bytes(serialization.Encoding.DER))


async def test_key_generated_delivered_and_kept_encrypted(
    client: AsyncClient, key_for: KeyFor, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    body = csr_body(key_for, "keygen.example.test")

    key_der, certificate = parts(await serverkeygen(client, body))

    key = serialization.load_der_private_key(key_der, password=None)
    assert key.public_key() == certificate.public_key()
    client_key = key_for(KeyAlgorithm.EC_P256)
    assert certificate.public_key() != client_key.public_key()  # not the key of the CSR
    assert certificate.subject.rfc4514_string() == "CN=keygen.example.test"
    record = await Certificate.get(
        sha256_fingerprint=certificate.fingerprint(hashes.SHA256()).hex()
    )
    assert record.channel is Channel.EST and record.private_key_id is not None
    stored = await PrivateKey.get(id=record.private_key_id)
    assert stored.purpose is KeyPurpose.SERVERKEYGEN and stored.algorithm is KeyAlgorithm.EC_P256
    assert key_der not in stored.encrypted_key
    with pytest.raises((TypeError, ValueError)):
        serialization.load_der_private_key(stored.encrypted_key, password=None)  # encrypted
    shown = (await client.get(f"/api/v1/certificates/{record.id}")).json()
    assert shown["has_stored_private_key"] is True
    assert "PRIVATE KEY" not in caplog.text
    assert base64.b64encode(key_der).decode()[:40] not in caplog.text
    audit = " ".join(str(entry.details) for entry in await AuditLog.all())
    assert base64.b64encode(key_der).decode()[:40] not in audit
    assert await AuditLog.exists(action="est.serverkeygen.deliver")


async def test_the_key_is_delivered_once(client: AsyncClient, key_for: KeyFor) -> None:
    body = csr_body(key_for, "once.example.test")
    parts(await serverkeygen(client, body))

    again = await serverkeygen(client, body)

    assert again.status_code == 409 and "already delivered" in again.text
    assert await CertificateRequest.filter(channel=Channel.EST).count() == 1


async def test_manual_approval_and_algorithm_fallback(client: AsyncClient, key_for: KeyFor) -> None:
    """sub_ca refuses RSA 2048: the key is generated with the first algorithm it allows."""
    body = ca_csr(key_for, KeyAlgorithm.RSA2048)

    first = await serverkeygen(client, body, label="sub_ca")
    [request] = await CertificateRequest.filter(channel=Channel.EST)
    assert await PrivateKey.filter(purpose=KeyPurpose.SERVERKEYGEN).count() == 0  # not yet
    await client.post(f"/api/v1/requests/{request.id}/approve")
    key_der, certificate = parts(await serverkeygen(client, body, label="sub_ca"))
    again = await serverkeygen(client, body, label="sub_ca")

    assert first.status_code == 202 and "retry-after" in first.headers
    key = serialization.load_der_private_key(key_der, password=None)
    assert isinstance(key, rsa.RSAPrivateKey) and key.key_size == 3072
    assert key.public_key() == certificate.public_key()
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert again.status_code == 409


async def test_deleted_key_is_not_delivered(client: AsyncClient, key_for: KeyFor) -> None:
    body = ca_csr(key_for, KeyAlgorithm.EC_P384)
    await serverkeygen(client, body, label="sub_ca")
    [request] = await CertificateRequest.filter(channel=Channel.EST)
    approved = (await client.post(f"/api/v1/requests/{request.id}/approve")).json()

    deleted = await client.delete(f"/api/v1/certificates/{approved['certificate_id']}/private-key")
    retry = await serverkeygen(client, body, label="sub_ca")

    assert deleted.status_code == 204
    assert retry.status_code == 409 and "deleted" in retry.text


# --- deleting the stored copy -----------------------------------------------------------------


async def test_delete_through_the_api(client: AsyncClient, key_for: KeyFor) -> None:
    _, certificate = parts(await serverkeygen(client, csr_body(key_for, "del.example.test")))
    record = await Certificate.get(
        sha256_fingerprint=certificate.fingerprint(hashes.SHA256()).hex()
    )
    url = f"/api/v1/certificates/{record.id}/private-key"

    deleted = await client.delete(url)
    again = await client.delete(url)

    assert deleted.status_code == 204
    assert again.status_code == 404
    assert await PrivateKey.filter(purpose=KeyPurpose.SERVERKEYGEN).count() == 0
    shown = (await client.get(f"/api/v1/certificates/{record.id}")).json()
    assert shown["has_stored_private_key"] is False and shown["status"] == "valid"
    entry = await AuditLog.get(action="private_key.delete")
    assert entry.details["purpose"] == "serverkeygen"


async def test_other_keys_cannot_be_deleted(client: AsyncClient, keystore: KeyStore) -> None:
    ca = await Certificate.get(authority_id__not_isnull=True)
    https = (await TlsServiceManager(keystore, ["pki.home42.test"]).ensure()).certificate
    assert https is not None

    for record in (ca, https):
        response = await client.delete(f"/api/v1/certificates/{record.id}/private-key")
        assert response.status_code == 409
        assert (await Certificate.get(id=record.id)).private_key_id is not None


async def test_no_route_returns_a_stored_key(client: AsyncClient) -> None:
    spec = (await client.get("/openapi.json")).json()

    key_paths = [path for path in spec["paths"] if path.endswith("/private-key")]

    assert key_paths == ["/api/v1/certificates/{certificate_id}/private-key"]
    assert set(spec["paths"][key_paths[0]]) == {"delete"}


# --- CLI --------------------------------------------------------------------------------------


def test_cli_delete_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from h42pki.cli._runtime import run
    from h42pki.config import ENV_PREFIX, Settings, get_settings
    from h42pki.keystore import get_keystore
    from h42pki.services import IssuanceService
    from tests.conftest import TEST_PASSPHRASE
    from tests.x509_helpers import csr_pem

    database = tmp_path / "data" / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", TEST_PASSPHRASE)
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    get_settings.cache_clear()
    runner = CliRunner()
    runner.invoke(app, ["authority", "init", "--name", "root", "--common-name", "Root CA"])

    async def operation(settings: Settings) -> str:
        from cryptography.hazmat.primitives.asymmetric import ec

        csr = make_csr(
            ec.generate_private_key(ec.SECP256R1()), name(CN="x.test"), sans=["dns:x.test"]
        )
        request = await IssuanceService(get_keystore(settings)).submit(
            csr=csr_pem(csr),
            profile_name="tls_server",
            validity_days=None,
            actor="cli",
            server_keygen=True,
        )
        return str(request.certificate_id)

    certificate_id = run(operation)

    def invoke(*args: str) -> Result:
        return runner.invoke(app, list(args))

    deleted = invoke("certificate", "delete-key", certificate_id)
    again = invoke("certificate", "delete-key", certificate_id)

    assert deleted.exit_code == 0, deleted.output
    assert "deleted" in plain(deleted)
    assert again.exit_code == 1 and "no private key" in plain(again)
